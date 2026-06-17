# pgb-iam — IAM-Aware PostgreSQL Connection Pooler

## The Problem

PgBouncer is the de facto PostgreSQL connection pooler, but it has a glaring gap in 2025+: **IAM-based database authentication**.

Teams running PostgreSQL on AWS RDS or GCP Cloud SQL want to use IAM auth (short-lived tokens via AWS `GenerateDBAuthToken` or GCP's Cloud SQL IAM) instead of static passwords. However, PgBouncer's auth model is built around static password files (`userlist.txt`) or SCRAM authentication. Getting IAM tokens to work with PgBouncer requires:

- External cron jobs or sidecars that refresh tokens every ~15 minutes
- Writing tokens to files that PgBouncer re-reads via `auth_query`
- Complex `auth_user` setups with shadow tables
- No native token refresh — if a token expires, connections start failing until manual intervention

This is fragile, operationally expensive, and undermines the security benefits of IAM auth.

## The Solution

**pgb-iam** is a PostgreSQL connection pooler built from the ground up for cloud-native deployments. It natively understands IAM authentication and handles token lifecycle automatically.

### Core Design

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Client   │ ──▶ │  pgb-iam  │ ──▶ │ Postgres  │
│  (psql)   │ ◀── │  :6432   │ ◀── │  :5432   │
└──────────┘     └──────────┘     └──────────┘
                      │
                      ▼
              ┌──────────────┐
              │ IAM Provider  │
              │ (AWS/GCP)     │
              └──────────────┘
```

### Two-Level Authentication

```
Client ──[trust|password|SCRAM|cert|PAM|LDAP|HBA]──▶ pgb-iam ──[IAM token|SCRAM|MD5|cleartext]──▶ PostgreSQL
                                                       │
                                                       └── PoolManager ── holds ServerStreams
```

1. **Client connection**: Authenticates to pgb-iam locally via any of 8 methods: `trust`, `password` (cleartext), `scram-sha-256` (SASL), `cert` (TLS client certificate), `PAM`, `LDAP`, `hba` (pg_hba.conf-style rules), or `auth_query` (dynamic DB lookup)
2. **Backend connection**: pgb-iam authenticates to PostgreSQL using IAM tokens (AWS RDS `GenerateDBAuthToken` / GCP Cloud SQL IAM) — supports `cleartext`, `MD5`, and `SCRAM-SHA-256` SASL for the backend auth handshake
3. **Pooling**: Already-authenticated backend connections are stored in a per-`(host, port, db_user, dbname)` pool
4. **Token lifecycle**: Tokens are cached and auto-refreshed via background task (10-min TTL, 5-min refresh check)

### Why Rust

- **Performance**: Async I/O with Tokio — ideal for connection pooling, zero-cost abstractions, no GC pauses
- **Safety**: No buffer overflows or use-after-free in the critical network path
- **Ecosystem**: First-class AWS SDK, async Postgres protocol support, Prometheus instrumentation

## Feature Comparison with PgBouncer

### Pooling

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Session pooling | ✅ | ✅ | Server assigned for client lifetime |
| Transaction pooling | ✅ | ✅ | Server released on ReadyForQuery('I') |
| Statement pooling | ✅ | ❌ | Not implemented |
| Per-database pool size | ✅ | ✅ | `[pool.database_limits]` table |
| Per-user pool size | ✅ | ✅ | `[pool.user_limits]` table |
| Reserve pool | ✅ | ✅ | `reserve_size` — burst beyond `max_size` |
| LIFO / round-robin | ✅ | ✅ | LIFO default; `strategy = "fifo"` opt-in |
| Min pool size (warm-up) | ✅ | ✅ | `min_size` — background spawn after relay |

### Authentication

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|---|
| Cleartext password | ✅ | ✅ | IAM token sent as cleartext |
| MD5 password | ✅ | ✅ | IAM token MD5-hashed with server salt |
| SCRAM-SHA-256 | ✅ | ✅ | Full SASL exchange (server + client) |
| PAM | ✅ | ✅ | Custom FFI — no external dependencies |
| LDAP | ✅ | ✅ | Async ldap3 bind + search + user verification |
| TLS client cert | ✅ | ✅ | `client_ca` config, `WebPkiClientVerifier` |
| HBA (host-based) | ✅ | ✅ | Inline matching by conn_type/db/user/address/TLS |
| `auth_query` (DB lookup) | ✅ | ✅ | `SELECT ... FROM pg_shadow WHERE usename = $1` |
| **AWS RDS IAM** | ❌ | ✅ | Full `GenerateDBAuthToken` integration |
| **GCP Cloud SQL IAM** | ❌ | ⚠️ | Stub only |
| **Auto token refresh** | ❌ | ✅ | Background task, 5-min cycle |

### TLS

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|---|
| Client TLS | ✅ Full | ✅ | rustls accept with optional client CA |
| Server TLS | ✅ Full | ⚠️ | `connect_with_tls: bool` only |
| Cipher / protocol selection | ✅ | ❌ | Uses rustls defaults |
| Client cert validation | ✅ | ✅ | `client_ca` → `WebPkiClientVerifier` |

### Protocol

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Wire protocol (startup, auth, relay) | ✅ | ✅ | Full basic flow |
| SSLRequest / TLS upgrade | ✅ | ✅ | rustls accept/connect |
| Extended query protocol | ✅ | ⚠️ | Relayed as opaque bytes |
| Prepared statement tracking | ✅ | ❌ | Not tracked |
| Cancel request | ✅ | ❌ | Not parsed |
| Replication protocol | ✅ | ❌ | Not implemented |

### Timeouts

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| `server_idle_timeout` | ✅ | ✅ | `idle_timeout_secs` in config |
| `server_lifetime` | ✅ | ❌ | No max connection age |
| `server_connect_timeout` | ✅ | ❌ | No connect deadline |
| `query_timeout` | ✅ | ❌ | Not implemented |
| `client_idle_timeout` | ✅ | ❌ | Not implemented |
| `transaction_timeout` | ✅ | ❌ | Not implemented |
| `query_wait_timeout` | ✅ | ❌ | Not implemented |

### Admin & Monitoring

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Admin console (`psql pgbouncer`) | ✅ | ❌ | HTTP JSON API instead |
| SHOW commands (stats, pools, clients) | ✅ | ❌ | `GET /stats`, `GET /health` |
| RECONNECT / PAUSE / RESUME / RELOAD | ✅ | ❌ | No live admin commands |
| Online restart (`-R`) | ✅ | ❌ | Restart required for config changes |
| Prometheus metrics | ⚠️ via SHOW + exporter | ✅ | Native `GET /metrics` |

### Configuration

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Config format | INI | TOML | Cleaner format |
| Per-database settings | ✅ | ✅ | `[pool.database_limits]` table |
| Per-user settings | ✅ | ✅ | `[pool.user_limits]` table |
| Online reload (SIGHUP) | ✅ | ❌ | Not implemented |

### Other

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Unix sockets | ✅ | ❌ | TCP only |
| SO_REUSEPORT (multi-process) | ✅ | ❌ | Single-process async |
| `server_reset_query` | ✅ | ✅ | `DISCARD ALL` (configurable) |
| `PoolManager` + `PoolKey` | ❌ | ✅ | Keyed by `(host, port, db_user, dbname)` |
| `ServerStream` (Plain/TLS) | ❌ | ✅ | Unified I/O enum |
| Two-level auth (local + IAM) | ❌ | ✅ | Unique to pgb-iam |

## Quick Start

```bash
# Build
cargo build --release

# Configure
cp config.toml config.toml
# edit config.toml with your RDS endpoint and IAM settings

# Run
./target/release/pgb-iam -c config.toml

# Metrics
curl http://127.0.0.1:9090/metrics
```

## Architecture

```
src/
├── main.rs          Entry point, config loading, runtime setup
├── config/          TOML config deserialization (listen, pool, client_auth, iam, tls, metrics, admin, health_check)
├── pool/            PoolManager — maps of pools keyed by (host, port, db_user, dbname), acquire/release lifecycle
├── proxy/           TCP relay + IAM auth injection + pool mode dispatch
│   ├── mod.rs       Handler: client TLS → startup → local auth → pool acquire → relay
│   ├── health.rs    Periodic backend health checks (TCP connect)
│   └── admin.rs     HTTP admin API (GET /stats, GET /health)
├── pgproto/         PostgreSQL wire protocol parser (startup, SSL, auth messages, relay)
├── auth/            IAM token providers, SCRAM, HBA, auth_query, PAM, LDAP + token cache
│   ├── aws.rs       AWS RDS GenerateDBAuthToken
│   ├── gcp.rs       GCP Cloud SQL IAM (stub)
│   ├── cache.rs     Token cache with auto-refresh (10-min TTL)
│   ├── scram.rs     SCRAM-SHA-256 client + server
│   ├── hba.rs       HBA rule parser (conn_type/db/user/address matching)
│   ├── auth_query.rs Dynamic password lookup from PostgreSQL
│   ├── pam_ffi.rs   Minimal PAM FFI (libpam bindings)
│   ├── pam.rs       PAM authentication wrapper
│   └── ldap.rs      LDAP authentication (async ldap3)
├── tls/             TLS accept/connect (rustls + tokio-rustls)
└── metrics/         Prometheus endpoint (GET /metrics)
```

## Configuration

```toml
[listen]
addr = "127.0.0.1"
port = 6432

[pool]
mode = "session"            # session | transaction
strategy = "lifo"           # lifo (default) | fifo
max_size = 10
min_size = 2
reserve_size = 2
idle_timeout_secs = 300
target_host = "your-db.xxxxxx.us-east-1.rds.amazonaws.com"
target_port = 5432
dbname = "postgres"
db_user = "iam_user"

[pool.database_limits]
"postgres" = { max_size = 20, min_size = 1 }

[pool.user_limits]
"admin" = { max_size = 15, reserve_size = 5 }

[client_auth]
# type = "trust"             # trust | password | scram-sha-256 | cert | pam | ldap | hba | auth_query
# password = "mypassword"    # required for password / scram-sha-256
# client_ca = "ca.pem"       # required for cert auth
# pam_service = "pgb-iam"    # required for pam auth

# For auth_query:
# [client_auth.auth_query]
# user = "pgb_iam_auth"
# query = "SELECT passwd FROM pg_shadow WHERE usename = $1"

# For LDAP:
# [client_auth.ldap]
# uri = "ldap://ldap.example.com"
# bind_dn = "cn=admin,dc=example,dc=com"
# bind_password = "admin_pass"
# search_base = "dc=example,dc=com"
# search_filter = "(uid=$1)"

# For HBA (rules are evaluated in order, first match wins):
# [[client_auth.hba_rules]]
# type = "hostssl"
# database = ["all"]
# user = ["all"]
# address = "0.0.0.0/0"
# auth = "cert"
# [[client_auth.hba_rules]]
# type = "host"
# database = ["mydb"]
# user = ["admin"]
# address = "10.0.0.0/8"
# auth = "scram-sha-256"

[metrics]
enabled = true
listen_addr = "127.0.0.1"
listen_port = 9090

[admin]
enabled = true
listen_addr = "127.0.0.1"
listen_port = 9091

[health_check]
enabled = true
interval_secs = 30
timeout_secs = 5

[tls]
enabled = false
cert_path = "server.crt"
key_path = "server.key"
connect_with_tls = false

[iam]
provider = "aws"            # aws | gcp | none
region = "us-east-1"
instance_host = "your-db.xxxxxx.us-east-1.rds.amazonaws.com"
instance_port = 5432
db_user = "iam_user"
```

## Authentication Methods

### Client Auth (method → how pgb-iam verifies the client)

| Method | Description |
|---|---|
| `trust` | No password required — accepts all connections |
| `password` | Cleartext password — matched against `password` field or `auth_query` |
| `scram-sha-256` | SASL SCRAM-SHA-256 exchange — password from `password` or `auth_query` |
| `cert` | TLS client certificate — validated against `client_ca` root |
| `pam` | Delegates to system PAM service (e.g., `/etc/pam.d/pgb-iam`) |
| `ldap` | Binds as admin, searches for user DN, then rebinds as user |
| `hba` | Evaluates `hba_rules` in order — each rule specifies method + filter |
| `auth_query` | Queries PostgreSQL (`SELECT passwd FROM pg_shadow`) for dynamic password |

### Backend Auth (how pgb-iam authenticates to PostgreSQL)

Once the client is authenticated, pgb-iam connects to PostgreSQL using IAM tokens or passwords. The backend auth flow automatically selects the method requested by the server:

1. **Cleartext** — IAM password token sent directly
2. **MD5** — IAM token MD5-hashed with server salt (`md5{hash}`)
3. **SCRAM-SHA-256** — Full SASL client exchange using IAM token as password

### HBA Rule Evaluation

HBA rules are processed **in order** for each connection. The first matching rule determines the auth method:

```
[[client_auth.hba_rules]]
type = "hostssl"     # hostssl | hostnossl | host | local
database = ["all"]   # "all", "sameuser", or specific DB names
user = ["all"]       # "all" or specific user names
address = "0.0.0.0/0"  # CIDR notation
auth = "cert"        # trust | reject | password | scram-sha-256 | cert | pam | ldap
```

If no rule matches, the connection is **rejected**.

## License

MIT
