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
Client ──[trust/password]──▶ pgb-iam ──[IAM token]──▶ PostgreSQL
                               │
                               └── PoolManager ── holds ServerStreams
```

1. **Client connection**: Authenticates to pgb-iam locally (`trust` or `password`)
2. **Backend connection**: pgb-iam authenticates to PostgreSQL using IAM tokens (AWS RDS `GenerateDBAuthToken`)
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
| Per-database pool size | ✅ | ❌ | Single global `max_size` |
| Per-user pool size | ✅ | ❌ | Single global `max_size` |
| Reserve pool | ✅ | ❌ | Emergency connections when pool exhausted |
| LIFO / round-robin | ✅ | ❌ | FIFO only |
| Min pool size (warm-up) | ✅ | ❌ | No pre-warming |

### Authentication

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Cleartext password | ✅ | ✅ | IAM token sent as cleartext |
| MD5 password | ✅ | ✅ | IAM token MD5-hashed with server salt |
| SCRAM-SHA-256 | ✅ | ❌ | Parsed but not handled |
| PAM | ✅ | ❌ | Not implemented |
| LDAP | ✅ | ❌ | Not implemented |
| TLS client cert | ✅ | ❌ | `with_no_client_auth()` |
| HBA (host-based) | ✅ | ❌ | `trust` / `password` only |
| `auth_query` (DB lookup) | ✅ | ❌ | Not implemented |
| **AWS RDS IAM** | ❌ | ✅ | Full `GenerateDBAuthToken` integration |
| **GCP Cloud SQL IAM** | ❌ | ⚠️ | Stub only |
| **Auto token refresh** | ❌ | ✅ | Background task, 5-min cycle |

### TLS

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Client TLS | ✅ Full | ⚠️ | `enabled: bool` only; no verify modes |
| Server TLS | ✅ Full | ⚠️ | `connect_with_tls: bool` only |
| Cipher / protocol selection | ✅ | ❌ | Uses rustls defaults |
| Client cert validation | ✅ | ❌ | Not implemented |

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
| Per-database settings | ✅ | ❌ | Single target backend |
| Per-user settings | ✅ | ❌ | Single `db_user` |
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
├── auth/            IAM token providers (AWS SDK) + token cache with auto-refresh
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
max_size = 10
idle_timeout_secs = 300
target_host = "your-db.xxxxxx.us-east-1.rds.amazonaws.com"
target_port = 5432
dbname = "postgres"
db_user = "iam_user"

[client_auth]
type = "trust"              # trust | password
# password = "mypassword"   # required if type = "password"

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

## License

MIT
