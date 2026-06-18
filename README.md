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

```mermaid
flowchart LR
    C["Client<br/>(psql)"] <-->|":6432"| P["pgb-iam"]
    P <-->|":5432"| PG[("PostgreSQL<br/>(RDS / Cloud SQL)")]

    I[("IAM Provider<br/>(AWS / GCP)")] -.->|"token"| P

    style C fill:#1a1a2e,stroke:#e94560,color:#fff
    style P fill:#16213e,stroke:#0f3460,color:#fff
    style PG fill:#1a1a2e,stroke:#00b4d8,color:#fff
    style I fill:#1a1a2e,stroke:#e9c46a,color:#fff
```

### Two-Level Authentication

```mermaid
flowchart LR
    CL["Client"] -->|"trust / password / scram / cert /<br/>PAM / LDAP / HBA / auth_query"| PO["pgb-iam"]
    PO -->|"IAM token (cleartext / MD5 / SCRAM)"| PG["PostgreSQL"]

    PO --> PM["PoolManager<br/>holds ServerStreams<br/>keyed by (host,port,db,user)"]

    style CL fill:#1a1a2e,stroke:#e94560,color:#fff
    style PO fill:#16213e,stroke:#0f3460,color:#fff
    style PG fill:#1a1a2e,stroke:#00b4d8,color:#fff
    style PM fill:#16213e,stroke:#e9c46a,color:#fff
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
|---|---|---|---|
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
|---|---|---|---|
| Client TLS | ✅ Full | ✅ | rustls accept with optional client CA |
| Server TLS | ✅ Full | ⚠️ | `connect_with_tls: bool` only |
| Cipher / protocol selection | ✅ | ✅ | Configurable via `ciphers` and `min_protocol_version` |
| Client cert validation | ✅ | ✅ | `client_ca` → `WebPkiClientVerifier` |

### Protocol

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| Wire protocol (startup, auth, relay) | ✅ | ✅ | Full basic flow |
| SSLRequest / TLS upgrade | ✅ | ✅ | rustls accept/connect |
| Extended query protocol | ✅ | ⚠️ | Message types defined; relayed as opaque bytes |
| Prepared statement tracking | ✅ | ✅ | Tracked per connection; DEALLOCATE on release |
| Cancel request | ✅ | ✅ | Parsed and forwarded on separate backend connection |
| Replication protocol | ✅ | ❌ | Not implemented |

### Timeouts

| Feature | PgBouncer | pgb-iam | Notes |
|---|---|---|---|
| `server_idle_timeout` | ✅ | ✅ | `idle_timeout_secs` in config |
| `server_lifetime` | ✅ | ✅ | `server_lifetime_secs` — enforced on pool release |
| `server_connect_timeout` | ✅ | ✅ | `server_connect_timeout_secs` — in `create_backend` |
| `query_timeout` | ✅ | ❌ | Not implemented |
| `client_idle_timeout` | ✅ | ✅ | Enforced in `transaction_loop` |
| `transaction_timeout` | ✅ | ✅ | Enforced in `transaction_loop` |
| `query_wait_timeout` | ✅ | ✅ | Enforced in `transaction_loop` |

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

## Pool Lifecycle

```mermaid
flowchart TD
    A["Client connects<br/>psql -h :6432"] --> B["Parse Startup / SSLRequest / Cancel"]

    B --> C{"Message type?"}
    C -->|Cancel| D["Forward cancel<br/>to backend"]
    D --> E["Done"]
    C -->|SSLRequest| F["TLS upgrade<br/>rustls accept"]
    F --> G["Re-read Startup"]
    G --> H
    C -->|Startup| H["Extract (user, db, params)"]

    H --> I["Authenticate client<br/>trust | password | scram | cert<br/>PAM | LDAP | HBA | auth_query"]

    I --> J["PoolManager.acquire(key)"]

    J --> K{"Idle connection<br/>in pool?"}
    K -->|Yes| L["Pop from idle pool<br/>(LIFO / FIFO)"]
    K -->|No| M["sem.acquire()<br/>wait for permit"]

    M --> N["create_backend()<br/>TCP → TLS → Startup → Auth<br/>IAM token (cleartext/MD5/SCRAM)"]
    N --> O["Return new backend<br/>to caller"]

    L --> P["Return idle backend<br/>to caller"]
    O --> P

    P --> Q{"Pool mode?"}

    Q -->|Transaction| R["Release backend to idle<br/>IMMEDIATELY (before any I/O)"]
    R --> S["send_fake_ready()"]
    S --> T["transaction_loop()"]

    T --> U["Wait for client msg<br/>(no server assigned)"]
    U --> V["Client sends query"]
    V --> W["acquire_backend()<br/>pool.acquire → idle or new"]
    W --> X["Forward query to server"]
    X --> Y["Forward response to client"]
    Y --> Z{"ReadyForQuery('I')?"}
    Z -->|Yes| AA["run_reset_query()<br/>pool.release() → idle"]
    AA --> U
    Z -->|No| T

    Q -->|Session| AB["send_fake_ready()"]
    AB --> AC["relay_and_release()<br/>copy_bidirectional<br/>(holds backend for session)"]
    AC --> AD["run_reset_query()"]
    AD -->|success| AE["pool.release()"]
    AD -->|failure| AF["pool.cancel()"]

    T -->|client disconnect| AG["Cleanup"]
    AC -->|client disconnect| AG

    AG --> AH["PoolManager.release(stream, born_at)"]

    AH --> AI{"born_at expired<br/>(server_lifetime)?"}
    AI -->|Yes| AJ["Drop connection<br/>sem.add_permits(1)"]
    AI -->|No| AK{"idle pool<br/>under max_size?"}
    AK -->|Yes| AL["Push to idle pool<br/>permit stays consumed"]
    AK -->|No| AM["Drop connection<br/>sem.add_permits(1)"]

    AL --> AN["spawn_warmup()<br/>if idle < min_size<br/>→ create backends"]

    style A fill:#1a1a2e,stroke:#e94560,color:#fff
    style I fill:#1a1a2e,stroke:#e94560,color:#fff
    style J fill:#1a1a2e,stroke:#e94560,color:#fff
    style Q fill:#1a1a2e,stroke:#e94560,color:#fff
    style AH fill:#1a1a2e,stroke:#e94560,color:#fff
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
server_lifetime_secs = 3600
server_connect_timeout_secs = 15
client_idle_timeout_secs = 0
transaction_timeout_secs = 0
query_wait_timeout_secs = 0
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
# ciphers = ["TLS13_AES_256_GCM_SHA384", "TLS13_AES_128_GCM_SHA256"]
# min_protocol_version = "TLSv1.2"

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
