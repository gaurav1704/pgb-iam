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

### Key Features

| Feature | Status |
|---------|--------|
| TCP proxy with connection pooling | ✅ Phase 1 |
| Config file (TOML) | ✅ Phase 1 |
| Prometheus metrics | ✅ Phase 1 |
| Health check endpoint | ✅ Phase 1 |
| PostgreSQL wire protocol parser | ✅ Phase 2 |
| AWS RDS IAM token generation | ✅ Phase 2 |
| Transparent auth injection (cleartext + MD5) | ✅ Phase 2 |
| Token cache with auto-refresh | ✅ Phase 2 |
| GCP Cloud SQL IAM auth | 🔧 Phase 2 (stub) |
| TLS support (client→pooler + pooler→backend) | ✅ Phase 3 |
| Health checks with reconnection logic | ✅ Phase 3 |
| Admin interface (pool stats + health status) | ✅ Phase 3 |

### How IAM Auth Works

1. Client connects to pgb-iam with their database username
2. pgb-iam reads the PostgreSQL startup packet, extracts the username
3. pgb-iam connects to the backend (RDS/Cloud SQL) and forwards the startup
4. When the backend requests a password, pgb-iam generates a fresh IAM token via the cloud provider's SDK
5. The token is sent as the password (cleartext or MD5-hashed, matching the backend's auth method)
6. Token is cached and automatically refreshed before expiry (~15 min for AWS, refreshed every 10 min)
7. After authentication, all traffic is relayed transparently — clients don't know IAM is involved

### Wire Protocol Flow

```
Client          pgb-iam           Backend (RDS)
  │                │                  │
  │── Startup ────▶│── Startup ──────▶│
  │                │◀─ AuthReq(R) ────│
  │                │── Password(p) ──▶│  ← IAM token injected here
  │                │◀─ AuthOk ────────│
  │◀─ AuthOk ──────│                  │
  │══════ relay ═══▶══════ relay ════▶│
```

### Why Rust

- **Performance**: Async I/O with Tokio is ideal for connection pooling — zero-cost abstractions, no GC pauses
- **Safety**: No buffer overflows or use-after-free in the critical network path
- **Ecosystem**: First-class AWS SDK, async Postgres protocol support, Prometheus instrumentation

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
├── main.rs          # Entry point, config loading, runtime setup
├── config/          # TOML config deserialization
├── pool/            # Connection pool (idle reaper, max size enforcement)
├── proxy/           # TCP relay + IAM auth injection
│   ├── mod.rs       # Client handler, TLS upgrade, auth flow, relay
│   ├── health.rs    # Periodic backend health checks
│   └── admin.rs     # HTTP admin API (stats, health status)
├── pgproto/         # PostgreSQL wire protocol parser (startup, SSL, auth)
├── auth/            # IAM token providers + token cache with auto-refresh
├── tls/             # TLS accept/connect (rustls-based)
└── metrics/         # Prometheus + health endpoint
```

### Configuration

```toml
[listen]
addr = "127.0.0.1"
port = 6432

[pool]
min_size = 2
max_size = 10
idle_timeout_secs = 300
target_host = "your-db.xxxxxx.us-east-1.rds.amazonaws.com"
target_port = 5432
dbname = "postgres"
db_user = "postgres"

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
provider = "Aws"              # Aws | Gcp | None
region = "us-east-1"
instance_host = "your-db.xxxxxx.us-east-1.rds.amazonaws.com"
instance_port = 5432
db_user = "iam_user"          # Which database user uses IAM auth
```

## License

MIT
