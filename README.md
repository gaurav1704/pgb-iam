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
| AWS RDS IAM token generation | 🔧 Phase 2 |
| GCP Cloud SQL IAM auth | 🔧 Phase 2 |
| Transparent auth injection | 🔧 Phase 2 |
| Automatic token refresh | 🔧 Phase 2 |
| TLS support | 📋 Phase 3 |

### How IAM Auth Works

1. Client connects to pgb-iam with their database username
2. pgb-iam detects that IAM auth is configured for this user
3. pgb-iam generates a fresh IAM token via the cloud provider's SDK
4. pgb-iam uses the token as the password when connecting to PostgreSQL
5. Token is cached and automatically refreshed before expiry (~15 min for AWS)
6. Client never sees or manages tokens — it "just works"

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
├── proxy/           # TCP relay (copy_bidirectional)
├── auth/            # IAM token providers (AWS, GCP)
└── metrics/         # Prometheus + health endpoint
```

## License

MIT
