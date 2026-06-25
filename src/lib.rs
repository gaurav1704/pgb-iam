//! # pgb-iam — IAM-Aware PostgreSQL Connection Pooler
//!
//! A production-ready PostgreSQL connection pooler with full PgBouncer feature
//! parity plus native IAM authentication for AWS RDS and GCP Cloud SQL.
//!
//! ## Features
//!
//! - **IAM auth**: AWS RDS `GenerateDBAuthToken` and GCP Cloud SQL IAM at runtime
//! - **Pooling**: session mode, transaction mode, LIFO/FIFO, reserve pool, warm-up
//! - **Auth methods**: trust, password, SCRAM-SHA-256, TLS cert, PAM, LDAP, HBA, auth_query
//! - **TLS**: rustls with configurable ciphers, protocol versions, and backend CA
//! - **Metrics**: Prometheus endpoint (`/metrics`)
//! - **Admin HTTP API**: pool status, health, configuration endpoints
//! - **Structured logging**: JSON or text to stderr/stdout/file with component/action fields
//!
//! ## Example
//!
//! ```toml
//! [listen]
//! addr = "127.0.0.1"
//! port = 6432
//!
//! [pool]
//! mode = "transaction"
//! max_size = 10
//! target_host = "your-db.example.com"
//! target_port = 5432
//!
//! [iam]
//! provider = "aws"
//! region = "us-east-1"
//! ```
//!
//! ## Quick Start
//!
//! ```bash
//! # Start the pooler
//! pgb-iam --config config.toml
//!
//! # Connect via psql
//! psql -h 127.0.0.1 -p 6432 -U postgres -d postgres
//!
//! # Metrics
//! curl http://127.0.0.1:9090/metrics
//! ```

pub mod config;
pub mod log;
pub mod pool;
pub mod proxy;
pub mod auth;
pub mod metrics;
pub mod pgproto;
pub mod tls;

use std::sync::Arc;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

use crate::auth::cache::TokenCache;
use crate::proxy::health::HealthChecker;

pub use config::{Config, PoolConfig, LoggingConfig, LogFormat, IamConfig};
pub use pool::PoolManager;
pub use log::{CLIENT, POOL, AUTH, IAM, CONFIG, METRICS, HEALTH, ADMIN, PROXY, SERVER, TLS};
pub use log::{CONNECT, DISCONNECT, AUTHENTICATE, STATS, TIMEOUT, ERROR, START, REFRESH, ACQUIRE, RELEASE, CREATE, DROP, CANCEL, CHECK, WARMUP, RESET};

/// Initialise the tracing subscriber with up to three output channels.
pub fn init_logging(cfg: &LoggingConfig) -> anyhow::Result<()> {
    use std::io;
    use tracing_subscriber::fmt;
    use tracing_subscriber::Layer;

    let filter = EnvFilter::from_default_env()
        .add_directive("pgb_iam=info".parse()?);
    let json_fmt = fmt::format().json();

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>> = Vec::with_capacity(3);

    if matches!(cfg.stderr, LogFormat::Json) {
        layers.push(Box::new(fmt::layer().with_writer(io::stderr).event_format(json_fmt.clone()).with_filter(filter.clone())));
    } else {
        layers.push(Box::new(fmt::layer().with_writer(io::stderr).with_filter(filter.clone())));
    }

    if let Some(fmt) = &cfg.stdout {
        if matches!(fmt, LogFormat::Json) {
            layers.push(Box::new(fmt::layer().with_writer(io::stdout).event_format(json_fmt.clone()).with_filter(filter.clone())));
        } else {
            layers.push(Box::new(fmt::layer().with_writer(io::stdout).with_filter(filter.clone())));
        }
    }

    if let Some(path) = &cfg.pipeline_path {
        let file = std::fs::File::create(path)
            .map_err(|e| anyhow::anyhow!("failed to create pipeline log file {}: {}", path, e))?;
        let writer = std::sync::Mutex::new(file);
        if matches!(cfg.pipeline_format, LogFormat::Json) {
            layers.push(Box::new(fmt::layer().with_writer(writer).event_format(json_fmt).with_filter(filter)));
        } else {
            layers.push(Box::new(fmt::layer().with_writer(writer).with_filter(filter)));
        }
    }

    let subscriber = Registry::default().with(layers);
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

/// Load config, initialise logging, set up pool, token cache, health checker,
/// metrics, admin, and start the proxy listener.
pub async fn run(config_path: &str) -> anyhow::Result<()> {
    let config = config::load(config_path).await?;
    init_logging(&config.logging)?;

    log_event!(
        INFO, CONFIG, START,
        "starting pgb-iam on {}:{} (pool max={}, mode={:?})",
        config.listen.addr,
        config.listen.port,
        config.pool.max_size,
        config.pool.mode,
    );

    let pool_manager = Arc::new(PoolManager::new(&config.pool));

    let token_cache: Option<Arc<TokenCache>> = config.iam.as_ref().map(|iam| {
        let cache = Arc::new(TokenCache::new(iam.clone()));
        let cache_clone = cache.clone();
        tokio::spawn(async move { cache_clone.spawn_refresh_task().await });
        cache
    });

    let health_handle = config.health_check.as_ref().and_then(|hc| {
        if hc.enabled {
            let checker = HealthChecker::new(config.target_addr(), hc);
            let handle = checker.status_handle();
            tokio::spawn(async move { checker.run_loop().await });
            Some(handle)
        } else {
            None
        }
    });

    if let Some(metrics_config) = &config.metrics {
        if metrics_config.enabled {
            let metrics_addr = format!("{}:{}", metrics_config.listen_addr, metrics_config.listen_port);
            let pool = pool_manager.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics::serve(pool, &metrics_addr).await {
                    log_event!(ERROR, METRICS, ERROR, "metrics server failed: {}", e);
                }
            });
        }
    }

    if let Some(admin_config) = &config.admin {
        if admin_config.enabled {
            let admin_addr = format!("{}:{}", admin_config.listen_addr, admin_config.listen_port);
            let pool = pool_manager.clone();
            let health_clone = health_handle.clone();
            tokio::spawn(async move {
                if let Err(e) = proxy::admin::serve(pool, health_clone, &admin_addr).await {
                    log_event!(ERROR, ADMIN, ERROR, "admin server failed: {}", e);
                }
            });
        }
    }

    proxy::run(pool_manager, config, token_cache).await?;
    Ok(())
}
