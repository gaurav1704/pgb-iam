mod config;
mod log;
mod pool;
mod proxy;
mod auth;
mod metrics;
mod pgproto;
mod tls;

use std::sync::Arc;
use clap::Parser;
use tracing_subscriber::filter::EnvFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::Registry;

use crate::auth::cache::TokenCache;
use crate::proxy::health::HealthChecker;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

fn init_logging(cfg: &config::LoggingConfig) -> anyhow::Result<()> {
    use std::io;
    use tracing_subscriber::fmt;
    use tracing_subscriber::Layer;

    let filter = EnvFilter::from_default_env()
        .add_directive("pgb_iam=info".parse()?);
    let json_fmt = fmt::format().json();

    let mut layers: Vec<Box<dyn Layer<Registry> + Send + Sync + 'static>> = Vec::with_capacity(3);

    // 1. stderr — always present
    if matches!(cfg.stderr, config::LogFormat::Json) {
        layers.push(Box::new(fmt::layer().with_writer(io::stderr).event_format(json_fmt.clone()).with_filter(filter.clone())));
    } else {
        layers.push(Box::new(fmt::layer().with_writer(io::stderr).with_filter(filter.clone())));
    }

    // 2. stdout — optional
    if let Some(fmt) = &cfg.stdout {
        if matches!(fmt, config::LogFormat::Json) {
            layers.push(Box::new(fmt::layer().with_writer(io::stdout).event_format(json_fmt.clone()).with_filter(filter.clone())));
        } else {
            layers.push(Box::new(fmt::layer().with_writer(io::stdout).with_filter(filter.clone())));
        }
    }

    // 3. pipeline file — optional
    if let Some(path) = &cfg.pipeline_path {
        let file = std::fs::File::create(path)
            .map_err(|e| anyhow::anyhow!("failed to create pipeline log file {}: {}", path, e))?;
        let writer = std::sync::Mutex::new(file);
        if matches!(cfg.pipeline_format, config::LogFormat::Json) {
            layers.push(Box::new(fmt::layer().with_writer(writer).event_format(json_fmt).with_filter(filter)));
        } else {
            layers.push(Box::new(fmt::layer().with_writer(writer).with_filter(filter)));
        }
    }

    let subscriber = Registry::default().with(layers);
    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let config = config::load(&args.config).await?;
    init_logging(&config.logging)?;

    crate::log_event!(
        INFO, crate::log::CONFIG, crate::log::START,
        "starting pgb-iam on {}:{} (pool max={}, mode={:?})",
        config.listen.addr,
        config.listen.port,
        config.pool.max_size,
        config.pool.mode,
    );

    let pool_manager = Arc::new(pool::PoolManager::new(&config.pool));

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
                    crate::log_event!(ERROR, crate::log::METRICS, crate::log::ERROR, "metrics server failed: {}", e);
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
                    crate::log_event!(ERROR, crate::log::ADMIN, crate::log::ERROR, "admin server failed: {}", e);
                }
            });
        }
    }

    proxy::run(pool_manager, config, token_cache).await?;
    Ok(())
}
