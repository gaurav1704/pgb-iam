mod config;
mod pool;
mod proxy;
mod auth;
mod metrics;
mod pgproto;
mod tls;

use std::sync::Arc;
use clap::Parser;
use tracing_subscriber::EnvFilter;

use crate::auth::cache::TokenCache;
use crate::proxy::health::HealthChecker;

#[derive(Parser)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("pgb_iam=info".parse()?))
        .init();

    let args = Args::parse();
    let config = config::load(&args.config).await?;

    tracing::info!(
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
                    tracing::error!("metrics server failed: {}", e);
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
                    tracing::error!("admin server failed: {}", e);
                }
            });
        }
    }

    proxy::run(pool_manager, config, token_cache).await?;
    Ok(())
}
