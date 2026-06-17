mod config;
mod pool;
mod proxy;
mod auth;
mod metrics;

use std::sync::Arc;
use clap::Parser;
use tracing_subscriber::EnvFilter;

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

    tracing::info!("starting pgb-iam on {}:{}", config.listen.addr, config.listen.port);

    let pool = Arc::new(pool::Pool::new(&config));
    let proxy_config = config.clone();

    if let Some(metrics_config) = &config.metrics {
        if metrics_config.enabled {
            let metrics_addr = format!("{}:{}", metrics_config.listen_addr, metrics_config.listen_port);
            let pool_clone = pool.clone();
            tokio::spawn(async move {
                if let Err(e) = metrics::serve(pool_clone, &metrics_addr).await {
                    tracing::error!("metrics server failed: {}", e);
                }
            });
        }
    }

    proxy::run(pool, proxy_config).await?;
    Ok(())
}
