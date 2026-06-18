use axum::{routing::get, Router};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use crate::pool::PoolManager;

pub async fn serve(pool: Arc<PoolManager>, addr: &str) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health", get(health_handler))
        .with_state(pool);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("metrics server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn metrics_handler(
    axum::extract::State(pool): axum::extract::State<Arc<PoolManager>>,
) -> String {
    let stats = pool.global_stats().await;

    format!(
        "# HELP pgb_iam_clients Current client connections\n\
         # TYPE pgb_iam_clients gauge\n\
         pgb_iam_clients {}\n\
         # HELP pgb_iam_client_max Maximum client connections (0 = unlimited)\n\
         # TYPE pgb_iam_client_max gauge\n\
         pgb_iam_client_max {}\n\
         # HELP pgb_iam_server_active Active server connections (in-use)\n\
         # TYPE pgb_iam_server_active gauge\n\
         pgb_iam_server_active {}\n\
         # HELP pgb_iam_server_idle Idle server connections (pooled)\n\
         # TYPE pgb_iam_server_idle gauge\n\
         pgb_iam_server_idle {}\n\
         # HELP pgb_iam_server_max Max server connections (max_size + reserve_size)\n\
         # TYPE pgb_iam_server_max gauge\n\
         pgb_iam_server_max {}\n\
         # HELP pgb_iam_server_reserve Reserve pool capacity\n\
         # TYPE pgb_iam_server_reserve gauge\n\
         pgb_iam_server_reserve {}\n\
         # HELP pgb_iam_server_min Min pool size target\n\
         # TYPE pgb_iam_server_min gauge\n\
         pgb_iam_server_min {}\n",
        pool.client_count.load(Ordering::Relaxed),
        pool.client_max,
        stats.active,
        stats.idle,
        stats.max + stats.reserve,
        stats.reserve,
        stats.min,
    )
}

async fn health_handler() -> &'static str {
    "ok"
}
