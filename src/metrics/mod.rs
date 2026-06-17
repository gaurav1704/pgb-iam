use axum::{routing::get, Router};
use std::sync::Arc;
use crate::pool::Pool;

pub async fn serve(pool: Arc<Pool>, addr: &str) -> anyhow::Result<()> {
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
    axum::extract::State(pool): axum::extract::State<Arc<Pool>>,
) -> String {
    let stats = pool.stats().await;
    format!(
        "# HELP pgb_iam_idle_connections Idle connections in pool\n\
         # TYPE pgb_iam_idle_connections gauge\n\
         pgb_iam_idle_connections {}\n\
         # HELP pgb_iam_active_connections Active connections\n\
         # TYPE pgb_iam_active_connections gauge\n\
         pgb_iam_active_connections {}\n\
         # HELP pgb_iam_max_connections Max pool size\n\
         # TYPE pgb_iam_max_connections gauge\n\
         pgb_iam_max_connections {}\n",
        stats.idle, stats.active, stats.max,
    )
}

async fn health_handler() -> &'static str {
    "ok"
}
