use axum::extract::State;
use axum::routing::get;
use axum::Router;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::pool::PoolManager;
use crate::proxy::health::HealthStatus;

struct AdminState {
    pool: Arc<PoolManager>,
    health: Option<Arc<RwLock<HealthStatus>>>,
}

pub async fn serve(
    pool: Arc<PoolManager>,
    health: Option<Arc<RwLock<HealthStatus>>>,
    addr: &str,
) -> anyhow::Result<()> {
    let state = Arc::new(AdminState { pool, health });

    let app = Router::new()
        .route("/stats", get(stats_handler))
        .route("/health", get(health_handler))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("admin server listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

async fn stats_handler(State(state): State<Arc<AdminState>>) -> String {
    let pool_stats = state.pool.global_stats().await;
    format!(
        "{{\n  \"pool\": {{\n    \"idle\": {},\n    \"active\": {},\n    \"max\": {}\n  }}\n}}\n",
        pool_stats.idle, pool_stats.active, pool_stats.max,
    )
}

async fn health_handler(State(state): State<Arc<AdminState>>) -> String {
    match &state.health {
        Some(h) => {
            let status = h.read().await;
            format!(
                "{{\n  \"healthy\": {},\n  \"last_error\": {},\n  \"last_check_ago_secs\": {}\n}}\n",
                if status.healthy { "true" } else { "false" },
                match &status.last_error {
                    Some(e) => format!("\"{}\"", e),
                    None => "null".to_string(),
                },
                status.last_check.elapsed().as_secs(),
            )
        }
        None => {
            "{{\n  \"healthy\": true,\n  \"note\": \"no health checker configured\"\n}}\n"
                .to_string()
        }
    }
}
