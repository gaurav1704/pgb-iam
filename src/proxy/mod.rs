use std::sync::Arc;
use tokio::io;
use tokio::net::TcpListener;
use tracing;

use crate::config::Config;
use crate::pool::Pool;

pub async fn run(pool: Arc<Pool>, config: Config) -> anyhow::Result<()> {
    let addr = config.listen_addr();
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", addr);

    loop {
        let (inbound, peer) = listener.accept().await?;
        let pool = pool.clone();

        tokio::spawn(async move {
            tracing::debug!("new client connection from {}", peer);

            let mut backend = match pool.acquire().await {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("failed to acquire backend connection: {}", e);
                    return;
                }
            };

            let mut inbound = inbound;
            if let Err(e) = io::copy_bidirectional(&mut inbound, &mut backend).await {
                tracing::error!("relay error for {}: {}", peer, e);
            }

            pool.release(backend).await;
            tracing::debug!("client {} disconnected", peer);
        });
    }
}
