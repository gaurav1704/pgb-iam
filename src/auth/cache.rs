use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing;

use crate::config::IamConfig;

struct CachedToken {
    token: String,
    expires_at: Instant,
}

pub struct TokenCache {
    inner: RwLock<Option<CachedToken>>,
    config: IamConfig,
}

impl TokenCache {
    pub fn new(config: IamConfig) -> Self {
        Self {
            inner: RwLock::new(None),
            config,
        }
    }

    pub async fn get(&self) -> anyhow::Result<String> {
        {
            let cached = self.inner.read().await;
            if let Some(c) = cached.as_ref() {
                if Instant::now() < c.expires_at {
                    tracing::debug!("using cached IAM token (expires in {:?})", c.expires_at - Instant::now());
                    return Ok(c.token.clone());
                }
            }
        }

        let mut cached = self.inner.write().await;
        if let Some(c) = cached.as_ref() {
            if Instant::now() < c.expires_at {
                return Ok(c.token.clone());
            }
        }

        let token = crate::auth::get_token(&self.config).await?;

        // AWS tokens expire in ~15 min; refresh after 10 min
        let ttl = Duration::from_secs(600);
        *cached = Some(CachedToken {
            token: token.clone(),
            expires_at: Instant::now() + ttl,
        });

        tracing::info!("cached new IAM token (TTL: {:?})", ttl);
        Ok(token)
    }

    pub async fn spawn_refresh_task(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await; // check every 5 min
            tracing::debug!("checking IAM token expiry");

            let needs_refresh = {
                let cached = self.inner.read().await;
                cached.as_ref().map_or(true, |c| Instant::now() >= c.expires_at)
            };

            if needs_refresh {
                match crate::auth::get_token(&self.config).await {
                    Ok(token) => {
                        let mut cached = self.inner.write().await;
                        *cached = Some(CachedToken {
                            token,
                            expires_at: Instant::now() + Duration::from_secs(600),
                        });
                        tracing::info!("refreshed IAM token");
                    }
                    Err(e) => {
                        tracing::error!("failed to refresh IAM token: {}", e);
                    }
                }
            }
        }
    }
}
