use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

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
                    crate::log_event!(DEBUG, crate::log::IAM, crate::log::AUTHENTICATE, "using cached IAM token (expires in {:?})", c.expires_at - Instant::now());
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

        crate::log_event!(INFO, crate::log::IAM, crate::log::REFRESH, "cached new IAM token (TTL: {:?})", ttl);
        Ok(token)
    }

    pub async fn spawn_refresh_task(self: Arc<Self>) {
        loop {
            tokio::time::sleep(Duration::from_secs(300)).await; // check every 5 min
            crate::log_event!(DEBUG, crate::log::IAM, crate::log::REFRESH, "checking IAM token expiry");

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
                        crate::log_event!(INFO, crate::log::IAM, crate::log::REFRESH, "refreshed IAM token");
                    }
                    Err(e) => {
                        crate::log_event!(ERROR, crate::log::IAM, crate::log::ERROR, "failed to refresh IAM token: {}", e);
                    }
                }
            }
        }
    }
}
