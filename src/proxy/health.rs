use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::RwLock;

use crate::config::HealthCheckConfig;

#[derive(Clone, Debug)]
pub struct HealthStatus {
    pub healthy: bool,
    pub last_check: std::time::Instant,
    pub last_error: Option<String>,
}

pub struct HealthChecker {
    status: Arc<RwLock<HealthStatus>>,
    target_addr: String,
    config: HealthCheckConfig,
}

impl HealthChecker {
    pub fn new(target_addr: String, config: &HealthCheckConfig) -> Self {
        Self {
            status: Arc::new(RwLock::new(HealthStatus {
                healthy: true,
                last_check: std::time::Instant::now(),
                last_error: None,
            })),
            target_addr,
            config: config.clone(),
        }
    }

    pub fn status_handle(&self) -> Arc<RwLock<HealthStatus>> {
        self.status.clone()
    }

    pub async fn run_loop(self) {
        loop {
            tokio::time::sleep(Duration::from_secs(self.config.interval_secs)).await;
            self.check().await;
        }
    }

    async fn check(&self) {
        let result = tokio::time::timeout(
            Duration::from_secs(self.config.timeout_secs),
            TcpStream::connect(&self.target_addr),
        )
        .await;

        let mut status = self.status.write().await;
        status.last_check = std::time::Instant::now();

        match result {
            Ok(Ok(stream)) => {
                let _ = stream;
                status.healthy = true;
                status.last_error = None;
                crate::log_event!(INFO, crate::log::HEALTH, crate::log::CHECK, "health check passed for {}", self.target_addr);
            }
            Ok(Err(e)) => {
                status.healthy = false;
                status.last_error = Some(format!("connection failed: {}", e));
                crate::log_event!(WARN, crate::log::HEALTH, crate::log::ERROR, "health check failed for {}: {}", self.target_addr, e);
            }
            Err(_) => {
                status.healthy = false;
                status.last_error = Some("connection timed out".to_string());
                crate::log_event!(WARN, crate::log::HEALTH, crate::log::TIMEOUT, "health check timed out for {}", self.target_addr);
            }
        }
    }
}
