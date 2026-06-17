use tokio::net::TcpStream;
use std::time::{Duration, Instant};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Mutex;
use tracing;

use crate::config::Config;

struct IdleConn {
    stream: TcpStream,
    parked_since: Instant,
}

pub struct Pool {
    config: Config,
    idle: Mutex<VecDeque<IdleConn>>,
    active_count: AtomicUsize,
    max_size: usize,
}

impl Pool {
    pub fn new(config: &Config) -> Self {
        Self {
            config: config.clone(),
            idle: Mutex::new(VecDeque::new()),
            active_count: AtomicUsize::new(0),
            max_size: config.pool.max_size as usize,
        }
    }

    pub async fn acquire(&self) -> anyhow::Result<TcpStream> {
        {
            let mut idle = self.idle.lock().await;
            while let Some(conn) = idle.pop_front() {
                if conn.parked_since.elapsed() < Duration::from_secs(self.config.pool.idle_timeout_secs) {
                    self.active_count.fetch_add(1, Ordering::SeqCst);
                    tracing::debug!("reusing idle connection");
                    return Ok(conn.stream);
                }
            }
        }

        if self.active_count.load(Ordering::SeqCst) >= self.max_size {
            anyhow::bail!("connection pool exhausted (max {})", self.max_size);
        }

        let stream = TcpStream::connect(self.config.target_addr()).await?;
        self.active_count.fetch_add(1, Ordering::SeqCst);
        tracing::info!("created new backend connection to {}", self.config.target_addr());
        Ok(stream)
    }

    pub async fn release(&self, stream: TcpStream) {
        let parked = IdleConn {
            stream,
            parked_since: Instant::now(),
        };
        let mut idle = self.idle.lock().await;
        if idle.len() < self.max_size {
            idle.push_back(parked);
        }
        // If pool is full, the connection drops here
        self.active_count.fetch_sub(1, Ordering::SeqCst);
    }

    pub async fn stats(&self) -> PoolStats {
        let idle = self.idle.lock().await;
        PoolStats {
            idle: idle.len(),
            active: self.active_count.load(Ordering::SeqCst),
            max: self.max_size,
        }
    }
}

pub struct PoolStats {
    pub idle: usize,
    pub active: usize,
    pub max: usize,
}
