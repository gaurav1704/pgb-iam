use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing;

/// A server connection that may be plain TCP or TLS-wrapped.
pub enum ServerStream {
    Plain(TcpStream),
    Tls(tokio_rustls::TlsStream<TcpStream>),
}

impl AsyncRead for ServerStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            ServerStream::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            ServerStream::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for ServerStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            ServerStream::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            ServerStream::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            ServerStream::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            ServerStream::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            ServerStream::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            ServerStream::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

/// Key that identifies a unique connection pool (per backend+database+db_user).
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
    pub db_user: String,
    pub dbname: String,
}

// ── Per-pool state ──────────────────────────────────────────────────

struct IdleConn {
    stream: ServerStream,
    parked_since: Instant,
}

struct PoolInner {
    idle: VecDeque<IdleConn>,
    active: usize,
    max: usize,
    idle_timeout: Duration,
}

impl PoolInner {
    fn acquire(&mut self) -> Option<ServerStream> {
        while let Some(c) = self.idle.pop_front() {
            if c.parked_since.elapsed() < self.idle_timeout {
                self.active += 1;
                return Some(c.stream);
            }
        }
        None
    }

    fn release(&mut self, stream: ServerStream) {
        if self.idle.len() < self.max {
            self.idle.push_back(IdleConn {
                stream,
                parked_since: Instant::now(),
            });
        }
        self.active = self.active.saturating_sub(1);
    }

    fn can_create(&self) -> bool {
        self.active + self.idle.len() < self.max
    }
}

// ── PoolManager ─────────────────────────────────────────────────────

pub struct PoolManager {
    pools: Mutex<HashMap<PoolKey, PoolInner>>,
    default_max: usize,
    default_timeout: Duration,
}

impl PoolManager {
    pub fn new(max_pool_size: usize, idle_timeout_secs: u64) -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
            default_max: max_pool_size,
            default_timeout: Duration::from_secs(idle_timeout_secs),
        }
    }

    /// Try to acquire an idle connection.
    pub async fn try_acquire_idle(&self, key: &PoolKey) -> Option<ServerStream> {
        let mut pools = self.pools.lock().await;
        let entry = pools.get_mut(key)?;
        entry.acquire()
    }

    /// Reserve capacity (increments active count). Returns false if full.
    pub async fn reserve(&self, key: &PoolKey) -> bool {
        let mut pools = self.pools.lock().await;
        let entry = self.entry_or_create(&mut *pools, key);
        if !entry.can_create() {
            return false;
        }
        entry.active += 1;
        true
    }

    /// Release a connection back to the pool.
    pub async fn release(&self, key: &PoolKey, stream: ServerStream) {
        let mut pools = self.pools.lock().await;
        let entry = self.entry_or_create(&mut *pools, key);
        entry.release(stream);
    }

    /// Cancel a reservation (decrement active count).
    pub async fn cancel_reservation(&self, key: &PoolKey) {
        let mut pools = self.pools.lock().await;
        if let Some(entry) = pools.get_mut(key) {
            entry.active = entry.active.saturating_sub(1);
        }
    }

    // ── Stats ────────────────────────────────────────────────────────

    #[allow(dead_code)]
    pub async fn stats_for(&self, key: &PoolKey) -> Option<PoolStats> {
        let pools = self.pools.lock().await;
        pools.get(key).map(|e| PoolStats {
            idle: e.idle.len(),
            active: e.active,
            max: e.max,
        })
    }

    #[allow(dead_code)]
    pub async fn all_stats(&self) -> HashMap<PoolKey, PoolStats> {
        let pools = self.pools.lock().await;
        pools
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    PoolStats {
                        idle: v.idle.len(),
                        active: v.active,
                        max: v.max,
                    },
                )
            })
            .collect()
    }

    pub async fn global_stats(&self) -> PoolStats {
        let pools = self.pools.lock().await;
        let mut total = PoolStats { idle: 0, active: 0, max: 0 };
        for entry in pools.values() {
            total.idle += entry.idle.len();
            total.active += entry.active;
            total.max += entry.max;
        }
        total
    }

    fn entry_or_create<'a>(
        &self,
        pools: &'a mut HashMap<PoolKey, PoolInner>,
        key: &PoolKey,
    ) -> &'a mut PoolInner {
        pools.entry(key.clone()).or_insert_with(|| {
            tracing::info!("creating pool for {}@{}", key.db_user, key.dbname);
            PoolInner {
                idle: VecDeque::new(),
                active: 0,
                max: self.default_max,
                idle_timeout: self.default_timeout,
            }
        })
    }
}

// ── Types ───────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PoolStats {
    pub idle: usize,
    pub active: usize,
    pub max: usize,
}
