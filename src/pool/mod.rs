use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tracing;

use crate::config;

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

impl ServerStream {
    /// Returns peer certificates if this is a TLS connection.
    #[allow(dead_code)]
    pub fn peer_certificates(&self) -> Option<Vec<rustls::pki_types::CertificateDer<'static>>> {
        match self {
            ServerStream::Plain(_) => None,
            ServerStream::Tls(tls) => {
                let (_, session) = tls.get_ref();
                session.peer_certificates().map(|c| c.to_vec())
            }
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

// ── Per-pool limits ─────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct PoolLimits {
    pub max_size: usize,
    pub min_size: usize,
    pub reserve_size: usize,
    pub strategy: PoolStrategy,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PoolStrategy {
    Lifo,
    Fifo,
}

// ── Per-pool state ──────────────────────────────────────────────────

struct IdleConn {
    stream: ServerStream,
    parked_since: Instant,
    born_at: Instant,
}

struct PoolInner {
    idle: VecDeque<IdleConn>,
    active: usize,
    limits: PoolLimits,
    idle_timeout: Duration,
    server_lifetime: Duration,
}

impl PoolInner {
    fn can_create(&self) -> bool {
        let hard_limit = self.limits.max_size + self.limits.reserve_size;
        self.active + self.idle.len() < hard_limit
    }

    fn needs_warmup(&self) -> usize {
        let currently = self.idle.len() + self.active;
        if self.limits.min_size > currently {
            self.limits.min_size - currently
        } else {
            0
        }
    }
}

// ── PoolManager ─────────────────────────────────────────────────────

pub struct PoolManager {
    pools: Mutex<HashMap<PoolKey, PoolInner>>,
    global_limits: PoolLimits,
    default_timeout: Duration,
    default_lifetime: Duration,
    database_limits: HashMap<String, PoolLimits>,
    user_limits: HashMap<String, PoolLimits>,
}

impl PoolManager {
    pub fn new(config: &config::PoolConfig) -> Self {
        let global_limits = PoolLimits {
            max_size: config.max_size as usize,
            min_size: config.min_size as usize,
            reserve_size: config.reserve_size as usize,
            strategy: match config.strategy {
                config::PoolStrategy::Lifo => PoolStrategy::Lifo,
                config::PoolStrategy::Fifo => PoolStrategy::Fifo,
            },
        };

        let database_limits = config
            .database_limits
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    PoolLimits {
                        max_size: v.max_size.unwrap_or(config.max_size) as usize,
                        min_size: v.min_size.unwrap_or(config.min_size) as usize,
                        reserve_size: v.reserve_size.unwrap_or(config.reserve_size) as usize,
                        strategy: global_limits.strategy,
                    },
                )
            })
            .collect();

        let user_limits = config
            .user_limits
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    PoolLimits {
                        max_size: v.max_size.unwrap_or(config.max_size) as usize,
                        min_size: v.min_size.unwrap_or(config.min_size) as usize,
                        reserve_size: v.reserve_size.unwrap_or(config.reserve_size) as usize,
                        strategy: global_limits.strategy,
                    },
                )
            })
            .collect();

        Self {
            pools: Mutex::new(HashMap::new()),
            global_limits,
            default_timeout: Duration::from_secs(config.idle_timeout_secs),
            default_lifetime: Duration::from_secs(config.server_lifetime_secs),
            database_limits,
            user_limits,
        }
    }

    /// Try to acquire an idle connection. Returns (stream, born_at).
    pub async fn try_acquire_idle(&self, key: &PoolKey) -> Option<(ServerStream, Instant)> {
        let mut pools = self.pools.lock().await;
        let entry = pools.get_mut(key)?;
        let c = loop {
            match match entry.limits.strategy {
                PoolStrategy::Lifo => entry.idle.pop_back(),
                PoolStrategy::Fifo => entry.idle.pop_front(),
            } {
                Some(c) => {
                    let expired = c.parked_since.elapsed() >= entry.idle_timeout
                        || c.born_at.elapsed() >= entry.server_lifetime;
                    if !expired {
                        entry.active += 1;
                        break Some(c);
                    }
                }
                None => break None,
            }
        };
        c.map(|c| (c.stream, c.born_at))
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
    pub async fn release(&self, key: &PoolKey, stream: ServerStream, born_at: Instant) {
        let mut pools = self.pools.lock().await;
        let entry = self.entry_or_create(&mut *pools, key);
        let expired = born_at.elapsed() >= entry.server_lifetime;
        if !expired && entry.idle.len() < entry.limits.max_size {
            entry.idle.push_back(IdleConn {
                stream,
                parked_since: Instant::now(),
                born_at,
            });
        }
        entry.active = entry.active.saturating_sub(1);
    }

    /// Cancel a reservation.
    pub async fn cancel_reservation(&self, key: &PoolKey) {
        let mut pools = self.pools.lock().await;
        if let Some(entry) = pools.get_mut(key) {
            entry.active = entry.active.saturating_sub(1);
        }
    }

    /// How many warm-up connections this pool needs.
    pub async fn needs_warmup(&self, key: &PoolKey) -> usize {
        let pools = self.pools.lock().await;
        pools.get(key).map(|e| e.needs_warmup()).unwrap_or(0)
    }

    // ── Stats ────────────────────────────────────────────────────────

    #[allow(dead_code)]
    pub async fn stats_for(&self, key: &PoolKey) -> Option<PoolStats> {
        let pools = self.pools.lock().await;
        pools.get(key).map(|e| PoolStats {
            idle: e.idle.len(),
            active: e.active,
            max: e.limits.max_size,
            reserve: e.limits.reserve_size,
            min: e.limits.min_size,
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
                        max: v.limits.max_size,
                        reserve: v.limits.reserve_size,
                        min: v.limits.min_size,
                    },
                )
            })
            .collect()
    }

    pub async fn global_stats(&self) -> PoolStats {
        let pools = self.pools.lock().await;
        let mut total = PoolStats {
            idle: 0,
            active: 0,
            max: 0,
            reserve: 0,
            min: 0,
        };
        for entry in pools.values() {
            total.idle += entry.idle.len();
            total.active += entry.active;
            total.max += entry.limits.max_size;
            total.reserve += entry.limits.reserve_size;
            total.min += entry.limits.min_size;
        }
        total
    }

    fn resolve_limits(&self, key: &PoolKey) -> PoolLimits {
        // Per-user limit takes precedence over per-database, which overrides global
        if let Some(limits) = self.user_limits.get(&key.db_user) {
            return limits.clone();
        }
        if let Some(limits) = self.database_limits.get(&key.dbname) {
            return limits.clone();
        }
        self.global_limits.clone()
    }

    fn entry_or_create<'a>(
        &self,
        pools: &'a mut HashMap<PoolKey, PoolInner>,
        key: &PoolKey,
    ) -> &'a mut PoolInner {
        let limits = self.resolve_limits(key);
        let timeout = self.default_timeout;
        let lifetime = self.default_lifetime;
        pools.entry(key.clone()).or_insert_with(|| {
            tracing::info!(
                "creating pool for {}@{} (max={}, min={}, reserve={}, strategy={:?})",
                key.db_user,
                key.dbname,
                limits.max_size,
                limits.min_size,
                limits.reserve_size,
                limits.strategy,
            );
            PoolInner {
                idle: VecDeque::new(),
                active: 0,
                limits,
                idle_timeout: timeout,
                server_lifetime: lifetime,
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
    pub reserve: usize,
    pub min: usize,
}
