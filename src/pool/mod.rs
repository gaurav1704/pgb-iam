use std::collections::{HashMap, VecDeque};
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;

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

struct IdleConn {
    stream: ServerStream,
    parked_since: Instant,
    born_at: Instant,
}

struct PoolInner {
    idle: VecDeque<IdleConn>,
    limits: PoolLimits,
    idle_timeout: Duration,
    server_lifetime: Duration,
}

// ── PoolManager ─────────────────────────────────────────────────────

pub struct PoolManager {
    pools: Mutex<HashMap<PoolKey, PoolInner>>,
    semaphores: tokio::sync::RwLock<HashMap<PoolKey, Arc<Semaphore>>>,
    global_limits: PoolLimits,
    default_timeout: Duration,
    default_lifetime: Duration,
    database_limits: HashMap<String, PoolLimits>,
    user_limits: HashMap<String, PoolLimits>,
    pub client_max: usize,
    pub client_count: AtomicUsize,
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
            semaphores: tokio::sync::RwLock::new(HashMap::new()),
            global_limits,
            default_timeout: Duration::from_secs(config.idle_timeout_secs),
            default_lifetime: Duration::from_secs(config.server_lifetime_secs),
            database_limits,
            user_limits,
            client_max: config.client_max as usize,
            client_count: AtomicUsize::new(0),
        }
    }

    fn resolve_limits(&self, key: &PoolKey) -> PoolLimits {
        if let Some(limits) = self.user_limits.get(&key.db_user) {
            return limits.clone();
        }
        if let Some(limits) = self.database_limits.get(&key.dbname) {
            return limits.clone();
        }
        self.global_limits.clone()
    }

    fn capacity(&self, key: &PoolKey) -> usize {
        let limits = self.resolve_limits(key);
        limits.max_size + limits.reserve_size
    }

    async fn get_or_create_semaphore(&self, key: &PoolKey) -> Arc<Semaphore> {
        {
            let read = self.semaphores.read().await;
            if let Some(s) = read.get(key) {
                return s.clone();
            }
        }
        let mut write = self.semaphores.write().await;
        write
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Semaphore::new(self.capacity(key))))
            .clone()
    }

    /// Acquire a backend connection slot — waits until one is available.
    /// Returns an idle connection if one exists, otherwise signals the
    /// caller to create a new backend via `create_backend`.
    ///
    /// On return, exactly one permit is consumed from the semaphore
    /// (either carried by the idle connection or held for a new backend).
    pub async fn acquire(
        &self,
        key: &PoolKey,
    ) -> Option<(ServerStream, Instant)> {
        let sem = self.get_or_create_semaphore(key).await;

        // 1. Check for an idle connection first — no extra permit needed
        //    because the idle connection already holds one.
        {
            let mut pools = self.pools.lock().await;
            if let Some(inner) = pools.get_mut(key) {
                loop {
                    match match inner.limits.strategy {
                        PoolStrategy::Lifo => inner.idle.pop_back(),
                        PoolStrategy::Fifo => inner.idle.pop_front(),
                    } {
                        Some(ic) => {
                            let expired = ic.parked_since.elapsed() >= inner.idle_timeout
                                || ic.born_at.elapsed() >= inner.server_lifetime;
                            if !expired {
                                return Some((ic.stream, ic.born_at));
                            }
                            // Expired — drop the connection, return its permit.
                            drop(ic);
                            sem.add_permits(1);
                        }
                        None => break,
                    }
                }
            }
        }

        // 2. No idle — acquire a permit for a new backend, then let the
        //    caller create one.  `forget()` prevents auto-return on drop.
        let permit = sem.acquire().await.ok()?;
        permit.forget();
        None
    }

    /// Release a connection back to the pool (returns the semaphore permit).
    pub async fn release(&self, key: &PoolKey, stream: ServerStream, born_at: Instant) {
        let limits = self.resolve_limits(key);
        let expired = born_at.elapsed() >= self.default_lifetime;
        if !expired {
            let mut pools = self.pools.lock().await;
            let inner = pools.entry(key.clone()).or_insert_with(|| PoolInner {
                idle: VecDeque::new(),
                limits: limits.clone(),
                idle_timeout: self.default_timeout,
                server_lifetime: self.default_lifetime,
            });
            if inner.idle.len() < inner.limits.max_size {
                inner.idle.push_back(IdleConn {
                    stream,
                    parked_since: Instant::now(),
                    born_at,
                });
                // Permit stays with the idle connection
                return;
            }
        }
        // Drop the connection and release the permit
        drop(stream);
        let sem = self.get_or_create_semaphore(key).await;
        sem.add_permits(1);
    }

    /// Cancel an in-progress backend creation (returns the semaphore permit).
    pub async fn cancel(&self, key: &PoolKey) {
        let sem = self.get_or_create_semaphore(key).await;
        sem.add_permits(1);
    }

    /// How many warm-up connections this pool needs.
    pub async fn needs_warmup(&self, key: &PoolKey) -> usize {
        let limits = self.resolve_limits(key);
        let pools = self.pools.lock().await;
        if let Some(inner) = pools.get(key) {
            let currently = inner.idle.len();
            if limits.min_size > currently {
                limits.min_size - currently
            } else {
                0
            }
        } else {
            limits.min_size
        }
    }

    // ── Stats ────────────────────────────────────────────────────────

    pub async fn stats_for(&self, key: &PoolKey) -> Option<PoolStats> {
        let limits = self.resolve_limits(key);
        let sem = self.get_or_create_semaphore(key).await;
        let available = sem.available_permits();
        let total = limits.max_size + limits.reserve_size;
        let pools = self.pools.lock().await;
        let idle = pools.get(key).map(|p| p.idle.len()).unwrap_or(0);
        Some(PoolStats {
            idle,
            active: total - available - idle,
            max: limits.max_size,
            reserve: limits.reserve_size,
            min: limits.min_size,
        })
    }

    #[allow(dead_code)]
    pub async fn all_stats(&self) -> HashMap<PoolKey, PoolStats> {
        let pools = self.pools.lock().await;
        let mut result = HashMap::new();
        for (key, inner) in pools.iter() {
            result.insert(
                key.clone(),
                PoolStats {
                    idle: inner.idle.len(),
                    active: 0,
                    max: inner.limits.max_size,
                    reserve: inner.limits.reserve_size,
                    min: inner.limits.min_size,
                },
            );
        }
        result
    }

    pub async fn global_stats(&self) -> PoolStats {
        let sems = self.semaphores.read().await;
        let pools = self.pools.lock().await;
        let mut total = PoolStats {
            idle: 0,
            active: 0,
            max: 0,
            reserve: 0,
            min: 0,
        };
        for (key, inner) in pools.iter() {
            total.idle += inner.idle.len();
            total.max += inner.limits.max_size;
            total.reserve += inner.limits.reserve_size;
            total.min += inner.limits.min_size;
            let cap = inner.limits.max_size + inner.limits.reserve_size;
            let available = sems.get(key).map(|s| s.available_permits() as usize).unwrap_or(cap);
            let consumed = cap.saturating_sub(available);
            total.active += consumed.saturating_sub(inner.idle.len());
        }
        total
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
