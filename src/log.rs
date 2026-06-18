/// Lazily-resolved hostname.
pub fn hostname() -> &'static str {
    static HOSTNAME: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    HOSTNAME.get_or_init(|| {
        std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("HOST"))
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

// ── Component identifiers ──────────────────────────────────────────────
pub const CLIENT: &str = "client";
pub const POOL: &str = "pool";
#[allow(dead_code)]
pub const SERVER: &str = "server";
pub const AUTH: &str = "auth";
pub const IAM: &str = "iam";
#[allow(dead_code)]
pub const TLS: &str = "tls";
pub const CONFIG: &str = "config";
pub const METRICS: &str = "metrics";
pub const HEALTH: &str = "health";
pub const ADMIN: &str = "admin";
pub const PROXY: &str = "proxy";

// ── Action identifiers ─────────────────────────────────────────────────
pub const CONNECT: &str = "connect";
pub const DISCONNECT: &str = "disconnect";
pub const AUTHENTICATE: &str = "authenticate";
pub const STATS: &str = "stats";
pub const TIMEOUT: &str = "timeout";
pub const ERROR: &str = "error";
pub const START: &str = "start";
#[allow(dead_code)]
pub const STOP: &str = "stop";
pub const REFRESH: &str = "refresh";
pub const ACQUIRE: &str = "acquire";
pub const RELEASE: &str = "release";
pub const CREATE: &str = "create";
pub const DROP: &str = "drop";
pub const CANCEL: &str = "cancel";
#[allow(dead_code)]
pub const RELAY: &str = "relay";
pub const CHECK: &str = "check";
pub const WARMUP: &str = "warmup";
#[allow(dead_code)]
pub const RESET: &str = "reset";

/// Emit a structured log event with `component`, `action`, and `hostname` fields.
///
/// Usage:
/// ```ignore
/// log_event!(INFO, log::CLIENT, log::CONNECT, "accepted connection", client_addr = %addr);
/// log_event!(ERROR, log::AUTH, log::ERROR, "authentication failed: {}", err);
/// ```
#[macro_export]
macro_rules! log_event {
    ($level:ident, $component:expr, $action:expr, $($arg:tt)+) => {
        tracing::event!(
            target: module_path!(),
            tracing::Level::$level,
            component = $component,
            action = $action,
            hostname = $crate::log::hostname(),
            $($arg)+
        )
    };
}
