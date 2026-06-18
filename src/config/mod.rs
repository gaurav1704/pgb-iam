use std::collections::HashMap;
use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct IamConfig {
    pub provider: IamProvider,
    pub region: Option<String>,
    pub instance_host: Option<String>,
    pub instance_port: Option<u16>,
    pub db_user: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum IamProvider {
    Aws,
    Gcp,
    None,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PoolMode {
    Session,
    Transaction,
}

impl Default for PoolMode {
    fn default() -> Self {
        Self::Session
    }
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum PoolStrategy {
    Lifo,
    Fifo,
}

impl Default for PoolStrategy {
    fn default() -> Self {
        Self::Lifo
    }
}

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PoolLimits {
    pub max_size: Option<u32>,
    pub min_size: Option<u32>,
    pub reserve_size: Option<u32>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PoolConfig {
    pub max_size: u32,
    #[serde(default)]
    pub min_size: u32,
    #[serde(default)]
    pub reserve_size: u32,
    #[serde(default)]
    pub strategy: PoolStrategy,
    pub idle_timeout_secs: u64,
    #[serde(default = "default_server_lifetime")]
    pub server_lifetime_secs: u64,
    #[serde(default = "default_server_connect_timeout")]
    pub server_connect_timeout_secs: u64,
    #[serde(default)]
    #[allow(dead_code)]
    pub query_timeout_secs: u64,
    #[serde(default)]
    pub client_idle_timeout_secs: u64,
    #[serde(default)]
    pub transaction_timeout_secs: u64,
    #[serde(default)]
    pub query_wait_timeout_secs: u64,
    pub target_host: String,
    pub target_port: u16,
    pub dbname: String,
    pub db_user: String,
    #[serde(default)]
    pub mode: PoolMode,
    #[serde(default = "default_reset_query")]
    pub server_reset_query: String,
    #[serde(default)]
    pub database_limits: HashMap<String, PoolLimits>,
    #[serde(default)]
    pub user_limits: HashMap<String, PoolLimits>,
    #[serde(default)]
    pub client_max: u32,
}

fn default_reset_query() -> String {
    "DISCARD ALL".to_string()
}

fn default_server_lifetime() -> u64 {
    3600
}

fn default_server_connect_timeout() -> u64 {
    15
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthConfig {
    #[serde(rename = "type")]
    pub auth_type: ClientAuthType,
    pub password: Option<String>,
    #[serde(default)]
    pub auth_query: Option<AuthQueryConfig>,
    #[serde(default)]
    pub pam_service: Option<String>,
    #[serde(default)]
    pub ldap: Option<LdapAuthConfig>,
    #[serde(default)]
    pub hba_rules: Vec<HbaRuleConfig>,
    #[serde(default)]
    pub client_ca: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthType {
    Trust,
    Password,
    ScramSha256,
    Cert,
    Pam,
    Ldap,
    Hba,
    AuthQuery,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthQueryConfig {
    pub user: String,
    pub query: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct LdapAuthConfig {
    pub uri: String,
    pub bind_dn: String,
    pub bind_password: String,
    pub search_base: String,
    pub search_filter: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HbaRuleConfig {
    #[serde(rename = "type")]
    pub conn_type: String,
    pub database: Vec<String>,
    pub user: Vec<String>,
    pub address: Option<String>,
    pub auth: String, // trust, password, scram-sha-256, cert, pam, ldap, reject
}

#[derive(Debug, Deserialize, Clone)]
pub struct ListenConfig {
    pub addr: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct MetricsConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    pub enabled: bool,
    pub cert_path: String,
    pub key_path: String,
    pub connect_with_tls: bool,
    #[serde(default)]
    pub backend_ca_path: Option<String>,
    #[serde(default)]
    pub ciphers: Option<Vec<String>>,
    #[serde(default)]
    pub min_protocol_version: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    pub enabled: bool,
    pub listen_addr: String,
    pub listen_port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct HealthCheckConfig {
    pub enabled: bool,
    pub interval_secs: u64,
    pub timeout_secs: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub listen: ListenConfig,
    pub pool: PoolConfig,
    pub client_auth: ClientAuthConfig,
    pub iam: Option<IamConfig>,
    pub metrics: Option<MetricsConfig>,
    pub tls: Option<TlsConfig>,
    pub admin: Option<AdminConfig>,
    pub health_check: Option<HealthCheckConfig>,
}

impl Config {
    pub fn listen_addr(&self) -> String {
        format!("{}:{}", self.listen.addr, self.listen.port)
    }

    pub fn target_addr(&self) -> String {
        format!("{}:{}", self.pool.target_host, self.pool.target_port)
    }
}

pub async fn load(path: &str) -> anyhow::Result<Config> {
    let content = tokio::fs::read_to_string(path).await?;
    let config: Config = toml::from_str(&content)?;
    Ok(config)
}
