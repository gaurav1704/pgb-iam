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
pub struct PoolConfig {
    pub max_size: u32,
    pub idle_timeout_secs: u64,
    pub target_host: String,
    pub target_port: u16,
    pub dbname: String,
    pub db_user: String,
    #[serde(default)]
    pub mode: PoolMode,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ClientAuthConfig {
    #[serde(rename = "type")]
    pub auth_type: ClientAuthType,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuthType {
    Trust,
    Password,
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
