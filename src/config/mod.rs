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
pub enum IamProvider {
    Aws,
    Gcp,
    None,
}

#[derive(Debug, Deserialize, Clone)]
pub struct PoolConfig {
    pub min_size: u32,
    pub max_size: u32,
    pub idle_timeout_secs: u64,
    pub target_host: String,
    pub target_port: u16,
    pub dbname: String,
    pub db_user: String,
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
pub struct Config {
    pub listen: ListenConfig,
    pub pool: PoolConfig,
    pub iam: Option<IamConfig>,
    pub metrics: Option<MetricsConfig>,
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
