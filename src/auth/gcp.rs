use crate::config::IamConfig;

pub async fn generate_token(_config: &IamConfig) -> anyhow::Result<String> {
    anyhow::bail!("GCP IAM auth not yet implemented")
}
