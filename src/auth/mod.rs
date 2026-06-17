pub mod aws;
pub mod gcp;
pub mod cache;

use crate::config::IamConfig;

pub async fn get_token(config: &IamConfig) -> anyhow::Result<String> {
    match config.provider {
        crate::config::IamProvider::Aws => aws::generate_token(config).await,
        crate::config::IamProvider::Gcp => gcp::generate_token(config).await,
        crate::config::IamProvider::None => {
            anyhow::bail!("no IAM provider configured")
        }
    }
}
