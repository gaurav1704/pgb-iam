pub mod aws;
pub mod gcp;

use crate::config::IamConfig;

pub enum IamToken {
    Aws(String),
    Gcp(String),
}

pub async fn get_token(config: &IamConfig) -> anyhow::Result<IamToken> {
    match config.provider {
        crate::config::IamProvider::Aws => {
            let token = aws::generate_token(config).await?;
            Ok(IamToken::Aws(token))
        }
        crate::config::IamProvider::Gcp => {
            let token = gcp::generate_token(config).await?;
            Ok(IamToken::Gcp(token))
        }
        crate::config::IamProvider::None => {
            anyhow::bail!("no IAM provider configured")
        }
    }
}
