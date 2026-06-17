pub mod aws;
pub mod gcp;
pub mod cache;
pub mod scram;
pub mod hba;
pub mod auth_query;
pub mod pam_ffi;
pub mod pam;
pub mod ldap;

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
