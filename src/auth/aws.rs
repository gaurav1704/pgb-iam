use crate::config::IamConfig;
use aws_sdk_rds::auth_token::{AuthTokenGenerator, Config as AuthTokenGeneratorConfig};

pub async fn generate_token(config: &IamConfig) -> anyhow::Result<String> {
    let region_str = config
        .region
        .clone()
        .unwrap_or_else(|| "us-east-1".to_string());
    let host = config
        .instance_host
        .clone()
        .ok_or_else(|| anyhow::anyhow!("instance_host required for AWS IAM"))?;
    let port = config.instance_port.unwrap_or(5432) as u64;
    let user = config
        .db_user
        .clone()
        .ok_or_else(|| anyhow::anyhow!("db_user required for AWS IAM"))?;

    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_types::region::Region::new(region_str))
        .load()
        .await;

    let generator_config = AuthTokenGeneratorConfig::builder()
        .hostname(&host)
        .port(port)
        .username(&user)
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build auth token config: {}", e))?;

    let generator = AuthTokenGenerator::new(generator_config);
    let token = generator
        .auth_token(&sdk_config)
        .await
        .map_err(|e| anyhow::anyhow!("failed to generate auth token: {}", e))?;

    tracing::info!("generated AWS RDS IAM token for {}@{}:{}", user, host, port);
    Ok(token.to_string())
}
