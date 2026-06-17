use crate::config::IamConfig;
use aws_credential_types::provider::ProvideCredentials;
use aws_credential_types::Credentials;
use aws_sdk_rds::auth_token::{AuthTokenGenerator, Config as AuthTokenGeneratorConfig};

pub async fn generate_token(config: &IamConfig) -> anyhow::Result<String> {
    let region = config
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

    let creds = resolve_credentials().await?;

    let sdk_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_types::region::Region::new(region))
        .credentials_provider(creds)
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

async fn resolve_credentials() -> anyhow::Result<Credentials> {
    // 1. Check environment variables
    if let Some(creds) = from_env() {
        return Ok(creds);
    }

    // 2. Check standard ~/.aws/credentials via the SDK's default chain
    let chain = aws_config::default_provider::credentials::DefaultCredentialsChain::builder()
        .region(aws_types::region::Region::new("us-east-1"))
        .build()
        .await;
    if let Ok(creds) = chain.provide_credentials().await {
        return Ok(creds);
    }

    // 3. Fallback: read ~/.aws/login/cache/*.json (aws login extension)
    if let Some(creds) = load_login_cache_credentials() {
        return Ok(creds);
    }

    anyhow::bail!(
        "no AWS credentials found. Configure via env vars, ~/.aws/credentials, or run 'aws login'"
    )
}

fn from_env() -> Option<Credentials> {
    let key_id = std::env::var("AWS_ACCESS_KEY_ID").ok()
        .or_else(|| std::env::var("AWS_ACCESS_KEY").ok())?;
    let secret = std::env::var("AWS_SECRET_ACCESS_KEY").ok()
        .or_else(|| std::env::var("AWS_SECRET_KEY").ok())?;
    let session = std::env::var("AWS_SESSION_TOKEN").ok()
        .or_else(|| std::env::var("AWS_SECURITY_TOKEN").ok());
    // Optionally parse AWS_CREDENTIAL_EXPIRATION for expiry
    let expires = std::env::var("AWS_CREDENTIAL_EXPIRATION").ok()
        .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
        .and_then(|dt| dt.timestamp().try_into().ok())
        .map(|secs| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs));
    Some(Credentials::new(key_id, secret, session, expires, "env"))
}

fn load_login_cache_credentials() -> Option<Credentials> {
    let home = std::env::var("HOME").ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    let cache_dir = std::path::Path::new(&home)
        .join(".aws")
        .join("login")
        .join("cache");
    let dir = std::fs::read_dir(cache_dir).ok()?;

    let mut latest: Option<(std::time::SystemTime, Credentials)> = None;

    for entry in dir {
        let entry = entry.ok()?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let content = std::fs::read_to_string(&path).ok()?;
        let data: serde_json::Value = serde_json::from_str(&content).ok()?;
        let token = data.get("accessToken")?;
        let key_id = token.get("accessKeyId")?.as_str()?;
        let secret = token.get("secretAccessKey")?.as_str()?;
        let session = token.get("sessionToken").and_then(|v| v.as_str());
        let expires = token.get("expiresAt")
            .and_then(|v| v.as_str())
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .and_then(|dt| dt.timestamp().try_into().ok())
            .map(|secs| std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(secs));

        // Skip expired credentials
        if let Some(exp) = expires {
            if std::time::SystemTime::now() > exp {
                continue;
            }
        }

        let creds = Credentials::new(
            key_id.to_string(),
            secret.to_string(),
            session.map(|s| s.to_string()),
            expires,
            "aws-login-cache",
        );

        let mtime = std::fs::metadata(&path).ok()?.modified().ok()?;
        latest = match latest.take() {
            None => Some((mtime, creds)),
            Some((ref last_time, _)) if mtime > *last_time => Some((mtime, creds)),
            Some(prev) => Some(prev),
        };
    }

    latest.map(|(_, creds)| creds)
}
