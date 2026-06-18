use crate::config::IamConfig;

pub async fn generate_token(_config: &IamConfig) -> anyhow::Result<String> {
    if let Some(token) = from_env() {
        crate::log_event!(INFO, crate::log::IAM, crate::log::AUTHENTICATE, "using GCP access token from GCP_ACCESS_TOKEN env var");
        return Ok(token);
    }

    if let Ok(token) = metadata_server_token().await {
        return Ok(token);
    }

    anyhow::bail!(
        "no GCP credentials found. Set GCP_ACCESS_TOKEN env var, or run on a GCP \
         instance with a service account that has Cloud SQL Client role. \
         For local development: `gcloud auth application-default login` then \
         set GOOGLE_APPLICATION_CREDENTIALS"
    )
}

fn from_env() -> Option<String> {
    let token = std::env::var("GCP_ACCESS_TOKEN").ok()?;
    if token.is_empty() { None } else { Some(token) }
}

async fn metadata_server_token() -> anyhow::Result<String> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()?;

    let resp = client
        .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
        .header("Metadata-Flavor", "Google")
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("GCP metadata server unreachable: {}", e))?;

    let data: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("failed to parse metadata response: {}", e))?;

    let token = data["access_token"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("no access_token in metadata response"))?;

    crate::log_event!(INFO, crate::log::IAM, crate::log::REFRESH, "generated GCP Cloud SQL IAM token via metadata server");
    Ok(token.to_string())
}
