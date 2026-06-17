use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;
use rustls::crypto::CryptoProvider;

pub struct TlsCipherConfig {
    pub ciphers: Option<Vec<String>>,
    pub min_protocol_version: Option<String>,
}

fn build_provider_with_ciphers(
    cipher_names: &[String],
) -> anyhow::Result<Arc<CryptoProvider>> {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    let suites = cipher_names
        .iter()
        .map(|name| parse_cipher_suite(name))
        .collect::<Result<Vec<_>, _>>()?;
    provider.cipher_suites = suites;
    Ok(Arc::new(provider))
}

fn load_server_config(
    cert_path: &str,
    key_path: &str,
    client_ca_path: Option<&str>,
    cipher_config: Option<&TlsCipherConfig>,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key_path)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

    let verifier_builder = build_verifier_builder(cipher_config)?;

    let config = if let Some(ca_path) = client_ca_path {
        let mut root_store = rustls::RootCertStore::empty();
        let ca_certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(ca_path)?))
            .collect::<Result<Vec<_>, _>>()?;
        for cert in ca_certs {
            root_store.add(cert).map_err(|e| anyhow::anyhow!("invalid CA cert: {}", e))?;
        }
        verifier_builder
            .with_client_cert_verifier(
                rustls::server::WebPkiClientVerifier::builder(root_store.into())
                    .build()
                    .map_err(|e| anyhow::anyhow!("client verifier: {}", e))?,
            )
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
    } else {
        verifier_builder
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?
    };

    Ok(Arc::new(config))
}

fn build_verifier_builder(
    cipher_config: Option<&TlsCipherConfig>,
) -> anyhow::Result<rustls::ConfigBuilder<rustls::ServerConfig, rustls::WantsVerifier>> {
    match cipher_config {
        Some(cfg) if cfg.ciphers.is_some() || cfg.min_protocol_version.is_some() => {
            if let Some(ref names) = cfg.ciphers {
                let provider = build_provider_with_ciphers(names)?;
                let builder = rustls::ServerConfig::builder_with_provider(provider);
                let builder = if let Some(ref v) = cfg.min_protocol_version {
                    let pv = parse_protocol_version(v)?;
                    builder
                        .with_protocol_versions(&[pv])
                        .map_err(|_| anyhow::anyhow!("incompatible TLS config: protocol version {} not supported by cipher suites", v))?
                } else {
                    builder
                        .with_safe_default_protocol_versions()
                        .map_err(|_| anyhow::anyhow!("incompatible TLS config: protocol versions not supported by cipher suites"))?
                };
                Ok(builder)
            } else {
                // Only custom protocol version, default cipher suites
                let v = cfg.min_protocol_version.as_ref().unwrap();
                let pv = parse_protocol_version(v)?;
                Ok(rustls::ServerConfig::builder_with_protocol_versions(&[pv]))
            }
        }
        _ => Ok(rustls::ServerConfig::builder()),
    }
}

fn parse_cipher_suite(name: &str) -> anyhow::Result<rustls::SupportedCipherSuite> {
    use rustls::CipherSuite::*;
    let cs = match name {
        "TLS13_AES_256_GCM_SHA384" => TLS13_AES_256_GCM_SHA384,
        "TLS13_AES_128_GCM_SHA256" => TLS13_AES_128_GCM_SHA256,
        "TLS13_CHACHA20_POLY1305_SHA256" => TLS13_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256" => TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384" => TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" => TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256" => TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        _ => anyhow::bail!("unknown cipher suite: {}", name),
    };
    let provider = rustls::crypto::aws_lc_rs::default_provider();
    provider
        .cipher_suites
        .iter()
        .find(|s| s.suite() == cs)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("cipher suite {} not available in provider", name))
}

fn parse_protocol_version(version: &str) -> anyhow::Result<&'static rustls::SupportedProtocolVersion> {
    match version.to_lowercase().as_str() {
        "tlsv1.2" | "tls1.2" | "tls12" => Ok(&rustls::version::TLS12),
        "tlsv1.3" | "tls1.3" | "tls13" => Ok(&rustls::version::TLS13),
        _ => anyhow::bail!("unsupported TLS protocol version: {}", version),
    }
}

fn load_client_config(
    cipher_config: Option<&TlsCipherConfig>,
    ca_path: Option<&str>,
) -> anyhow::Result<Arc<rustls::ClientConfig>> {
    let mut root_store = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        root_store.add(cert).ok();
    }
    if let Some(ca) = ca_path {
        let ca_certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(ca)?))
            .collect::<Result<Vec<_>, _>>()?;
        for cert in ca_certs {
            root_store.add(cert).ok();
        }
    }

    let config = match cipher_config {
        Some(cfg) if cfg.ciphers.is_some() || cfg.min_protocol_version.is_some() => {
            match &cfg.ciphers {
                Some(names) => {
                    let provider = build_provider_with_ciphers(names)?;
                    let builder = rustls::ClientConfig::builder_with_provider(provider);
                    let builder = if let Some(ref v) = cfg.min_protocol_version {
                        let pv = parse_protocol_version(v)?;
                        builder
                            .with_protocol_versions(&[pv])
                            .map_err(|_| anyhow::anyhow!("incompatible TLS client config"))?
                    } else {
                        builder
                            .with_safe_default_protocol_versions()
                            .map_err(|_| anyhow::anyhow!("incompatible TLS client config"))?
                    };
                    builder
                        .with_root_certificates(root_store)
                        .with_no_client_auth()
                }
                None => {
                    let v = cfg.min_protocol_version.as_ref().unwrap();
                    let pv = parse_protocol_version(v)?;
                    rustls::ClientConfig::builder_with_protocol_versions(&[pv])
                        .with_root_certificates(root_store)
                        .with_no_client_auth()
                }
            }
        }
        _ => rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    };

    Ok(Arc::new(config))
}

pub async fn tls_accept(
    stream: TcpStream,
    cert_path: &str,
    key_path: &str,
    client_ca: Option<&str>,
    cipher_config: Option<&TlsCipherConfig>,
) -> anyhow::Result<tokio_rustls::TlsStream<TcpStream>> {
    let config = load_server_config(cert_path, key_path, client_ca, cipher_config)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let tls = acceptor.accept(stream).await?;
    Ok(tokio_rustls::TlsStream::Server(tls))
}

pub async fn tls_connect(
    stream: TcpStream,
    domain: &str,
    cipher_config: Option<&TlsCipherConfig>,
    ca_path: Option<&str>,
) -> anyhow::Result<tokio_rustls::TlsStream<TcpStream>> {
    let config = load_client_config(cipher_config, ca_path)?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let domain: &'static str = Box::leak(domain.to_string().into_boxed_str());
    let server_name = rustls::pki_types::ServerName::try_from(domain)
        .map_err(|_| anyhow::anyhow!("invalid domain name: {}", domain))?;
    let tls = connector.connect(server_name, stream).await?;
    Ok(tokio_rustls::TlsStream::Client(tls))
}
