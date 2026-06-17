use std::io::BufReader;
use std::sync::Arc;
use tokio::net::TcpStream;

fn load_server_config(cert_path: &str, key_path: &str) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(std::fs::File::open(cert_path)?))
        .collect::<Result<Vec<_>, _>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(std::fs::File::open(key_path)?))?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", key_path))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS config error: {}", e))?;

    Ok(Arc::new(config))
}

fn load_client_config() -> Arc<rustls::ClientConfig> {
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    Arc::new(config)
}

pub async fn tls_accept(
    stream: TcpStream,
    cert_path: &str,
    key_path: &str,
) -> anyhow::Result<tokio_rustls::TlsStream<TcpStream>> {
    let config = load_server_config(cert_path, key_path)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let tls = acceptor.accept(stream).await?;
    Ok(tokio_rustls::TlsStream::Server(tls))
}

pub async fn tls_connect(
    stream: TcpStream,
    domain: &str,
) -> anyhow::Result<tokio_rustls::TlsStream<TcpStream>> {
    let config = load_client_config();
    let connector = tokio_rustls::TlsConnector::from(config);
    // Leak the domain string to get a 'static lifetime for the ServerName.
    // Acceptable since this runs per-connection in a long-lived proxy.
    let domain: &'static str = Box::leak(domain.to_string().into_boxed_str());
    let server_name = rustls::pki_types::ServerName::try_from(domain)
        .map_err(|_| anyhow::anyhow!("invalid domain name: {}", domain))?;
    let tls = connector.connect(server_name, stream).await?;
    Ok(tokio_rustls::TlsStream::Client(tls))
}
