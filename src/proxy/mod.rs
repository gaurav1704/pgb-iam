pub mod admin;
pub mod health;

use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing;

use crate::auth::cache::TokenCache;
use crate::config::{Config, IamProvider};
use crate::pgproto;
use crate::pool::Pool;
use crate::tls;

enum StreamEither {
    Plain(TcpStream),
    Tls(tokio_rustls::TlsStream<TcpStream>),
}

impl AsyncRead for StreamEither {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.get_mut() {
            StreamEither::Plain(s) => std::pin::Pin::new(s).poll_read(cx, buf),
            StreamEither::Tls(s) => std::pin::Pin::new(s).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for StreamEither {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        match self.get_mut() {
            StreamEither::Plain(s) => std::pin::Pin::new(s).poll_write(cx, buf),
            StreamEither::Tls(s) => std::pin::Pin::new(s).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            StreamEither::Plain(s) => std::pin::Pin::new(s).poll_flush(cx),
            StreamEither::Tls(s) => std::pin::Pin::new(s).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        match self.get_mut() {
            StreamEither::Plain(s) => std::pin::Pin::new(s).poll_shutdown(cx),
            StreamEither::Tls(s) => std::pin::Pin::new(s).poll_shutdown(cx),
        }
    }
}

pub async fn run(
    _pool: Arc<Pool>,
    config: Config,
    token_cache: Option<Arc<TokenCache>>,
) -> anyhow::Result<()> {
    let addr = config.listen_addr();
    let listener = TcpListener::bind(&addr).await?;
    tracing::info!("listening on {}", addr);

    loop {
        let (inbound, peer) = listener.accept().await?;
        let config = config.clone();
        let token_cache = token_cache.clone();

        tokio::spawn(async move {
            tracing::debug!("new client connection from {}", peer);

            if let Err(e) = handle_client(inbound, &config, token_cache.as_ref()).await {
                tracing::error!("handler error for {}: {}", peer, e);
            }

            tracing::debug!("client {} disconnected", peer);
        });
    }
}

async fn handle_client(
    mut client: TcpStream,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<()> {
    let client_tls = config.tls.as_ref().is_some_and(|t| t.enabled);
    let backend_tls = config
        .tls
        .as_ref()
        .is_some_and(|t| t.enabled && t.connect_with_tls);

    // ---- Client side: handle optional TLS upgrade ----
    let mut client_stream: StreamEither = if client_tls {
        let tls_config = config.tls.as_ref().unwrap();
        let initial = pgproto::read_initial_message(&mut client).await?;
        match initial {
            pgproto::InitialMessage::SslRequest => {
                pgproto::send_ssl_accept(&mut client).await?;
                let tls_stream =
                    tls::tls_accept(client, &tls_config.cert_path, &tls_config.key_path).await?;
                StreamEither::Tls(tls_stream)
            }
            pgproto::InitialMessage::Startup(_) => {
                anyhow::bail!("client sent startup without SSLRequest, but TLS is required");
            }
        }
    } else {
        StreamEither::Plain(client)
    };

    // ---- Read startup (may be on TLS or plain) ----
    let startup = pgproto::read_initial_message(&mut client_stream).await?;
    let startup = match startup {
        pgproto::InitialMessage::Startup(s) => s,
        pgproto::InitialMessage::SslRequest => {
            anyhow::bail!("unexpected SSLRequest after TLS handshake");
        }
    };

    tracing::info!(
        "client connecting as user={} db={}",
        startup.user,
        startup.database
    );

    // ---- Backend side: connect and optionally upgrade to TLS ----
    let mut backend = TcpStream::connect(config.target_addr()).await?;
    let mut backend_stream: StreamEither = if backend_tls {
        let host = config.pool.target_host.clone();
        let accepted = pgproto::ssl_request(&mut backend).await?;
        if !accepted {
            anyhow::bail!("backend does not support TLS");
        }
        let tls_stream = tls::tls_connect(backend, &host).await?;
        StreamEither::Tls(tls_stream)
    } else {
        StreamEither::Plain(backend)
    };

    // ---- Forward startup and handle auth ----
    pgproto::write_startup_message(&mut backend_stream, &startup).await?;

    let iam_for_user = config.iam.as_ref().is_some_and(|iam| {
        iam.db_user.as_deref() == Some(&startup.user)
            && !matches!(iam.provider, IamProvider::None)
    });

    loop {
        let msg = pgproto::read_pg_message(&mut backend_stream).await?;
        match msg {
            None => anyhow::bail!("backend closed connection during auth"),
            Some((type_byte, payload)) => {
                match type_byte {
                    b'R' => {
                        let auth_req = pgproto::parse_auth_request(&payload)?;
                        match auth_req {
                            pgproto::AuthRequest::Ok => {
                                tracing::info!("authentication successful for {}", startup.user);
                                forward_msg(&mut client_stream, type_byte, &payload).await?;
                                break;
                            }
                            pgproto::AuthRequest::CleartextPassword
                            | pgproto::AuthRequest::MD5Password(_) => {
                                if iam_for_user {
                                    let iam_config = config.iam.as_ref().unwrap();
                                    let token = if let Some(cache) = token_cache {
                                        cache.get().await?
                                    } else {
                                        crate::auth::get_token(iam_config).await?
                                    };

                                    if let pgproto::AuthRequest::MD5Password(salt) = auth_req {
                                        let md5 = md5_iam_password(&token, &startup.user, &salt);
                                        pgproto::send_password(&mut backend_stream, &md5).await?;
                                    } else {
                                        pgproto::send_password(&mut backend_stream, &token).await?;
                                    }
                                } else {
                                    forward_msg(&mut client_stream, type_byte, &payload).await?;
                                    if let Some((_, pwd_payload)) =
                                        pgproto::read_pg_message(&mut client_stream).await?
                                    {
                                        backend_stream.write_all(&pwd_payload).await?;
                                        backend_stream.flush().await?;
                                    }
                                }
                            }
                            _ => {
                                forward_msg(&mut client_stream, type_byte, &payload).await?;
                            }
                        }
                    }
                    b'E' | b'K' | b'S' | b'N' => {
                        forward_msg(&mut client_stream, type_byte, &payload).await?;
                        if type_byte == b'E' {
                            anyhow::bail!("backend auth error: {}", String::from_utf8_lossy(&payload));
                        }
                    }
                    _ => {
                        tracing::warn!("unexpected message type {} during auth", type_byte as char);
                        break;
                    }
                }
            }
        }
    }

    pgproto::relay(client_stream, backend_stream).await;
    Ok(())
}

async fn forward_msg(
    stream: &mut (impl AsyncWrite + Unpin),
    type_byte: u8,
    payload: &[u8],
) -> anyhow::Result<()> {
    let mut msg = Vec::with_capacity(1 + 4 + payload.len());
    msg.push(type_byte);
    msg.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
    msg.extend_from_slice(payload);
    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

fn md5_iam_password(token: &str, user: &str, salt: &[u8; 4]) -> String {
    use md5::{Digest, Md5};

    let mut hasher = Md5::new();
    hasher.update(token.as_bytes());
    hasher.update(user.as_bytes());
    let hash = hasher.finalize();
    let hex = format!("{:x}", hash);

    let mut final_hasher = Md5::new();
    final_hasher.update(hex.as_bytes());
    final_hasher.update(salt);
    let final_hash = final_hasher.finalize();

    format!("md5{:x}", final_hash)
}
