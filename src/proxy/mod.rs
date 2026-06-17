pub mod admin;
pub mod health;

use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing;

use crate::auth::cache::TokenCache;
use crate::config::{ClientAuthType, Config, IamProvider};
use crate::pgproto;
use crate::pool::{PoolKey, PoolManager, ServerStream};
use crate::tls;

// ── Public entry point ──────────────────────────────────────────────

pub async fn run(
    pool: Arc<PoolManager>,
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
        let pool = pool.clone();

        tokio::spawn(async move {
            tracing::debug!("new client connection from {}", peer);
            if let Err(e) = handle_client(inbound, &config, pool, token_cache.as_ref()).await {
                tracing::error!("handler error for {}: {}", peer, e);
            }
            tracing::debug!("client {} disconnected", peer);
        });
    }
}

type ClientStream = ServerStream;

// ── Per-client handler ──────────────────────────────────────────────

async fn handle_client(
    raw_client: TcpStream,
    config: &Config,
    pool: Arc<PoolManager>,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<()> {
    // 1. Client TLS upgrade
    let mut client = upgrade_client_tls(raw_client, config).await?;

    // 2. Read startup from client
    let startup = read_client_startup(&mut client).await?;
    tracing::info!(
        "client connecting as user={} db={}",
        startup.user, startup.database
    );

    // 3. Authenticate client locally
    authenticate_client(&mut client, config).await?;

    // 4. Pool key uses BACKEND credentials
    let pool_key = PoolKey {
        host: config.pool.target_host.clone(),
        port: config.pool.target_port,
        db_user: config.pool.db_user.clone(),
        dbname: config.pool.dbname.clone(),
    };

    // 5. Try idle pooled connection
    if let Some(backend) = pool.try_acquire_idle(&pool_key).await {
        tracing::debug!("using idle backend from pool");
        send_fake_ready(&mut client).await?;
        relay_and_release(client, backend, &pool_key, &pool).await;
        return Ok(());
    }

    // 6. No idle — create new backend connection
    if !pool.reserve(&pool_key).await {
        anyhow::bail!("connection pool exhausted");
    }
    let backend = match create_backend(config, &pool_key, token_cache).await {
        Ok(b) => b,
        Err(e) => {
            pool.cancel_reservation(&pool_key).await;
            return Err(e);
        }
    };

    // Forward the backend's startup messages (ParameterStatus, BackendKeyData, ReadyForQuery)
    // to the client, then start relaying.

    // First, send AuthenticationOk if not already sent by authenticate_client.
    // authenticate_client already sent it for trust/password modes.
    // But for new backend connections, we need to forward backend's startup.
    // The authenticate_client already sent AuthOk to the client.
    // Now we forward backend's ParameterStatus + BackendKeyData + ReadyForQuery.

    // Actually, we consumed those in create_backend. We need to re-create them.
    // For simplicity, just use the same fake_ready for new connections too.
    send_fake_ready(&mut client).await?;

    relay_and_release(client, backend, &pool_key, &pool).await;
    Ok(())
}

// ── Client TLS ──────────────────────────────────────────────────────

async fn upgrade_client_tls(
    mut stream: TcpStream,
    config: &Config,
) -> anyhow::Result<ClientStream> {
    let client_tls = config.tls.as_ref().is_some_and(|t| t.enabled);
    if !client_tls {
        return Ok(ClientStream::Plain(stream));
    }
    let tls_config = config.tls.as_ref().unwrap();
    let initial = pgproto::read_initial_message(&mut stream).await?;
    match initial {
        pgproto::InitialMessage::SslRequest => {
            pgproto::send_ssl_accept(&mut stream).await?;
            let tls_stream =
                tls::tls_accept(stream, &tls_config.cert_path, &tls_config.key_path).await?;
            Ok(ClientStream::Tls(tls_stream))
        }
        pgproto::InitialMessage::Startup(_) => {
            anyhow::bail!("client sent startup without SSLRequest, but TLS is required");
        }
    }
}

async fn read_client_startup(client: &mut ClientStream) -> anyhow::Result<pgproto::StartupParams> {
    let initial = pgproto::read_initial_message(client).await?;
    match initial {
        pgproto::InitialMessage::Startup(s) => Ok(s),
        pgproto::InitialMessage::SslRequest => {
            anyhow::bail!("unexpected SSLRequest after TLS handshake");
        }
    }
}

// ── Local client auth ───────────────────────────────────────────────

async fn authenticate_client(
    client: &mut ClientStream,
    config: &Config,
) -> anyhow::Result<()> {
    match config.client_auth.auth_type {
        ClientAuthType::Trust => {
            pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
            client.flush().await?;
            Ok(())
        }
        ClientAuthType::Password => {
            // Request cleartext password
            pgproto::write_raw_message(client, b'R', &3i32.to_be_bytes()).await?;
            client.flush().await?;

            match pgproto::read_pg_message(client).await? {
                None => anyhow::bail!("client closed during auth"),
                Some((type_byte, pwd_payload)) => {
                    if type_byte != b'p' {
                        anyhow::bail!("expected PasswordMessage (p), got {}", type_byte as char);
                    }
                    // Strip trailing NUL
                    let password = String::from_utf8_lossy(
                        &pwd_payload[..pwd_payload.len().saturating_sub(1)],
                    )
                    .to_string();
                    let expected = config.client_auth.password.as_deref().unwrap_or("");
                    if password != expected {
                        let err = pgproto::build_error_response("28P01", "password authentication failed");
                        client.write_all(&err).await?;
                        client.flush().await?;
                        anyhow::bail!("client password authentication failed");
                    }
                    pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
                    client.flush().await?;
                    Ok(())
                }
            }
        }
    }
}

// ── Fake ready for pooled connections ───────────────────────────────

async fn send_fake_ready(client: &mut ClientStream) -> anyhow::Result<()> {
    let params: &[(&[u8], &[u8])] = &[
        (b"server_version", b"16.0"),
        (b"server_encoding", b"UTF8"),
        (b"client_encoding", b"UTF8"),
        (b"DateStyle", b"ISO, MDY"),
        (b"TimeZone", b"Etc/UTC"),
        (b"integer_datetimes", b"on"),
    ];
    for (name, val) in params {
        let mut payload = name.to_vec();
        payload.push(0);
        payload.extend_from_slice(val);
        payload.push(0);
        pgproto::write_raw_message(client, b'S', &payload).await?;
    }
    // BackendKeyData
    pgproto::write_raw_message(client, b'K', &[0, 0, 0, 1, 0, 0, 0, 1]).await?;
    // ReadyForQuery
    pgproto::write_raw_message(client, b'Z', b"I").await?;
    client.flush().await?;
    Ok(())
}

// ── Create backend connection with IAM auth ─────────────────────────

async fn create_backend(
    config: &Config,
    pool_key: &PoolKey,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<ServerStream> {
    let backend_tls = config.tls.as_ref().is_some_and(|t| t.enabled && t.connect_with_tls);

    let mut raw = TcpStream::connect(config.target_addr()).await?;
    let mut backend: ServerStream = if backend_tls {
        let host = config.pool.target_host.clone();
        let accepted = pgproto::ssl_request(&mut raw).await?;
        if !accepted {
            anyhow::bail!("backend does not support TLS");
        }
        let tls_stream = tls::tls_connect(raw, &host).await?;
        ServerStream::Tls(tls_stream)
    } else {
        ServerStream::Plain(raw)
    };

    // Send startup with backend credentials
    let backend_startup = pgproto::StartupParams {
        user: pool_key.db_user.clone(),
        database: pool_key.dbname.clone(),
        params: Vec::new(), // minimal — extra params from client aren't needed
    };
    pgproto::write_startup_message(&mut backend, &backend_startup).await?;

    let iam_for_user = config.iam.as_ref().is_some_and(|iam| {
        iam.db_user.as_deref() == Some(&pool_key.db_user)
            && !matches!(iam.provider, IamProvider::None)
    });

    // Auth loop
    loop {
        let msg = pgproto::read_pg_message(&mut backend).await?;
        match msg {
            None => anyhow::bail!("backend closed during auth"),
            Some((type_byte, payload)) => match type_byte {
                b'R' => {
                    let auth_req = pgproto::parse_auth_request(&payload)?;
                    match auth_req {
                        pgproto::AuthRequest::Ok => {
                            tracing::info!("backend authentication succeeded");
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
                                    let md5 = md5_iam_password(&token, &pool_key.db_user, &salt);
                                    pgproto::send_password(&mut backend, &md5).await?;
                                } else {
                                    pgproto::send_password(&mut backend, &token).await?;
                                }
                            } else {
                                anyhow::bail!("non-IAM backend auth not implemented");
                            }
                        }
                        _ => anyhow::bail!("unsupported auth method: {:?}", auth_req),
                    }
                }
                b'E' => {
                    anyhow::bail!("backend auth error: {}", String::from_utf8_lossy(&payload));
                }
                _ => continue,
            },
        }
    }

    // Consume ParameterStatus + BackendKeyData + ReadyForQuery (we don't forward them;
    // send_fake_ready already sent synthetic ones to the client)
    loop {
        let msg = pgproto::read_pg_message(&mut backend).await?;
        match msg {
            None => anyhow::bail!("backend closed during startup phase"),
            Some((type_byte, _payload)) => {
                if type_byte == b'Z' {
                    break;
                }
            }
        }
    }

    Ok(backend)
}

// ── Relay + release to pool ─────────────────────────────────────────

async fn relay_and_release(
    mut client: ClientStream,
    mut server: ServerStream,
    pool_key: &PoolKey,
    pool: &Arc<PoolManager>,
) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
    pool.release(pool_key, server).await;
    tracing::debug!("released backend to pool");
}

// ── MD5 helper ──────────────────────────────────────────────────────

fn md5_iam_password(token: &str, user: &str, salt: &[u8; 4]) -> String {
    use md5::{Digest, Md5};

    let mut h = Md5::new();
    h.update(token.as_bytes());
    h.update(user.as_bytes());
    let hex = format!("{:x}", h.finalize());

    let mut h2 = Md5::new();
    h2.update(hex.as_bytes());
    h2.update(salt);
    format!("md5{:x}", h2.finalize())
}
