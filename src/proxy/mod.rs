use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tracing;

use crate::auth::cache::TokenCache;
use crate::config::{Config, IamProvider};
use crate::pgproto;
use crate::pool::Pool;

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
    let startup = pgproto::read_startup_message(&mut client).await?;
    tracing::info!(
        "client {} connecting as user={} db={}",
        client.peer_addr()?,
        startup.user,
        startup.database
    );

    let mut backend = TcpStream::connect(config.target_addr()).await?;
    pgproto::write_startup_message(&mut backend, &startup).await?;

    let iam_for_user = config.iam.as_ref().is_some_and(|iam| {
        iam.db_user.as_deref() == Some(&startup.user)
            && !matches!(iam.provider, IamProvider::None)
    });

    loop {
        let msg = pgproto::read_pg_message(&mut backend).await?;
        match msg {
            None => anyhow::bail!("backend closed connection during auth"),
            Some((type_byte, payload)) => {
                match type_byte {
                    b'R' => {
                        let auth_req = pgproto::parse_auth_request(&payload)?;
                        match auth_req {
                            pgproto::AuthRequest::Ok => {
                                tracing::info!("authentication successful for {}", startup.user);
                                forward_msg(&mut client, type_byte, &payload).await?;
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
                                        pgproto::send_password(&mut backend, &md5).await?;
                                    } else {
                                        pgproto::send_password(&mut backend, &token).await?;
                                    }
                                } else {
                                    forward_msg(&mut client, type_byte, &payload).await?;
                                    if let Some((_, pwd_payload)) =
                                        pgproto::read_pg_message(&mut client).await?
                                    {
                                        backend.write_all(&pwd_payload).await?;
                                        backend.flush().await?;
                                    }
                                }
                            }
                            _ => {
                                forward_msg(&mut client, type_byte, &payload).await?;
                            }
                        }
                    }
                    b'E' | b'K' | b'S' | b'N' => {
                        forward_msg(&mut client, type_byte, &payload).await?;
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

    pgproto::relay(client, backend).await;
    Ok(())
}

async fn forward_msg(
    stream: &mut TcpStream,
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
