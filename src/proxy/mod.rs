pub mod admin;
pub mod health;

use std::net::SocketAddr;
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
            if let Err(e) = handle_client(inbound, peer, &config, pool, token_cache.as_ref()).await {
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
    peer: SocketAddr,
    config: &Config,
    pool: Arc<PoolManager>,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<()> {
    // 1. Client TLS upgrade (with optional client cert request)
    let mut client = upgrade_client_tls(raw_client, config).await?;
    let client_cert_present = client_cert_was_present(&client);

    // 2. Read startup from client
    let startup = read_client_startup(&mut client).await?;
    tracing::info!(
        "client connecting as user={} db={}",
        startup.user, startup.database
    );

    // 3. Authenticate client locally
    authenticate_client(
        &mut client,
        config,
        &startup.user,
        peer.ip(),
        client_cert_present,
    )
    .await?;

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
        match config.pool.mode {
            crate::config::PoolMode::Session => {
                relay_and_release(client, backend, &pool_key, &pool).await;
            }
            crate::config::PoolMode::Transaction => {
                transaction_loop(client, Some(backend), &pool_key, &pool, config, token_cache).await;
            }
        }
        spawn_warmup(&pool, &pool_key, config, token_cache).await;
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

    match config.pool.mode {
        crate::config::PoolMode::Session => {
            relay_and_release(client, backend, &pool_key, &pool).await;
        }
        crate::config::PoolMode::Transaction => {
            transaction_loop(client, Some(backend), &pool_key, &pool, config, token_cache).await;
        }
    }

    spawn_warmup(&pool, &pool_key, config, token_cache).await;
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
    let client_ca = config.client_auth.client_ca.as_deref();
    let initial = pgproto::read_initial_message(&mut stream).await?;
    match initial {
        pgproto::InitialMessage::SslRequest => {
            pgproto::send_ssl_accept(&mut stream).await?;
            let tls_stream =
                tls::tls_accept(stream, &tls_config.cert_path, &tls_config.key_path, client_ca).await?;
            Ok(ClientStream::Tls(tls_stream))
        }
        pgproto::InitialMessage::Startup(_) => {
            anyhow::bail!("client sent startup without SSLRequest, but TLS is required");
        }
    }
}

/// Check if the TLS session has a verified client certificate.
fn client_cert_was_present(client: &ClientStream) -> bool {
    match client {
        ClientStream::Tls(tls_stream) => {
            let (_, session) = tls_stream.get_ref();
            session.peer_certificates().is_some_and(|c| !c.is_empty())
        }
        _ => false,
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
    user: &str,
    client_ip: std::net::IpAddr,
    client_cert: bool,
) -> anyhow::Result<()> {
    let auth = &config.client_auth;
    let tls_on = matches!(client, ClientStream::Tls(_));

    // HBA: if rules are configured, iterate to find first match.
    if !auth.hba_rules.is_empty() {
        for hba_cfg in &auth.hba_rules {
            let conn_types = if tls_on { vec!["hostssl", "host"] } else { vec!["hostnossl", "host"] };
            let ct_match = conn_types.iter().any(|ct| *ct == hba_cfg.conn_type);
            if !ct_match { continue; }
            let db_match = hba_cfg.database.iter().any(|d| d == "all" || d == user || (d == "sameuser" && user == user));
            if !db_match { continue; }
            if !hba_cfg.user.iter().any(|u| u == "all" || u == user) { continue; }
            if let Some(ref addr_str) = hba_cfg.address {
                if let Ok(net) = addr_str.parse::<ipnetwork::IpNetwork>() {
                    if !net.contains(client_ip) { continue; }
                }
            }
            return hba_dispatch(client, config, &hba_cfg.auth, user, client_ip, client_cert, tls_on).await;
        }
        let err = pgproto::build_error_response("28P01", "no pg_hba.conf entry for connection");
        client.write_all(&err).await?;
        client.flush().await?;
        anyhow::bail!("no matching HBA rule for user {}", user);
    }

    auth_dispatch(client, config, &auth.auth_type, user, client_ip, client_cert).await
}

async fn hba_dispatch(
    client: &mut ClientStream,
    config: &Config,
    method: &str,
    user: &str,
    client_ip: std::net::IpAddr,
    client_cert: bool,
    _tls_on: bool,
) -> anyhow::Result<()> {
    match method {
        "trust" => {
            pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
            client.flush().await?;
            Ok(())
        }
        "reject" => {
            let err = pgproto::build_error_response("28P01", "pg_hba rejects connection");
            client.write_all(&err).await?;
            client.flush().await?;
            anyhow::bail!("connection rejected by pg_hba.conf")
        }
        "password" => auth_dispatch(client, config, &ClientAuthType::Password, user, client_ip, client_cert).await,
        "scram-sha-256" => auth_dispatch(client, config, &ClientAuthType::ScramSha256, user, client_ip, client_cert).await,
        "cert" => auth_dispatch(client, config, &ClientAuthType::Cert, user, client_ip, client_cert).await,
        "pam" => auth_dispatch(client, config, &ClientAuthType::Pam, user, client_ip, client_cert).await,
        "ldap" => auth_dispatch(client, config, &ClientAuthType::Ldap, user, client_ip, client_cert).await,
        other => {
            let err = pgproto::build_error_response("28P01", &format!("unknown HBA auth method: {other}"));
            client.write_all(&err).await?;
            client.flush().await?;
            anyhow::bail!("unknown HBA auth method: {other}")
        }
    }
}

async fn auth_dispatch(
    client: &mut ClientStream,
    config: &Config,
    auth_type: &ClientAuthType,
    user: &str,
    _client_ip: std::net::IpAddr,
    client_cert: bool,
) -> anyhow::Result<()> {
    let auth = &config.client_auth;
    let target = config.target_addr();

    match *auth_type {
        ClientAuthType::Trust => {
            pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
            client.flush().await?;
            Ok(())
        }
        ClientAuthType::Password => {
            pgproto::write_raw_message(client, b'R', &3i32.to_be_bytes()).await?;
            client.flush().await?;
            let password = read_password_message(client).await?;
            match check_password(&password, user, auth, &target).await {
                Ok(()) => {
                    pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
                    client.flush().await?;
                    Ok(())
                }
                Err(e) => {
                    let err = pgproto::build_error_response("28P01", &format!("password authentication failed: {e}"));
                    client.write_all(&err).await?;
                    client.flush().await?;
                    Err(e)
                }
            }
        }
        ClientAuthType::ScramSha256 => {
            let password = if let Some(ref pwd) = auth.password {
                pwd.clone()
            } else if let Some(ref aq) = auth.auth_query {
                crate::auth::auth_query::lookup_password(&target, &aq.user, &aq.query, user).await?
            } else {
                anyhow::bail!("no password source for SCRAM auth")
            };
            do_scram_server_auth(client, &password).await
        }
        ClientAuthType::Cert => {
            if !client_cert {
                let err = pgproto::build_error_response("28P01", "certificate authentication failed");
                client.write_all(&err).await?;
                client.flush().await?;
                anyhow::bail!("cert auth requires TLS client certificate");
            }
            pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
            client.flush().await?;
            Ok(())
        }
        ClientAuthType::Pam => {
            pgproto::write_raw_message(client, b'R', &3i32.to_be_bytes()).await?;
            client.flush().await?;
            let password = read_password_message(client).await?;
            let service = auth.pam_service.as_deref().unwrap_or("pgb-iam");
            if let Err(e) = crate::auth::pam::authenticate(service, user, &password) {
                let err = pgproto::build_error_response("28P01", &format!("pam authentication failed: {e}"));
                client.write_all(&err).await?;
                client.flush().await?;
                return Err(e.into());
            }
            pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
            client.flush().await?;
            Ok(())
        }
        ClientAuthType::Ldap => {
            pgproto::write_raw_message(client, b'R', &3i32.to_be_bytes()).await?;
            client.flush().await?;
            let password = read_password_message(client).await?;
            let ldap_cfg = auth.ldap.as_ref().ok_or_else(|| anyhow::anyhow!("LDAP not configured"))?;
            let cfg = crate::auth::ldap::LdapConfig {
                uri: ldap_cfg.uri.clone(),
                bind_dn: ldap_cfg.bind_dn.clone(),
                bind_password: ldap_cfg.bind_password.clone(),
                search_base: ldap_cfg.search_base.clone(),
                search_filter: ldap_cfg.search_filter.clone(),
            };
            if let Err(e) = crate::auth::ldap::authenticate(&cfg, user, &password).await {
                let err = pgproto::build_error_response("28P01", &format!("ldap authentication failed: {e}"));
                client.write_all(&err).await?;
                client.flush().await?;
                return Err(e.into());
            }
            pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
            client.flush().await?;
            Ok(())
        }
        ClientAuthType::Hba | ClientAuthType::AuthQuery => {
            anyhow::bail!("auth type {:?} requires HBA rules or password source", auth_type)
        }
    }
}

async fn check_password(
    password: &str,
    user: &str,
    auth: &crate::config::ClientAuthConfig,
    target: &str,
) -> anyhow::Result<()> {
    // Try local password
    if let Some(ref expected) = auth.password {
        if password == expected {
            return Ok(());
        }
        anyhow::bail!("password mismatch")
    }
    // Try auth_query
    if let Some(ref aq) = auth.auth_query {
        let server_pwd = crate::auth::auth_query::lookup_password(target, &aq.user, &aq.query, user).await?;
        if password == server_pwd {
            return Ok(());
        }
        anyhow::bail!("password mismatch (auth_query)")
    }
    anyhow::bail!("no password source configured")
}

async fn read_password_message(client: &mut ClientStream) -> anyhow::Result<String> {
    match pgproto::read_pg_message(client).await? {
        None => anyhow::bail!("client closed during auth"),
        Some((type_byte, payload)) => {
            if type_byte != b'p' {
                anyhow::bail!("expected PasswordMessage (p), got {}", type_byte as char);
            }
            Ok(String::from_utf8_lossy(&payload[..payload.len().saturating_sub(1)]).to_string())
        }
    }
}

/// Server-side SCRAM-SHA-256 SASL exchange for client auth.
async fn do_scram_server_auth(
    client: &mut ClientStream,
    password: &str,
) -> anyhow::Result<()> {
    use crate::auth::scram::ScramServer;

    // Send AuthenticationSASL with SCRAM-SHA-256
    let mut payload = vec![0u8; 4 + 13]; // int32(10) + "SCRAM-SHA-256\0"
    payload[..4].copy_from_slice(&10i32.to_be_bytes());
    payload[4..].copy_from_slice(b"SCRAM-SHA-256\0");
    pgproto::write_raw_message(client, b'R', &payload).await?;
    client.flush().await?;

    let mut server = ScramServer::new(password);

    // Read client-first-message (SASLInitialResponse)
    match pgproto::read_pg_message(client).await? {
        None => anyhow::bail!("client closed during SASL auth"),
        Some((b'p', data)) => {
            // payload: name\0 client-first-message
            let sasl_mech_end = data.iter().position(|&b| b == 0).unwrap_or(0);
            let client_first = String::from_utf8_lossy(&data[sasl_mech_end + 1..]).to_string();
            let server_first = server.build_server_first(&client_first)?;

            // Send AuthenticationSASLContinue
            let mut cont_payload = vec![0u8; 4 + server_first.len() + 1]; // int32(11) + data + \0
            cont_payload[..4].copy_from_slice(&11i32.to_be_bytes());
            cont_payload[4..4 + server_first.len()].copy_from_slice(server_first.as_bytes());
            pgproto::write_raw_message(client, b'R', &cont_payload).await?;
            client.flush().await?;
        }
        Some((t, _)) => anyhow::bail!("expected SASLInitialResponse, got {}", t as char),
    }

    // Read client-final-message
    match pgproto::read_pg_message(client).await? {
        None => anyhow::bail!("client closed during SASL auth"),
        Some((b'p', data)) => {
            let client_final = String::from_utf8_lossy(&data).to_string();

            match server.handle_client_final(&client_final) {
                Ok(server_final) => {
                    // Send AuthenticationSASLFinal (12)
                    let mut final_payload = vec![0u8; 4 + server_final.len() + 1];
                    final_payload[..4].copy_from_slice(&12i32.to_be_bytes());
                    final_payload[4..4 + server_final.len()].copy_from_slice(server_final.as_bytes());
                    pgproto::write_raw_message(client, b'R', &final_payload).await?;

                    // Send AuthenticationOk
                    pgproto::write_raw_message(client, b'R', &0i32.to_be_bytes()).await?;
                    client.flush().await?;
                    Ok(())
                }
                Err(e) => {
                    let err = pgproto::build_error_response("28P01", &format!("SASL auth failed: {}", e));
                    client.write_all(&err).await?;
                    client.flush().await?;
                    Err(e)
                }
            }
        }
        Some((t, _)) => anyhow::bail!("expected SASLResponse, got {}", t as char),
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
        params: Vec::new(),
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
                        pgproto::AuthRequest::Sasl(mechs) => {
                            if iam_for_user {
                                do_scram_client_auth(&mut backend, &mechs, &pool_key.db_user, config, token_cache).await?;
                            } else {
                                anyhow::bail!("non-IAM SCRAM auth not implemented");
                            }
                        }
                        pgproto::AuthRequest::SaslContinue(_) => {
                            anyhow::bail!("unexpected SASL continue from server");
                        }
                        pgproto::AuthRequest::Unknown(t, _) => {
                            anyhow::bail!("unknown auth type {} from server", t);
                        }
                    }
                }
                b'E' => {
                    anyhow::bail!("backend auth error: {}", String::from_utf8_lossy(&payload));
                }
                _ => continue,
            },
        }
    }

    // Consume ParameterStatus + BackendKeyData + ReadyForQuery
    loop {
        let msg = pgproto::read_pg_message(&mut backend).await?;
        match msg {
            None => anyhow::bail!("backend closed during startup phase"),
            Some((type_byte, _)) => {
                if type_byte == b'Z' {
                    break;
                }
            }
        }
    }

    Ok(backend)
}

/// Client-side SCRAM-SHA-256 exchange for IAM backend auth.
async fn do_scram_client_auth(
    backend: &mut ServerStream,
    mechs: &[String],
    user: &str,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<()> {
    use crate::auth::scram::ScramClient;

    if !mechs.iter().any(|m| m == "SCRAM-SHA-256") {
        anyhow::bail!("backend doesn't offer SCRAM-SHA-256 (offers {:?})", mechs);
    }

    let iam_config = config.iam.as_ref().unwrap();
    let iam_password = if let Some(cache) = token_cache {
        cache.get().await?
    } else {
        crate::auth::get_token(iam_config).await?
    };

    let mut client = ScramClient::new(user, &iam_password);

    // Send SASLInitialResponse
    let client_first = client.build_client_first();
    let payload = format!("SCRAM-SHA-256\x00{}", client_first);
    pgproto::write_raw_message(backend, b'p', payload.as_bytes()).await?;
    backend.flush().await?;

    // Read SASLContinue
    match pgproto::read_pg_message(backend).await? {
        None => anyhow::bail!("backend closed during SASL"),
        Some((b'R', data)) => {
            let req = pgproto::parse_auth_request(&data)?;
            match req {
                pgproto::AuthRequest::SaslContinue(server_first) => {
                    let sf = std::str::from_utf8(&server_first)?;
                    client.parse_server_first(sf)?;
                    let client_final = client.build_client_final()?;
                    pgproto::write_raw_message(backend, b'p', client_final.as_bytes()).await?;
                    backend.flush().await?;
                }
                _ => anyhow::bail!("expected SASLContinue, got {:?}", req),
            }
        }
        Some((t, _)) => anyhow::bail!("expected SASLContinue, got {}", t as char),
    }

    // Read SASLFinal (or AuthenticationOk)
    loop {
        match pgproto::read_pg_message(backend).await? {
            None => anyhow::bail!("backend closed during SASL final"),
            Some((b'R', data)) => {
                let req = pgproto::parse_auth_request(&data)?;
                match req {
                    pgproto::AuthRequest::Ok => return Ok(()),
                    pgproto::AuthRequest::SaslContinue(server_final) => {
                        let sf = std::str::from_utf8(&server_final)?;
                        client.verify_server_final(sf)?;
                        // Continue reading until AuthOk
                    }
                    _ => anyhow::bail!("unexpected auth request: {:?}", req),
                }
            }
            Some((t, _)) if t != b'R' => continue,
            Some((t, _)) => anyhow::bail!("unexpected message {} during SASL auth", t as char),
        }
    }
}

// ── Transaction pooling ────────────────────────────────────────────

async fn transaction_loop(
    mut client: ClientStream,
    initial_server: Option<ServerStream>,
    pool_key: &PoolKey,
    pool: &Arc<PoolManager>,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) {
    let mut server: Option<ServerStream> = initial_server;

    loop {
        if server.is_none() {
            server = acquire_backend(pool, pool_key, config, token_cache).await;
        }
        if server.is_none() {
            tracing::error!("transaction_loop: failed to acquire backend");
            break;
        }

        let server_borrow: *mut ServerStream =
            server.as_mut().map(|s| s as *mut ServerStream).unwrap();
        let server_ref = unsafe { &mut *server_borrow };

        enum Event {
            ClientMsg(Option<(u8, Vec<u8>)>),
            ServerMsg(Option<(u8, Vec<u8>)>),
        }

        let event = {
            let client_fut = pgproto::read_pg_message(&mut client);
            let server_fut = pgproto::read_pg_message(server_ref);
            tokio::select! {
                msg = client_fut => Event::ClientMsg(msg.ok().flatten()),
                msg = server_fut => Event::ServerMsg(msg.ok().flatten()),
            }
        };

        match event {
            Event::ClientMsg(None) => break,
            Event::ClientMsg(Some((b'X', _))) => {
                if let Some(ref mut s) = server {
                    let _ = pgproto::write_raw_message(s, b'X', &[]).await;
                    let _ = s.flush().await;
                }
                break;
            }
            Event::ClientMsg(Some((t, p))) => {
                if let Some(ref mut s) = server {
                    if pgproto::write_raw_message(s, t, &p).await.is_err()
                        || s.flush().await.is_err()
                    {
                        break;
                    }
                }
            }
            Event::ServerMsg(None) => break,
            Event::ServerMsg(Some((t, p))) => {
                if pgproto::write_raw_message(&mut client, t, &p).await.is_err()
                    || client.flush().await.is_err()
                {
                    break;
                }
                if t == b'Z' && p.first() == Some(&b'I') {
                    if let Some(ref mut s) = server {
                        run_reset_query(s, config).await;
                    }
                    if let Some(released) = server.take() {
                        pool.release(pool_key, released).await;
                    }
                }
            }
        }
    }

    if let Some(mut s) = server.take() {
        run_reset_query(&mut s, config).await;
        pool.release(pool_key, s).await;
    }
}

async fn acquire_backend(
    pool: &Arc<PoolManager>,
    pool_key: &PoolKey,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) -> Option<ServerStream> {
    if let Some(s) = pool.try_acquire_idle(pool_key).await {
        tracing::debug!("transaction_loop: acquired idle backend");
        return Some(s);
    }

    if !pool.reserve(pool_key).await {
        tracing::warn!("transaction_loop: pool exhausted");
        return None;
    }

    match create_backend(config, pool_key, token_cache).await {
        Ok(s) => Some(s),
        Err(e) => {
            tracing::error!("transaction_loop: create_backend failed: {e}");
            pool.cancel_reservation(pool_key).await;
            None
        }
    }
}

async fn run_reset_query(
    server: &mut (impl tokio::io::AsyncRead + AsyncWriteExt + Unpin),
    config: &Config,
) {
    let reset_query = config.pool.server_reset_query.as_bytes();
    let mut payload = reset_query.to_vec();
    payload.push(0);
    let len = (payload.len() + 4) as i32;
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&payload);

    if let Err(e) = server.write_all(&msg).await {
        tracing::warn!("run_reset_query: write failed: {e}");
        return;
    }
    if let Err(e) = server.flush().await {
        tracing::warn!("run_reset_query: flush failed: {e}");
        return;
    }

    loop {
        match pgproto::read_pg_message(server).await {
            Ok(Some((type_byte, _))) => {
                if type_byte == b'Z' {
                    break;
                }
            }
            _ => break,
        }
    }
}

// ── Session pooling relay ───────────────────────────────────────────

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

// ── Pool warm-up ────────────────────────────────────────────────────

async fn spawn_warmup(
    pool: &Arc<PoolManager>,
    pool_key: &PoolKey,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) {
    let needed = pool.needs_warmup(pool_key).await;
    if needed == 0 {
        return;
    }
    tracing::info!("warming up pool ({} connections needed) for {}@{}", needed, pool_key.db_user, pool_key.dbname);

    for _ in 0..needed {
        let pool = pool.clone();
        let key = pool_key.clone();
        let config = config.clone();
        let token_cache = token_cache.cloned();

        tokio::spawn(async move {
            if !pool.reserve(&key).await {
                return;
            }
            match create_backend(&config, &key, token_cache.as_ref()).await {
                Ok(stream) => {
                    pool.release(&key, stream).await;
                    tracing::debug!("warm-up connection created for {}@{}", key.db_user, key.dbname);
                }
                Err(e) => {
                    pool.cancel_reservation(&key).await;
                    tracing::warn!("warm-up connection failed for {}@{}: {}", key.db_user, key.dbname, e);
                }
            }
        });
    }
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
