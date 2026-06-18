pub mod admin;
pub mod health;

use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};

use crate::auth::cache::TokenCache;

struct ClientTracker(Arc<crate::pool::PoolManager>);

impl ClientTracker {
    fn new(pool: Arc<crate::pool::PoolManager>) -> Self {
        pool.client_count.fetch_add(1, Ordering::Relaxed);
        Self(pool)
    }
}

impl Drop for ClientTracker {
    fn drop(&mut self) {
        self.0.client_count.fetch_sub(1, Ordering::Relaxed);
    }
}
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
    crate::log_event!(INFO, crate::log::PROXY, crate::log::START, "listening on {}", addr);

    loop {
        let (inbound, peer) = listener.accept().await?;
        let config = config.clone();
        let token_cache = token_cache.clone();
        let pool = pool.clone();

        tokio::spawn(async move {
            crate::log_event!(DEBUG, crate::log::CLIENT, crate::log::CONNECT, "new client connection from {}", peer);
            if let Err(e) = handle_client(inbound, peer, &config, pool, token_cache.as_ref()).await {
                crate::log_event!(ERROR, crate::log::CLIENT, crate::log::ERROR, "handler error for {}: {}", peer, e);
            }
            crate::log_event!(DEBUG, crate::log::CLIENT, crate::log::DISCONNECT, "client {} disconnected", peer);
        });
    }
}

type ClientStream = ServerStream;

// ── Per-client handler ──────────────────────────────────────────────

async fn handle_client(
    mut raw_client: TcpStream,
    peer: SocketAddr,
    config: &Config,
    pool: Arc<PoolManager>,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<()> {
    let _tracker = ClientTracker::new(pool.clone());

    // 0. Read initial message once — Cancel, SSLRequest, or Startup
    let mut initial = pgproto::read_initial_message(&mut raw_client).await?;

    // Cancel requests come on their own plain connection; forward and close.
    if let pgproto::InitialMessage::Cancel(cancel) = &initial {
        crate::log_event!(DEBUG, crate::log::CLIENT, crate::log::CANCEL, "cancel request from {} (pid={} key={})", peer, cancel.pid, cancel.secret_key);
        forward_cancel(config, cancel).await;
        return Ok(());
    }

    // Determine if we need TLS and pre-save startup params before consuming initial
    let mut pre_parsed_startup = match &initial {
        pgproto::InitialMessage::Startup(s) => Some(s.clone()),
        _ => None,
    };

    // 1. TLS upgrade — loops to handle SSLRequest with TLS disabled
    let mut client = loop {
        match initial {
            pgproto::InitialMessage::SslRequest => {
                let client_tls = config.tls.as_ref().is_some_and(|t| t.enabled);
                if !client_tls {
                    pgproto::send_ssl_reject(&mut raw_client).await?;
                    initial = pgproto::read_initial_message(&mut raw_client).await?;
                    pre_parsed_startup = match &initial {
                        pgproto::InitialMessage::Startup(s) => Some(s.clone()),
                        _ => None,
                    };
                    continue;
                }
                let tls_config = config.tls.as_ref().unwrap();
                let client_ca = config.client_auth.client_ca.as_deref();
                let cipher_config = (tls_config.ciphers.is_some() || tls_config.min_protocol_version.is_some())
                    .then(|| tls::TlsCipherConfig {
                        ciphers: tls_config.ciphers.clone(),
                        min_protocol_version: tls_config.min_protocol_version.clone(),
                    });
                pgproto::send_ssl_accept(&mut raw_client).await?;
                let tls_stream = tls::tls_accept(
                    raw_client,
                    &tls_config.cert_path,
                    &tls_config.key_path,
                    client_ca,
                    cipher_config.as_ref(),
                ).await?;
                break ClientStream::Tls(tls_stream);
            }
            pgproto::InitialMessage::Startup(_) => {
                break ClientStream::Plain(raw_client);
            }
            _ => anyhow::bail!("unexpected initial message"),
        }
    };

    // 2. Extract startup params (pre-parsed for Startup, read from stream for SslRequest)
    let startup: pgproto::StartupParams = match pre_parsed_startup {
        Some(s) => s,
        None => read_client_startup(&mut client).await?,
    };
    let client_cert_present = client_cert_was_present(&client);

    crate::log_event!(
        INFO, crate::log::CLIENT, crate::log::CONNECT,
        db_user = &startup.user[..],
        db_name = &startup.database[..],
        "client connecting as user={} db={}",
        startup.user, startup.database,
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

    // Log pool utilization
    let client_count = pool.client_count.load(Ordering::Relaxed);
    let client_max = pool.client_max;
    if let Some(stats) = pool.stats_for(&pool_key).await {
            crate::log_event!(
                INFO, crate::log::POOL, crate::log::STATS,
                clients = client_count,
                client_max = client_max,
                servers_active = stats.active,
                servers_idle = stats.idle,
                servers_max = stats.max + stats.reserve,
                db_user = &pool_key.db_user[..],
                db_name = &pool_key.dbname[..],
                "pool {}@{}: clients={}/{} servers={}/{} ready={}",
                pool_key.db_user, pool_key.dbname,
                client_count,
                if client_max > 0 { client_max.to_string() } else { "–".to_string() },
                stats.active,
                stats.max + stats.reserve,
                stats.idle,
            );
    }
    // 5. Acquire backend (waits for capacity, tries idle first).
    match config.pool.mode {
        crate::config::PoolMode::Session => {
            let (backend, born_at) = acquire_session_backend(&pool, &pool_key, config, token_cache, &mut client).await?;
            relay_and_release(client, backend, &pool_key, &pool, config, born_at).await;
        }
        crate::config::PoolMode::Transaction => {
            // Acquire + release backend BEFORE send_fake_ready so the slot
            // is freed before any async writes reach the client network.
            acquire_and_release_initial(&pool, &pool_key, config, token_cache).await?;
            send_fake_ready(&mut client).await?;
            transaction_loop(client, None, &pool_key, &pool, config, token_cache).await;
        }
    }

    spawn_warmup(&pool, &pool_key, config, token_cache).await;
    Ok(())
}

// ── Client TLS ──────────────────────────────────────────────────────

async fn forward_cancel(config: &Config, cancel: &pgproto::CancelRequest) {
    let target = config.target_addr();
    if let Ok(mut stream) = TcpStream::connect(&target).await {
        let msg = [
            0u8, 0, 0, 16,   // len=16
            4, 210, 22, 46,  // CancelRequest code = 80877102
        ];
        let pid_bytes = cancel.pid.to_be_bytes();
        let secret_bytes = cancel.secret_key.to_be_bytes();
        let mut full = msg.to_vec();
        full.extend_from_slice(&pid_bytes);
        full.extend_from_slice(&secret_bytes);
        let _ = stream.write_all(&full).await;
        let _ = stream.flush().await;
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

/// Acquire (or create) a backend and send fake ReadyForQuery to the client.
/// Used in session mode where the backend is held for the full relay.
async fn acquire_session_backend(
    pool: &Arc<PoolManager>,
    pool_key: &PoolKey,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
    client: &mut ClientStream,
) -> anyhow::Result<(ServerStream, std::time::Instant)> {
    match pool.acquire(pool_key).await {
        Some((backend, born_at)) => {
            crate::log_event!(DEBUG, crate::log::POOL, crate::log::ACQUIRE, "using idle backend from pool");
            if let Err(e) = send_fake_ready(client).await {
                pool.release(pool_key, backend, born_at).await;
                return Err(e);
            }
            Ok((backend, born_at))
        }
        None => {
            let (backend, born_at) = create_backend(config, pool_key, token_cache).await?;
            if let Err(e) = send_fake_ready(client).await {
                pool.cancel(pool_key).await;
                return Err(e);
            }
            Ok((backend, born_at))
        }
    }
}

/// Acquire (or create) a backend and release it to the idle pool immediately.
/// Transaction mode calls this before `send_fake_ready` so the backend slot
/// is freed before any async writes to the client.
async fn acquire_and_release_initial(
    pool: &Arc<PoolManager>,
    pool_key: &PoolKey,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) -> anyhow::Result<()> {
    match pool.acquire(pool_key).await {
        Some((backend, born_at)) => {
            crate::log_event!(DEBUG, crate::log::POOL, crate::log::ACQUIRE, "using idle backend from pool");
            pool.release(pool_key, backend, born_at).await;
            Ok(())
        }
        None => {
            let (backend, born_at) = create_backend(config, pool_key, token_cache).await?;
            pool.release(pool_key, backend, born_at).await;
            Ok(())
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
        pgproto::InitialMessage::Cancel(_) => {
            anyhow::bail!("unexpected cancel request after TLS handshake");
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
) -> anyhow::Result<(ServerStream, std::time::Instant)> {
    let born_at = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(
        if config.pool.server_connect_timeout_secs > 0 {
            config.pool.server_connect_timeout_secs
        } else {
            15
        },
    );
    let mut raw = tokio::time::timeout(timeout, TcpStream::connect(config.target_addr()))
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout to {}", config.target_addr()))??;
    let backend_tls = config.tls.as_ref().is_some_and(|t| t.connect_with_tls);
    let mut backend: ServerStream = if backend_tls {
        let host = config.pool.target_host.clone();
        let accepted = pgproto::ssl_request(&mut raw).await?;
        if !accepted {
            anyhow::bail!("backend does not support TLS");
        }
        let tls_config = config.tls.as_ref().unwrap();
        let cipher_config = (tls_config.ciphers.is_some() || tls_config.min_protocol_version.is_some())
            .then(|| tls::TlsCipherConfig {
                ciphers: tls_config.ciphers.clone(),
                min_protocol_version: tls_config.min_protocol_version.clone(),
            });
        let ca_path = tls_config.backend_ca_path.as_deref();
        let tls_stream = tls::tls_connect(raw, &host, cipher_config.as_ref(), ca_path).await?;
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
                            crate::log_event!(INFO, crate::log::AUTH, crate::log::AUTHENTICATE, "backend authentication succeeded");
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

    Ok((backend, born_at))
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
    initial_server: Option<(ServerStream, std::time::Instant)>,
    pool_key: &PoolKey,
    pool: &Arc<PoolManager>,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) {
    let mut server: Option<(ServerStream, std::time::Instant)> = initial_server;
    let mut prepared: Vec<String> = Vec::new();
    let mut in_transaction = false;
    let mut tx_start = std::time::Instant::now();

    loop {
        enum Event {
            ClientMsg(Option<(u8, Vec<u8>)>),
            ServerMsg(Option<(u8, Vec<u8>)>),
            Timeout,
        }

        // Only read from the server when one is assigned.
        let event = if let Some((ref mut s, _)) = server {
            let client_fut = pgproto::read_pg_message(&mut client);
            let server_fut = pgproto::read_pg_message(s);
            let client_idle = if config.pool.client_idle_timeout_secs > 0 {
                std::time::Duration::from_secs(config.pool.client_idle_timeout_secs)
            } else {
                std::time::Duration::MAX
            };
            let query_wait = if config.pool.query_wait_timeout_secs > 0 {
                std::time::Duration::from_secs(config.pool.query_wait_timeout_secs)
            } else {
                std::time::Duration::MAX
            };

            if in_transaction && config.pool.transaction_timeout_secs > 0 {
                let remaining = std::time::Duration::from_secs(config.pool.transaction_timeout_secs)
                    .saturating_sub(tx_start.elapsed());
                if remaining.is_zero() {
                    Event::Timeout
                } else {
                    tokio::select! {
                        msg = client_fut => Event::ClientMsg(msg.ok().flatten()),
                        msg = server_fut => Event::ServerMsg(msg.ok().flatten()),
                        _ = tokio::time::sleep(remaining) => Event::Timeout,
                        _ = tokio::time::sleep(client_idle) => Event::Timeout,
                        _ = tokio::time::sleep(query_wait) => Event::Timeout,
                    }
                }
            } else {
                tokio::select! {
                    msg = client_fut => Event::ClientMsg(msg.ok().flatten()),
                    msg = server_fut => Event::ServerMsg(msg.ok().flatten()),
                    _ = tokio::time::sleep(client_idle) => Event::Timeout,
                    _ = tokio::time::sleep(query_wait) => Event::Timeout,
                }
            }
        } else {
            // No server assigned — only wait for client input.
            let client_fut = pgproto::read_pg_message(&mut client);
            let client_idle = if config.pool.client_idle_timeout_secs > 0 {
                std::time::Duration::from_secs(config.pool.client_idle_timeout_secs)
            } else {
                std::time::Duration::MAX
            };
            tokio::select! {
                msg = client_fut => Event::ClientMsg(msg.ok().flatten()),
                _ = tokio::time::sleep(client_idle) => Event::Timeout,
            }
        };

        match event {
            Event::Timeout => {
                crate::log_event!(WARN, crate::log::CLIENT, crate::log::TIMEOUT, "timeout triggered for {}@{}, closing", pool_key.db_user, pool_key.dbname);
                break;
            }
            Event::ClientMsg(None) => break,
            Event::ClientMsg(Some((b'X', _))) => {
                if let Some((ref mut s, _)) = server {
                    let _ = pgproto::write_raw_message(s, b'X', &[]).await;
                    let _ = s.flush().await;
                }
                break;
            }
            Event::ClientMsg(Some((t, p))) => {
                // Acquire a backend on demand — don't hold one while idle.
                if server.is_none() {
                    server = acquire_backend(pool, pool_key, config, token_cache).await;
                }
                if server.is_none() {
                    crate::log_event!(ERROR, crate::log::POOL, crate::log::ERROR, "transaction_loop: failed to acquire backend");
                    break;
                }

                // Track extended query messages
                match t {
                    pgproto::ext::PARSE => {
                        let name = pgproto::parse_statement_name(&p).to_string();
                        if !name.is_empty() {
                            prepared.push(name);
                        }
                    }
                    pgproto::ext::CLOSE => {
                        let (_obj_type, name) = pgproto::parse_close_target(&p);
                        if !name.is_empty() {
                            prepared.retain(|s| s != name);
                        }
                    }
                    b'Q' => {
                        // Simple query — starts a transaction if it contains BEGIN
                        let query_str = String::from_utf8_lossy(&p);
                        if query_str.to_uppercase().contains("BEGIN")
                            || query_str.to_uppercase().contains("START TRANSACTION")
                        {
                            in_transaction = true;
                            tx_start = std::time::Instant::now();
                        }
                    }
                    _ => {}
                }
                if let Some((ref mut s, _)) = server {
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
                // Track transaction state
                match t {
                    b'Z' => {
                        if p.first() == Some(&b'I') {
                            // Idle — transaction complete, release server
                            if let Some((ref mut s, _)) = server {
                                if run_reset_query(s, config).await {
                                    // DEALLOCATE tracked prepared statements
                                    for stmt_name in &prepared {
                                        let dealloc = format!("DEALLOCATE \"{}\"", stmt_name);
                                        let mut payload = dealloc.into_bytes();
                                        payload.push(0);
                                        let len = (payload.len() + 4) as i32;
                                        let mut msg = vec![b'Q'];
                                        msg.extend_from_slice(&len.to_be_bytes());
                                        msg.extend_from_slice(&payload);
                                        let _ = s.write_all(&msg).await;
                                        let _ = s.flush().await;
                                        // Drain until ReadyForQuery
                                        loop {
                                            match pgproto::read_pg_message(s).await {
                                                Ok(Some((b'Z', _))) => break,
                                                _ => break,
                                            }
                                        }
                                    }
                                    prepared.clear();
                                    in_transaction = false;
                                }
                            }
                            if let Some((released, born)) = server.take() {
                                pool.release(pool_key, released, born).await;
                            }
                        } else if p.first() == Some(&b'T') {
                            // In transaction
                            in_transaction = true;
                            tx_start = std::time::Instant::now();
                        }
                    }
                    b'E' if !in_transaction => {
                        // Error outside transaction — connection may need reset
                        if let Some((ref mut s, _)) = server {
                            if run_reset_query(s, config).await {
                                if let Some((released, born)) = server.take() {
                                    pool.release(pool_key, released, born).await;
                                }
                            } else {
                                server.take();
                                pool.cancel(pool_key).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    if let Some((mut s, born)) = server.take() {
        if run_reset_query(&mut s, config).await {
            pool.release(pool_key, s, born).await;
        } else {
            pool.cancel(pool_key).await;
        }
    }
}

async fn acquire_backend(
    pool: &Arc<PoolManager>,
    pool_key: &PoolKey,
    config: &Config,
    token_cache: Option<&Arc<TokenCache>>,
) -> Option<(ServerStream, std::time::Instant)> {
    match pool.acquire(pool_key).await {
        Some(s) => {
            crate::log_event!(DEBUG, crate::log::POOL, crate::log::ACQUIRE, "transaction_loop: acquired idle backend");
            Some(s)
        }
        None => match create_backend(config, pool_key, token_cache).await {
            Ok(s) => Some(s),
            Err(e) => {
                crate::log_event!(ERROR, crate::log::POOL, crate::log::ERROR, "transaction_loop: create_backend failed: {e}");
                pool.cancel(pool_key).await;
                None
            }
        },
    }
}

async fn run_reset_query(
    server: &mut (impl tokio::io::AsyncRead + AsyncWriteExt + Unpin),
    config: &Config,
) -> bool {
    let reset_query = config.pool.server_reset_query.as_bytes();
    let mut payload = reset_query.to_vec();
    payload.push(0);
    let len = (payload.len() + 4) as i32;
    let mut msg = vec![b'Q'];
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(&payload);

    if let Err(e) = server.write_all(&msg).await {
        crate::log_event!(WARN, crate::log::POOL, crate::log::ERROR, "run_reset_query: write failed: {e}");
        return false;
    }
    if let Err(e) = server.flush().await {
        crate::log_event!(WARN, crate::log::POOL, crate::log::ERROR, "run_reset_query: flush failed: {e}");
        return false;
    }

    loop {
        match pgproto::read_pg_message(server).await {
            Ok(Some((type_byte, _))) => {
                if type_byte == b'Z' {
                    return true;
                }
            }
            _ => return false,
        }
    }
}

// ── Session pooling relay ───────────────────────────────────────────

 async fn relay_and_release(
    mut client: ClientStream,
    mut server: ServerStream,
    pool_key: &PoolKey,
    pool: &Arc<PoolManager>,
    config: &Config,
    born_at: std::time::Instant,
) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;

    if run_reset_query(&mut server, config).await {
        pool.release(pool_key, server, born_at).await;
        crate::log_event!(DEBUG, crate::log::POOL, crate::log::RELEASE, "released backend to pool");
    } else {
        crate::log_event!(WARN, crate::log::POOL, crate::log::DROP, "dropping dead backend");
        pool.cancel(pool_key).await;
    }
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
    crate::log_event!(INFO, crate::log::POOL, crate::log::WARMUP, "warming up pool ({} connections needed) for {}@{}", needed, pool_key.db_user, pool_key.dbname);

    for _ in 0..needed {
        let pool = pool.clone();
        let key = pool_key.clone();
        let config = config.clone();
        let token_cache = token_cache.cloned();

        tokio::spawn(async move {
            match pool.acquire(&key).await {
                Some((stream, born_at)) => {
                    // Got idle — already warm enough, just put it back
                    pool.release(&key, stream, born_at).await;
                }
                None => match create_backend(&config, &key, token_cache.as_ref()).await {
                    Ok((stream, born_at)) => {
                        pool.release(&key, stream, born_at).await;
                        crate::log_event!(DEBUG, crate::log::POOL, crate::log::CREATE, "warm-up connection created for {}@{}", key.db_user, key.dbname);
                    }
                    Err(e) => {
                        pool.cancel(&key).await;
                        crate::log_event!(WARN, crate::log::POOL, crate::log::ERROR, "warm-up connection failed for {}@{}: {}", key.db_user, key.dbname, e);
                    }
                },
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
