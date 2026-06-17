use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const PROTOCOL_VERSION_3: i32 = 196608;
const SSL_REQUEST_CODE: i32 = 80877103;

#[derive(Debug)]
pub struct StartupParams {
    pub user: String,
    pub database: String,
    pub params: Vec<(String, String)>,
}

#[derive(Debug)]
pub enum AuthRequest {
    Ok,
    CleartextPassword,
    MD5Password([u8; 4]),
    Sasl(Vec<String>),
    SaslContinue(Vec<u8>),
    Unknown(i32, Vec<u8>),
}

#[derive(Debug)]
pub enum InitialMessage {
    SslRequest,
    Startup(StartupParams),
}

pub async fn read_pg_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
    let mut type_byte = [0u8; 1];
    if stream.read_exact(&mut type_byte).await.is_err() {
        return Ok(None);
    }

    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf) as usize - 4;

    let mut payload = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut payload).await?;
    }

    Ok(Some((type_byte[0], payload)))
}

pub async fn read_initial_message(
    stream: &mut (impl AsyncRead + Unpin),
) -> anyhow::Result<InitialMessage> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf) as usize;

    // SSLRequest is exactly 8 bytes total: len=8 + code=80877103
    if len == 8 {
        let mut code_buf = [0u8; 4];
        stream.read_exact(&mut code_buf).await?;
        let code = i32::from_be_bytes(code_buf);
        if code == SSL_REQUEST_CODE {
            return Ok(InitialMessage::SslRequest);
        }
        anyhow::bail!("unknown protocol message: len={} code={}", len, code);
    }

    // Startup message: len includes itself (4) + protocol (4) + params
    let payload_len = len - 4;
    let mut buf = vec![0u8; payload_len];
    stream.read_exact(&mut buf).await?;

    let protocol = i32::from_be_bytes(buf[0..4].try_into().unwrap());
    if protocol != PROTOCOL_VERSION_3 {
        anyhow::bail!("unsupported protocol version: {}", protocol);
    }

    let mut params = Vec::new();
    let mut offset = 4;
    loop {
        let end = buf[offset..].iter().position(|&b| b == 0).map(|p| offset + p);
        match end {
            None => break,
            Some(key_end) => {
                if key_end == offset {
                    break;
                }
                let key = String::from_utf8_lossy(&buf[offset..key_end]).to_string();
                offset = key_end + 1;

                let val_end = buf[offset..]
                    .iter()
                    .position(|&b| b == 0)
                    .map(|p| offset + p)
                    .unwrap_or(buf.len());
                let value = String::from_utf8_lossy(&buf[offset..val_end]).to_string();
                offset = val_end + 1;
                params.push((key, value));
            }
        }
    }

    let user = params
        .iter()
        .find(|(k, _)| k == "user")
        .map(|(_, v)| v.clone())
        .ok_or_else(|| anyhow::anyhow!("no user in startup message"))?;

    let database = params
        .iter()
        .find(|(k, _)| k == "database")
        .map(|(_, v)| v.clone())
        .unwrap_or_else(|| user.clone());

    Ok(InitialMessage::Startup(StartupParams { user, database, params }))
}

pub async fn write_startup_message(
    stream: &mut (impl AsyncWrite + Unpin),
    params: &StartupParams,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();
    buf.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());

    for (key, value) in &params.params {
        buf.extend_from_slice(key.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }
    buf.push(0);

    let len = (buf.len() + 4) as i32;
    let mut header = len.to_be_bytes().to_vec();
    header.extend_from_slice(&buf);
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(())
}

pub async fn send_password(
    stream: &mut (impl AsyncWrite + Unpin),
    password: &str,
) -> anyhow::Result<()> {
    let payload = password.as_bytes();
    let len = (payload.len() + 4 + 1) as i32;

    let mut msg = Vec::with_capacity(1 + 4 + payload.len() + 1);
    msg.push(b'p');
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(payload);
    msg.push(0);

    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

pub fn parse_auth_request(payload: &[u8]) -> anyhow::Result<AuthRequest> {
    if payload.len() < 4 {
        anyhow::bail!("auth response too short");
    }
    let auth_type = i32::from_be_bytes(payload[0..4].try_into()?);
    let rest = &payload[4..];

    match auth_type {
        0 => Ok(AuthRequest::Ok),
        3 => Ok(AuthRequest::CleartextPassword),
        5 => {
            if rest.len() < 4 {
                anyhow::bail!("MD5 auth response too short");
            }
            let mut salt = [0u8; 4];
            salt.copy_from_slice(&rest[..4]);
            Ok(AuthRequest::MD5Password(salt))
        }
        10 => {
            let mechs = rest
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            Ok(AuthRequest::Sasl(mechs))
        }
        11 => Ok(AuthRequest::SaslContinue(rest.to_vec())),
        t => Ok(AuthRequest::Unknown(t, rest.to_vec())),
    }
}

pub async fn relay(
    mut client: impl AsyncRead + AsyncWrite + Unpin,
    mut server: impl AsyncRead + AsyncWrite + Unpin,
) {
    let _ = tokio::io::copy_bidirectional(&mut client, &mut server).await;
}

pub async fn send_ssl_accept(
    stream: &mut (impl AsyncWrite + Unpin),
) -> anyhow::Result<()> {
    stream.write_all(b"S").await?;
    stream.flush().await?;
    Ok(())
}

pub async fn ssl_request(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
) -> anyhow::Result<bool> {
    let msg = [0u8, 0, 0, 8, 4, 210, 44, 143]; // int32 8, int32 80877103
    stream.write_all(&msg).await?;
    stream.flush().await?;

    let mut resp = [0u8; 1];
    stream.read_exact(&mut resp).await?;
    Ok(resp[0] == b'S')
}
