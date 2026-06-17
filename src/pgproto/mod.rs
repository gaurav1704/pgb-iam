use tokio::io::AsyncReadExt;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

const PROTOCOL_VERSION_3: i32 = 196608; // 3.0

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

/// Read a complete PostgreSQL message: 1-byte type + 4-byte length + payload
pub async fn read_pg_message(stream: &mut TcpStream) -> anyhow::Result<Option<(u8, Vec<u8>)>> {
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

/// The startup message has no type byte — just length + protocol + params
pub async fn read_startup_message(stream: &mut TcpStream) -> anyhow::Result<StartupParams> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = i32::from_be_bytes(len_buf) as usize - 4;

    let mut buf = vec![0u8; len];
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
                    break; // trailing null
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

    Ok(StartupParams { user, database, params })
}

/// Write a StartupMessage (no type byte): int32 len, int32 protocol, then key-value pairs
pub async fn write_startup_message(
    stream: &mut TcpStream,
    params: &StartupParams,
) -> anyhow::Result<()> {
    let mut buf = Vec::new();

    // protocol version
    buf.extend_from_slice(&PROTOCOL_VERSION_3.to_be_bytes());

    // key-value pairs
    for (key, value) in &params.params {
        buf.extend_from_slice(key.as_bytes());
        buf.push(0);
        buf.extend_from_slice(value.as_bytes());
        buf.push(0);
    }
    buf.push(0); // trailing null

    // write length-prefixed message
    let len = (buf.len() + 4) as i32;
    let mut header = len.to_be_bytes().to_vec();
    header.extend_from_slice(&buf);
    stream.write_all(&header).await?;
    stream.flush().await?;
    Ok(())
}

/// Send a PasswordMessage: 'p' + int32 len + password
pub async fn send_password(stream: &mut TcpStream, password: &str) -> anyhow::Result<()> {
    let payload = password.as_bytes();
    let len = (payload.len() + 4 + 1) as i32; // +1 for null terminator

    let mut msg = Vec::with_capacity(1 + 4 + payload.len() + 1);
    msg.push(b'p');
    msg.extend_from_slice(&len.to_be_bytes());
    msg.extend_from_slice(payload);
    msg.push(0); // null-terminated

    stream.write_all(&msg).await?;
    stream.flush().await?;
    Ok(())
}

/// Parse an AuthenticationRequest from the server
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
            // SASL: list of null-terminated mechanism strings
            let mechs = rest
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).to_string())
                .collect();
            Ok(AuthRequest::Sasl(mechs))
        }
        11 => Ok(AuthRequest::SaslContinue(rest.to_vec())),
        t => {
            Ok(AuthRequest::Unknown(t, rest.to_vec()))
        }
    }
}

/// Relay raw bytes bidirectionally until one side disconnects
pub async fn relay(mut client: TcpStream, mut server: TcpStream) {
    use tokio::io;
    let _ = io::copy_bidirectional(&mut client, &mut server).await;
}
