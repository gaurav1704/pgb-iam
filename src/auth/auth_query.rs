use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::pgproto;

/// Query the database to look up a user's password.
/// This connects as the auth_user, runs the auth_query, and returns
/// the password string for the requested user.
pub async fn lookup_password(
    target_addr: &str,
    auth_user: &str,
    auth_query: &str,
    lookup_user: &str,
) -> anyhow::Result<String> {
    let mut stream = TcpStream::connect(target_addr).await?;

    // Send startup
    let startup = pgproto::StartupParams {
        user: auth_user.to_string(),
        database: auth_user.to_string(),
        params: vec![
            ("user".to_string(), auth_user.to_string()),
            ("database".to_string(), auth_user.to_string()),
        ],
    };
    pgproto::write_startup_message(&mut stream, &startup).await?;

    // Auth loop — assumes trust or password (simple for now)
    loop {
        let msg = pgproto::read_pg_message(&mut stream).await?;
        match msg {
            None => anyhow::bail!("backend closed during auth_query auth"),
            Some((type_byte, payload)) => match type_byte {
                b'R' => {
                    let auth = pgproto::parse_auth_request(&payload)?;
                    match auth {
                        pgproto::AuthRequest::Ok => break,
                        pgproto::AuthRequest::CleartextPassword => {
                            anyhow::bail!("auth_query user requires password, not supported yet");
                        }
                        _ => anyhow::bail!("unsupported auth for auth_query user"),
                    }
                }
                b'E' => anyhow::bail!("auth_query auth error: {}", String::from_utf8_lossy(&payload)),
                _ => continue,
            },
        }
    }

    // Drain startup messages until ReadyForQuery
    loop {
        let msg = pgproto::read_pg_message(&mut stream).await?;
        match msg {
            None => anyhow::bail!("backend closed during auth_query startup"),
            Some((type_byte, _)) if type_byte == b'Z' => break,
            _ => continue,
        }
    }

    // Build simple query: `SELECT passwd FROM pg_shadow WHERE usename = 'user'`
    let query = auth_query.replace("$1", &format!("'{}'", lookup_user));
    let query_bytes = query.as_bytes();
    let mut qmsg = vec![b'Q'];
    let len = (query_bytes.len() + 4 + 1) as i32; // +1 for trailing NUL
    qmsg.extend_from_slice(&len.to_be_bytes());
    qmsg.extend_from_slice(query_bytes);
    qmsg.push(0);
    stream.write_all(&qmsg).await?;
    stream.flush().await?;

    // Read response — expect RowDescription + DataRow + CommandComplete + ReadyForQuery
    let mut password = None;
    loop {
        let msg = pgproto::read_pg_message(&mut stream).await?;
        match msg {
            None => break,
            Some((type_byte, payload)) => {
                match type_byte {
                    b'T' => continue, // RowDescription
                    b'D' => {
                        // DataRow: int16 ncols, then for each col: int32 len + data
                        if payload.len() < 2 {
                            continue;
                        }
                        let cols = u16::from_be_bytes([payload[0], payload[1]]) as usize;
                        let mut off = 2;
                        for _ in 0..cols {
                            if off + 4 > payload.len() {
                                break;
                            }
                            let col_len = i32::from_be_bytes(payload[off..off+4].try_into().unwrap());
                            off += 4;
                            if col_len == -1 {
                                continue; // NULL
                            }
                            if col_len as usize + off > payload.len() {
                                break;
                            }
                            let val = String::from_utf8_lossy(&payload[off..off + col_len as usize]).to_string();
                            password = Some(val);
                            off += col_len as usize;
                        }
                    }
                    b'C' => continue, // CommandComplete
                    b'Z' => break,    // ReadyForQuery
                    b'E' => anyhow::bail!("auth_query error: {}", String::from_utf8_lossy(&payload)),
                    _ => continue,
                }
            }
        }
    }

    match password {
        Some(p) => Ok(p),
        None => anyhow::bail!("auth_query returned no password for user {}", lookup_user),
    }
}
