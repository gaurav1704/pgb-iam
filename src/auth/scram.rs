use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn gen_nonce() -> String {
    let mut buf = [0u8; 24];
    rand::thread_rng().fill(&mut buf);
    use base64::Engine;
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(buf)
}

fn salted_password(password: &str, salt: &[u8], iterations: u32) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, iterations, &mut out);
    out
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC key");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn sha256(data: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().to_vec()
}

fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter()).map(|(x, y)| x ^ y).collect()
}

use base64::Engine;

fn b64(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD_NO_PAD.encode(data)
}

fn unb64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD_NO_PAD.decode(s).unwrap_or_default()
}

// ── Client side: authenticate to server (backend IAM auth) ──

pub struct ScramClient {
    pub username: String,
    password: String,
    client_nonce: String,
    client_first_bare: String,
    server_first: Option<String>,
    salted_password: Option<Vec<u8>>,
    auth_message: Option<String>,
}

impl ScramClient {
    pub fn new(username: &str, password: &str) -> Self {
        Self {
            username: username.to_string(),
            password: password.to_string(),
            client_nonce: gen_nonce(),
            client_first_bare: String::new(),
            server_first: None,
            salted_password: None,
            auth_message: None,
        }
    }

    /// Build: `n,,n=user,r=nonce`
    pub fn build_client_first(&mut self) -> String {
        let bare = format!("n={},r={}", self.username, self.client_nonce);
        self.client_first_bare = bare.clone();
        format!("n,,{}", bare)
    }

    /// Parse: `r=...,s=...,i=...`
    pub fn parse_server_first(&mut self, msg: &str) -> anyhow::Result<(String, Vec<u8>, u32)> {
        let mut full_nonce = String::new();
        let mut salt = Vec::new();
        let mut iterations = 0u32;
        for part in msg.split(',') {
            if let Some(val) = part.strip_prefix("r=") {
                full_nonce = val.to_string();
                if !full_nonce.starts_with(&self.client_nonce) {
                    anyhow::bail!("server nonce doesn't start with client nonce");
                }
            } else if let Some(val) = part.strip_prefix("s=") {
                salt = unb64(val);
            } else if let Some(val) = part.strip_prefix("i=") {
                iterations = val.parse()?;
            }
        }
        if full_nonce.is_empty() || salt.is_empty() || iterations == 0 {
            anyhow::bail!("invalid server-first-message");
        }
        self.server_first = Some(msg.to_string());
        self.salted_password = Some(salted_password(&self.password, &salt, iterations));
        Ok((full_nonce, salt, iterations))
    }

    /// Build: `c=biws,r=nonce,p=proof`
    pub fn build_client_final(&mut self) -> anyhow::Result<String> {
        let salted = self.salted_password.as_ref().ok_or_else(|| anyhow::anyhow!("no salted password"))?;
        let server_first = self.server_first.as_deref().ok_or_else(|| anyhow::anyhow!("no server-first"))?;

        let client_key = hmac_sha256(salted, b"Client Key");
        let stored_key = sha256(&client_key);

        let gs2_header_b64 = b64(b"n,,");
        let client_final_wo_proof = format!("c={},r={}", gs2_header_b64, self.client_nonce);

        let auth_message = format!("{},{},{}", self.client_first_bare, server_first, client_final_wo_proof);
        self.auth_message = Some(auth_message);

        let client_signature = hmac_sha256(&stored_key, self.auth_message.as_ref().unwrap().as_bytes());
        let client_proof = xor_bytes(&client_key, &client_signature);

        Ok(format!("{},p={}", client_final_wo_proof, b64(&client_proof)))
    }

    /// Verify: `v=signature`
    pub fn verify_server_final(&self, msg: &str) -> anyhow::Result<()> {
        let salted = self.salted_password.as_ref().ok_or_else(|| anyhow::anyhow!("no salted password"))?;
        let auth_msg = self.auth_message.as_ref().ok_or_else(|| anyhow::anyhow!("no auth message"))?;
        let server_key = hmac_sha256(salted, b"Server Key");
        let expected = b64(&hmac_sha256(&server_key, auth_msg.as_bytes()));
        if let Some(val) = msg.strip_prefix("v=") {
            if val == expected {
                return Ok(());
            }
        }
        anyhow::bail!("server signature mismatch")
    }
}

// ── Server side: authenticate a client (local client auth) ──

pub struct ScramServer {
    password: String,
    server_nonce: String,
    client_nonce: String,
    username: String,
    salt: Vec<u8>,
    iterations: u32,
    server_first: Option<String>,
    stored_key: Option<Vec<u8>>,
    server_key: Option<Vec<u8>>,
    auth_message: Option<String>,
    client_first_bare: String,
}

impl ScramServer {
    pub fn new(password: &str) -> Self {
        let salt: Vec<u8> = (0..16).map(|_| rand::thread_rng().gen()).collect();
        Self {
            password: password.to_string(),
            server_nonce: gen_nonce(),
            client_nonce: String::new(),
            username: String::new(),
            salt,
            iterations: 4096,
            server_first: None,
            stored_key: None,
            server_key: None,
            auth_message: None,
            client_first_bare: String::new(),
        }
    }

    /// Parse `n,,n=user,r=nonce` → build `r=nonce+server,s=...,i=...`
    pub fn build_server_first(&mut self, client_first: &str) -> anyhow::Result<String> {
        let bare = client_first.strip_prefix("n,,").unwrap_or(client_first);
        self.client_first_bare = bare.to_string();

        for part in bare.split(',') {
            if let Some(val) = part.strip_prefix("n=") {
                self.username = val.to_string();
            } else if let Some(val) = part.strip_prefix("r=") {
                self.client_nonce = val.to_string();
            }
        }
        if self.client_nonce.is_empty() {
            anyhow::bail!("no client nonce in client-first-message");
        }
        let full_nonce = format!("{}{}", self.client_nonce, self.server_nonce);
        let sf = format!("r={},s={},i={}", full_nonce, b64(&self.salt), self.iterations);
        self.server_first = Some(sf.clone());

        // Pre-compute StoredKey and ServerKey
        let salted = salted_password(&self.password, &self.salt, self.iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        self.stored_key = Some(sha256(&client_key));
        self.server_key = Some(hmac_sha256(&salted, b"Server Key"));

        Ok(sf)
    }

    /// Parse `c=...,r=...,p=proof` → verify → `v=signature`
    pub fn handle_client_final(&mut self, client_final: &str) -> anyhow::Result<String> {
        let sf = self.server_first.as_deref().ok_or_else(|| anyhow::anyhow!("no server-first"))?;
        let stored_key = self.stored_key.as_ref().ok_or_else(|| anyhow::anyhow!("no stored key"))?;
        let server_key = self.server_key.as_ref().ok_or_else(|| anyhow::anyhow!("no server key"))?;

        let mut channel_binding = String::new();
        let mut nonce = String::new();
        let mut proof = String::new();
        for part in client_final.split(',') {
            if let Some(val) = part.strip_prefix("c=") { channel_binding = val.to_string(); }
            else if let Some(val) = part.strip_prefix("r=") { nonce = val.to_string(); }
            else if let Some(val) = part.strip_prefix("p=") { proof = val.to_string(); }
        }
        if channel_binding.is_empty() || nonce.is_empty() || proof.is_empty() {
            anyhow::bail!("invalid client-final-message");
        }

        let client_final_wo_proof = format!("c={},r={}", channel_binding, nonce);
        let auth_message = format!("{},{},{}", self.client_first_bare, sf, client_final_wo_proof);
        self.auth_message = Some(auth_message.clone());

        let client_signature = hmac_sha256(stored_key, auth_message.as_bytes());
        let proof_bytes = unb64(&proof);
        let recovered_client_key = xor_bytes(&proof_bytes, &client_signature);

        if sha256(&recovered_client_key) != *stored_key {
            anyhow::bail!("SCRAM proof verification failed");
        }

        let server_sig = b64(&hmac_sha256(server_key, auth_message.as_bytes()));
        Ok(format!("v={}", server_sig))
    }
}
