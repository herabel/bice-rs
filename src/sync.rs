use std::{fs, sync::mpsc, thread};

use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use pqcrypto_kyber::kyber1024;
use pqcrypto_traits::kem::{Ciphertext, PublicKey, SharedSecret};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Shake, Xof};
use uuid::Uuid;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct Session {
    pub session_token: Uuid,
    pub session_id: i32,
    pub user_id: Uuid,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub url: String,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            url: "http://localhost:3000".to_string(),
        }
    }
}

/// Commands sent from TUI event-loop to the background worker thread.
pub enum SyncCommand {
    Login {
        config: ServerConfig,
        login: String,
        password: String,
    },
    Register {
        config: ServerConfig,
        login: String,
        password: String,
    },
    Push {
        config: ServerConfig,
        session: Session,
        file_path: String,
    },
    Pull {
        config: ServerConfig,
        session: Session,
        version: i32,
        file_path: String,
    },
    GetVersions {
        config: ServerConfig,
        session: Session,
    },
}

/// Results sent from the background worker back to the TUI.
pub enum SyncResult {
    LoginOk(Session),
    RegisterOk(String),
    PushOk(i32),  // new version number
    PullOk,
    VersionsOk(Vec<i32>),
    Error(String),
}

#[derive(Deserialize)]
struct LoginResponse {
    session: Session,
}

#[derive(Deserialize)]
struct RegisterResponse {
    message: String,
}

#[derive(Serialize)]
struct HandshakeRequest {
    session: Session,
    #[serde(with = "serde_bytes")]
    kyber_pub: [u8; 1568],
    #[serde(with = "serde_bytes")]
    x25519_pub: [u8; 32],
}

#[derive(Deserialize)]
struct HandshakeResponse {
    #[serde(with = "serde_bytes")]
    x25519_pub: [u8; 32],
    #[serde(with = "serde_bytes")]
    cipher_text: [u8; 1568],
    auth_tag: [u8; 16],
}

#[derive(Serialize)]
struct SyncRequest {
    session: Session,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
    timestamp: u64,
}

#[derive(Deserialize)]
struct SyncResponse {
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "type")]
enum SyncPayload {
    Pull { version: i32 },
    Push { encrypted_blob: Vec<u8> },
    GetVersions {},
}

#[derive(Deserialize)]
#[allow(unused)]
struct PullResponsePayload {
    status: String,
    file_bytes: Vec<u8>,
    server_time: i64,
}

#[derive(Deserialize)]
#[allow(unused)]
struct PushResponsePayload {
    status: String,
    version: i32,
    server_time: i64,
}

/// Spawns a background thread that processes [`SyncCommand`]s and sends
/// [`SyncResult`]s back. The TUI checks the receiver with `try_recv()` every
/// frame — no blocking, no `tokio` required.
pub fn spawn_worker(
    cmd_rx: mpsc::Receiver<SyncCommand>,
    res_tx: mpsc::Sender<SyncResult>,
) {
    thread::spawn(move || {
        for cmd in cmd_rx {
            let result = match cmd {
                SyncCommand::Login { config, login, password } => {
                    do_login(&config, &login, &password)
                }
                SyncCommand::Register { config, login, password } => {
                    do_register(&config, &login, &password)
                }
                SyncCommand::Push { config, session, file_path } => {
                    do_push(&config, &session, &file_path)
                }
                SyncCommand::Pull { config, session, version, file_path } => {
                    do_pull(&config, &session, version, &file_path)
                }
                SyncCommand::GetVersions { config, session } => {
                    do_get_versions(&config, &session)
                }
            };
            let _ = res_tx.send(result);
        }
    });
}

fn do_login(config: &ServerConfig, login: &str, password: &str) -> SyncResult {
    let url = format!("{}/api/v1/users/login", config.url);
    match ureq::get(&url).send_json(ureq::json!({ "login": login, "password": password })) {
        Ok(resp) => match resp.into_json::<LoginResponse>() {
            Ok(r) => SyncResult::LoginOk(r.session),
            Err(e) => SyncResult::Error(format!("Parse error: {e}")),
        },
        Err(e) => SyncResult::Error(format!("Login failed: {e}")),
    }
}

fn do_register(config: &ServerConfig, login: &str, password: &str) -> SyncResult {
    let url = format!("{}/api/v1/users/register", config.url);
    match ureq::post(&url).send_json(ureq::json!({ "login": login, "password": password })) {
        Ok(resp) => match resp.into_json::<RegisterResponse>() {
            Ok(r) => SyncResult::RegisterOk(r.message),
            Err(e) => SyncResult::Error(format!("Parse error: {e}")),
        },
        Err(e) => SyncResult::Error(format!("Register failed: {e}")),
    }
}

fn do_handshake(config: &ServerConfig, session: &Session) -> Result<XChaCha20Poly1305, String> {
    let (kyber_pk, kyber_sk) = kyber1024::keypair();
    let kyber_pub_bytes: [u8; 1568] = kyber_pk
        .as_bytes()
        .try_into()
        .map_err(|_| "kyber pub size mismatch".to_string())?;

    let x25519_rand: [u8; 32] = crate::entropy::generate_random_bytes(32)
        .try_into()
        .map_err(|_| "entropy size mismatch".to_string())?;
    let x25519_secret = StaticSecret::from(x25519_rand);
    let x25519_pub = X25519PublicKey::from(&x25519_secret);

    let req = HandshakeRequest {
        session: session.clone(),
        kyber_pub: kyber_pub_bytes,
        x25519_pub: *x25519_pub.as_bytes(),
    };

    let url = format!("{}/api/v1/sync/handshake", config.url);
    let resp: HandshakeResponse = ureq::post(&url)
        .send_json(&req)
        .map_err(|e| format!("Handshake HTTP error: {e}"))?
        .into_json()
        .map_err(|e| format!("Handshake parse error: {e}"))?;

    let server_pub = X25519PublicKey::from(resp.x25519_pub);
    let x25519_ss = x25519_secret.diffie_hellman(&server_pub);

    let kyber_ct = kyber1024::Ciphertext::from_bytes(&resp.cipher_text)
        .map_err(|e| format!("Kyber CT error: {e}"))?;
    let kyber_ss = kyber1024::decapsulate(&kyber_ct, &kyber_sk);

    let mut hasher = Shake::v256();
    hasher.update(b"BICE_v1_Handshake_SHAKE256");
    hasher.update(x25519_ss.as_bytes());
    hasher.update(kyber_ss.as_bytes());
    hasher.update(session.session_token.as_bytes());
    hasher.update(&session.session_id.to_le_bytes());
    hasher.update(session.user_id.as_bytes());

    let mut kdf_buf = [0u8; 64];
    hasher.squeeze(&mut kdf_buf);

    let mut auth_tag_local = [0u8; 16];
    hasher.squeeze(&mut auth_tag_local);

    if auth_tag_local != resp.auth_tag {
        return Err("Auth tag mismatch – possible MITM!".to_string());
    }

    let key = Key::from_slice(&kdf_buf[..32]);
    Ok(XChaCha20Poly1305::new(key))
}

fn do_push(config: &ServerConfig, session: &Session, file_path: &str) -> SyncResult {
    let file_bytes = match fs::read(file_path) {
        Ok(b) => b,
        Err(e) => return SyncResult::Error(format!("File read error: {e}")),
    };

    let cipher = match do_handshake(config, session) {
        Ok(c) => c,
        Err(e) => return SyncResult::Error(e),
    };

    let cmd = SyncPayload::Push { encrypted_blob: file_bytes };
    let cmd_bytes = match serde_json::to_vec(&cmd) {
        Ok(b) => b,
        Err(e) => return SyncResult::Error(format!("Serialize error: {e}")),
    };

    let nonce_bytes: [u8; 24] =
        match crate::entropy::generate_random_bytes(24).try_into() {
            Ok(n) => n,
            Err(_) => return SyncResult::Error("Nonce gen failed".to_string()),
        };
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = match cipher.encrypt(nonce, cmd_bytes.as_ref()) {
        Ok(c) => c,
        Err(e) => return SyncResult::Error(format!("Encrypt error: {e}")),
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sync_req = SyncRequest {
        session: session.clone(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        timestamp,
    };

    let url = format!("{}/api/v1/sync/", config.url);
    let sync_resp: SyncResponse = match ureq::post(&url).send_json(&sync_req) {
        Ok(r) => match r.into_json() {
            Ok(j) => j,
            Err(e) => return SyncResult::Error(format!("Push response parse error: {e}")),
        },
        Err(e) => return SyncResult::Error(format!("Push HTTP error: {e}")),
    };

    let resp_nonce: [u8; 24] = match sync_resp.nonce.try_into() {
        Ok(n) => n,
        Err(_) => return SyncResult::Error("Response nonce size mismatch".to_string()),
    };
    let resp_nonce = XNonce::from_slice(&resp_nonce);
    let decrypted = match cipher.decrypt(resp_nonce, sync_resp.ciphertext.as_ref()) {
        Ok(d) => d,
        Err(e) => return SyncResult::Error(format!("Response decrypt error: {e}")),
    };

    match postcard::from_bytes::<PushResponsePayload>(&decrypted) {
        Ok(p) => SyncResult::PushOk(p.version),
        Err(e) => SyncResult::Error(format!("Push payload parse error: {e}")),
    }
}

fn do_pull(
    config: &ServerConfig,
    session: &Session,
    version: i32,
    file_path: &str,
) -> SyncResult {
    let cipher = match do_handshake(config, session) {
        Ok(c) => c,
        Err(e) => return SyncResult::Error(e),
    };

    let cmd = SyncPayload::Pull { version };
    let cmd_bytes = match serde_json::to_vec(&cmd) {
        Ok(b) => b,
        Err(e) => return SyncResult::Error(format!("Serialize error: {e}")),
    };

    let nonce_bytes: [u8; 24] =
        match crate::entropy::generate_random_bytes(24).try_into() {
            Ok(n) => n,
            Err(_) => return SyncResult::Error("Nonce gen failed".to_string()),
        };
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = match cipher.encrypt(nonce, cmd_bytes.as_ref()) {
        Ok(c) => c,
        Err(e) => return SyncResult::Error(format!("Encrypt error: {e}")),
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sync_req = SyncRequest {
        session: session.clone(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        timestamp,
    };

    let url = format!("{}/api/v1/sync/", config.url);
    let sync_resp: SyncResponse = match ureq::post(&url).send_json(&sync_req) {
        Ok(r) => match r.into_json() {
            Ok(j) => j,
            Err(e) => return SyncResult::Error(format!("Pull response parse error: {e}")),
        },
        Err(e) => return SyncResult::Error(format!("Pull HTTP error: {e}")),
    };

    // Decrypt server response
    let resp_nonce: [u8; 24] = match sync_resp.nonce.try_into() {
        Ok(n) => n,
        Err(_) => return SyncResult::Error("Response nonce size mismatch".to_string()),
    };
    let resp_nonce = XNonce::from_slice(&resp_nonce);
    let decrypted = match cipher.decrypt(resp_nonce, sync_resp.ciphertext.as_ref()) {
        Ok(d) => d,
        Err(e) => return SyncResult::Error(format!("Response decrypt error: {e}")),
    };

    let payload: PullResponsePayload = match postcard::from_bytes(&decrypted) {
        Ok(p) => p,
        Err(e) => return SyncResult::Error(format!("Pull payload parse error: {e}")),
    };

    if payload.file_bytes.len() < 70 {
        return SyncResult::Error("Pulled file is too small or empty. Aborting to protect local vault.".to_string());
    }

    match fs::write(file_path, &payload.file_bytes) {
        Ok(_) => SyncResult::PullOk,
        Err(e) => SyncResult::Error(format!("File write error: {e}")),
    }
}

fn do_get_versions(config: &ServerConfig, session: &Session) -> SyncResult {
    let cipher = match do_handshake(config, session) {
        Ok(c) => c,
        Err(e) => return SyncResult::Error(e),
    };

    let cmd = SyncPayload::GetVersions {};
    let cmd_bytes = match serde_json::to_vec(&cmd) {
        Ok(b) => b,
        Err(e) => return SyncResult::Error(format!("Serialize error: {e}")),
    };

    let nonce_bytes: [u8; 24] =
        match crate::entropy::generate_random_bytes(24).try_into() {
            Ok(n) => n,
            Err(_) => return SyncResult::Error("Nonce gen failed".to_string()),
        };
    let nonce = XNonce::from_slice(&nonce_bytes);

    let ciphertext = match cipher.encrypt(nonce, cmd_bytes.as_ref()) {
        Ok(c) => c,
        Err(e) => return SyncResult::Error(format!("Encrypt error: {e}")),
    };

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let sync_req = SyncRequest {
        session: session.clone(),
        nonce: nonce_bytes.to_vec(),
        ciphertext,
        timestamp,
    };

    let url = format!("{}/api/v1/sync/", config.url);
    let sync_resp: SyncResponse = match ureq::post(&url).send_json(&sync_req) {
        Ok(r) => match r.into_json() {
            Ok(j) => j,
            Err(e) => return SyncResult::Error(format!("GetVersions response parse error: {e}")),
        },
        Err(e) => return SyncResult::Error(format!("GetVersions HTTP error: {e}")),
    };

    let resp_nonce: [u8; 24] = match sync_resp.nonce.try_into() {
        Ok(n) => n,
        Err(_) => return SyncResult::Error("Response nonce size mismatch".to_string()),
    };
    let resp_nonce = XNonce::from_slice(&resp_nonce);
    let decrypted = match cipher.decrypt(resp_nonce, sync_resp.ciphertext.as_ref()) {
        Ok(d) => d,
        Err(e) => return SyncResult::Error(format!("Response decrypt error: {e}")),
    };

    match postcard::from_bytes::<Vec<i32>>(&decrypted) {
        Ok(versions) => SyncResult::VersionsOk(versions),
        Err(e) => SyncResult::Error(format!("Versions payload parse error: {e}")),
    }
}

/// Saves session next to the vault file (e.g. "B1CE.bice" → "B1CE_session.json").
pub fn save_session(file_path: &str, session: &Session) {
    let session_path = session_path_for(file_path);
    if let Ok(json) = serde_json::to_string(session) {
        let _ = fs::write(session_path, json);
    }
}

/// Loads a previously saved session from disk.
pub fn load_session(file_path: &str) -> Option<Session> {
    let session_path = session_path_for(file_path);
    let json = fs::read_to_string(session_path).ok()?;
    serde_json::from_str(&json).ok()
}

fn session_path_for(vault_path: &str) -> String {
    let stem = vault_path.trim_end_matches(".bice");
    format!("{}_session.json", stem)
}
