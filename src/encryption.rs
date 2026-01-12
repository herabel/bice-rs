use crate::entropy;
use chacha20poly1305::{self, Key, KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};

pub fn encrypt(data: &[u8], master_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    let nonce_bytes= entropy::generate_random_bytes(24);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let key = Key::from_slice(master_key);
    let cipher = XChaCha20Poly1305::new(key);
    let cipher_data = cipher.encrypt(nonce, data).map_err(|e| e.to_string())?;

    let mut final_blob = nonce_bytes;
    final_blob.extend_from_slice(&cipher_data);
    
    Ok(final_blob)
}

pub fn decrypt(encrypted_data: &[u8], master_key: &[u8; 32]) -> Result<Vec<u8>, String> {
    if encrypted_data.len() < 24 {
        return Err("Данные повреждены или слишком коротки. Восстановить их не получится.".to_string());
    };
    let key = Key::from_slice(master_key);
    let cipher = XChaCha20Poly1305::new(key);
    let (nonce_part, cipher_part) = encrypted_data.split_at(24);
    let decrypted_data = cipher.decrypt(XNonce::from_slice(nonce_part), cipher_part.as_ref()).map_err(|e| e.to_string())?;

    Ok(decrypted_data)
}