use argon2::{self, Argon2, Params};

pub fn get_master_key(password: &str, entropy: &[u8; 64]) -> Result<[u8; 32], String>{
    let m_cost = 512 * 1024; //512МБ x * 1024 = x МБ
    let params = Params::new(m_cost, 8, 4, Some(32))
        .expect("Ошибка в параметрах Argon2id");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = [0u8; 32];

    argon2.hash_password_into(password.as_bytes(), entropy, &mut output).map_err(|e| e.to_string()).map(|_| output)
}