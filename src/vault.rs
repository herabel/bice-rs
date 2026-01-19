use argon2::{self, Argon2, Params};

pub enum SecurityProfile {
    Fast,
    Standard,
    Paranoid,
    Extreme
}
pub fn get_master_key(password: &str, entropy: &[u8; 64], profile: SecurityProfile) -> Result<[u8; 32], String>{
    //стоит задавать m_cost (1 параметр) как желаемое МБ * 1024 => (64 (МБ) * 1024)
    let (m,t,p) = match profile {
    SecurityProfile::Fast => (64 * 1024, 8, 4),
    SecurityProfile::Standard => (128 * 1024, 4, 4),
    SecurityProfile::Paranoid => (512 * 1024, 8, 4),
    SecurityProfile::Extreme => (1024 * 1024, 12, 4),
};
    let params = Params::new(m, t, p, Some(32))
        .expect("Ошибка в параметрах Argon2id");
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut output = [0u8; 32];

    argon2.hash_password_into(password.as_bytes(), entropy, &mut output).map_err(|e| e.to_string()).map(|_| output)
}