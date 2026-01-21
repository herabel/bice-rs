use std::fs::File;
use std::io::{BufReader, Read, Write};

pub struct BiceFile {
    pub salt: [u8;64],
    pub encrypted_data: Vec<u8>
}

pub fn save_bice(path: &str, salt: &[u8; 64], data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;

    file.write_all(b"B1CE")?;
    file.write_all(&[1u8])?;
    file.write_all(salt)?;
    file.write_all(data)?;
    Ok(())
}

pub fn read_bice(path: &str) -> Result<BiceFile, String> {
    let file = File::open(path).map_err(|e| format!("[ERROR] Ошибка открытия файла: {}", e))?;
    let mut buf_reader = BufReader::new(file);
    let mut magic_bytes= [0u8; 4]; // 4 байта
    buf_reader.read_exact(&mut magic_bytes).map_err(|e| e.to_string())?;
    if &magic_bytes != b"B1CE" {
        return Err("[ERROR] Неверный формат файла: отсутствует сигнатура B1CE".to_string());
    }
    let mut version = [0u8; 1];
    buf_reader.read_exact(&mut version).map_err(|e| e.to_string())?;
    let mut salt = [0u8; 64];
    buf_reader.read_exact(&mut salt).map_err(|e| e.to_string())?;
    let mut encrypted_data = Vec::new();
    buf_reader.read_to_end(&mut encrypted_data).map_err(|e| e.to_string())?;

    Ok(BiceFile {salt, encrypted_data})
}