// TODO: Рефакторинг, модуль должен получать все данные для шифрования и работать по принципу чёрного ящика, чтобы разгрузить логику main.rs
// main.rs не должен выступать оркестратором данных, это снижает поддержку и излишне усложняет код
#[allow(unused)]
pub struct BiceFile{
    pub header: [u8;4],
    pub version: u8,
    pub salt: [u8;64],
    pub data: Vec<u8>
}

impl BiceFile{
    pub fn new(salt: &Vec<u8>, encrypted_data: &[u8]) -> Self {
        let mut salt_array = [0u8; 64];
        salt_array.copy_from_slice(salt);
        Self {
            header: *b"B1CE",
            version: 1,
            salt: salt_array,
            data: encrypted_data.to_vec()
        }
    }
}

// deprecated

/*
#[allow(unused)]
pub fn create_bice (path: &str, salt: &Vec<u8>) -> std::io::Result<()> {
    let mut file = OpenOptions::new().create(true).read(true).write(true).open(path).expect("[ERROR] Создание файла (create_bice) неудачно.");
    file.write_all(b"B1CE")?;
    file.write_all(&[1u8])?;
    file.write_all(salt)?;
    Ok(())
}

pub fn save_password_bice(path: &str, password_hashed: &[u8]) -> std::io::Result<()>{
    let mut file = OpenOptions::new().read(true).write(true).open(path).expect("[ERROR] Не удалось сохранить BICE!");
    let _ = file.write_all(&password_hashed);
    file.write(b"0909")?;
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
*/