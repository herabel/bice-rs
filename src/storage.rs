use std::time::Instant;
use std::{fs::{self, File, OpenOptions}, io::{self, BufReader, Read, Write}};

use crate::{vault::{self, SecurityProfile}};

// TODO: Рефакторинг, модуль должен получать все данные для шифрования и работать по принципу чёрного ящика, чтобы разгрузить логику main.rs
// main.rs не должен выступать оркестратором данных, это снижает поддержку и излишне усложняет код
pub struct BiceFile{
    pub header: [u8;4],
    pub version: u8,
    profile_id: u8,
    pub salt: [u8;64],
    pub data: Vec<u8>
}

impl BiceFile{
    pub fn new(salt: &[u8], encrypted_data: &[u8], profile_id: u8) -> Self {
        let mut salt_array = [0u8; 64];
        salt_array.copy_from_slice(salt);
        Self {
            header: *b"B1CE",
            version: 1,
            profile_id,
            salt: salt_array,
            data: encrypted_data.to_vec()
        }
    }*/

    /// Создает новый экземпляр BiceFile из сырых данных.
    /// Внутри происходит:
    /// 1. Генерация ключа из пароля и переданной соли (Argon2).
    /// 2. Шифрование raw_data (XChaCha20Poly1305).
    /// 3. Упаковка всего этого в структуру.
    pub fn encrypt_new(
        raw_data: &[u8], 
        password: &str, 
        salt: &[u8],
        profile: vault::SecurityProfile
    ) -> Result<Self,String>
    {
        let start_vault = Instant::now();
        let master_key = vault::get_master_key(password, &salt.to_vec(), profile).map_err(|e| format!("Ошибка Argon2id: {e}"))?;
        let duration_vault = start_vault.elapsed();
        println!("[PERF] Argon2id выполнен за: {:?}", duration_vault);

        let encrypted_bytes = crate::encryption::encrypt(raw_data, &master_key)?;

        let mut salt_array = [0u8; 64];

        let profile_id = profile as u8;

        if salt.len() == 64 {
            salt_array.copy_from_slice(salt);
        } else {
            return Err("Соль должна быть ровно 64 байта".to_string());
        };

        Ok(Self { 
            header: (*b"B1CE"), 
            version: (1), 
            profile_id,
            salt: (salt_array), 
            data: (encrypted_bytes)
        })
    }
    /// Сохраняет текущий BiceFile по указанному пути.
    /// Логика:
    /// 1. Создать/Перезаписать файл.
    /// 2. Последовательно записать: header -> version -> profile_id -> salt -> data.
    /// 3. Атомарно перезапсывает файл, создавая tmp верисию.
    /// 4. Гарантирует, что файл не будет уничтожен если вдруг компьютер выключится во время перезаписи.
    pub fn save(&self, path: impl AsRef<std::path::Path>) -> std::io::Result<()> {
        let path = path.as_ref();
        let tmp_path = path.with_extension("tmp");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&tmp_path)?;
            
            file.write_all(&self.header)?;
            file.write_all(&[self.version])?;
            file.write_all(&[self.profile_id])?;
            file.write_all(&self.salt)?;
            file.write_all(&self.data)?;
            file.sync_all()?;
        }

        fs::rename(&tmp_path, path)?;

        Ok(())
    }
    /// Открывает файл, проверяет структуру и читает данные в память.
    /// Логика:
    /// 1. Открыть файл.
    /// 2. Прочитать и сверить header (если не B1CE - ошибка).
    /// 3. Прочитать version, salt и profile.
    /// 4. Прочитать остаток файла в data.
    /// 5. Вернуть Self.
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let mut reader = BufReader::new(file);

        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        if &header != b"B1CE" {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Неверный формат файла: отсутствует сигнатура B1CE"));
        }
        let mut version_buf = [0u8;1];
        reader.read_exact(&mut version_buf)?;
        let version = version_buf[0];

        let mut profile_buf = [0u8;1];
        reader.read_exact(&mut profile_buf)?;
        let profile_id = profile_buf[0];
        if SecurityProfile::from_u8(profile_id).is_none(){
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Неизвестный профиль безопасности"));
        }

        let mut salt = [0u8;64];
        reader.read_exact(&mut salt)?;
        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        Ok(Self{
            header,
            version,
            profile_id,
            salt,
            data
        })
    }
    /// Дешифрует переданную базу данных
    /// 1. Берёт соль из файла
    /// 2. Возвращает дешифрованные данные
    pub fn decrypt(&self, password: &str) -> Result<Vec<u8>, String> {
        let profile = SecurityProfile::from_u8(self.profile_id).unwrap();
        // 1. Восстанавливаем ключ, используя СОЛЬ ИЗ ФАЙЛА (self.salt)
        let master_key = crate::vault::get_master_key(password, &self.salt.to_vec(), crate::vault::SecurityProfile::Paranoid)?;
        
        // 2. Расшифровываем
        crate::encryption::decrypt(&self.data, &master_key)
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

    Ok(BiceFile {salt, data: encrypted_data, header: *b"B1CE", version: 1 })
}
*/