use std::io::Seek;
use std::path;
use std::time::Instant;
use std::{fs::{self, File, OpenOptions}, io::{self, BufReader, Read, Write}};

use crate::{vault::{self, SecurityProfile}};

// TODO: Рефакторинг, модуль должен получать все данные для шифрования и работать по принципу чёрного ящика, чтобы разгрузить логику main.rs
// main.rs не должен выступать оркестратором данных, это снижает поддержку и излишне усложняет код
pub struct BiceFile{
    pub header: [u8;4],
    pub version: u8,
    pub profile_id: u8,
    pub salt: [u8;64],
    pub data: Vec<u8>
}

impl BiceFile{
    /// Создает новый экземпляр BiceFile из сырых данных.
    /// Внутри происходит:
    /// 1. Генерация ключа из пароля и переданной соли (Argon2).
    /// 2. Шифрование raw_data (XChaCha20Poly1305).
    /// 3. Упаковка всего этого в структуру.
    pub fn encrypt_new(
        raw_data: &[u8], 
        password: [u8;32], 
        salt: &[u8],
        profile: vault::SecurityProfile
    ) -> Result<Self,String>
    {

        let encrypted_bytes = crate::encryption::encrypt(raw_data, &password)?;

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

    pub fn get_salt_from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<[u8;64]>{
        let mut file = File::open(path)?;
        let _ = file.seek(io::SeekFrom::Start(6));
        let mut reader = BufReader::new(file);
        let mut salt = [0u8;64];
        reader.read_exact(&mut salt)?;
        Ok(salt)
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
            return Err(io::Error::new(io::ErrorKind::InvalidData, "[FS] : отсутствует сигнатура B1CE"));
        }
        let mut version_buf = [0u8;1];
        reader.read_exact(&mut version_buf)?;
        let version = version_buf[0];

        let mut profile_buf = [0u8;1];
        reader.read_exact(&mut profile_buf)?;
        let profile_id = profile_buf[0];
        if SecurityProfile::from_u8(profile_id).is_none(){
            return Err(io::Error::new(io::ErrorKind::InvalidData, "[FS] : Неизвестный профиль безопасности"));
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
    pub fn decrypt(&self, password: [u8;32]) -> Result<Vec<u8>, String> {
        let profile = SecurityProfile::from_u8(self.profile_id).unwrap();
        crate::encryption::decrypt(&self.data, &password)
    }

    pub fn get_profile_id(path: impl AsRef<std::path::Path>) -> u8 {
        let file = File::open(path).unwrap();
        let mut reader = BufReader::new(file);

        reader.seek_relative(5).unwrap();
        let mut profile_buf = [0u8;1];
        reader.read_exact(&mut profile_buf).unwrap();
        profile_buf[0]
    }
}