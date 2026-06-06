use std::{fs::{self, File, OpenOptions}, io::{self, BufReader, Read, Seek, Write}};

use crate::{vault::{self, SecurityProfile}};

pub struct BiceFile{
    pub header: [u8;4],
    pub version: u8,
    pub profile_id: u8,
    pub flags: u8,
    pub salt: [u8;64],
    pub esp32_pubkey: Option<[u8;32]>,
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
        profile: vault::SecurityProfile,
        flags: u8,
        esp32_pubkey: Option<[u8;32]>,
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
            version: (2), 
            profile_id,
            flags,
            salt: (salt_array), 
            esp32_pubkey,
            data: (encrypted_bytes)
        })
    }

    ///Additional function for fuzzing
    #[allow(unused)]
    pub fn from_bytes(data: &[u8]) -> std::io::Result<Self> {
        let cursor = std::io::Cursor::new(data);
        let mut reader = std::io::BufReader::new(cursor);

        let mut header = [0u8; 4];
        reader.read_exact(&mut header)?;
        if &header != b"B1CE" {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "[FS] : отсутствует сигнатура B1CE"));
        }

        let mut version_buf = [0u8; 1];
        reader.read_exact(&mut version_buf)?;
        let version = version_buf[0];

        let mut profile_buf = [0u8; 1];
        reader.read_exact(&mut profile_buf)?;
        let profile_id = profile_buf[0];

        if SecurityProfile::from_u8(profile_id).is_none() {
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "[FS] : Неизвестный профиль безопасности"));
        }

        let mut flags = 0u8;
        if version >= 2 {
            let mut flags_buf = [0u8; 1];
            reader.read_exact(&mut flags_buf)?;
            flags = flags_buf[0];
        }

        let mut salt = [0u8; 64];
        reader.read_exact(&mut salt)?;

        let mut esp32_pubkey = None;
        if flags & 1 != 0 {
            let mut pubkey = [0u8; 32];
            reader.read_exact(&mut pubkey)?;
            esp32_pubkey = Some(pubkey);
        }

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        Ok(Self {
            header,
            version,
            profile_id,
            flags,
            salt,
            esp32_pubkey,
            data,
        })
    }

    pub fn get_salt_from_file(path: impl AsRef<std::path::Path>) -> std::io::Result<[u8;64]>{
        let mut file = File::open(&path)?;
        let mut version_buf = [0u8; 1];
        file.seek(io::SeekFrom::Start(4))?;
        file.read_exact(&mut version_buf)?;
        let offset: u64 = if version_buf[0] >= 2 { 7 } else { 6 };
        file.seek(io::SeekFrom::Start(offset))?;
        let mut salt = [0u8;64];
        file.read_exact(&mut salt)?;
        Ok(salt)
    }


    /// Сохраняет текущий BiceFile по указанному пути.
    /// Логика:
    /// 1. Создать/Перезаписать файл.
    /// 2. Последовательно записать: header -> version -> profile_id -> flags -> salt -> [esp32_pubkey] -> data.
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
            file.write_all(&[self.flags])?;
            file.write_all(&self.salt)?;
            if let Some(ref pubkey) = self.esp32_pubkey {
                file.write_all(pubkey)?;
            }
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

        let mut flags = 0u8;
        if version >= 2 {
            let mut flags_buf = [0u8; 1];
            reader.read_exact(&mut flags_buf)?;
            flags = flags_buf[0];
        }

        let mut salt = [0u8;64];
        reader.read_exact(&mut salt)?;

        let mut esp32_pubkey = None;
        if flags & 1 != 0 {
            let mut pubkey = [0u8; 32];
            reader.read_exact(&mut pubkey)?;
            esp32_pubkey = Some(pubkey);
        }

        let mut data = Vec::new();
        reader.read_to_end(&mut data)?;

        Ok(Self{
            header,
            version,
            profile_id,
            flags,
            salt,
            esp32_pubkey,
            data
        })
    }
    /// Дешифрует переданную базу данных
    /// 1. Берёт соль из файла
    /// 2. Возвращает дешифрованные данные
    pub fn decrypt(&self, password: [u8;32]) -> Result<Vec<u8>, String> {
        crate::encryption::decrypt(&self.data, &password)
    }

    pub fn get_profile_id(path: impl AsRef<std::path::Path>) -> Option<u8> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);

        reader.seek_relative(5).ok()?;
        let mut profile_buf = [0u8;1];
        reader.read_exact(&mut profile_buf).ok()?;
        Some(profile_buf[0])
    }

    pub fn get_flags(path: impl AsRef<std::path::Path>) -> Option<u8> {
        let file = File::open(&path).ok()?;
        let mut reader = BufReader::new(file);
        let mut version_buf = [0u8; 1];
        reader.seek_relative(4).ok()?;
        reader.read_exact(&mut version_buf).ok()?;
        if version_buf[0] < 2 {
            return Some(0);
        }
        reader.seek_relative(1).ok()?;
        let mut flags_buf = [0u8; 1];
        reader.read_exact(&mut flags_buf).ok()?;
        Some(flags_buf[0])
    }

    pub fn requires_esp32(&self) -> bool {
        self.flags & 1 != 0
    }
}