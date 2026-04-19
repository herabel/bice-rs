use serde::{Serialize, Deserialize};
use crate::{storage::{self, BiceFile}, vault::{self}};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PasswordEntry {
    pub service: String,
    pub login: String,
    pub password: String,
    pub description: Option<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Vault {
    pub entries: Vec<PasswordEntry>,
}

impl PartialEq for Vault{
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Vault { 
    pub fn new() -> Self {
        Self {entries: Vec::new()}
    }
    pub fn add(&mut self, service: String, login: String, password: String, description: Option<String>) {
        self.entries.push(PasswordEntry { service, login, password, description });
    }

    pub fn get_profile_id(path: &str) -> vault::SecurityProfile {
        let id_u8 = storage::BiceFile::get_profile_id(path);
        vault::SecurityProfile::from_u8(id_u8).unwrap()
    }

    pub fn load_from_disk(path: &str, master_pass: &str) -> Result<Self, String> {
        let bice = BiceFile::open(path).map_err(|e| e.to_string())?;
        let decrypted_data = bice.decrypt(master_pass)?;
        let vault: Vault = postcard::from_bytes(&decrypted_data).map_err(|e| format!("Ошибка структуры данных {e}!"))?;
        Ok(vault)
    }

    pub fn save_to_disk(&self, path: &str, master_pass: &str, profile: crate::vault::SecurityProfile) -> Result<(), String> {
        let bytes = postcard::to_stdvec(self).map_err(|e| e.to_string())?;

        let new_salt = crate::entropy::generate_random_bytes(64);

        let bice = BiceFile::encrypt_new(&bytes, master_pass, &new_salt, profile)?;

        bice.save(path).map_err(|e| e.to_string())?;

        Ok(())
    }
}