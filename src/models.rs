use serde::{Serialize, Deserialize};
use crate::{storage::BiceFile};

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
