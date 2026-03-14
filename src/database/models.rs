use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id:                 String,      // UUID v4
    pub title:              String,
    pub username:           String,
    pub password_encrypted: Vec<u8>,     // AES-256-GCM : nonce (12 B) + ciphertext + tag
    pub url:                Option<String>,
    pub category:           String,
    pub notes_encrypted:    Option<Vec<u8>>,
    pub created_at:         i64,         // Unix timestamp secondes
    pub updated_at:         i64,
}
