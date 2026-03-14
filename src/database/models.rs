use serde::{Deserialize, Serialize};

/// Newtype autour d'un UUID v4 string — interdit de confondre un ID avec un titre.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(pub String);

impl EntryId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl rusqlite::ToSql for EntryId {
    fn to_sql(&self) -> rusqlite::Result<rusqlite::types::ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id:                 EntryId,
    pub title:              String,
    pub username:           String,
    pub password_encrypted: Vec<u8>,   // AES-256-GCM : nonce(12B) + ciphertext + tag
    pub url:                Option<String>,
    pub category:           String,
    pub notes_encrypted:    Option<Vec<u8>>,
    pub created_at:         i64,       // Unix timestamp (secondes)
    pub updated_at:         i64,
}
