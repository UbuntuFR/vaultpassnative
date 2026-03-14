use rusqlite::types::{FromSql, FromSqlResult, ValueRef, ToSql, ToSqlOutput};
use uuid::Uuid;

#[derive(Debug, Clone, PartialEq)]
pub struct EntryId(pub String);

impl EntryId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl std::fmt::Display for EntryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl ToSql for EntryId {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.0.to_sql()
    }
}

impl FromSql for EntryId {
    fn column_result(value: ValueRef<'_>) -> FromSqlResult<Self> {
        String::column_result(value).map(EntryId)
    }
}

#[derive(Debug, Clone)]
pub struct VaultEntry {
    pub id:                 EntryId,
    pub title:              String,
    pub username:           String,
    pub password_encrypted: Vec<u8>,
    pub url:                Option<String>,
    pub category:           String,
    pub notes_encrypted:    Option<Vec<u8>>,
    pub is_favorite:        bool,
    pub created_at:         i64,
    pub updated_at:         i64,
}
