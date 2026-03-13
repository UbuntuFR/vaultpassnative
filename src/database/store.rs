use rusqlite::{Connection, Result as SqlResult, params, OptionalExtension};
use thiserror::Error;
use crate::database::models::VaultEntry;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Erreur SQLite : {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Entrée introuvable : {0}")]
    NotFound(String),
}

pub struct VaultStore {
    conn: Connection,
}

impl VaultStore {
    /// Ouvre (ou crée) la base de données au chemin donné.
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        let store = VaultStore { conn };
        store.migrate()?;
        Ok(store)
    }

    /// Crée les tables si elles n'existent pas (migration v1).
    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault_meta (
                id      INTEGER PRIMARY KEY,
                salt    BLOB NOT NULL,
                version INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS entries (
                id                 TEXT PRIMARY KEY,
                title              TEXT NOT NULL,
                username           TEXT NOT NULL,
                password_encrypted BLOB NOT NULL,
                url                TEXT,
                category           TEXT NOT NULL DEFAULT 'Général',
                notes_encrypted    BLOB,
                created_at         INTEGER NOT NULL,
                updated_at         INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entries_category
                ON entries(category);
        ")?;
        Ok(())
    }

    /// Sauvegarde le sel Argon2 (une seule fois à la création du coffre).
    pub fn save_salt(&self, salt: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO vault_meta (id, salt, version) VALUES (1, ?1, 1)",
            params![salt],
        )?;
        Ok(())
    }

    /// Récupère le sel stocké.
    pub fn load_salt(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self.conn
            .prepare("SELECT salt FROM vault_meta WHERE id = 1")?;
        let result = stmt
            .query_row([], |row| row.get(0))
            .optional()?;
        Ok(result)
    }

    /// Insère une nouvelle entrée chiffrée.
    pub fn insert_entry(&self, entry: &VaultEntry) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO entries
             (id, title, username, password_encrypted, url, category,
              notes_encrypted, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                entry.id,
                entry.title,
                entry.username,
                entry.password_encrypted,
                entry.url,
                entry.category,
                entry.notes_encrypted,
                entry.created_at,
                entry.updated_at,
            ],
        )?;
        Ok(())
    }

    /// Retourne toutes les entrées (mot de passe encore chiffré).
    /// 🦀 CONCEPT — impl Trait en retour :
    /// On retourne un Vec<VaultEntry>, pas un type opaque ici,
    /// mais Result<T,E> évite tout panic si SQLite échoue.
    pub fn list_entries(&self) -> Result<Vec<VaultEntry>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, title, username, password_encrypted, url,
                    category, notes_encrypted, created_at, updated_at
             FROM entries ORDER BY updated_at DESC"
        )?;

        let entries = stmt.query_map([], |row| {
            Ok(VaultEntry {
                id:                 row.get(0)?,
                title:              row.get(1)?,
                username:           row.get(2)?,
                password_encrypted: row.get(3)?,
                url:                row.get(4)?,
                category:           row.get(5)?,
                notes_encrypted:    row.get(6)?,
                created_at:         row.get(7)?,
                updated_at:         row.get(8)?,
            })
        })?
        .collect::<SqlResult<Vec<_>>>()?;

        Ok(entries)
    }

    /// Supprime une entrée par son UUID.
    pub fn delete_entry(&self, id: &str) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "DELETE FROM entries WHERE id = ?1",
            params![id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(id.to_string()));
        }
        Ok(())
    }
}
