use rusqlite::{Connection, Result as SqlResult, params, OptionalExtension};
use thiserror::Error;
use zeroize::Zeroizing;
use crate::database::models::VaultEntry;
use crate::crypto::cipher::{encrypt, decrypt, SENTINEL_PLAINTEXT, CipherError};
use crate::crypto::kdf;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Erreur SQLite : {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("Erreur de chiffrement : {0}")]
    Cipher(#[from] CipherError),
    #[error("Erreur KDF : {0}")]
    Kdf(String),
    #[error("Entrée introuvable : {0}")]
    NotFound(String),
}

pub struct VaultStore {
    conn: Connection,
}

impl VaultStore {
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let store = VaultStore { conn };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&self) -> Result<(), StoreError> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault_meta (
                id               INTEGER PRIMARY KEY,
                salt             BLOB    NOT NULL,
                sentinel         BLOB,
                version          INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS entries (
                id                 TEXT    PRIMARY KEY,
                title              TEXT    NOT NULL,
                username           TEXT    NOT NULL,
                password_encrypted BLOB    NOT NULL,
                url                TEXT,
                category           TEXT    NOT NULL DEFAULT 'Général',
                notes_encrypted    BLOB,
                created_at         INTEGER NOT NULL,
                updated_at         INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entries_category ON entries(category);
            CREATE INDEX IF NOT EXISTS idx_entries_updated  ON entries(updated_at DESC);
        ")?;

        let sentinel_exists: bool = self.conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('vault_meta') WHERE name = 'sentinel'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap_or(0) > 0;

        if !sentinel_exists {
            self.conn.execute_batch("ALTER TABLE vault_meta ADD COLUMN sentinel BLOB;")?;
        }
        Ok(())
    }

    pub fn save_salt(&self, salt: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO vault_meta (id, salt, version) VALUES (1, ?1, 1)",
            params![salt],
        )?;
        Ok(())
    }

    pub fn load_salt(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT salt FROM vault_meta WHERE id = 1")?;
        Ok(stmt.query_row([], |row| row.get(0)).optional()?)
    }

    pub fn verify_or_init_sentinel(
        &self,
        key: &Zeroizing<[u8; 32]>,
    ) -> Result<bool, StoreError> {
        let existing: Option<Vec<u8>> = {
            let mut stmt = self.conn
                .prepare("SELECT sentinel FROM vault_meta WHERE id = 1")?;
            stmt.query_row([], |row| row.get::<_, Option<Vec<u8>>>(0))
                .optional()?
                .flatten()
        };

        match existing {
            None | Some(ref _empty) if existing.as_ref().map_or(true, |b| b.is_empty()) => {
                let encrypted = encrypt(&**key, SENTINEL_PLAINTEXT)?;
                self.conn.execute(
                    "UPDATE vault_meta SET sentinel = ?1 WHERE id = 1",
                    params![encrypted],
                )?;
                Ok(true)
            }
            Some(blob) => {
                match decrypt(&**key, &blob) {
                    Ok(plain) => Ok(&*plain == SENTINEL_PLAINTEXT),
                    Err(_)    => Ok(false),
                }
            }
        }
    }

    pub fn insert_entry(&self, entry: &VaultEntry) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO entries
             (id, title, username, password_encrypted, url, category,
              notes_encrypted, created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![
                entry.id, entry.title, entry.username,
                entry.password_encrypted, entry.url, entry.category,
                entry.notes_encrypted, entry.created_at, entry.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn update_entry(&self, entry: &VaultEntry) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE entries SET
                title = ?1, username = ?2, password_encrypted = ?3,
                url = ?4, category = ?5, notes_encrypted = ?6, updated_at = ?7
             WHERE id = ?8",
            params![
                entry.title, entry.username, entry.password_encrypted,
                entry.url, entry.category, entry.notes_encrypted,
                entry.updated_at, entry.id,
            ],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(entry.id.clone()));
        }
        Ok(())
    }

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

    /// Re-chiffre toutes les entrées avec un nouveau mot de passe maître.
    pub fn change_master_password(
        &self,
        old_key: &Zeroizing<[u8; 32]>,
        new_password: &[u8],
    ) -> Result<(), StoreError> {
        // Générer nouveau sel + dériver nouvelle clé
        let new_salt = kdf::generate_salt();
        let new_master = kdf::derive_master_key(new_password, &new_salt)
            .map_err(|e| StoreError::Kdf(e.to_string()))?;
        let new_key = new_master.0;

        // Re-chiffrer toutes les entrées
        let entries = self.list_entries()?;
        for entry in &entries {
            let plain_pw = decrypt(&**old_key, &entry.password_encrypted)
                .map_err(StoreError::Cipher)?;
            let new_pw_enc = encrypt(&*new_key, &plain_pw)?;

            let new_notes_enc = match &entry.notes_encrypted {
                Some(enc) => {
                    let plain = decrypt(&**old_key, enc).map_err(StoreError::Cipher)?;
                    Some(encrypt(&*new_key, &plain)?)
                }
                None => None,
            };

            self.conn.execute(
                "UPDATE entries SET password_encrypted = ?1, notes_encrypted = ?2 WHERE id = ?3",
                params![new_pw_enc, new_notes_enc, entry.id],
            )?;
        }

        // Nouveau sel + nouvelle sentinelle
        let new_sentinel = encrypt(&*new_key, SENTINEL_PLAINTEXT)?;
        self.conn.execute(
            "UPDATE vault_meta SET salt = ?1, sentinel = ?2 WHERE id = 1",
            params![new_salt.as_ref(), new_sentinel],
        )?;

        Ok(())
    }
}
