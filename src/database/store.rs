use rusqlite::{Connection, Result as SqlResult, params, OptionalExtension};
use thiserror::Error;
use zeroize::Zeroizing;
use std::path::{Path, PathBuf};
use std::fs;
use crate::database::models::{VaultEntry, EntryId};
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
    #[error("Erreur I/O : {0}")]
    Io(#[from] std::io::Error),
    #[error("Base de données verrouillée par une autre instance de VaultPass")]
    AlreadyLocked,
}

pub struct VaultStore {
    conn:       Connection,
    db_path:    Option<PathBuf>,
    _lock_file: Option<fs::File>,
}

impl VaultStore {
    pub fn open(path: &str) -> Result<Self, StoreError> {
        let db_path   = PathBuf::from(path);
        let lock_path = db_path.with_extension("lock");
        let lock_file = acquire_lock(&lock_path)?;
        let conn = Connection::open(&db_path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
        let mut store = VaultStore { conn, db_path: Some(db_path), _lock_file: Some(lock_file) };
        store.migrate()?;
        Ok(store)
    }

    #[cfg(test)]
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let conn = Connection::open_in_memory()?;
        let mut store = VaultStore { conn, db_path: None, _lock_file: None };
        store.migrate()?;
        Ok(store)
    }

    fn migrate(&mut self) -> Result<(), StoreError> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS vault_meta (
                id       INTEGER PRIMARY KEY,
                salt     BLOB    NOT NULL,
                sentinel BLOB,
                version  INTEGER NOT NULL DEFAULT 2
            );
            CREATE TABLE IF NOT EXISTS entries (
                id                 TEXT    PRIMARY KEY,
                title              TEXT    NOT NULL,
                username           TEXT    NOT NULL,
                password_encrypted BLOB    NOT NULL,
                url                TEXT,
                category           TEXT    NOT NULL DEFAULT 'Général',
                notes_encrypted    BLOB,
                is_favorite        INTEGER NOT NULL DEFAULT 0,
                created_at         INTEGER NOT NULL,
                updated_at         INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_entries_category  ON entries(category);
            CREATE INDEX IF NOT EXISTS idx_entries_updated   ON entries(updated_at DESC);
            CREATE INDEX IF NOT EXISTS idx_entries_favorite  ON entries(is_favorite);
        ")?;

        // Migration sentinel (bases v1)
        let sentinel_exists: bool = self.conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('vault_meta') WHERE name='sentinel'",
                [], |row| row.get::<_, i64>(0),
            ).unwrap_or(0) > 0;
        if !sentinel_exists {
            self.conn.execute_batch("ALTER TABLE vault_meta ADD COLUMN sentinel BLOB;")?;
        }

        // Migration notepad (bases v2)
        let notepad_exists: bool = self.conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('vault_meta') WHERE name='notepad'",
                [], |row| row.get::<_, i64>(0),
            ).unwrap_or(0) > 0;
        if !notepad_exists {
            self.conn.execute_batch("ALTER TABLE vault_meta ADD COLUMN notepad BLOB;")?;
        }

        // Migration is_favorite (bases v3)
        let fav_exists: bool = self.conn
            .query_row(
                "SELECT COUNT(*) FROM pragma_table_info('entries') WHERE name='is_favorite'",
                [], |row| row.get::<_, i64>(0),
            ).unwrap_or(0) > 0;
        if !fav_exists {
            self.conn.execute_batch(
                "ALTER TABLE entries ADD COLUMN is_favorite INTEGER NOT NULL DEFAULT 0;"
            )?;
        }

        Ok(())
    }

    // ---- Sel ----

    pub fn save_salt(&self, salt: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT OR IGNORE INTO vault_meta (id, salt, version) VALUES (1, ?1, 2)",
            params![salt],
        )?;
        Ok(())
    }

    pub fn load_salt(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT salt FROM vault_meta WHERE id=1")?;
        Ok(stmt.query_row([], |row| row.get(0)).optional()?)
    }

    // ---- Sentinel ----

    pub fn verify_or_init_sentinel(
        &self,
        key: &Zeroizing<[u8; 32]>,
    ) -> Result<bool, StoreError> {
        let existing: Option<Vec<u8>> = {
            let mut stmt = self.conn.prepare("SELECT sentinel FROM vault_meta WHERE id=1")?;
            stmt.query_row([], |row| row.get::<_, Option<Vec<u8>>>(0))
                .optional()?.flatten()
        };
        match existing {
            None => {
                let enc = encrypt(key, SENTINEL_PLAINTEXT)?;
                self.conn.execute("UPDATE vault_meta SET sentinel=?1 WHERE id=1", params![enc])?;
                Ok(true)
            }
            Some(blob) => Ok(
                decrypt(key, &blob)
                    .map(|p| p.as_slice() == SENTINEL_PLAINTEXT)
                    .unwrap_or(false)
            ),
        }
    }

    // ---- CRUD ----

    pub fn insert_entry(&self, entry: &VaultEntry) -> Result<(), StoreError> {
        self.conn.execute(
            "INSERT INTO entries
             (id,title,username,password_encrypted,url,category,notes_encrypted,is_favorite,created_at,updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                entry.id, entry.title, entry.username,
                entry.password_encrypted, entry.url, entry.category,
                entry.notes_encrypted, entry.is_favorite as i64,
                entry.created_at, entry.updated_at,
            ],
        )?;
        Ok(())
    }

    pub fn update_entry(&self, entry: &VaultEntry) -> Result<(), StoreError> {
        let rows = self.conn.execute(
            "UPDATE entries SET
                title=?1, username=?2, password_encrypted=?3,
                url=?4, category=?5, notes_encrypted=?6,
                is_favorite=?7, updated_at=?8
             WHERE id=?9",
            params![
                entry.title, entry.username, entry.password_encrypted,
                entry.url, entry.category, entry.notes_encrypted,
                entry.is_favorite as i64, entry.updated_at, entry.id,
            ],
        )?;
        if rows == 0 { return Err(StoreError::NotFound(entry.id.to_string())); }
        Ok(())
    }

    pub fn list_entries(&self) -> Result<Vec<VaultEntry>, StoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id,title,username,password_encrypted,url,
                    category,notes_encrypted,is_favorite,created_at,updated_at
             FROM entries ORDER BY updated_at DESC"
        )?;
        let entries = stmt.query_map([], |row| {
            Ok(VaultEntry {
                id:                 EntryId(row.get(0)?),
                title:              row.get(1)?,
                username:           row.get(2)?,
                password_encrypted: row.get(3)?,
                url:                row.get(4)?,
                category:           row.get(5)?,
                notes_encrypted:    row.get(6)?,
                is_favorite:        row.get::<_, i64>(7)? != 0,
                created_at:         row.get(8)?,
                updated_at:         row.get(9)?,
            })
        })?.collect::<SqlResult<Vec<_>>>()?;
        Ok(entries)
    }

    pub fn delete_entry(&self, id: &EntryId) -> Result<(), StoreError> {
        let rows = self.conn.execute("DELETE FROM entries WHERE id=?1", params![id])?;
        if rows == 0 { return Err(StoreError::NotFound(id.to_string())); }
        Ok(())
    }

    /// Bascule le favori d'une entrée.
    pub fn toggle_favorite(&self, id: &EntryId) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE entries SET is_favorite = CASE WHEN is_favorite=1 THEN 0 ELSE 1 END WHERE id=?1",
            params![id],
        )?;
        Ok(())
    }

    // ---- Changement de mot de passe (atomique + backup) ----

    pub fn change_master_password(
        &self,
        old_key:      &Zeroizing<[u8; 32]>,
        new_password: &[u8],
    ) -> Result<(), StoreError> {
        if let Some(ref db_path) = self.db_path {
            let bak = db_path.with_extension("db.bak");
            fs::copy(db_path, &bak)?;
        }
        let new_salt   = kdf::generate_salt();
        let new_master = kdf::derive_master_key(new_password, &new_salt)
            .map_err(|e| StoreError::Kdf(e.to_string()))?;
        let new_key = new_master.0;
        let entries = self.list_entries()?;
        let tx = self.conn.unchecked_transaction()?;
        for e in &entries {
            let plain_pw   = decrypt(old_key, &e.password_encrypted).map_err(StoreError::Cipher)?;
            let new_pw_enc = encrypt(&new_key, &plain_pw)?;
            let new_notes_enc = match &e.notes_encrypted {
                Some(enc) => Some(encrypt(&new_key, &decrypt(old_key, enc).map_err(StoreError::Cipher)?)?),
                None      => None,
            };
            tx.execute(
                "UPDATE entries SET password_encrypted=?1, notes_encrypted=?2 WHERE id=?3",
                params![new_pw_enc, new_notes_enc, e.id],
            )?;
        }
        let new_sentinel = encrypt(&new_key, SENTINEL_PLAINTEXT)?;
        tx.execute(
            "UPDATE vault_meta SET salt=?1, sentinel=?2 WHERE id=1",
            params![new_salt.as_ref(), new_sentinel],
        )?;
        tx.commit()?;
        Ok(())
    }

    // ---- Bloc-notes chiffré ----

    pub fn save_notepad(&self, enc: &[u8]) -> Result<(), StoreError> {
        self.conn.execute(
            "UPDATE vault_meta SET notepad=?1 WHERE id=1",
            rusqlite::params![enc],
        )?;
        Ok(())
    }

    pub fn load_notepad(&self) -> Result<Option<Vec<u8>>, StoreError> {
        let mut stmt = self.conn.prepare("SELECT notepad FROM vault_meta WHERE id=1")?;
        Ok(stmt.query_row([], |row| row.get::<_, Option<Vec<u8>>>(0))
            .optional()?
            .flatten())
    }

    pub fn db_path(&self) -> Option<&Path> {
        self.db_path.as_deref()
    }
}

// ---- Lock fichier exclusif (Unix flock) ----

#[cfg(unix)]
fn acquire_lock(path: &Path) -> Result<fs::File, StoreError> {
    use std::os::unix::io::AsRawFd;
    let file = fs::OpenOptions::new().create(true).truncate(true).write(true).open(path)?;
    let ret  = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret != 0 { return Err(StoreError::AlreadyLocked); }
    Ok(file)
}

#[cfg(not(unix))]
fn acquire_lock(path: &Path) -> Result<fs::File, StoreError> {
    Ok(fs::OpenOptions::new().create(true).truncate(true).write(true).open(path)?)
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{cipher, kdf};

    fn make_key() -> Zeroizing<[u8; 32]> {
        kdf::derive_master_key(b"test_password", &kdf::generate_salt()).unwrap().0
    }

    fn make_entry(key: &Zeroizing<[u8; 32]>) -> VaultEntry {
        VaultEntry {
            id:                 EntryId::new(),
            title:              "GitHub".to_string(),
            username:           "user@example.com".to_string(),
            password_encrypted: cipher::encrypt(&*key, b"secret123").unwrap(),
            url:                Some("https://github.com".to_string()),
            category:           "Pro".to_string(),
            notes_encrypted:    None,
            is_favorite:        false,
            created_at:         1_700_000_000,
            updated_at:         1_700_000_000,
        }
    }

    #[test]
    fn test_insert_and_list() {
        let store = VaultStore::open_in_memory().unwrap();
        let key   = make_key();
        store.insert_entry(&make_entry(&key)).unwrap();
        let list  = store.list_entries().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].title, "GitHub");
    }

    #[test]
    fn test_update_entry() {
        let store     = VaultStore::open_in_memory().unwrap();
        let key       = make_key();
        let mut entry = make_entry(&key);
        store.insert_entry(&entry).unwrap();
        entry.title = "GitLab".to_string();
        store.update_entry(&entry).unwrap();
        assert_eq!(store.list_entries().unwrap()[0].title, "GitLab");
    }

    #[test]
    fn test_delete_entry() {
        let store = VaultStore::open_in_memory().unwrap();
        let key   = make_key();
        let entry = make_entry(&key);
        let id    = entry.id.clone();
        store.insert_entry(&entry).unwrap();
        store.delete_entry(&id).unwrap();
        assert!(store.list_entries().unwrap().is_empty());
    }

    #[test]
    fn test_delete_nonexistent_returns_error() {
        let store = VaultStore::open_in_memory().unwrap();
        let fake  = EntryId("00000000-0000-0000-0000-000000000000".to_string());
        assert!(matches!(store.delete_entry(&fake), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn test_update_nonexistent_returns_error() {
        let store = VaultStore::open_in_memory().unwrap();
        let key   = make_key();
        assert!(matches!(store.update_entry(&make_entry(&key)), Err(StoreError::NotFound(_))));
    }

    #[test]
    fn test_salt_save_and_load() {
        let store = VaultStore::open_in_memory().unwrap();
        let salt  = kdf::generate_salt();
        store.save_salt(&salt).unwrap();
        assert_eq!(store.load_salt().unwrap().unwrap(), salt.as_ref());
    }

    #[test]
    fn test_sentinel_init_and_verify() {
        let store = VaultStore::open_in_memory().unwrap();
        let salt  = kdf::generate_salt();
        let key   = kdf::derive_master_key(b"master", &salt).unwrap().0;
        store.save_salt(&salt).unwrap();
        assert!(store.verify_or_init_sentinel(&key).unwrap());
        assert!(store.verify_or_init_sentinel(&key).unwrap());
    }

    #[test]
    fn test_sentinel_wrong_key_fails() {
        let store = VaultStore::open_in_memory().unwrap();
        let salt  = kdf::generate_salt();
        let key1  = kdf::derive_master_key(b"correct", &salt).unwrap().0;
        let key2  = kdf::derive_master_key(b"wrong",   &salt).unwrap().0;
        store.save_salt(&salt).unwrap();
        store.verify_or_init_sentinel(&key1).unwrap();
        assert!(!store.verify_or_init_sentinel(&key2).unwrap());
    }

    #[test]
    fn test_change_master_password() {
        let store = VaultStore::open_in_memory().unwrap();
        let salt  = kdf::generate_salt();
        let key   = kdf::derive_master_key(b"old_pass", &salt).unwrap().0;
        store.save_salt(&salt).unwrap();
        store.verify_or_init_sentinel(&key).unwrap();
        store.insert_entry(&make_entry(&key)).unwrap();
        store.change_master_password(&key, b"new_pass").unwrap();
        let new_salt: [u8; 32] = store.load_salt().unwrap().unwrap().try_into().unwrap();
        let new_key = kdf::derive_master_key(b"new_pass", &new_salt).unwrap().0;
        assert!(store.verify_or_init_sentinel(&new_key).unwrap());
        let entries = store.list_entries().unwrap();
        let plain   = cipher::decrypt(&*new_key, &entries[0].password_encrypted).unwrap();
        assert_eq!(&*plain, b"secret123");
    }

    #[test]
    fn test_notes_encrypted_roundtrip() {
        let store = VaultStore::open_in_memory().unwrap();
        let key   = make_key();
        let mut e = make_entry(&key);
        e.notes_encrypted = Some(cipher::encrypt(&*key, b"notes secretes").unwrap());
        store.insert_entry(&e).unwrap();
        let list = store.list_entries().unwrap();
        let dec  = cipher::decrypt(&*key, list[0].notes_encrypted.as_ref().unwrap()).unwrap();
        assert_eq!(&*dec, b"notes secretes");
    }

    #[test]
    fn test_change_password_atomicity_in_memory() {
        let store = VaultStore::open_in_memory().unwrap();
        let salt  = kdf::generate_salt();
        let key   = kdf::derive_master_key(b"pass1", &salt).unwrap().0;
        store.save_salt(&salt).unwrap();
        store.verify_or_init_sentinel(&key).unwrap();
        for i in 0..5 {
            let mut e = make_entry(&key);
            e.title = format!("Entry {}", i);
            store.insert_entry(&e).unwrap();
        }
        store.change_master_password(&key, b"pass2").unwrap();
        let new_salt: [u8; 32] = store.load_salt().unwrap().unwrap().try_into().unwrap();
        let new_key = kdf::derive_master_key(b"pass2", &new_salt).unwrap().0;
        assert!(store.verify_or_init_sentinel(&new_key).unwrap());
        let entries = store.list_entries().unwrap();
        assert_eq!(entries.len(), 5);
        for e in &entries {
            let plain = cipher::decrypt(&*new_key, &e.password_encrypted).unwrap();
            assert_eq!(&*plain, b"secret123");
        }
    }

    #[test]
    fn test_notepad_save_and_load() {
        let store = VaultStore::open_in_memory().unwrap();
        let salt  = kdf::generate_salt();
        store.save_salt(&salt).unwrap();
        let enc = b"donnees_chiffrees_fictives".to_vec();
        store.save_notepad(&enc).unwrap();
        let loaded = store.load_notepad().unwrap().unwrap();
        assert_eq!(loaded, enc);
    }

    #[test]
    fn test_toggle_favorite() {
        let store = VaultStore::open_in_memory().unwrap();
        let key   = make_key();
        let entry = make_entry(&key);
        let id    = entry.id.clone();
        store.insert_entry(&entry).unwrap();
        assert!(!store.list_entries().unwrap()[0].is_favorite);
        store.toggle_favorite(&id).unwrap();
        assert!(store.list_entries().unwrap()[0].is_favorite);
        store.toggle_favorite(&id).unwrap();
        assert!(!store.list_entries().unwrap()[0].is_favorite);
    }
}
