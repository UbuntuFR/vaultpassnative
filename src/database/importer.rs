//! Import depuis Bitwarden (JSON export) et CSV générique.
//!
//! Usage :
//!   let entries = importer::from_bitwarden_json(path, &key)?;
//!   let entries = importer::from_csv(path, &key)?;
//!   for e in entries { store.insert_entry(&e)?; }

use std::path::Path;
use zeroize::Zeroizing;
use serde::Deserialize;

use crate::database::models::{EntryId, VaultEntry};
use crate::database::custom_fields::{EntrySecrets, CustomField, FieldKind};
use crate::crypto::cipher;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("Lecture fichier : {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON invalide : {0}")]
    Json(#[from] serde_json::Error),
    #[error("CSV invalide : {0}")]
    Csv(String),
    #[error("Chiffrement : {0}")]
    Cipher(#[from] crate::crypto::cipher::CipherError),
    #[error("Format non reconnu")]
    UnknownFormat,
}

// ── Bitwarden ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct BwExport {
    items: Vec<BwItem>,
}

#[derive(Debug, Deserialize)]
struct BwItem {
    name:     String,
    #[serde(rename = "type")]
    kind:     u8,          // 1=login, 2=note, 3=card, 4=identity
    login:    Option<BwLogin>,
    card:     Option<BwCard>,
    notes:    Option<String>,
    #[serde(rename = "fields")]
    fields:   Option<Vec<BwField>>,
    #[serde(rename = "folderId")]
    folder_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwLogin {
    username: Option<String>,
    password: Option<String>,
    uris:     Option<Vec<BwUri>>,
}

#[derive(Debug, Deserialize)]
struct BwUri {
    uri: Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwCard {
    #[serde(rename = "cardholderName")]
    cardholder_name: Option<String>,
    number:          Option<String>,
    #[serde(rename = "expMonth")]
    exp_month:       Option<String>,
    #[serde(rename = "expYear")]
    exp_year:        Option<String>,
    code:            Option<String>,
}

#[derive(Debug, Deserialize)]
struct BwField {
    name:  Option<String>,
    value: Option<String>,
}

pub fn from_bitwarden_json(
    path: &Path,
    key:  &Zeroizing<[u8; 32]>,
) -> Result<Vec<VaultEntry>, ImportError> {
    let raw: BwExport = serde_json::from_str(&std::fs::read_to_string(path)?)?;
    let now = now_ts();
    let mut out = Vec::new();

    for item in raw.items {
        let (username, password, url, category) = match item.kind {
            1 => {
                // Login
                let login    = item.login.as_ref();
                let username = login.and_then(|l| l.username.clone()).unwrap_or_default();
                let password = login.and_then(|l| l.password.clone()).unwrap_or_default();
                let url      = login.and_then(|l| l.uris.as_ref())
                                    .and_then(|u| u.first())
                                    .and_then(|u| u.uri.clone());
                let cat = if item.folder_id.is_some() { "Importé".to_string() }
                          else { "Général".to_string() };
                (username, password, url, cat)
            }
            3 => {
                // Carte bancaire
                let card     = item.card.as_ref();
                let username = card.and_then(|c| c.cardholder_name.clone()).unwrap_or_default();
                let password = card.and_then(|c| c.number.clone()).unwrap_or_default();
                (username, password, None, "Finance".to_string())
            }
            _ => {
                // Note sécurisée / identité — import comme entrée texte sans mdp
                ("".to_string(), "".to_string(), None, "Importé".to_string())
            }
        };

        // Construire EntrySecrets (notes + champs custom)
        let mut secrets = EntrySecrets {
            notes:  item.notes.unwrap_or_default(),
            fields: Vec::new(),
        };

        // Champs Bitwarden → CustomField
        if let Some(bw_fields) = item.fields {
            for f in bw_fields {
                let label = f.name.unwrap_or_else(|| "Champ".to_string());
                let value = f.value.unwrap_or_default();
                secrets.fields.push(CustomField::new(FieldKind::Text, label, value));
            }
        }

        // Carte : ajouter expiration + CVV comme champs
        if item.kind == 3 {
            if let Some(card) = &item.card {
                if let (Some(m), Some(y)) = (&card.exp_month, &card.exp_year) {
                    secrets.fields.push(CustomField::new(
                        FieldKind::Text, "Expiration", format!("{}/{}", m, y)
                    ));
                }
                if let Some(cvv) = &card.code {
                    secrets.fields.push(CustomField::new(
                        FieldKind::Password, "CVV", cvv.clone()
                    ));
                }
            }
        }

        let pw_enc       = cipher::encrypt(&**key, password.as_bytes())?;
        let secrets_json = secrets.to_json().map_err(ImportError::Json)?;
        let empty_secrets: &[u8] = br#"{"notes":"","fields":[]}"#;
        let notes_enc    = if secrets_json.as_slice() != empty_secrets {
            Some(cipher::encrypt(&**key, &secrets_json)?)
        } else {
            None
        };

        out.push(VaultEntry {
            id:                 EntryId::new(),
            title:              item.name,
            username,
            password_encrypted: pw_enc,
            url,
            category,
            notes_encrypted:    notes_enc,
            created_at:         now,
            updated_at:         now,
        });
    }

    Ok(out)
}

// ── CSV générique ─────────────────────────────────────────────────────────────
// Colonnes attendues (insensibles à la casse) :
//   name/title, username/login/email, password, url/website, notes, category/folder

pub fn from_csv(
    path: &Path,
    key:  &Zeroizing<[u8; 32]>,
) -> Result<Vec<VaultEntry>, ImportError> {
    let content = std::fs::read_to_string(path)?;
    let mut lines = content.lines();

    let header_line = lines.next().ok_or(ImportError::UnknownFormat)?;
    let headers: Vec<String> = split_csv_line(header_line)
        .iter().map(|s| s.to_lowercase().trim().to_string()).collect();

    let col = |names: &[&str]| -> Option<usize> {
        names.iter().find_map(|n| headers.iter().position(|h| h == n))
    };

    let idx_title    = col(&["name","title"]).ok_or(ImportError::UnknownFormat)?;
    let idx_username = col(&["username","login","email"]);
    let idx_password = col(&["password","pwd","pass"]);
    let idx_url      = col(&["url","website","uri"]);
    let idx_notes    = col(&["notes","note","comment"]);
    let idx_category = col(&["category","folder","group","type"]);

    let now = now_ts();
    let mut out = Vec::new();

    for (lineno, line) in lines.enumerate() {
        if line.trim().is_empty() { continue; }
        let cols = split_csv_line(line);

        let get = |idx: Option<usize>| -> String {
            idx.and_then(|i| cols.get(i)).cloned().unwrap_or_default()
        };

        let title    = get(Some(idx_title));
        let username = get(idx_username);
        let password = get(idx_password);
        let url_s    = get(idx_url);
        let notes_s  = get(idx_notes);
        let category = {
            let c = get(idx_category);
            if c.is_empty() { "Importé".to_string() } else { c }
        };

        if title.is_empty() {
            eprintln!("CSV ligne {} : titre vide, ignorée", lineno + 2);
            continue;
        }

        let pw_enc  = cipher::encrypt(&**key, password.as_bytes())
            .map_err(|e| ImportError::Csv(format!("ligne {}: {}", lineno+2, e)))?;

        let notes_enc = if !notes_s.is_empty() {
            let s = EntrySecrets { notes: notes_s, fields: Vec::new() };
            let j = s.to_json().map_err(ImportError::Json)?;
            Some(cipher::encrypt(&**key, &j)
                .map_err(|e| ImportError::Csv(format!("ligne {}: {}", lineno+2, e)))?)
        } else {
            None
        };

        out.push(VaultEntry {
            id:                 EntryId::new(),
            title,
            username,
            password_encrypted: pw_enc,
            url:                if url_s.is_empty() { None } else { Some(url_s) },
            category,
            notes_encrypted:    notes_enc,
            created_at:         now,
            updated_at:         now,
        });
    }

    Ok(out)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn now_ts() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

/// Parse une ligne CSV en respectant les guillemets.
fn split_csv_line(line: &str) -> Vec<String> {
    let mut fields    = Vec::new();
    let mut current   = String::new();
    let mut in_quotes = false;
    let mut chars     = line.chars().peekable();

    while let Some(c) = chars.next() {
        match c {
            '"' => {
                // guillemet doublé "" → un seul "
                if in_quotes && chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = !in_quotes;
                }
            }
            ',' if !in_quotes => {
                fields.push(current.trim().to_string());
                current = String::new();
            }
            other => current.push(other),
        }
    }
    fields.push(current.trim().to_string());
    fields
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_csv_simple() {
        let r = split_csv_line("title,username,password,url");
        assert_eq!(r, vec!["title","username","password","url"]);
    }

    #[test]
    fn test_split_csv_quoted() {
        let r = split_csv_line(r#""My Site","user@example.com","p,a,ss","https://x.com""#);
        assert_eq!(r[0], "My Site");
        assert_eq!(r[2], "p,a,ss");
    }

    #[test]
    fn test_split_csv_empty_fields() {
        let r = split_csv_line("title,,password,,");
        assert_eq!(r.len(), 5);
        assert_eq!(r[1], "");
    }

    #[test]
    fn test_bitwarden_json_empty() {
        use crate::crypto::kdf;
        let salt = kdf::generate_salt();
        let key  = kdf::derive_master_key(b"test", &salt).unwrap().0;
        // JSON Bitwarden minimal valide
        let json = r#"{"encrypted":false,"items":[]}"#;
        let tmp  = std::env::temp_dir().join("bw_test_empty.json");
        std::fs::write(&tmp, json).unwrap();
        let entries = from_bitwarden_json(&tmp, &key).unwrap();
        assert!(entries.is_empty());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_bitwarden_json_login() {
        use crate::crypto::{kdf, cipher};
        let salt = kdf::generate_salt();
        let key  = kdf::derive_master_key(b"test", &salt).unwrap().0;
        let json = r#"{
            "encrypted": false,
            "items": [{
                "id": "abc",
                "type": 1,
                "name": "GitHub",
                "notes": null,
                "login": {
                    "username": "bob",
                    "password": "s3cr3t",
                    "uris": [{"uri": "https://github.com"}]
                }
            }]
        }"#;
        let tmp = std::env::temp_dir().join("bw_test_login.json");
        std::fs::write(&tmp, json).unwrap();
        let entries = from_bitwarden_json(&tmp, &key).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        assert_eq!(entries[0].username, "bob");
        let plain = cipher::decrypt(&*key, &entries[0].password_encrypted).unwrap();
        assert_eq!(&*plain, b"s3cr3t");
        assert_eq!(entries[0].url.as_deref(), Some("https://github.com"));
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_csv_import() {
        use crate::crypto::{kdf, cipher};
        let salt = kdf::generate_salt();
        let key  = kdf::derive_master_key(b"test", &salt).unwrap().0;
        let csv  = "name,username,password,url,notes
GitHub,bob,s3cr3t,https://github.com,ma note
";
        let tmp  = std::env::temp_dir().join("test_import.csv");
        std::fs::write(&tmp, csv).unwrap();
        let entries = from_csv(&tmp, &key).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].title, "GitHub");
        let plain = cipher::decrypt(&*key, &entries[0].password_encrypted).unwrap();
        assert_eq!(&*plain, b"s3cr3t");
        assert!(entries[0].notes_encrypted.is_some());
        std::fs::remove_file(&tmp).ok();
    }

    #[test]
    fn test_csv_quoted_comma() {
        use crate::crypto::kdf;
        let salt = kdf::generate_salt();
        let key  = kdf::derive_master_key(b"test", &salt).unwrap().0;
        let csv  = "name,username,password\n\"Site, Pro\",alice,pwd123\n";
        let tmp  = std::env::temp_dir().join("test_import_quoted.csv");
        std::fs::write(&tmp, csv).unwrap();
        let entries = from_csv(&tmp, &key).unwrap();
        assert_eq!(entries[0].title, "Site, Pro");
        std::fs::remove_file(&tmp).ok();
    }
}
