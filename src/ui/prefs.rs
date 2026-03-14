//! Préférences persistantes stockées dans ~/.config/vaultpass/prefs.json
use std::path::PathBuf;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Prefs {
    pub sort_ascending:    bool,
    pub active_category:   Option<String>,
    pub theme:             String,
    pub lock_delay_secs:   u64,
}

impl Default for Prefs {
    fn default() -> Self {
        Self {
            sort_ascending:  true,
            active_category: None,
            theme:           "system".to_string(),
            lock_delay_secs: 300,
        }
    }
}

fn prefs_path() -> PathBuf {
    let mut p = gtk4::glib::user_config_dir();
    p.push("vaultpass");
    std::fs::create_dir_all(&p).ok();
    p.push("prefs.json");
    p
}

impl Prefs {
    pub fn load() -> Self {
        let path = prefs_path();
        std::fs::read_to_string(&path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        if let Ok(json) = serde_json::to_string_pretty(self) {
            let _ = std::fs::write(prefs_path(), json);
        }
    }
}
