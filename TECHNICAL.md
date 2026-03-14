# Documentation Technique - VaultPass Native

## Architecture du Projet

VaultPass Native est un gestionnaire de mots de passe sécurisé construit avec Rust et GTK4/Libadwaita pour l'environnement de bureau GNOME.

### Structure des Modules

```
vaultpassnative/
├── src/
│   ├── main.rs              # Point d'entrée de l'application
│   ├── crypto/              # Module de chiffrement
│   │   ├── mod.rs
│   │   ├── aes.rs          # Chiffrement AES-256-GCM
│   │   ├── argon2.rs        # Dérivation de clé Argon2id
│   │   └── error.rs        # Gestion des erreurs cryptographiques
│   ├── database/           # Module base de données
│   │   ├── mod.rs
│   │   ├── schema.rs       # Schéma de la base SQLite
│   │   └── vault.rs        # Opérations du coffre-fort
│   └── ui/                 # Interface utilisateur GTK4
│       ├── mod.rs
│       ├── autolock.rs     # Verrouillage automatique
│       ├── theme.rs        # Gestion du thème
│       ├── notepad.rs      # Notes chiffrées
│       ├── generator.rs    # Générateur de mots de passe
│       └── dialogs.rs      # Dialogues GTK
├── data/                   # Ressources graphiques
├── po/                     # Fichiers de traduction
└── .github/
    └── workflows/          # CI/CD GitHub Actions
```

## Implémentation Cryptographique

### Chiffrement AES-256-GCM

Le projet utilise AES-256-GCM (Galois/Counter Mode) pour le chiffrement symétrique :

- **256 bits** : Taille de clé conforme à la norme NIST
- **GCM** : Mode authentifié garantissant confidentialité et intégrité
- **Nonce unique** : Chaque opération de chiffrement génère un nouveau nonce

```rust
// Exemple d'utilisation (src/crypto/aes.rs)
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};

pub fn encrypt(plaintext: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Result<Vec<u8>, CryptoError> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|_| CryptoError::KeyGeneration)?;
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext)
        .map_err(|_| CryptoError::Encryption)
}
```

### Dérivation de Clé Argon2id

Le mot de passe maître est dérivé en clé de chiffrement utilisant Argon2id (recommander OWASP 2024) :

- **Mode id** : Combine Argon2d et Argon2i pour résistance aux attaques GPU et timing
- **Paramètres** : m=65536 (64 MiB), t=3 iterations, p=4 parallelism
- **Sel** : 32 octets aléatoires générés par OsRng (CSPRNG)

```rust
// Exemple d'utilisation (src/crypto/argon2.rs)
use argon2::{
    password_hash::{PasswordHasher, SaltString},
    Argon2,
};

pub fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32], CryptoError> {
    let salt = SaltString::encode_b64(salt)
        .map_err(|_| CryptoError::KeyDerivation)?;
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .map_err(|_| CryptoError::KeyDerivation)?;
    // Extraire les 32 premiers octets du hash
    Ok(hash.hash.unwrap().as_bytes()[..32].try_into().unwrap())
}
```

### Gestion Sécurisée de la Mémoire

Le projet utilise la crate `zeroize` pour effacer les données sensibles de la mémoire :

```rust
use zeroize::Zeroize;

pub struct SecureBuffer {
    data: Vec<u8>,
}

impl Drop for SecureBuffer {
    fn drop(&mut self) {
        self.data.zeroize();
    }
}
```

## Base de Données SQLite

### Schéma

```sql
CREATE TABLE vault (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    username TEXT,
    password_encrypted BLOB NOT NULL,
    url TEXT,
    notes TEXT,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE notepad (
    id INTEGER PRIMARY KEY,
    content_encrypted BLOB NOT NULL,
    updated_at INTEGER NOT NULL
);
```

### Opérations

Toutes les opérations de base de données sont effectuées avec des requêtes paramétrées pour prévenir les injections SQL :

```rust
// Exemple (src/database/vault.rs)
pub fn add_entry(vault: &Vault, entry: &VaultEntry) -> Result<i64, DbError> {
    let mut stmt = vault.prepare(
        "INSERT INTO vault (title, username, password_encrypted, url, notes, created_at, updated_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
    )?;
    // Utilisation de rusqlite avec paramètres
    stmt.execute(params![
        entry.title,
        entry.username,
        entry.password,
        entry.url,
        entry.notes,
        entry.created_at,
        entry.updated_at
    ])?;
    Ok(vault.last_insert_rowid())
}
```

## Interface Utilisateur GTK4

### AutoLock

Le système de verrouillage automatique protège l'application contre l'accès non autorisé :

```rust
// Exemple (src/ui/autolock.rs)
pub enum LockDelay {
    OneMin     = 60,
    TwoMin     = 120,
    FiveMin    = 300,
    FifteenMin = 900,
    ThirtyMin  = 1800,
    OneHour    = 3600,
    Never      = -1,  // Sentinelle pour désactivation
}
```

### Générateur de Mots de Passe

Génère des mots de passe sécurisés avec distribution uniforme :

```rust
// Exemple (src/ui/generator.rs)
use rand::rngs::OsRng;
use rand::seq::SliceRandom;

pub fn generate_password(length: usize, options: &GenOptions) -> String {
    let charset: Vec<char> = build_charset(options);
    let mut rng = OsRng;
    let mut password: Vec<char> = (0..length)
        .map(|_| *charset.choose(&mut rng).unwrap())
        .collect();
    // Mélanger pour éviter les biais de position
    password.shuffle(&mut rng);
    password.into_iter().collect()
}
```

### Thème Dynamique

L'application s'adapte au thème système (clair/sombre) :

```rust
// Exemple (src/ui/theme.rs)
fn setup_theme() {
    if let Some(display) = gdk4::Display::default() {
        let provider = gtk4::CssProvider::new();
        provider.load_from_string(include_str!("../style.css"));
        gtk4::style_context_add_provider_for_display(&display, &provider, 400);
    }
}
```

## Tests et Qualité du Code

### Couverture de Tests

Le projet utilise `cargo test` pour les tests unitaires et d'intégration :

```bash
# Exécuter tous les tests
cargo test

# Exécuter avec couverture
cargo tarpaulin --out Html

# Tests de chiffrement spécifiques
cargo test crypto --
```

### Analyse Statique

```bash
# Clippy - Lints Rust
cargo clippy -- -D warnings

# fmt - Formatage du code
cargo fmt --check

# Audits de sécurité
cargo audit
cargo deny check
```

## CI/CD GitHub Actions

### Pipeline de Build

Le workflow automatise :

1. **Vérification** : `cargo check`, `cargo fmt`, `cargo clippy`
2. **Tests** : `cargo test`, `cargo bench` (benchmarks)
3. **Build** : Compilation multi-plateforme (x86_64, aarch64)
4. **Publication** : Artifacts et release automatique

```yaml
# .github/workflows/rust.yml
name: Rust CI
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test
      - run: cargo clippy -- -D warnings
```

## Dépendances Principales

| Crate | Version | Usage |
|-------|---------|-------|
| gtk4 | 0.8 | Interface GNOME |
| libadwaita | 1.4 | Widgets GNOME |
| rusqlite | 0.31 | Base SQLite |
| aes-gcm | 0.10 | Chiffrement |
| argon2 | 0.5 | Dérivation clé |
| zeroize | 1.7 | Mémoire sécurisée |
| rand | 0.8 | Génération aléatoire |

## Contribution

Voir [CONTRIBUTING.md](CONTRIBUTING.md) pour les guidelines de contribution.

## Licence

Ce projet est sous licence AGPL-3.0 - voir [LICENSE](LICENSE) pour plus de détails.
