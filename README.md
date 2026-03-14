# VaultPass Native

[![CI](https://github.com/UbuntuFR/vaultpassnative/actions/workflows/ci.yml/badge.svg)](https://github.com/UbuntuFR/vaultpassnative/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL%203.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.2.0-green.svg)](Cargo.toml)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20GNOME-red.svg)](https://gnome.org)

Un gestionnaire de mots de passe natif pour GNOME, développé en Rust avec GTK4 et Libadwaita.

## Fonctionnalités

- **Sécurité de niveau professionnel**
  - Chiffrement AES-256-GCM (standard NIST)
  - Dérivation de clé Argon2id (recommandé OWASP 2024)
  - Verrouillage automatique configurable
  - Clipboard auto-nettoyant (30 secondes)
  - Stockage chiffré de toutes les données sensibles

- **Interface moderne GNOME**
  - Design natif Libadwaita
  - Thèmes multiples (Système, Clair, Sombre, Nord, Catppuccin, Everforest)
  - Support HiDPI
  - Mode hors-ligne complet

- **Fonctionnalités avancées**
  - Générateur de mots de passe sécurisé
  - Catégories personnalisées
  - Champs personnalisés par entrée
  - Bloc-notes chiffré
  - Import Bitwarden JSON / CSV
  - Recherche et filtrage rapide

## Installation

### Depuis les sources

```bash
# Installer les dépendances (Ubuntu/Debian)
sudo apt-get install \
    pkg-config \
    libgtk-4-dev \
    libadwaita-1-dev \
    libsqlite3-dev \
    libssl-dev \
    build-essential

# Compiler
cargo build --release

# Lancer
./target/release/vaultpass-native
```

### Flatpak (à venir)

```bash
flatpak install flathub io.github.UbuntuFR.VaultpassNative
```

## Utilisation

1. **Premier lancement** : Entrez votre mot de passe maître pour créer un nouveau coffre
2. **Déverrouillage** : Entrez votre mot de passe maître à chaque ouverture
3. **Ajouter une entrée** : Cliquez sur le bouton "+" dans la barre latérale
4. **Générer un mot de passe** : Utilisez le bouton "Générateur" ou la fonction dans le formulaire d'ajout
5. **Copier un mot de passe** : Cliquez sur l'icône de copie (auto-effacé après 30s)

## Sécurité

### Architecture de sécurité

| Composant | Algorithme | Norme |
|-----------|------------|-------|
| Chiffrement | AES-256-GCM | NIST SP 800-38D |
| Dérivation de clé | Argon2id | OWASP 2024 |
| Génération aléatoire | OsRng | RFC 4086 |

### Bonnes pratiques

- Utilisez un mot de passe maître long (16+ caractères)
- Activez le verrouillage automatique
- Ne partagez jamais votre mot de passe maître
- Utilisez le générateur pour des mots de passe uniques

## Contribution

Les contributions sont les bienvenues ! Veuillez lire [CONTRIBUTING.md](CONTRIBUTING.md) pour commencer.

### Développement

```bash
# Installer Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Installer les dépendances de développement
sudo apt-get install libgtk-4-dev libadwaita-1-dev

# Lancer les tests
cargo test

# Lancer avec logs de débogage
RUST_LOG=debug cargo run
```

## License

Ce projet est sous license GNU Affero General Public License v3.0 - voir [LICENSE](LICENSE) pour plus de détails.

## Remerciements

- [GNOME](https://gnome.org) pour GTK4 et Libadwaita
- [Rust](https://rust-lang.org) pour le langage de programmation
- [LibrePassword](https://github.com) pour l'inspiration

---

*Développé avec ❤️ par la communauté UbuntuFR*
