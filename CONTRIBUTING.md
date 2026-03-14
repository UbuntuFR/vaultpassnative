# Guide de Contribution

Merci de votre intérêt pour VaultPass Native ! Ce guide vous aider à contribuer efficacement au projet.

## Code de Conduite

Veuillez lire notre [Code de Conduite](CODE_OF_CONDUCT.md) avant de participer.

## Comment Contribuer

### Signaler des Bugs

1. **Vérifiez** si le bug n'a pas déjà été signalé
2. **Utilisez** le [template de bug](https://github.com/UbuntuFR/vaultpassnative/issues/new?template=bug_report.md)
3. **Incluez**:
   - Reproduction étape par étape
   - Version du logiciel (cargo run --version)
   - Logs d'erreur (si applicables)
   - Environnement (OS, version GNOME)

### Proposer des Fonctionnalités

1. **Discutez** d'abord de l'idée dans les [Discussions](https://github.com/UbuntuFR/vaultpassnative/discussions)
2. **Utilisez** le [template de feature request](https://github.com/UbuntuFR/vaultpassnative/issues/new?template=feature_request.md)
3. **Expliquez**:
   - Le problème que ça résout
   - Votre solution proposée
   - Alternatives considérées

### Soumettre des Pull Requests

#### Avant de commencer

1. **Forkez** le dépôt
2. **Créez** une branche : `git checkout -b feature/ma-fonctionnalite`
3. **Testez** localement avec `cargo test`

#### Standards de Code

- **Format** : Utilisez `cargo fmt` avant de commit
- **Linter** : Assurez-vous que `cargo clippy` ne signale aucun warning
- **Tests** : Ajoutez des tests pour toute nouvelle fonctionnalité

```bash
# Vérifications avant PR
cargo fmt --all
cargo clippy --all-features -- -D warnings
cargo test --all-features
```

#### Structure du Commit

Utilisez des messages de commit clairs :

```
type(portée): description courte

-Détail 1
-Détail 2

Types:
- fix: correction de bug
- feat: nouvelle fonctionnalité
- docs: documentation
- refactor: refactorisation
- test: ajout de tests
- ci: modifications CI/CD
```

Exemple :
```
fix(autolock): corriger overflow du délai de verrouillage

- Utiliser une valeur sentinelle au lieu de u64::MAX
- Ajouter des méthodes utilitaires pour la conversion
- Mettre à jour les tests
```

#### Processus de Review

1. Le CI doit passer (tests, clippy, format)
2. Au moins une review approuvative requise
3. Répondez aux commentaires de review
4. Squashz vos commits si nécessaire

## Environnement de Développement

### Dépendances

```bash
# Ubuntu/Debian
sudo apt-get install \
    pkg-config \
    libgtk-4-dev \
    libadwaita-1-dev \
    libsqlite3-dev \
    libssl-dev \
    build-essential
```

### Commandes Utiles

```bash
# Développement
cargo run                      # Lancer en mode développement
cargo test                     # Exécuter les tests
cargo test --doc              # Tests de documentation
cargo build --release         # Build optimisé

# Qualité
cargo fmt                     # Formater le code
cargo clippy                  # Analyse statique
cargo audit                   # Audit de sécurité

# Débogage
RUST_LOG=debug cargo run     # Logs détaillés
cargo build --features verbose # Mode verbeux
```

## Ressources

- [Documentation GNOME](https://gtk-rs.org/)
- [Libadwaita API](https://gnome.pages.gitlab.gnome.org/libadwaita/)
- [Rust Book](https://doc.rust-lang.org/book/)

## Questions ?

- **Discussions** : [GitHub Discussions](https://github.com/UbuntuFR/vaultpassnative/discussions)
- **Issues** : [GitHub Issues](https://github.com/UbuntuFR/vaultpassnative/issues)

Merci de contribuer ! 🎉
