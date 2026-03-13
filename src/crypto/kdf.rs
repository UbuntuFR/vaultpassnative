use argon2::{Argon2, Algorithm, Version, Params};
use zeroize::Zeroizing;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KdfError {
    #[error("Paramètres Argon2 invalides : {0}")]
    InvalidParams(String),
    #[error("Échec de dérivation : {0}")]
    DerivationFailed(String),
}

// 🦀 CONCEPT — newtype pattern :
// MasterKey n'est PAS un simple Vec<u8>.
// Le type distinct empêche de passer accidentellement
// n'importe quel Vec<u8> là où une clé maître est attendue.
// Zeroizing efface la RAM au Drop automatiquement.
pub struct MasterKey(pub Zeroizing<Vec<u8>>);

/// Dérive une clé 256-bit depuis le mot de passe maître via Argon2id.
/// Paramètres OWASP 2024 : 64MB RAM, 3 itérations, 4 threads.
pub fn derive_master_key(
    password: &[u8],
    salt: &[u8; 32],
) -> Result<MasterKey, KdfError> {
    // 🦀 CONCEPT — Result + ? :
    // map_err convertit l'erreur de type argon2 vers notre KdfError.
    // Si ça échoue, la fonction retourne Err(...) immédiatement.
    let params = Params::new(64 * 1024, 3, 4, Some(32))
        .map_err(|e| KdfError::InvalidParams(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key_bytes = Zeroizing::new(vec![0u8; 32]);

    argon2
        .hash_password_into(password, salt, &mut key_bytes)
        .map_err(|e| KdfError::DerivationFailed(e.to_string()))?;

    Ok(MasterKey(key_bytes))
}

/// Génère un sel aléatoire cryptographiquement sûr (32 bytes).
pub fn generate_salt() -> [u8; 32] {
    use rand::RngCore;
    let mut salt = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_deterministic() {
        let salt = [7u8; 32];
        let k1 = derive_master_key(b"password", &salt).unwrap();
        let k2 = derive_master_key(b"password", &salt).unwrap();
        assert_eq!(*k1.0, *k2.0);
    }

    #[test]
    fn test_derive_different_passwords() {
        let salt = [0u8; 32];
        let k1 = derive_master_key(b"password1", &salt).unwrap();
        let k2 = derive_master_key(b"password2", &salt).unwrap();
        assert_ne!(*k1.0, *k2.0);
    }

    #[test]
    fn test_derive_different_salts() {
        let k1 = derive_master_key(b"password", &[1u8; 32]).unwrap();
        let k2 = derive_master_key(b"password", &[2u8; 32]).unwrap();
        assert_ne!(*k1.0, *k2.0);
    }
}
