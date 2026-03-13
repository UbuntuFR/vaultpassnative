use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use aes_gcm::aead::rand_core::RngCore;
use thiserror::Error;
use zeroize::Zeroizing;

// Taille du nonce AES-GCM : 96 bits = 12 bytes (standard NIST)
const NONCE_SIZE: usize = 12;

#[derive(Error, Debug)]
pub enum CipherError {
    #[error("Chiffrement échoué")]
    EncryptFailed,
    #[error("Déchiffrement échoué — clé incorrecte ou données corrompues")]
    DecryptFailed,
    #[error("Données trop courtes pour contenir un nonce")]
    InvalidData,
}

/// Chiffre du texte clair avec AES-256-GCM.
/// Retourne : [nonce (12 bytes) || ciphertext+tag]
pub fn encrypt(key_bytes: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, CipherError> {
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);

    // Nonce aléatoire unique par chiffrement
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|_| CipherError::EncryptFailed)?;

    // Préfixer le nonce au ciphertext pour le stockage
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Déchiffre des données produites par encrypt().
/// Retourne le plaintext dans un Zeroizing pour effacement automatique.
pub fn decrypt(key_bytes: &[u8; 32], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CipherError> {
    if data.len() < NONCE_SIZE {
        return Err(CipherError::InvalidData);
    }

    // 🦀 CONCEPT — slices &[u8] :
    // data[..12] et data[12..] sont des vues zero-copy sur les données.
    // Aucune copie mémoire, le borrow checker garantit leur validité.
    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| CipherError::DecryptFailed)?;

    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let plaintext = b"mot_de_passe_secret";
        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(&*decrypted, plaintext);
    }

    #[test]
    fn test_decrypt_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let encrypted = encrypt(&key1, b"secret").unwrap();
        assert!(decrypt(&key2, &encrypted).is_err());
    }

    #[test]
    fn test_decrypt_truncated_data_fails() {
        let key = [0u8; 32];
        assert!(decrypt(&key, &[0u8; 5]).is_err());
    }

    #[test]
    fn test_nonce_unique_per_encrypt() {
        let key = [0u8; 32];
        let e1 = encrypt(&key, b"same").unwrap();
        let e2 = encrypt(&key, b"same").unwrap();
        // Deux chiffrements du même texte → nonces différents
        assert_ne!(&e1[..12], &e2[..12]);
    }
}
