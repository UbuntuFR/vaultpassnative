use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS:    &[u8] = b"0123456789";
const SYMBOLS:   &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

pub struct GeneratorConfig {
    pub length:    usize,
    pub uppercase: bool,
    pub digits:    bool,
    pub symbols:   bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self { length: 20, uppercase: true, digits: true, symbols: true }
    }
}

impl GeneratorConfig {
    /// Génère un mot de passe aléatoire via OsRng (CSPRNG).
    /// Garantit au moins 1 caractère de chaque classe activée.
    pub fn generate(&self) -> String {
        let mut charset: Vec<u8> = LOWERCASE.to_vec();
        let mut required: Vec<u8> = Vec::new();

        if self.uppercase {
            charset.extend_from_slice(UPPERCASE);
            required.push(Self::pick_one(UPPERCASE));
        }
        if self.digits {
            charset.extend_from_slice(DIGITS);
            required.push(Self::pick_one(DIGITS));
        }
        if self.symbols {
            charset.extend_from_slice(SYMBOLS);
            required.push(Self::pick_one(SYMBOLS));
        }
        required.push(Self::pick_one(LOWERCASE));

        let remaining = self.length.saturating_sub(required.len());
        let mut password: Vec<u8> = (0..remaining)
            .map(|_| charset[Self::rand_index(charset.len())])
            .collect();

        password.extend_from_slice(&required);
        Self::shuffle(&mut password);
        String::from_utf8(password).unwrap_or_default()
    }

    /// Retourne un octet aléatoire issu d'une slice via OsRng.
    fn pick_one(set: &[u8]) -> u8 {
        set[Self::rand_index(set.len())]
    }

    /// Génère un index aléatoire dans [0, len) via OsRng.
    /// Utilise le rejection sampling pour éliminer tout biais de modulo.
    fn rand_index(len: usize) -> usize {
        assert!(len > 0 && len <= u64::MAX as usize);
        // Calcule la limite supérieure sans biais :
        // on rejette les valeurs au-delà du plus grand multiple de len.
        let len64    = len as u64;
        let limit    = u64::MAX - (u64::MAX % len64) - 1;
        let mut buf  = [0u8; 8];
        loop {
            OsRng.fill_bytes(&mut buf);
            let v = u64::from_le_bytes(buf);
            if v <= limit {
                return (v % len64) as usize;
            }
            // Rejet : on tire un nouveau nombre (très rare, < 0.0000000001% par itération)
        }
    }

    /// Fisher-Yates shuffle via OsRng.
    fn shuffle(v: &mut [u8]) {
        let n = v.len();
        // FIX: Use mut n instead of immutable n for iteration
        for i in (1..n).rev() {
            let j = Self::rand_index(i + 1);
            v.swap(i, j);
        }
    }

    /// Calcule un score de force 0-4.
    pub fn strength_score(password: &str) -> u8 {
        let len        = password.len();
        let has_upper  = password.chars().any(|c| c.is_uppercase());
        let has_lower  = password.chars().any(|c| c.is_lowercase());
        let has_digit  = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

        let variety = [has_upper, has_lower, has_digit, has_symbol]
            .iter().filter(|&&x| x).count();

        match (len, variety) {
            (l, _) if l < 8              => 0,
            (l, v) if l < 12 && v < 3   => 1,
            (l, v) if l < 16 && v >= 2  => 2,
            (l, v) if l >= 20 && v == 4 => 4,
            (l, v) if l >= 16 && v >= 3 => 3,
            _                            => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_length_respected() {
        let config = GeneratorConfig { length: 24, ..Default::default() };
        assert_eq!(config.generate().len(), 24);
    }

    #[test]
    fn test_contains_uppercase() {
        let config = GeneratorConfig { length: 32, uppercase: true, digits: false, symbols: false };
        assert!(config.generate().chars().any(|c| c.is_uppercase()));
    }

    #[test]
    fn test_no_symbols_when_disabled() {
        let config = GeneratorConfig { length: 32, uppercase: false, digits: false, symbols: false };
        let pw = config.generate();
        assert!(pw.chars().all(|c| c.is_ascii_lowercase()));
    }

    #[test]
    fn test_strength_short_password() {
        assert_eq!(GeneratorConfig::strength_score("abc"), 0);
    }

    #[test]
    fn test_strength_excellent() {
        assert_eq!(GeneratorConfig::strength_score("AbC123!@#defGHI456xy"), 4);
    }

    #[test]
    fn test_uniqueness() {
        let pw1 = GeneratorConfig::default().generate();
        let pw2 = GeneratorConfig::default().generate();
        assert_ne!(pw1, pw2);
    }

    /// Vérifie que rand_index ne produit pas de valeurs hors [0, len)
    #[test]
    fn test_rand_index_bounds() {
        for len in [1usize, 2, 10, 26, 62, 88] {
            for _ in 0..1000 {
                let idx = GeneratorConfig::rand_index(len);
                assert!(idx < len, "rand_index({len}) retourna {idx}");
            }
        }
    }
}
