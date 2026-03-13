use rand::Rng;

const LOWERCASE: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const UPPERCASE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS:    &[u8] = b"0123456789";
const SYMBOLS:   &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

pub struct GeneratorConfig {
    pub length:      usize,
    pub uppercase:   bool,
    pub digits:      bool,
    pub symbols:     bool,
}

impl Default for GeneratorConfig {
    fn default() -> Self {
        Self { length: 20, uppercase: true, digits: true, symbols: true }
    }
}

// 🦀 CONCEPT — impl sur struct :
// On ajoute des méthodes à GeneratorConfig via "impl".
// C'est l'équivalent Rust des méthodes de classe, sans héritage.
impl GeneratorConfig {
    /// Génère un mot de passe aléatoire cryptographiquement sûr.
    /// Garantit au moins 1 caractère de chaque classe activée.
    pub fn generate(&self) -> String {
        let mut rng = rand::thread_rng();
        let mut charset: Vec<u8> = LOWERCASE.to_vec();
        let mut required: Vec<u8> = Vec::new();

        if self.uppercase {
            charset.extend_from_slice(UPPERCASE);
            required.push(UPPERCASE[rng.gen_range(0..UPPERCASE.len())]);
        }
        if self.digits {
            charset.extend_from_slice(DIGITS);
            required.push(DIGITS[rng.gen_range(0..DIGITS.len())]);
        }
        if self.symbols {
            charset.extend_from_slice(SYMBOLS);
            required.push(SYMBOLS[rng.gen_range(0..SYMBOLS.len())]);
        }
        required.push(LOWERCASE[rng.gen_range(0..LOWERCASE.len())]);

        let remaining = self.length.saturating_sub(required.len());
        let mut password: Vec<u8> = (0..remaining)
            .map(|_| charset[rng.gen_range(0..charset.len())])
            .collect();

        password.extend_from_slice(&required);

        // 🦀 Fisher-Yates shuffle : mélange aléatoire en O(n)
        for i in (1..password.len()).rev() {
            let j = rng.gen_range(0..=i);
            password.swap(i, j);
        }

        String::from_utf8(password).unwrap_or_default()
    }

    /// Calcule un score de force 0-4 basique.
    pub fn strength_score(password: &str) -> u8 {
        let len = password.len();
        let has_upper  = password.chars().any(|c| c.is_uppercase());
        let has_lower  = password.chars().any(|c| c.is_lowercase());
        let has_digit  = password.chars().any(|c| c.is_ascii_digit());
        let has_symbol = password.chars().any(|c| !c.is_alphanumeric());

        let variety = [has_upper, has_lower, has_digit, has_symbol]
            .iter().filter(|&&x| x).count();

        match (len, variety) {
            (l, _) if l < 8             => 0,
            (l, v) if l < 12 && v < 3   => 1,
            (l, v) if l < 16 && v >= 2  => 2,
            (l, v) if l >= 20 && v == 4 => 4,
            (l, v) if l >= 16 && v >= 3 => 3,
            _                           => 2,
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
        let pw = config.generate();
        assert!(pw.chars().any(|c| c.is_uppercase()));
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
}
