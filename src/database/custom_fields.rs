//! Champs personnalisés par entrée, sérialisés en JSON et chiffrés dans
//! `notes_encrypted` aux côtés de la note texte.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    Text,
    Password,
    Url,
    Email,
    Phone,
    CreditCard,
    BankAccount,
    SshKey,
}

impl FieldKind {
    pub fn label(&self) -> &'static str {
        match self {
            FieldKind::Text        => "Texte",
            FieldKind::Password    => "Mot de passe",
            FieldKind::Url         => "URL",
            FieldKind::Email       => "E-mail",
            FieldKind::Phone       => "Téléphone",
            FieldKind::CreditCard  => "Carte bancaire",
            FieldKind::BankAccount => "Compte bancaire",
            FieldKind::SshKey      => "Clé SSH",
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            FieldKind::Text        => "text-x-generic-symbolic",
            FieldKind::Password    => "dialog-password-symbolic",
            FieldKind::Url         => "web-browser-symbolic",
            FieldKind::Email       => "mail-unread-symbolic",
            FieldKind::Phone       => "phone-symbolic",
            FieldKind::CreditCard  => "credit-card-symbolic",
            FieldKind::BankAccount => "bank-symbolic",
            FieldKind::SshKey      => "channel-secure-symbolic",
        }
    }

    pub fn all() -> &'static [FieldKind] {
        &[
            FieldKind::Text,
            FieldKind::Password,
            FieldKind::Url,
            FieldKind::Email,
            FieldKind::Phone,
            FieldKind::CreditCard,
            FieldKind::BankAccount,
            FieldKind::SshKey,
        ]
    }

    pub fn is_secret(&self) -> bool {
        matches!(self,
            FieldKind::Password | FieldKind::CreditCard |
            FieldKind::BankAccount | FieldKind::SshKey
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub id:    String,   // uuid v4
    pub kind:  FieldKind,
    pub label: String,
    pub value: String,   // toujours en clair ici — chiffré via notes_encrypted
}

impl CustomField {
    pub fn new(kind: FieldKind, label: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            id:    uuid::Uuid::new_v4().to_string(),
            kind,
            label: label.into(),
            value: value.into(),
        }
    }
}

/// Enveloppe stockée dans `notes_encrypted` (JSON → chiffré AES-GCM).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct EntrySecrets {
    #[serde(default)]
    pub notes:  String,
    #[serde(default)]
    pub fields: Vec<CustomField>,
}

impl EntrySecrets {
    pub fn to_json(&self) -> Result<Vec<u8>, serde_json::Error> {
        serde_json::to_vec(self)
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip_empty() {
        let s = EntrySecrets::default();
        let j = s.to_json().unwrap();
        let s2 = EntrySecrets::from_json(&j).unwrap();
        assert_eq!(s2.notes, "");
        assert!(s2.fields.is_empty());
    }

    #[test]
    fn test_roundtrip_with_fields() {
        let mut s = EntrySecrets::default();
        s.notes = "ma note".to_string();
        s.fields.push(CustomField::new(FieldKind::Password, "PIN", "1234"));
        s.fields.push(CustomField::new(FieldKind::CreditCard, "Numéro", "4111111111111111"));
        let j  = s.to_json().unwrap();
        let s2 = EntrySecrets::from_json(&j).unwrap();
        assert_eq!(s2.notes, "ma note");
        assert_eq!(s2.fields.len(), 2);
        assert_eq!(s2.fields[0].value, "1234");
        assert!(s2.fields[1].kind.is_secret());
    }

    #[test]
    fn test_field_kind_labels() {
        for k in FieldKind::all() {
            assert!(!k.label().is_empty());
            assert!(!k.icon().is_empty());
        }
    }

    #[test]
    fn test_is_secret() {
        assert!(FieldKind::Password.is_secret());
        assert!(FieldKind::CreditCard.is_secret());
        assert!(!FieldKind::Text.is_secret());
        assert!(!FieldKind::Email.is_secret());
    }
}
