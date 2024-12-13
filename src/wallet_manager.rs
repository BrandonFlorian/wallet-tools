use solana_sdk::signature::SeedDerivable;
use {
    base64::{engine::general_purpose::STANDARD as BASE64, Engine as _},
    bip39::Mnemonic,
    ring::{aead, pbkdf2},
    serde::{Deserialize, Serialize},
    solana_sdk::{
        pubkey::Pubkey,
        signature::{Keypair, Signer},
    },
    std::{
        fs,
        io::{self},
        path::Path,
        str::FromStr,
    },
};

#[derive(Serialize, Deserialize)]
pub struct EncryptedWallet {
    pub salt: String,
    pub nonce: String,
    pub encrypted_data: String,
}

pub struct WalletManager {
    pub keypair: Keypair,
    pub mnemonic: Option<String>,
}

impl WalletManager {
    pub fn new_random() -> Self {
        let mut entropy = [0u8; 32];
        getrandom::getrandom(&mut entropy).expect("Failed to generate random bytes");
        let mnemonic = Mnemonic::from_entropy(&entropy).expect("Failed to create mnemonic");

        let seed = mnemonic.to_seed("");
        // Just use first 32 bytes for the secret key
        let secret_key: [u8; 32] = seed[..32].try_into().expect("Seed wrong length");
        let keypair = Keypair::from_seed(&secret_key).expect("Failed to create keypair");

        Self {
            keypair,
            mnemonic: Some(mnemonic.to_string()),
        }
    }

    pub fn from_mnemonic(phrase: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mnemonic = Mnemonic::from_str(phrase)?;
        let seed = mnemonic.to_seed("");

        // Just use first 32 bytes for the secret key
        let secret_key: [u8; 32] = seed[..32].try_into().map_err(|_| "Invalid seed length")?;
        let keypair = Keypair::from_seed(&secret_key)?;

        Ok(Self {
            keypair,
            mnemonic: Some(phrase.to_string()),
        })
    }

    pub fn encrypt_wallet(
        &self,
        password: &str,
    ) -> Result<EncryptedWallet, Box<dyn std::error::Error>> {
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)?;
        let mut nonce = [0u8; 12];
        getrandom::getrandom(&mut nonce)?;

        // Derive key using PBKDF2
        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &salt,
            password.as_bytes(),
            &mut key,
        );

        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key)
            .map_err(|_| "Failed to create key")?;
        let sealing_key = aead::LessSafeKey::new(unbound_key);

        let wallet_data = serde_json::json!({
            "private_key": self.keypair.to_bytes().to_vec(),
            "mnemonic": self.mnemonic,
        })
        .to_string();

        let mut in_out = wallet_data.into_bytes();
        sealing_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut in_out,
            )
            .map_err(|_| "Encryption failed")?;

        Ok(EncryptedWallet {
            salt: BASE64.encode(salt),
            nonce: BASE64.encode(nonce),
            encrypted_data: BASE64.encode(in_out),
        })
    }

    pub fn decrypt_wallet(
        encrypted: &EncryptedWallet,
        password: &str,
    ) -> Result<WalletManager, Box<dyn std::error::Error>> {
        let salt = BASE64.decode(&encrypted.salt)?;
        let nonce = BASE64.decode(&encrypted.nonce)?;
        let mut encrypted_data = BASE64.decode(&encrypted.encrypted_data)?;

        let mut key = [0u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            std::num::NonZeroU32::new(100_000).unwrap(),
            &salt,
            password.as_bytes(),
            &mut key,
        );

        let unbound_key = aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &key)
            .map_err(|_| "Failed to create key")?;
        let opening_key = aead::LessSafeKey::new(unbound_key);

        let decrypted = opening_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(
                    nonce
                        .as_slice()
                        .try_into()
                        .map_err(|e| format!("Invalid nonce length: {}", e))?,
                ),
                aead::Aad::empty(),
                &mut encrypted_data,
            )
            .map_err(|_| "Decryption failed")?;

        let wallet_data: serde_json::Value = serde_json::from_slice(decrypted)?;

        let private_key = wallet_data["private_key"]
            .as_array()
            .ok_or("Invalid private key format")?
            .iter()
            .map(|v| v.as_u64().ok_or("Invalid byte in private key"))
            .collect::<Result<Vec<u64>, _>>()?;

        let keypair =
            Keypair::from_bytes(&private_key.iter().map(|&v| v as u8).collect::<Vec<u8>>())?;

        let mnemonic = wallet_data["mnemonic"].as_str().map(String::from);

        Ok(WalletManager { keypair, mnemonic })
    }

    pub fn get_public_key(&self) -> Pubkey {
        self.keypair.pubkey()
    }

    pub fn create_offset_cipher(
        &self,
        word_list: &[String],
        offset: i32,
    ) -> Result<Vec<String>, Box<dyn std::error::Error>> {
        if let Some(mnemonic) = &self.mnemonic {
            let words: Vec<&str> = mnemonic.split_whitespace().collect();
            let ciphered: Vec<String> = words
                .iter()
                .enumerate()
                .map(|(i, &word)| {
                    if (i + 1) % 3 == 0 {
                        // Every third word
                        let current_index = word_list.iter().position(|w| w == word).unwrap_or(0);
                        let new_index = (current_index as i32 + offset)
                            .rem_euclid(word_list.len() as i32)
                            as usize;
                        word_list[new_index].clone()
                    } else {
                        word.to_string()
                    }
                })
                .collect();

            Ok(ciphered)
        } else {
            Err("No mnemonic present in wallet".into())
        }
    }

    pub fn save_encrypted(&self, password: &str, path: &Path) -> io::Result<()> {
        let encrypted = self
            .encrypt_wallet(password)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        let json = serde_json::to_string_pretty(&encrypted)?;
        fs::write(path, json)?;
        Ok(())
    }

    pub fn save_ciphered(
        &self,
        password: &str,
        path: &Path,
        ciphered_mnemonic: &str,
    ) -> io::Result<()> {
        let keypair_bytes = self.keypair.to_bytes();
        let wallet = WalletManager {
            keypair: Keypair::from_bytes(&keypair_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?,
            mnemonic: Some(ciphered_mnemonic.to_string()),
        };

        wallet.save_encrypted(password, path)
    }
}

// Utility functions for the CLI interface
pub fn create_new_wallet() -> WalletManager {
    WalletManager::new_random()
}

pub fn recover_wallet(mnemonic: &str) -> Result<WalletManager, Box<dyn std::error::Error>> {
    WalletManager::from_mnemonic(mnemonic)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    #[test]
    fn test_wallet_creation_and_recovery() {
        let original_wallet = create_new_wallet();
        let mnemonic = original_wallet.mnemonic.clone().unwrap();

        let recovered_wallet = recover_wallet(&mnemonic).unwrap();
        assert_eq!(
            original_wallet.get_public_key(),
            recovered_wallet.get_public_key()
        );
    }

    #[test]
    fn test_cipher_reversible() {
        let wallet = create_new_wallet();
        let word_list: Vec<String> = bip39::Language::English
            .word_list()
            .iter()
            .map(|&s| s.to_string())
            .collect();
        let offset = 3;

        let ciphered = wallet
            .create_offset_cipher(&word_list, offset)
            .expect("Failed to create cipher");

        let temp_wallet = WalletManager {
            keypair: Keypair::new(),
            mnemonic: Some(ciphered.join(" ")),
        };

        let deciphered = temp_wallet
            .create_offset_cipher(&word_list, -offset)
            .expect("Failed to decipher");

        assert_eq!(wallet.mnemonic.unwrap(), deciphered.join(" "));
    }

    #[test]
    fn test_encryption_decryption() {
        let wallet = create_new_wallet();
        let password = "test_password";

        let encrypted = wallet.encrypt_wallet(password).unwrap();
        let decrypted = WalletManager::decrypt_wallet(&encrypted, password).unwrap();

        assert_eq!(wallet.get_public_key(), decrypted.get_public_key());
    }

    #[test]
    fn test_save_and_load_wallet() {
        // Create a temporary directory that will be cleaned up when test ends
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test_wallet.json");

        // Create and save wallet
        let original_wallet = create_new_wallet();
        let password = "test_password";
        original_wallet
            .save_encrypted(password, &file_path)
            .unwrap();

        // Verify file exists and can be read
        assert!(file_path.exists());
        let file_content = fs::read_to_string(&file_path).unwrap();
        let encrypted: EncryptedWallet = serde_json::from_str(&file_content).unwrap();

        // Decrypt and verify
        let loaded_wallet = WalletManager::decrypt_wallet(&encrypted, password).unwrap();
        assert_eq!(
            original_wallet.get_public_key(),
            loaded_wallet.get_public_key()
        );
    }

    #[test]
    #[should_panic(expected = "Invalid nonce length")]
    fn test_decrypt_invalid_wallet() {
        let invalid_encrypted = EncryptedWallet {
            salt: BASE64.encode([0u8; 16]),
            nonce: BASE64.encode([0u8; 6]), // Invalid nonce length
            encrypted_data: BASE64.encode([0u8; 32]),
        };

        WalletManager::decrypt_wallet(&invalid_encrypted, "password").unwrap();
    }

    #[test]
    fn test_wrong_password() {
        let wallet = create_new_wallet();
        let encrypted = wallet.encrypt_wallet("correct_password").unwrap();

        let result = WalletManager::decrypt_wallet(&encrypted, "wrong_password");
        assert!(result.is_err());
    }

    #[test]
    fn test_cipher_with_empty_word_list() {
        let wallet = create_new_wallet();
        let empty_word_list: Vec<String> = vec![];
        let result = wallet.create_offset_cipher(&empty_word_list, 3);
        assert!(result.is_err());
    }
}
