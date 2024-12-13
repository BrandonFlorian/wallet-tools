use clap::{Parser, Subcommand};
use std::{fs, path::PathBuf};

mod wallet_manager;
use wallet_manager::{create_new_wallet, recover_wallet, EncryptedWallet, WalletManager};

#[derive(Parser)]
#[command(name = "solana-wallet-manager")]
#[command(about = "A Solana wallet management tool")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new wallet
    New {
        /// Password for encryption
        #[arg(short, long)]
        password: String,
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Recover wallet from mnemonic
    Recover {
        /// Mnemonic phrase
        #[arg(short, long)]
        mnemonic: String,
        /// Password for encryption
        #[arg(short, long)]
        password: String,
        /// Output file path
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Create a ciphered version of a wallet's mnemonic
    Cipher {
        /// Input wallet file
        #[arg(short, long)]
        input: PathBuf,
        /// Password for decryption
        #[arg(short, long)]
        password: String,
        /// Offset for cipher (positive or negative integer)
        #[arg(short = 'n', long)]
        offset: i32,
        /// Output file path (optional)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
    /// Decipher a ciphered mnemonic from a wallet file
    Decipher {
        /// Input wallet file
        #[arg(short, long)]
        input: PathBuf,
        /// Password for decryption
        #[arg(short, long)]
        password: String,
        /// Original cipher offset (will be reversed)
        #[arg(short = 'n', long)]
        offset: i32,
    },
    /// Load and decrypt a wallet file
    Load {
        /// Input wallet file
        #[arg(short, long)]
        input: PathBuf,
        /// Password for decryption
        #[arg(short, long)]
        password: String,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::New { password, output } => {
            let wallet = create_new_wallet();
            if let Err(e) = wallet.save_encrypted(&password, &output) {
                eprintln!("Failed to save wallet: {}", e);
                return;
            }
            println!("New wallet created and saved!");
            println!("Public key: {}", wallet.get_public_key());
            if let Some(mnemonic) = wallet.mnemonic {
                println!("Mnemonic (KEEP SAFE): {}", mnemonic);
            }
        }
        Commands::Recover {
            mnemonic,
            password,
            output,
        } => match recover_wallet(&mnemonic) {
            Ok(wallet) => {
                if let Err(e) = wallet.save_encrypted(&password, &output) {
                    eprintln!("Failed to save wallet: {}", e);
                    return;
                }
                println!("Wallet recovered and saved!");
                println!("Public key: {}", wallet.get_public_key());
            }
            Err(e) => eprintln!("Failed to recover wallet: {}", e),
        },
        Commands::Cipher {
            input,
            password,
            offset,
            output,
        } => {
            if !input.exists() {
                eprintln!("Error: Wallet file not found at: {}", input.display());
                return;
            }

            let file_content = match fs::read_to_string(&input) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Error reading wallet file: {}", e);
                    return;
                }
            };

            let encrypted: EncryptedWallet = match serde_json::from_str(&file_content) {
                Ok(wallet) => wallet,
                Err(e) => {
                    eprintln!("Error parsing wallet file (invalid format): {}", e);
                    return;
                }
            };

            let wallet = match WalletManager::decrypt_wallet(&encrypted, &password) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Error decrypting wallet (wrong password?): {}", e);
                    return;
                }
            };

            let word_list: Vec<String> = bip39::Language::English
                .word_list()
                .iter()
                .map(|&s| s.to_string())
                .collect();

            let original_mnemonic = wallet.mnemonic.as_deref().unwrap_or_default();
            let ciphered = match wallet.create_offset_cipher(&word_list, offset) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error creating cipher: {}", e);
                    return;
                }
            };

            println!("Original mnemonic: {}", original_mnemonic);
            println!("Ciphered mnemonic: {}", ciphered.join(" "));
            println!("\nNote: The ciphered mnemonic is intentionally not a valid BIP39 phrase.");
            println!(
                "You will need the original offset value ({}) to decipher it.",
                offset
            );

            // Save to new file if output path provided
            if let Some(output_path) = output {
                if let Err(e) = wallet.save_ciphered(&password, &output_path, &ciphered.join(" ")) {
                    eprintln!("Error saving ciphered wallet: {}", e);
                    return;
                }
                println!("\nSaved ciphered wallet to: {}", output_path.display());
            }
        }
        Commands::Decipher {
            input,
            password,
            offset,
        } => {
            // Similar to Cipher but use negative offset
            let file_content = match fs::read_to_string(&input) {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("Error reading wallet file: {}", e);
                    return;
                }
            };

            let encrypted: EncryptedWallet = match serde_json::from_str(&file_content) {
                Ok(wallet) => wallet,
                Err(e) => {
                    eprintln!("Error parsing wallet file (invalid format): {}", e);
                    return;
                }
            };

            let wallet = match WalletManager::decrypt_wallet(&encrypted, &password) {
                Ok(w) => w,
                Err(e) => {
                    eprintln!("Error decrypting wallet (wrong password?): {}", e);
                    return;
                }
            };

            let word_list: Vec<String> = bip39::Language::English
                .word_list()
                .iter()
                .map(|&s| s.to_string())
                .collect();

            let deciphered = match wallet.create_offset_cipher(&word_list, -offset) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("Error deciphering: {}", e);
                    return;
                }
            };

            println!("Ciphered mnemonic: {}", wallet.mnemonic.unwrap_or_default());
            println!("Deciphered mnemonic: {}", deciphered.join(" "));
        }
        Commands::Load { input, password } => {
            // Read the wallet file
            let file_content = fs::read_to_string(&input).expect("Failed to read wallet file");
            let encrypted: EncryptedWallet =
                serde_json::from_str(&file_content).expect("Failed to parse wallet file");

            // Decrypt and display wallet info
            let wallet = WalletManager::decrypt_wallet(&encrypted, &password)
                .expect("Failed to decrypt wallet");

            println!("Wallet loaded successfully!");
            println!("Public key: {}", wallet.get_public_key());
            if let Some(mnemonic) = wallet.mnemonic {
                println!("Mnemonic: {}", mnemonic);
            }
        }
    }
}
