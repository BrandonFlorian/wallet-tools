# Solana Wallet Tools 🔐

A secure command-line tool for managing Solana wallets with advanced mnemonic ciphering capabilities.

## Features 🌟

- ✨ Create new Solana wallets with BIP39 mnemonics
- 🔄 Recover wallets from existing mnemonics
- 🔒 Encrypt wallets with password protection (ChaCha20-Poly1305)
- 🎯 Create obfuscated versions of mnemonics using word-shifting cipher
- 🔍 Load and view wallet details
- 🛡️ Industry-standard security practices

## Installation 🚀

```bash
# Clone the repository
git clone https://github.com/yourusername/wallet-tools.git
cd wallet-tools

# Build the project
cargo build --release

# Run the binary
./target/release/wallet-tools
```

## Usage 📝

### Create a New Wallet

```bash
wallet-tools new -p <password> -o <output-file>

# Example:
wallet-tools new -p Password123 -o wallet.json
```

### Recover a Wallet from Mnemonic

```bash
wallet-tools recover -m <mnemonic-phrase> -p <password> -o <output-file>

# Example:
wallet-tools recover -m "your twelve word mnemonic phrase here" -p Password123 -o recovered_wallet.json
```

### Create a Ciphered Version

```bash
wallet-tools cipher -i <input-file> -p <password> -n <offset> -o <output-file>

# Example:
wallet-tools cipher -i wallet.json -p Password123 -n 3 -o ciphered_wallet.json
```

### Decipher a Wallet

```bash
wallet-tools decipher -i <input-file> -p <password> -n <offset>

# Example:
wallet-tools decipher -i ciphered_wallet.json -p Password123 -n 3
```

### Load and View a Wallet

```bash
wallet-tools load -i <input-file> -p <password>

# Example:
wallet-tools load -i wallet.json -p Password123
```

## How it Works 🔧

### Wallet Creation

- Generates secure random entropy for BIP39 mnemonic generation
- Creates Solana keypair from mnemonic seed
- Encrypts wallet data using ChaCha20-Poly1305 with password-based key derivation

### Mnemonic Ciphering

The tool includes a unique mnemonic ciphering feature that:

- Shifts every third word in the mnemonic by a specified offset
- Maintains the same keypair while obfuscating the mnemonic
- Allows for reversible transformation using the same offset

### Security Features

- Strong encryption using ChaCha20-Poly1305
- Password-based key derivation using PBKDF2-SHA256 (100,000 iterations)
- Secure random number generation for all cryptographic operations
- No mnemonic storage in plain text

## Example Workflow 🔄

```bash
# 1. Create a new wallet
wallet-tools new -p Password123 -o wallet.json

# 2. Create a ciphered version
wallet-tools cipher -i wallet.json -p Password123 -n 3 -o ciphered_wallet.json

# 3. View the ciphered wallet
wallet-tools load -i ciphered_wallet.json -p Password123

# 4. Decipher back to original
wallet-tools decipher -i ciphered_wallet.json -p Password123 -n 3
```

## Security Considerations ⚠️

- Always keep your mnemonic phrase secure
- Use strong passwords for encryption
- Keep track of cipher offsets when using the cipher feature
- Backup your wallet files securely
- Never share your private keys or mnemonics
- The ciphered mnemonic is intentionally invalid as a BIP39 phrase

## Dependencies 📦

```toml
[dependencies]
bip39 = "2.1.0"
ring = "0.17.8"
serde = { version = "1.0.216", features = ["derive"] }
base64 = "0.22.1"
solana-client = "1.17.16"
solana-sdk = "1.17.16"
getrandom = "0.2.15"
serde_json = "1.0.133"
clap = { version = "4.4.8", features = ["derive"] }
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer ⚠️

This tool is provided as-is. Always verify the generated wallets and test with small amounts first.
