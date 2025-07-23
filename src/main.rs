use clap::Parser;
use rust_advanced_encryption_standard::crypto::aes;

/// AES Encryption/Decryption Tool
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Text to process
    #[arg(short, long)]
    text: String,

    /// Operation mode (encrypt or decrypt)
    #[arg(short, long, default_value = "encrypt")]
    mode: String,

    /// Key size in bits (128, 192, or 256)
    #[arg(short, long, default_value_t = 128)]
    key_bits: usize,
}

fn main() {
    let args = Cli::parse();

    // Convert key bits to bytes and validate
    let key_bytes = args.key_bits / 8;
    if ![16, 24, 32].contains(&key_bytes) {
        eprintln!("Error: Key size must be 128, 192, or 256 bits");
        std::process::exit(1);
    }

    match args.mode.to_lowercase().as_str() {
        "encrypt" | "e" => {
            match aes::ecb::encrypt(&args.text, key_bytes) {
                Ok((ciphertext, key)) => {
                    println!("Encrypted: {}", ciphertext);
                    println!("Key: {}", key);
                }
                Err(e) => eprintln!("Encryption failed: {}", e),
            }
        }
        "decrypt" | "d" => {
            match aes::ecb::decrypt(args.text, args.key_bits.to_string()) {
                Ok(plaintext) => println!("Decrypted: {}", plaintext),
                Err(e) => eprintln!("Decryption failed: {}", e),
            }
        }
        _ => {
            eprintln!("Error: Invalid mode. Use -e/encrypt or -d/decrypt");
            std::process::exit(1);
        }
    }
}