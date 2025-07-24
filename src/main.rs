use clap::Parser;
use rust_advanced_encryption_standard::crypto::aes;
use zeroize::Zeroize;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Text to encrypt/decrypt
    #[arg(short, long, conflicts_with = "file")]
    text: Option<String>,

    /// Input file
    #[arg(short, long, conflicts_with = "text")]
    file: Option<String>,

    /// Key (text or file path)
    #[arg(short, long)]
    key: Option<String>,

    /// Key size in bits (128/192/256) - encryption only
    #[arg(short, long, default_value_t = 128, conflicts_with = "key")]
    bits: usize,

    /// Output file
    #[arg(short, long, default_value = "output.txt")]
    output: String,

    /// Encrypt mode
    #[arg(short, long, conflicts_with = "decrypt")]
    encrypt: bool,

    /// Decrypt mode
    #[arg(short, long, conflicts_with = "encrypt")]
    decrypt: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Cli::parse();

    // Validate mode
    if !args.encrypt && !args.decrypt {
        eprintln!("Error: Specify --encrypt or --decrypt");
        std::process::exit(1);
    }

    // Read input
    let input = match (args.text, args.file) {
        (Some(text), None) => text,
        (None, Some(file)) => fs::read_to_string(&file)?,
        _ => {
            eprintln!("Error: Use either --text or --file");
            std::process::exit(1);
        }
    };

    if args.encrypt {
        // Validate key size

        //Support for 128 bit key's at the moment, will break with larger key sizes
        let key_bytes = args.bits / 8;
        if ![16, 24, 32].contains(&key_bytes) {
            eprintln!("Error: Key size must be 128, 192, or 256 bits");
            std::process::exit(1);
        }

        // Encrypt and save (using Zeroizing for automatic cleanup)
        let (ciphertext, key) = {
            let result = aes::ecb::encrypt(&input, key_bytes)?;
            (result.0, zeroize::Zeroizing::new(result.1))
        };

        fs::write(&args.output, ciphertext)?;
        fs::write("key.txt", &*key)?; // Deref to access inner data
        
        println!("Encrypted to: {}", args.output);
        println!("Key saved to: key.txt");
    
    } else {
        // Get key content (file or direct string)
        let key = match args.key {
            Some(k) => {
                if Path::new(&k).exists() {
                    fs::read_to_string(&k)?
                } else {
                    k
                }
            }
            None => {
                eprintln!("Error: --key required for decryption");
                std::process::exit(1);
            }
        };

        // Decrypt and save
        let plaintext = aes::ecb::decrypt(input, key)?;
        
        fs::write(&args.output, plaintext)?;
        println!("Decrypted to: {}", args.output);
    }

    Ok(())
}