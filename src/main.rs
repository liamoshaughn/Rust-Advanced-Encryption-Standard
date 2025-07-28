use clap::Parser;
use rust_advanced_encryption_standard::crypto::aes;
use std::fs;
use std::path::Path;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {

    // Text to encrypt/decrypt
    #[arg(short, long, conflicts_with = "file")]
    text: Option<String>,

    // Input file
    #[arg(short, long, conflicts_with = "text")]
    file: Option<String>,

    // Key (text or file path)
    #[arg(short, long)]
    key: Option<String>,

    // Key size in bits (128/192/256) - encryption only
    #[arg(short, long, default_value_t = 256, conflicts_with = "key")]
    bits: usize,

    // Output file
    #[arg(short, long, default_value = "output.txt")]
    output: String,

    // Encrypt mode
    #[arg(short, long, conflicts_with = "decrypt")]
    encrypt: bool,

    // Decrypt mode
    #[arg(short, long, conflicts_with = "encrypt")]
    decrypt: bool,

    // Mode of encryption: cbc, ecb
    #[arg(short, long)]
    mode: String,
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
        let key_bytes = args.bits / 8;
        if ![16, 24, 32].contains(&key_bytes) {
            eprintln!("Error: Key size must be 128, 192, or 256 bits");
            std::process::exit(1);
        }

        let encryption_result = match args.mode.to_lowercase().as_str() {
            "ecb" => {
                aes::ecb::encrypt(&input, key_bytes)
                    .map(|(ct, k)| (ct, zeroize::Zeroizing::new(k)))
            },
            "cbc" => {
                aes::cbc::encrypt(&input, key_bytes)
                    .map(|(ct, k)| (ct, zeroize::Zeroizing::new(k)))
            },
            _ => return Err(format!("Unsupported mode: {}. Use 'cbc' or 'ecb'", args.mode).into()),
        };

        let (ciphertext, key) = encryption_result.map_err(|e| format!("Encryption failed: {}", e))?;

        fs::write(&args.output, ciphertext)?;
        fs::write("key.txt", &*key)?;
        
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
        let decryption_result = match args.mode.to_lowercase().as_str() {
                "ecb" => aes::ecb::decrypt(input, key),
                "cbc" => {
                    if input.len() < 16 {
                        return Err("Input too short for CBC mode (needs IV)".into());
                    }
                    aes::cbc::decrypt(input, key)
                },
                _ => return Err(format!("Unsupported mode: {}. Use 'cbc' or 'ecb'", args.mode).into()),
            };

        let plaintext = decryption_result.map_err(|e| format!("Decryption failed: {}", e))?;

        fs::write(&args.output, plaintext)?;
        println!("Decrypted to: {}", args.output);

    }

    Ok(())
}