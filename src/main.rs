use rust_advanced_encryption_standard::crypto::aes;


fn main() {
    let mut encrypted = aes::ecb::encrypt("Liam O'Shaughnessy is a great name, I wonder if anyone else has this name?",16);

    aes::ecb::decrypt(encrypted[0].clone(), encrypted[1].clone());
}
