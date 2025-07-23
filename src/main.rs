use rust_advanced_encryption_standard::crypto::aes;


fn main() {
    aes::ecb::encrypt("Liam O'Shaughnessy is a great name, I wonder if anyone else has this name?",16);
}
