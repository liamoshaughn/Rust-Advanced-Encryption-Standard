use crate::crypto::functions;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};

const BLOCK_SIZE: usize = 16;

pub fn encrypt(plaintext: &str, key_size: usize) -> Result<(String, Zeroizing<String>), String> {
    let rounds = 6 + (key_size / 4);

    // Generate random key 
    let mut key_bytes = Zeroizing::new(vec![0u8; key_size]);
    getrandom::fill(&mut key_bytes)
        .map_err(|e| format!("Failed to generate key: {}", e))?;

    // Expand key
    let round_keys = Zeroizing::new(functions::expand_key(&key_bytes, rounds));
    let key_hex = Zeroizing::new(hex::encode(&*key_bytes));

    // Process plaintext
    let plaintext_bytes = plaintext.as_bytes();
    let padded_bytes = functions::padding(plaintext_bytes, BLOCK_SIZE);

    let mut encrypted_data = Vec::with_capacity(padded_bytes.len());

    // Encrypt in 16-byte blocks
    for chunk in padded_bytes.chunks_exact(BLOCK_SIZE) {

        let mut state_matrix = functions::bytes_to_state(chunk);

        functions::add_round_key(&round_keys[0], &mut state_matrix);

        for round in 1..rounds {

            functions::sub_bytes(&mut state_matrix);

            functions::shift_rows(&mut state_matrix);
            
            if round != rounds - 1 {
                functions::mix_columns(&mut state_matrix);
            }
            
            functions::add_round_key(&round_keys[round], &mut state_matrix);
        }

        encrypted_data.extend_from_slice(&functions::state_to_bytes(state_matrix));
    }

    Ok((STANDARD.encode(encrypted_data), key_hex))
}


pub fn decrypt(ciphertext_b64: String, key_hex: String) -> Result<String, String> {

    let rounds = 6 + ((key_hex.len() / 2) / 4);
    let key_bytes = hex::decode(key_hex)
        .map_err(|e| format!("Invalid key hex: {}", e))?;
    
    if ![16, 24, 32].contains(&key_bytes.len()) {
        return Err(format!("Invalid key length: {} bytes", key_bytes.len()));
    }

    let ciphertext = STANDARD.decode(ciphertext_b64)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;


    let round_keys = functions::expand_key(&key_bytes, rounds);


    let mut decrypted_data = Vec::with_capacity(ciphertext.len());
    
    for chunk in ciphertext.chunks_exact(BLOCK_SIZE){
        let mut state_matrix = functions::bytes_to_state(chunk);
        

        for round in 1..rounds{

            functions::add_round_key(&round_keys[rounds-round], &mut state_matrix);

            if rounds-round != rounds-1{
                functions::inv_mix_columns(&mut state_matrix);
            }

            functions::inv_shift_rows(&mut state_matrix);

            functions::inv_sub_bytes(&mut state_matrix);
    
      
        }
        functions::add_round_key(&round_keys[0], &mut state_matrix);
        decrypted_data.extend_from_slice(&functions::state_to_bytes(state_matrix));
    }

    functions::unpad( &mut decrypted_data);
    String::from_utf8(decrypted_data).map_err(|e| format!("Decryption failed found Invalid UTF-8: {}", e))
}