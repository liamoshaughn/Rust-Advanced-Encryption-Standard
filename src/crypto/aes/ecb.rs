use crate::crypto::functions;

const ROUNDS: usize = 11;
const BLOCK_SIZE: usize = 16;

pub fn encrypt(plaintext: &str, key_size: usize) -> Result<(String, String), String> {

    // Generate random key
    let mut key_bytes = vec![0u8; key_size];
    getrandom::fill(&mut key_bytes)
        .map_err(|e| format!("Failed to generate key: {}", e))?;

    // Expand key
    let rounds_keys = functions::expand_key(&key_bytes, ROUNDS);
    let key_hex = hex::encode(&key_bytes);

    // Process plaintext
    let plaintext_bytes = plaintext.as_bytes();
    let padded_bytes = functions::padding(plaintext_bytes, BLOCK_SIZE);

    let mut encrypted_data = Vec::with_capacity(padded_bytes.len());

    // Encrypt in 16 byte rounds
    for chunk in padded_bytes.chunks_exact(BLOCK_SIZE) {
        let mut state_matrix = functions::bytes_to_state(chunk.try_into().unwrap());

        functions::add_round_key(&rounds_keys[0], &mut state_matrix);

        for round in 1..ROUNDS {
            functions::sub_bytes(&mut state_matrix);
            functions::shift_rows(&mut state_matrix);
            
            if round != ROUNDS - 1 {
                functions::mix_columns(&mut state_matrix);
            }
            
            functions::add_round_key(&rounds_keys[round], &mut state_matrix);
        }

        encrypted_data.extend_from_slice(&functions::state_to_bytes(state_matrix));
    }

    Ok((hex::encode(encrypted_data), key_hex))
}


pub fn decrypt(ciphertext_hex: String, key_hex: String) -> Result<String, String> {
    
    let key_bytes = hex::decode(key_hex)
        .map_err(|e| format!("Invalid key hex: {}", e))?;
    
    if ![16, 24, 32].contains(&key_bytes.len()) {
        return Err(format!("Invalid key length: {} bytes", key_bytes.len()));
    }

    let ciphertext = hex::decode(ciphertext_hex)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;


    let rounds_keys = functions::expand_key(&key_bytes, ROUNDS);


    let mut decrypted_data = Vec::with_capacity(ciphertext.len());
    
    for chunk in ciphertext.chunks_exact(BLOCK_SIZE){
        let mut state_matrix = functions::bytes_to_state(chunk);
        

        for round in 1..ROUNDS{

            functions::add_round_key(&rounds_keys[ROUNDS-round], &mut state_matrix);

            if ROUNDS-round != ROUNDS-1{
                functions::inv_mix_columns(&mut state_matrix);
            }

            functions::inv_shift_rows(&mut state_matrix);

            functions::inv_sub_bytes(&mut state_matrix);
    
      
        }
        functions::add_round_key(&rounds_keys[0], &mut state_matrix);
        decrypted_data.extend_from_slice(&functions::state_to_bytes(state_matrix));
    }

    functions::unpad(&decrypted_data);

    String::from_utf8(decrypted_data).map_err(|e| format!("Decryption Failed found Invalid UTF-8: {}", e))
}