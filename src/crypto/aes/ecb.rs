use crate::crypto::functions;

const ROUNDS: usize = 11;

pub fn encrypt(plaintext: &str, key_size: usize) -> [String; 2]{
    let mut key_bytes = vec![0u8; key_size];
    getrandom::fill(&mut key_bytes).expect("Failed to generate key");
    
    let key_array = functions::expand_key(&key_bytes, ROUNDS);
    let key = hex::encode(key_bytes);

    let plaintext_bytes: &[u8] = plaintext.as_bytes();
    let block_size = 16;
    let padded_bytes = functions::padding(plaintext_bytes, block_size);

    let mut encrypted_data = Vec::with_capacity(padded_bytes.len());

    // Process in 16-byte chunks
    for (i, chunk) in padded_bytes.chunks(block_size).enumerate() {
        
        let mut state_matrix = functions::bytes_to_state(chunk);

        functions::add_round_key(&key_array[0], &mut state_matrix);

        for round in 1..ROUNDS{

            functions::sub_bytes(&mut state_matrix);

            functions::shift_rows(&mut state_matrix);

            if round != ROUNDS-1{
                functions::mix_columns(&mut state_matrix);
            }

            functions::add_round_key(&key_array[round], &mut state_matrix);
      
        }

        encrypted_data.extend_from_slice(&functions::state_to_bytes(state_matrix));

    }

    [key, hex::encode(encrypted_data)]
}