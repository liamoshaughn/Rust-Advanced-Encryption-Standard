use crate::crypto::functions;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use zeroize::{Zeroize, Zeroizing};
use rayon::prelude::*;

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
    let mut data_bytes = plaintext.as_bytes().to_vec();

    //this will be our iv
    let mut iv =[0u8; 12];
    getrandom::fill(&mut iv)
        .map_err(|e| format!("Failed to IV: {}", e))?;


    data_bytes.par_chunks_mut(BLOCK_SIZE).enumerate()
    .for_each(|(i,chunk)| {

        let mut counter =  [0u8; 16];
        counter[..12].copy_from_slice(&iv);    
        counter[12..].copy_from_slice(&(i as u32).to_be_bytes());


        let mut state_matrix = functions::bytes_to_state(&counter);

        functions::add_round_key(&round_keys[0], &mut state_matrix);

        for round in 1..rounds {

            functions::sub_bytes(&mut state_matrix);

            functions::shift_rows(&mut state_matrix);
            
            if round != rounds - 1 {
                functions::mix_columns(&mut state_matrix);
            }
            
            functions::add_round_key(&round_keys[round], &mut state_matrix);
        }

        counter.zeroize();

        for  (byte1, byte2) in chunk.iter_mut().zip(functions::state_to_bytes(state_matrix).iter()) {
            *byte1 ^= byte2;
        }

        state_matrix.zeroize();
    });

    data_bytes.splice(0..0, iv.iter().copied());
    Ok((STANDARD.encode(data_bytes), key_hex))
}


pub fn decrypt(ciphertext_b64: String, key_hex: String) -> Result<String, String> {
    let rounds = 6 + ((key_hex.len() / 2) / 4);

    let key_bytes = hex::decode(key_hex)
        .map_err(|e| format!("Invalid key hex: {}", e))?;
    
    if ![16, 24, 32].contains(&key_bytes.len()) {
        return Err(format!("Invalid key length: {} bytes", key_bytes.len()));
    }

    let mut data_bytes = STANDARD.decode(ciphertext_b64)
        .map_err(|e| format!("Invalid ciphertext hex: {}", e))?;



    let round_keys = functions::expand_key(&key_bytes, rounds);

    let mut iv: [u8; 12] = data_bytes[..12].try_into().expect("Somethings wrong with ciphertext!");
    data_bytes.drain(0..12);

    //Same operation as encryption because in encryption we XOR plain text with the keystream, XOR again and we reverse
    data_bytes.par_chunks_mut(BLOCK_SIZE).enumerate().for_each(|(i,chunk)| {

        let mut counter =  [0u8; 16];
        counter[..12].copy_from_slice(&iv);    
        counter[12..].copy_from_slice(&(i as u32).to_be_bytes());


        let mut state_matrix = functions::bytes_to_state(&counter);

        functions::add_round_key(&round_keys[0], &mut state_matrix);

        for round in 1..rounds {

            functions::sub_bytes(&mut state_matrix);

            functions::shift_rows(&mut state_matrix);
            
            if round != rounds - 1 {
                functions::mix_columns(&mut state_matrix);
            }
            
            functions::add_round_key(&round_keys[round], &mut state_matrix);
        }

        counter.zeroize();

        for  (byte1, byte2) in chunk.iter_mut().zip(functions::state_to_bytes(state_matrix).iter()) {
            *byte1 ^= byte2;
        }

        state_matrix.zeroize();

    });

    String::from_utf8(data_bytes).map_err(|e| format!("Decryption failed found Invalid UTF-8: {}", e))
}