//This file is for Cryptography functions used in AES



const S_BOX: [[u8; 16]; 16] = 
[
    [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
    [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
    [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
    [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
    [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
    [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
    [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
    [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
    [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
    [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
    [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
    [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
    [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
    [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
    [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
    [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
];

const INV_S_BOX: [[u8; 16]; 16] = [
    [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
    [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
    [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
    [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
    [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
    [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
    [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
    [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
    [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
    [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
    [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
    [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
    [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
    [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
    [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
];

fn gf_mult(a: u8, b: u8) -> u8 { 
    let mut p: u16 = 0;
    let mut a = a as u16;
    let mut b = b as u16;
    for _ in 0..8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let carry = a & 0x80;
        a <<= 1;
        if carry != 0 {
            a ^= 0x11B; 
        }
        b >>= 1;
    }
    p as u8 
}



//Probably should be moved to a     dedicated util file
pub fn print_state_u8(state: &[[u8; 4]; 4]) {
    for row in state {
        for &byte in row {
            print!("{:02x} ", byte); 
        }
        println!();
    }
}

// Converts a 16-byte array into a column-major order state matrix
pub fn bytes_to_state(bytes: &[u8]) -> [[u8; 4]; 4] {
    let mut state = [[0u8; 4]; 4];
    for col in 0..4 {
        for row in 0..4 {
            state[row][col] = bytes[col * 4 + row];
        }
    }
    state
}


pub fn state_to_bytes(state: [[u8; 4]; 4]) -> [u8; 16] {
    let mut bytes = [0u8; 16];
    for col in 0..4 {
        for row in 0..4 {
            bytes[col * 4 + row] = state[row][col];
        }
    }
    bytes
}


pub fn shift_rows(state: &mut[[u8; 4]; 4]){
    for i in 0..4{

        //shift rows to the left
        state[i].rotate_left(i);
    }
}

pub fn inv_shift_rows(state: &mut [[u8; 4]; 4]){
    for i in 0..4{

        //shift rows to the left
        state[i].rotate_right(i);
    }
}

pub fn mix_columns(state: &mut [[u8; 4]; 4]) {
    // AES MixColumns constant matrix
    const CONST_MATRIX: [[u8; 4]; 4] = 
    [
        [0x02, 0x03, 0x01, 0x01],
        [0x01, 0x02, 0x03, 0x01],
        [0x01, 0x01, 0x02, 0x03],
        [0x03, 0x01, 0x01, 0x02]
    ];

    //Calculate a number using a polynomial formula with the variables being the above matrix and column first of the state matrix
        let mut temp_column = [0u8; 4];

    for i in 0..4 {
        for j in 0..4 {
            temp_column[j] = gf_mult(CONST_MATRIX[j][0], state[0][i]) ^
                             gf_mult(CONST_MATRIX[j][1], state[1][i]) ^
                             gf_mult(CONST_MATRIX[j][2], state[2][i]) ^
                             gf_mult(CONST_MATRIX[j][3], state[3][i]);
        }

        for j in 0..4 {
            state[j][i] = temp_column[j];
        }
    }
}


pub fn inv_mix_columns(state: &mut [[u8; 4]; 4]) {

    // AES Inverse MixColumns constant matrix
    const INV_CONST_MATRIX: [[u8; 4]; 4] = [
        [0x0e, 0x0b, 0x0d, 0x09],
        [0x09, 0x0e, 0x0b, 0x0d],
        [0x0d, 0x09, 0x0e, 0x0b],
        [0x0b, 0x0d, 0x09, 0x0e]
    ];

    let mut temp_column = [0u8; 4];

    for i in 0..4 {
        for j in 0..4 {
            temp_column[j] = gf_mult(INV_CONST_MATRIX[j][0], state[0][i]) ^
                             gf_mult(INV_CONST_MATRIX[j][1], state[1][i]) ^
                             gf_mult(INV_CONST_MATRIX[j][2], state[2][i]) ^
                             gf_mult(INV_CONST_MATRIX[j][3], state[3][i]);
        }

        for j in 0..4 {
            state[j][i] = temp_column[j];
        }
    }
}


pub fn sub_bytes(state: &mut [[u8; 4]; 4]) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {

            // Split byte into high/low nibbles (4-bit halves)
            let high_nibble = (*byte >> 4) as usize;
            let low_nibble = (*byte & 0x0F) as usize;
            
            // Substitute using S-box
            *byte = S_BOX[high_nibble][low_nibble];
        }
    }
}

pub fn inv_sub_bytes(state: &mut [[u8; 4]; 4]) {
    for row in state.iter_mut() {
        for byte in row.iter_mut() {

            // Split byte into high/low nibbles (4-bit halves)
            let high_nibble = (*byte >> 4) as usize;
            let low_nibble = (*byte & 0x0F) as usize;
            
            // Substitute using Inverse S-box
            *byte = INV_S_BOX[high_nibble][low_nibble];
        }
    }
}

pub fn add_round_key(key: &[u8; 16], state: &mut [[u8; 4]; 4]) {

    //xor round key with state_matrix
    let key_matrix = bytes_to_state(key);
    for (state_row, key_row) in state.iter_mut().zip(key_matrix.iter()) {
        for (state_byte, key_byte) in state_row.iter_mut().zip(key_row.iter()) {
            *state_byte ^= *key_byte; // XOR in-place
        }
    }
}

pub fn expand_key(key: &[u8], rounds: usize) -> Vec<[u8; 16]> {
    let key_size = key.len()/4;

    let mut words = Vec::<[u8;4]>::new();

    let round_constants: [u8; 10] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36];
    let mut round_count = 0;

    //Add initial key
    for word in key.chunks_exact(4){
        words.push(word.try_into().unwrap());
    }

    //key expansion is here
    while words.len() < 4 * (rounds + 1) {

        //init new word
        let mut new_word = words[words.len() - key_size].clone();

        if words.len() % key_size == 0 {

            //When the above triggers it means we are about to create a new key, first word of each key is created by xor'ing the new word created above with the previous word that has had operations done to it as below
            let mut new_key_word = words[words.len()-1].clone();

            //Rotate Word
            new_key_word.rotate_left(1);

            //Sub Word
            for  byte in new_key_word.iter_mut() {
                let high_nibble = (*byte >> 4) as usize;
                let low_nibble = (*byte & 0x0F) as usize;
                
                *byte = S_BOX[high_nibble][low_nibble];
            }

            //rcon added
            new_key_word[0] ^= round_constants[round_count];
            round_count += 1; 

            //xor with new word
            for  (byte1, byte2) in new_word.iter_mut().zip(new_key_word.iter()) {
                *byte1 ^= byte2;
            }

        } else {

            //xor with previous word
            for (byte1 , byte2) in new_word.iter_mut().zip(words[words.len()-1].iter()) {
                *byte1 ^= byte2;
            }
        }



        words.push(new_word);
    }
    println!("Total Words: {}", words.len());

    let round_keys = words.chunks(4).filter(|chunk| chunk.len() == 4).map(
        |chunk| {
            let mut new = [0; 16];
            for (i, &arr) in chunk.iter().enumerate() {
                new[i*4..(i+1)*4].copy_from_slice(&arr);
            }
            new
        }).collect(); 

    round_keys
}


pub fn padding(unpadded: &[u8], block_size: usize) -> Vec<u8>{
    let padding_length = block_size - (unpadded.len() % block_size);
    
    let mut padded = Vec::with_capacity(unpadded.len() + padding_length);
    padded.extend(unpadded);
    
    padded.extend(std::iter::repeat(padding_length as u8).take(padding_length));
    
    padded
}

/// Removes PKCS#7 padding in-place from a vector
/// Panics if padding is invalid
pub fn unpad(padded: &mut Vec<u8>) {
    if padded.is_empty() {
        return;
    }

    let pad_length = *padded.last().unwrap() as usize;
    
    if pad_length == 0 || pad_length > padded.len() || pad_length > 256 {
        panic!("Invalid padding length");
    }

    for &byte in &padded[padded.len() - pad_length..] {
        if byte != pad_length as u8 {
            panic!("Invalid padding bytes");
        }
    }
    
    // Remove padding in-place
    padded.truncate(padded.len() - pad_length);
}