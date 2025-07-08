use std::{io::Read, slice::Chunks};

use sha2::{Sha512, Digest};

pub fn sha512(mut message: String) -> Vec<String> {
    const H0: u128 = 0x6a09e667f3bcc908;
    const H1: u128 = 0xbb67ae8584caa73b;
    const H2: u128 = 0x3c6ef372fe94f82b;
    const H3: u128 = 0xa54ff53a5f1d36f1;
    const H4: u128 = 0x510e527fade682d1;
    const H5: u128 = 0x9b05688c2b3e6c1f;
    const H6: u128 = 0x1f83d9abfb41bd6b;
    const H7: u128 = 0x5be0cd19137e2179;
    let mut bytes = message.as_bytes().to_vec();
    let mut words: Vec<String> = Vec::new();
    bytes.push(0x80);
    while bytes.len() % 127 != 0  {
        bytes.push(0);
    }
    let length = message.len() as u8;
    bytes.push(&length * 8);
    
    let chunks = bytes.chunks(8);
    for chunk in chunks {
        words.push(hex::encode(chunk));
    }
    words
}

pub fn hmac_sha512(mut key: Vec<u8>, message: &'static [u8]) -> String {
    let mut outer_pad: Vec<u8> = Vec::new();
    let mut inner_pad: Vec<u8> = Vec::new();
    let mut inner_pad_hasher = Sha512::new();
    let mut outter_pad_hasher = Sha512::new();

    if key.len() > 128 {
        let mut hasher = Sha512::new();
        hasher.update(key);
        key = hasher.finalize().to_vec();
    }
    
    let mut key_appended_message = key.clone();
    
    while key_appended_message.len() % 128 != 0 ||
        key_appended_message.len() == 0 {
        key_appended_message.push(0);
    }

    for byte in key_appended_message.clone() {
        inner_pad.push(byte ^ 0x36);
    }

    for byte in message {
        inner_pad.push(*byte);
    }

    inner_pad_hasher.update(&inner_pad);

    let inner_pad = inner_pad_hasher.finalize();

    for byte in key_appended_message.clone() {
        outer_pad.push(byte ^ 0x5C);
    }

    for byte in inner_pad {
        outer_pad.push(byte);
    }

    outter_pad_hasher.update(&outer_pad);

    let result = outter_pad_hasher.finalize();

    hex::encode(result.to_vec())
}