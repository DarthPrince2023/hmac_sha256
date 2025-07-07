use sha2::{Sha256, Digest};

pub fn hmac_sha256(key: Vec<u8>, message: &'static [u8]) -> String {
    let mut outter_pad: Vec<u8> = Vec::new();
    let mut inner_pad: Vec<u8> = Vec::new();
    let mut key_appended_message = key.clone();
    let mut inner_pad_hasher = Sha256::new();
    let mut outter_pad_hasher = Sha256::new();
    
    while key_appended_message.len() % 64 != 0 {
        key_appended_message.push(0);
    }

    for byte in key_appended_message {
        inner_pad.push(byte ^ 0x36);
    }

    for byte in message {
        inner_pad.push(*byte);
    }

    inner_pad_hasher.update(inner_pad);
    
    let inner_hash = inner_pad_hasher.finalize();


    for byte in key {
        outter_pad.push(byte ^ 0x5C);
    }

    for byte in inner_hash {
        outter_pad.push(byte);
    }

    outter_pad_hasher.update(outter_pad);
    
    let outter_hash_bytes = outter_pad_hasher.finalize();
    
    hex::encode(outter_hash_bytes)
}