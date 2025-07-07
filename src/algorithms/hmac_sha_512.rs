use sha2::{Sha512, Digest};

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