use sha256::digest;

pub fn hmac_sha256(key: Vec<u8>, message: &'static [u8]) -> String {
    let mut outer_pad: Vec<u8> = Vec::new();
    let mut inner_pad: Vec<u8> = Vec::new();
    let mut key_appended_message = key.clone();
    
    while key_appended_message.len() % 64 != 0 {
        key_appended_message.push(0);
    }

    for byte in key_appended_message {
        inner_pad.push(byte ^ 0x36);
    }

    for byte in message {
        inner_pad.push(*byte);
    }

    let inner_hash = digest(inner_pad);

    for byte in key {
        outer_pad.push(byte ^ 0x5C);
    }

    for byte in inner_hash.as_bytes() {
        outer_pad.push(*byte);
    }

    digest(outer_pad)
    
}