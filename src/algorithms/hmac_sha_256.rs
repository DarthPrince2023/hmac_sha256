use sha2::{Sha256, Digest};

pub fn hmac_sha256(key: Vec<u8>, message: &'static [u8]) -> String {
    // The outter pad is going to store the padded key,
    // with the hashed bytes for the inner pad, concatenated to the message bytes
    let mut outter_pad: Vec<u8> = Vec::new();
    let mut inner_pad: Vec<u8> = Vec::new();
    let mut key_appended_message = key.clone();

    // Create a SHA256 hasher for the inner pad
    let mut inner_pad_hasher = Sha256::new();

    // Create a SHA256 hasher for the outter pad
    let mut outter_pad_hasher = Sha256::new();

    if key_appended_message.len() > 64 {
        let mut hasher = Sha256::new();
        hasher.update(key_appended_message);
        key_appended_message = hasher.finalize().to_vec();
    }
    
    // Make sure the key block is 512 bytes by padding it out with 0s
    while key_appended_message.len() % 64 != 0 ||
        key_appended_message.len() == 0 {
        key_appended_message.push(0);
    }

    // xor each byte in the key with 0x36, push the result to the inner pad vector
    for byte in key_appended_message.clone() {
        inner_pad.push(byte ^ 0x36);
    }

    // Finally concatenate the message bytes to the ipad
    for byte in message {
        inner_pad.push(*byte);
    }

    // hash the inner_pad bytes
    inner_pad_hasher.update(inner_pad);
    
    let inner_hash = inner_pad_hasher.finalize();

    // Push the key to the outter pad
    for byte in key_appended_message {
        outter_pad.push(byte ^ 0x5C);
    }

    // Append the hashed ipad and message bytes to the outter pad bytes
    for byte in inner_hash {
        outter_pad.push(byte);
    }

    // Hash the outter final data
    outter_pad_hasher.update(outter_pad);
    
    let outter_hash_bytes = outter_pad_hasher.finalize();
    
    // Return the hashed bytes as a hex string
    hex::encode(outter_hash_bytes)
}