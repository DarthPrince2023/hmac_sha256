use sha::{sha1::Sha1, utils::{Digest, DigestExt}};

pub fn sha1(data: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha1::default();
    let sha1 = hasher.digest(data.as_slice())
        .to_hex()
        .as_bytes()
        .to_vec();

    sha1
}

pub fn hmac_sha1(mut key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
    // The outter pad is going to store the padded key,
    // with the hashed bytes for the inner pad, concatenated to the message bytes
    let mut outter_pad: Vec<u8> = Vec::new();
    let mut inner_pad: Vec<u8> = Vec::new();

    if key.len() > 64 {
        key = sha1(key);
    }

    let mut key_appended_message = key.clone();
        
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
    for byte in message{
        inner_pad.push(byte);
    }

    // hash the inner_pad bytes
    let inner_hash = sha1(inner_pad);

    // Push the key to the outter pad
    for byte in key_appended_message {
        outter_pad.push(byte ^ 0x5C);
    }

    // Append the hashed ipad and message bytes to the outter pad bytes
    for byte in inner_hash {
        outter_pad.push(byte);
    }

    // Hash the outter final data
    let outter_hash_bytes = sha1(outter_pad);

    // Return the hashed bytes as a hex string
    outter_hash_bytes.to_vec()
}