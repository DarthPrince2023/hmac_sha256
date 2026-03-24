    use sha2::{Sha256, Digest};

    pub fn sha256(data: Vec<u8>) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        
        let inner_hash = hasher
            .finalize()
            .to_vec();

        inner_hash
    }

    pub fn hmac_sha256(mut key: Vec<u8>, message: Vec<u8>) -> Vec<u8> {
        // The outter pad is going to store the padded key,
        // with the hashed bytes for the inner pad, concatenated to the message bytes
        let mut outter_pad: Vec<u8> = Vec::new();
        let mut inner_pad: Vec<u8> = Vec::new();

        if key.len() > 64 {
            let mut hasher = Sha256::new();
            hasher.update(key);
            key = hasher.finalize().to_vec();
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
        for byte in message {
            inner_pad.push(byte);
        }

        // hash the inner_pad bytes
        let inner_hash = sha256(inner_pad);

        // Push the key to the outter pad
        for byte in key_appended_message {
            outter_pad.push(byte ^ 0x5C);
        }

        // Append the hashed ipad and message bytes to the outter pad bytes
        for byte in inner_hash {
            outter_pad.push(byte);
        }

        // Hash the outter final data
        let outter_hash_bytes = sha256(outter_pad);

        // Return the hashed bytes as a hex string
        outter_hash_bytes.to_vec()
    }