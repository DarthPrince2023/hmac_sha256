use sha256::digest;

pub fn hmac_sha256(key: &'static [u8], message: &'static [u8]) -> String {
    let mut outer_pad: Vec<u8> = Vec::new();
    let mut inner_pad: Vec<u8> = Vec::new();
    let mut key_appended_message: Vec<u8> = key.to_vec();
    
    while key_appended_message.len() % 64 != 0 {
        key_appended_message.push(0);
    }

    for byte in &key_appended_message {
        inner_pad.push(byte ^ 0x36);
    }

    for byte in message {
        inner_pad.push(*byte);
    }

    let inner_hash = digest(inner_pad);
    
    for byte in &key.to_vec() {
        outer_pad.push(byte ^ 0x5C);
    }

    for byte in inner_hash.as_bytes() {
        outer_pad.push(*byte);
    }

    digest(outer_pad)
    
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(result, "74d96e41a3cdf8ae8ee54014089166ccc2e3d7d76ea38fc0e0d936d2152a4007");
    }
}
