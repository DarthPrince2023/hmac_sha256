use hmac_crate::algorithms::{hmac_sha_256::hmac_sha256, hmac_sha_512::hmac_sha512};

#[test]
fn test_rfc4231_sha256() {
    let key = vec![0x0b; 20];
    let message = b"Hi There";
    let expected = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";
    assert_eq!(hmac_sha256(key, message), expected);
}

#[test]
fn test_rfc4231_sha512() {
    let key = vec![0x0b; 20];
    let message = b"Hi There";
    let expected = "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854";
    assert_eq!(hmac_sha512(key, message), expected);
}

#[test]
fn test_empty_key_message_sha256() {
    let key = vec![];
    let message = b"";
    let expected = "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad";
    assert_eq!(hmac_sha256(key.clone(), message), expected);
}

#[test]
fn test_empty_key_message_sha512() {
    let key = vec![];
    let message = b"";
    let expected = "b936cee86c9f87aa5d3c6f2e84cb5a4239a5fe50480a6ec66b70ab5b1f4ac6730c6c515421b327ec1d69402e53dfb49ad7381eb067b338fd7b0cb22247225d47";
    assert_eq!(hmac_sha512(key, message), expected);
}

#[test]
fn test_long_key_sha256() {
    let key = vec![0x41; 100];
    let message = b"Test message";
    let expected = "a950e7a98d0cc5f64d8764894463f0d8209f9901365bb01220a500664ca67c40";
    assert_eq!(hmac_sha256(key, message), expected);
}

#[test]
fn test_long_key_sha512() {
    let key = vec![0x41; 100];
    let message = b"Test message";
    let expected = "e4932e489431201fc6c72aa1e719fd7f25cadb5b0591df7ce9216b438f9ae00f54f50b655da8553c61de3e36a0e6fa5224ae31b2e385a74b121c97833bc47daa";
    assert_eq!(hmac_sha512(key, message), expected);
}

#[test]
fn test_unicode_input_sha256() {
    let key = b"key".to_vec();
    let message = "προγραμματισμός".as_bytes();
    let expected = "c8ff9a1520589850b90e076598d67121d9e6c95569103f8c3c6a08ee36ea5deb";
    assert_eq!(hmac_sha256(key, message), expected);
}

#[test]
fn test_unicode_input_sha512() {
    let key = b"key".to_vec();
    let message = "προγραμματισμός".as_bytes();
    let expected = "04402eac9ed70cff10f2aed49ce8d991fb3446560c2facca6a7e0413ec6fb019d4a03e2256b66c9bbb2f4aef835cc557725983cc5e605bee92d1d507841ca500";
    assert_eq!(hmac_sha512(key, message), expected);
}
