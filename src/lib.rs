pub mod algorithms;

#[cfg(test)]
mod tests {
    use crate::algorithms::{hmac_sha_256::hmac_sha256, hmac_sha_512::hmac_sha512, };

    #[test]
    fn it_works() {
        let sha256 = hmac_sha256(b"Jefe".to_vec(), b"what do ya want for nothing?");
        let sha512 = hmac_sha512(b"Jefe".to_vec(), b"heaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

        assert_eq!(sha256, "74d96e41a3cdf8ae8ee54014089166ccc2e3d7d76ea38fc0e0d936d2152a4007");
        assert_eq!(sha512, "99d12091f2112502c9062a3a072c463cf15240035acac6db13bba2556e36a3a902ae610401f7c2552ca82d624b880ec8d8adba7ca037aeb68448f09f5af5c92d");
    }
}
