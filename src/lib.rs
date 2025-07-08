pub mod algorithms;

#[cfg(test)]
mod tests {
    use crate::algorithms::{hmac_sha_256::hmac_sha256, hmac_sha_512::{hmac_sha512, sha512}, };

    #[test]
    fn it_works() {
        println!("{}", hex::encode("3732313031313038313038313131303030"));
        let sha256 = hmac_sha256(b"Jefe".to_vec(), b"what do ya want for nothing?");
        let sha5123 = hmac_sha512(b"Jefe".to_vec(), b"heaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        println!("{:?}", sha512("Hello".to_string()));
        assert_eq!(sha256, "7112d130efb0ed1417a6c9f80ea18d1b51c76a173236c29cda4a7e87b88413b2");
        assert_eq!(sha5123, "99d12091f2112502c9062a3a072c463cf15240035acac6db13bba2556e36a3a902ae610401f7c2552ca82d624b880ec8d8adba7ca037aeb68448f09f5af5c92d");
    }
}
