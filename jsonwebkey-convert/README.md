# jsonwebkey-convert
Convert an RSA public key between Json Web Key and DER/PEM format.

## Convert PEM to JWK
```rust
use jsonwebkey_convert::*;

fn main() -> Result<(), JWKConvertError> {
    let pem_data = include_bytes!("../testfiles/test1.pem");
    let pem_rsa = load_pem(&pem_data[..])?;
    let jwk_data = RSAJWK {
        kid: Some("3f5fbba0-06c4-467c-8d5e-e935a71437b0".to_string()),
        jwk_use: Some("sig".to_string()),
        pubkey: pem_rsa
    };

    let jwk_byte_vec = jwk_data.to_jwk()?;
    Ok(())
}
```

## Convert JWK to PEM

```rust
use jsonwebkey_convert::*;

fn main() -> Result<(), JWKConvertError> {
    let jwk_byte_vec = include_bytes!("../testfiles/test1.json");
    let jwk_data = load_jwk(&jwk_byte_vec[..])?;
    let rsa_pubkey = jwk_data.pubkey;
    let pem_string = rsa_pubkey.to_pem()?;
    Ok(())
}
```