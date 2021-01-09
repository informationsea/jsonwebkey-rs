# jsonwebkey-convert
Convert an RSA public key between Json Web Key and DER/PEM format.

## Convert PEM to JWK
``` rust
use jsonwebkey_convert::*;
use jsonwebkey_convert::der::FromPem;

fn main() -> Result<(), Error> {
    let pem_data = include_str!("../testfiles/test1.pem");
    let rsa_jwk = RSAPublicKey::from_pem(pem_data)?;
    let jwk_byte_vec = serde_json::to_string(&rsa_jwk);
    Ok(())
}
```

## Convert JWK to PEM

```rust
use jsonwebkey_convert::*;
use jsonwebkey_convert::der::ToPem;

fn main() -> Result<(), Error> {
    let jwk_data = include_str!("../testfiles/test1.json");
    let rsa_jwk: RSAPublicKey = jwk_data.parse()?;
    let pem_data = rsa_jwk.to_pem()?;
    Ok(())
}
```