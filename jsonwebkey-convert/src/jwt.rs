use super::*;
use jsonwebtoken::DecodingKey;

pub trait ToDecodingKey {
    fn to_decoding_key(&'_ self) -> DecodingKey<'_>;
}

impl ToDecodingKey for RSAPublicKey {
    fn to_decoding_key(&'_ self) -> DecodingKey<'_> {
        DecodingKey::from_rsa_components(&self.n.base64, &self.e.base64)
    }
}
