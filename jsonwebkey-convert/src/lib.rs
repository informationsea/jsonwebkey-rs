//! # jsonwebkey-convert
//! Handle Json Web Key without nightly rust compiler.
//!
//! ## Load JSON Web Key Set
//!
//! ```
//! use jsonwebkey_convert::JsonWebKeySet;
//! # use jsonwebkey_convert::Error;
//!
//! # fn main() -> Result<(), Error> {
//! # let jwks_str = include_str!("../testfiles/example-public-key.json");
//! let jwks: JsonWebKeySet = jwks_str.parse()?;
//! # Ok(())
//! # }
//! ```
//!
//!
//! ## Convert PEM to JWK
//! `pem_support` feature is required.
//!
//! ```
//! use jsonwebkey_convert::*;
//! use jsonwebkey_convert::der::FromPem;
//!
//! # fn main() -> Result<(), Error> {
//! # let pem_data = include_str!("../testfiles/test1.pem");
//! let rsa_jwk = RSAPublicKey::from_pem(pem_data)?;
//! let jwk_byte_vec = serde_json::to_string(&rsa_jwk);
//! # Ok(())
//! # }
//! ```
//!
//! ## Convert JWK to PEM
//! `pem_support` feature is required.
//!
//! ```
//! use jsonwebkey_convert::*;
//! use jsonwebkey_convert::der::ToPem;
//!
//! # fn main() -> Result<(), Error> {
//! # let jwk_data = include_str!("../testfiles/test1.json");
//! let rsa_jwk: RSAPublicKey = jwk_data.parse()?;
//! let pem_data = rsa_jwk.to_pem()?;
//! # Ok(())
//! # }
//! ```

/// DER and PEM format support
#[cfg(feature = "simple_asn1")]
pub mod der;

/// Json Web Token support
#[cfg(feature = "jsonwebtoken")]
pub mod jwt;

use num_bigint::BigUint;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Public Key Parse Error: {0}")]
    PubKeyParse(&'static str),
    #[cfg(feature = "simple_asn1")]
    #[error(transparent)]
    ANS1DecodeError(#[from] simple_asn1::ASN1DecodeErr),
    #[cfg(feature = "simple_asn1")]
    #[error(transparent)]
    ANS1EncodeError(#[from] simple_asn1::ASN1EncodeErr),
    #[error(transparent)]
    #[cfg(feature = "pem")]
    PEMParseError(#[from] pem::PemError),
    #[error(transparent)]
    Base64UrlError(#[from] base64::DecodeError),
    #[error(transparent)]
    JSONParseError(#[from] serde_json::Error),
}

/// A set of Json Web Keys
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JsonWebKeySet {
    pub keys: Vec<JsonWebKey>,
}

impl JsonWebKeySet {
    pub fn from_bytes(data: &[u8]) -> Result<JsonWebKeySet, Error> {
        Ok(serde_json::from_slice(data)?)
    }
}

impl FromStr for JsonWebKeySet {
    type Err = Error;
    fn from_str(data: &str) -> Result<JsonWebKeySet, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

/// A JSON Web Key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum JsonWebKey {
    ECPrivateKey {
        #[serde(flatten)]
        value: ECPrivateKey,
    },
    ECPublicKey {
        #[serde(flatten)]
        value: ECPublicKey,
    },
    RSAPrivateKey {
        #[serde(flatten)]
        value: Box<RSAPrivateKey>,
    },
    RSAPublicKey {
        #[serde(flatten)]
        value: RSAPublicKey,
    },
    SymmetricKey {
        #[serde(flatten)]
        value: SymmetricKey,
    },
}
impl FromStr for JsonWebKey {
    type Err = Error;
    fn from_str(data: &str) -> Result<JsonWebKey, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

impl JsonWebKey {
    pub fn from_bytes(data: &[u8]) -> Result<JsonWebKey, Error> {
        Ok(serde_json::from_slice(data)?)
    }

    pub fn ec_private_key(&self) -> Option<&ECPrivateKey> {
        match self {
            JsonWebKey::ECPrivateKey { value } => Some(value),
            _ => None,
        }
    }

    pub fn ec_public_key(&self) -> Option<&ECPublicKey> {
        match self {
            JsonWebKey::ECPublicKey { value } => Some(value),
            _ => None,
        }
    }

    pub fn rsa_private_key(&self) -> Option<&RSAPrivateKey> {
        match self {
            JsonWebKey::RSAPrivateKey { value } => Some(value),
            _ => None,
        }
    }

    pub fn rsa_public_key(&self) -> Option<&RSAPublicKey> {
        match self {
            JsonWebKey::RSAPublicKey { value } => Some(value),
            _ => None,
        }
    }

    pub fn symmetric_key(&self) -> Option<&SymmetricKey> {
        match self {
            JsonWebKey::SymmetricKey { value } => Some(value),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Copy, Serialize, Deserialize)]
pub enum ECCurveParameter {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

/// BASE64 encoded big integer
#[derive(Debug, Clone, PartialEq)]
pub struct Base64BigUint {
    big_uint: BigUint,
    base64: String,
}

impl Base64BigUint {
    pub fn to_base64url(&self) -> String {
        base64::encode_config(&self.big_uint.to_bytes_be(), base64::URL_SAFE_NO_PAD)
    }

    pub fn from_base64url(value: &str) -> Result<Self, Error> {
        Ok(Base64BigUint {
            big_uint: BigUint::from_bytes_be(&base64::decode_config(
                value,
                base64::URL_SAFE_NO_PAD,
            )?),
            base64: value.to_string(),
        })
    }
}

impl Into<BigUint> for Base64BigUint {
    fn into(self) -> BigUint {
        self.big_uint
    }
}

impl Into<Base64BigUint> for BigUint {
    fn into(self) -> Base64BigUint {
        Base64BigUint {
            base64: base64::encode_config(self.to_bytes_be(), base64::URL_SAFE_NO_PAD),
            big_uint: self,
        }
    }
}

impl Serialize for Base64BigUint {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_base64url().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Base64BigUint {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Ok(Base64BigUint::from_base64url(&value).map_err(|e| {
            D::Error::custom(format!("failed to decode BASE64 URL: {} : {}", value, e))
        })?)
    }
}

// RFC 7518
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct ECPublicKey {
    #[serde(flatten)]
    pub generic: Generic,
    pub crv: ECCurveParameter,
    pub x: Base64BigUint,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<Base64BigUint>,
}

impl FromStr for ECPublicKey {
    type Err = Error;
    fn from_str(data: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct ECPrivateKey {
    #[serde(flatten)]
    pub public_key: ECPublicKey,
    pub d: Base64BigUint,
}

impl FromStr for ECPrivateKey {
    type Err = Error;
    fn from_str(data: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct RSAPublicKey {
    #[serde(flatten)]
    pub generic: Generic,
    pub n: Base64BigUint,
    pub e: Base64BigUint,
}

impl FromStr for RSAPublicKey {
    type Err = Error;
    fn from_str(data: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct RSAPrivateKey {
    #[serde(flatten)]
    pub public_key: RSAPublicKey,
    pub d: Base64BigUint,
    #[serde(flatten)]
    pub optimizations: Option<RSAPrivateKeyOptimizations>,
    pub oth: Option<Vec<RSAPrivateKeyOtherPrimesInfo>>,
}

impl FromStr for RSAPrivateKey {
    type Err = Error;
    fn from_str(data: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct RSAPrivateKeyOptimizations {
    pub p: Base64BigUint,
    pub q: Base64BigUint,
    pub dp: Base64BigUint,
    pub dq: Base64BigUint,
    pub qi: Base64BigUint,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
//#[serde(deny_unknown_fields)]
pub struct RSAPrivateKeyOtherPrimesInfo {
    pub r: Base64BigUint,
    pub d: Base64BigUint,
    pub t: Base64BigUint,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SymmetricKey {
    #[serde(flatten)]
    pub generic: Generic,
    pub k: String,
}

impl FromStr for SymmetricKey {
    type Err = Error;
    fn from_str(data: &str) -> Result<Self, Error> {
        Ok(serde_json::from_str(data)?)
    }
}

/// A type of JWK.
/// See RFC 7518 Section 6.1.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    #[serde(rename = "EC")]
    EllipticCurve,
    #[serde(rename = "RSA")]
    Rsa,
    #[serde(rename = "oct")]
    OctetSequence,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum KeyUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
}

/// Generic parameters for JSON Web Key.
/// See RFC 7517, Section 4.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Generic {
    // Generic parameters
    pub kty: KeyType,
    #[serde(skip_serializing_if = "Option::is_none", rename = "use")]
    pub use_: Option<KeyUse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", rename = "x5t#S256")]
    pub x5t_s256: Option<String>,
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn load_rsa_pubkey1() -> Result<(), serde_json::Error> {
        let pubkey_json: JsonWebKey =
            serde_json::from_str(include_str!("../testfiles/test1.json"))?;
        let pubkey_data = pubkey_json.rsa_public_key().unwrap();
        assert_eq!(pubkey_data.generic.kty, KeyType::Rsa);
        assert_eq!(pubkey_data.e.big_uint, BigUint::from(65537u64));
        Ok(())
    }

    #[test]
    fn load_rsa_pubkey2() -> Result<(), serde_json::Error> {
        let pubkey_json: JsonWebKey =
            serde_json::from_str(include_str!("../testfiles/test2.json"))?;
        let pubkey_data = pubkey_json.rsa_public_key().unwrap();
        assert_eq!(pubkey_data.generic.kty, KeyType::Rsa);
        assert_eq!(pubkey_data.generic.alg.as_ref().unwrap(), "RS256");
        assert_eq!(pubkey_data.generic.use_.unwrap(), KeyUse::Signature);
        assert_eq!(
            pubkey_data.generic.kid.as_ref().unwrap(),
            "ctFNPw6mrKynlD3atDovZGBlbWRXj7IK0IBODJ_hqeI"
        );
        assert_eq!(
            pubkey_data.generic.x5t.as_ref().unwrap(),
            "ZsHe1ebgPQqmqNF8rjKqWEjh4hk"
        );
        assert_eq!(
            pubkey_data.generic.x5t_s256.as_ref().unwrap(),
            "VaYCCwkyvl8K71fldYXJtNjHAPTGom2ylqdAbedtKUI"
        );
        assert_eq!(pubkey_data.e.big_uint, BigUint::from(65537u64));
        Ok(())
    }

    #[test]
    fn load_private_keys() -> Result<(), serde_json::Error> {
        let privkey_json: JsonWebKeySet =
            serde_json::from_str(include_str!("../testfiles/example-private-key.json"))?;
        assert_eq!(privkey_json.keys.len(), 2);

        let ec_private_key = privkey_json.keys[0].ec_private_key().unwrap();
        assert_eq!(
            ec_private_key.public_key.generic.kty,
            KeyType::EllipticCurve
        );
        assert_eq!(ec_private_key.public_key.crv, ECCurveParameter::P256);
        assert_eq!(
            ec_private_key.public_key.generic.use_.unwrap(),
            KeyUse::Encryption
        );
        assert_eq!(ec_private_key.public_key.generic.kid.as_ref().unwrap(), "1");

        let rsa_private_key = privkey_json.keys[1].rsa_private_key().unwrap();
        assert_eq!(rsa_private_key.public_key.generic.kty, KeyType::Rsa);
        assert!(rsa_private_key.optimizations.is_some());

        Ok(())
    }

    #[test]
    fn load_public_keys() -> Result<(), serde_json::Error> {
        let pubkey_json: JsonWebKeySet =
            serde_json::from_str(include_str!("../testfiles/example-public-key.json"))?;

        let ec_public_key = pubkey_json.keys[0].ec_public_key().unwrap();
        assert_eq!(ec_public_key.generic.kty, KeyType::EllipticCurve);
        assert_eq!(ec_public_key.crv, ECCurveParameter::P256);
        assert_eq!(ec_public_key.generic.use_.unwrap(), KeyUse::Encryption);
        assert_eq!(ec_public_key.generic.kid.as_ref().unwrap(), "1");
        assert_eq!(
            ec_public_key.x.to_base64url(),
            "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4"
        );
        assert_eq!(
            ec_public_key.y.as_ref().unwrap().to_base64url(),
            "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
        );

        let rsa_public_key = pubkey_json.keys[1].rsa_public_key().unwrap();
        assert_eq!(rsa_public_key.generic.kty, KeyType::Rsa);
        assert_eq!(rsa_public_key.e.to_base64url(), "AQAB");
        assert_eq!(rsa_public_key.n.to_base64url(), "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw");
        assert_eq!(rsa_public_key.generic.alg.as_ref().unwrap(), "RS256");
        Ok(())
    }

    #[test]
    fn load_symmetric_keys() -> Result<(), serde_json::Error> {
        let symmetric_json: JsonWebKeySet =
            serde_json::from_str(include_str!("../testfiles/example-symmetric-keys.json"))?;

        let symmetric_key = symmetric_json.keys[0].symmetric_key().unwrap();
        assert_eq!(symmetric_key.generic.kty, KeyType::OctetSequence);
        assert_eq!(symmetric_key.generic.alg.as_ref().unwrap(), "A128KW");
        assert_eq!(symmetric_key.k, "GawgguFyGrWKav7AX4VKUg");

        let symmetric_key = symmetric_json.keys[1].symmetric_key().unwrap();
        assert_eq!(symmetric_key.generic.kty, KeyType::OctetSequence);
        assert_eq!(symmetric_key.k, "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow");
        assert_eq!(
            symmetric_key.generic.kid.as_ref().unwrap(),
            "HMAC key used in JWS spec Appendix A.1 example"
        );
        Ok(())
    }
}
