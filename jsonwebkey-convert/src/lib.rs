//! # jsonwebkey-convert
//! Convert an RSA public key between Json Web Key and DER/PEM format.
//!
//! ## Convert PEM to JWK
//! ```
//! use jsonwebkey_convert::*;
//!
//! # fn main() -> Result<(), JWKConvertError> {
//! # let pem_data = include_bytes!("../testfiles/test1.pem");
//! let pem_rsa = load_pem(&pem_data[..])?;
//! let jwk_data = RSAJWK {
//!     kid: Some("3f5fbba0-06c4-467c-8d5e-e935a71437b0".to_string()),
//!     jwk_use: Some("sig".to_string()),
//!     pubkey: pem_rsa
//! };
//! let jwk_byte_vec = jwk_data.to_jwk()?;
//! # Ok(())
//! # }
//! ```
//!
//! ## Convert JWK to PEM
//! ```
//! use jsonwebkey_convert::*;
//!
//! # fn main() -> Result<(), JWKConvertError> {
//! # let jwk_byte_vec = include_bytes!("../testfiles/test1.json");
//! let jwk_data = load_jwk(&jwk_byte_vec[..])?;
//! let rsa_pubkey = jwk_data.pubkey;
//! let pem_string = rsa_pubkey.to_pem()?;
//! # Ok(())
//! # }
//! ```

use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use simple_asn1::{oid, ASN1Block, BigInt, BigUint, OID};
use std::convert::TryInto;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum JWKConvertError {
    #[error("JWK Parse Error: {0}")]
    JWKParseError(&'static str),
    #[error("Public Key Parse Error: {0}")]
    PubKeyParse(&'static str),
    #[error(transparent)]
    ANS1DecodeError(#[from] simple_asn1::ASN1DecodeErr),
    #[error(transparent)]
    ANS1EncodeError(#[from] simple_asn1::ASN1EncodeErr),
    #[error(transparent)]
    PEMParseError(#[from] pem::PemError),
    #[error(transparent)]
    Base64UrlError(#[from] base64_url::base64::DecodeError),
    #[error(transparent)]
    JSONParseError(#[from] serde_json::Error),
}

lazy_static! {
    static ref RSA_OID: simple_asn1::OID = oid!(1, 2, 840, 113549, 1, 1, 1);
}

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct RSAPubKeyJWK {
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    kty: String,

    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    use_: Option<String>,
    n: String,
    e: String,
}

/// RSA Public Key with kid and use
#[derive(Debug, PartialEq)]
pub struct RSAJWK {
    pub kid: Option<String>,
    pub jwk_use: Option<String>,
    pub pubkey: RSAPubKey,
}

impl Into<RSAPubKey> for RSAJWK {
    fn into(self) -> RSAPubKey {
        self.pubkey
    }
}

/// RSA Public Key
#[derive(Debug, PartialEq)]
pub struct RSAPubKey {
    pub n: BigInt,
    pub e: BigInt,
}

impl Into<RSAJWK> for RSAPubKey {
    fn into(self) -> RSAJWK {
        RSAJWK {
            kid: None,
            jwk_use: None,
            pubkey: self,
        }
    }
}

impl TryInto<RSAJWK> for RSAPubKeyJWK {
    type Error = JWKConvertError;
    fn try_into(self) -> Result<RSAJWK, Self::Error> {
        if self.kty != "RSA" {
            return Err(JWKConvertError::JWKParseError("Unspported type"));
        }
        let n = base64_url::decode(&self.n)?;
        let e = base64_url::decode(&self.e)?;
        Ok(RSAJWK {
            kid: self.kid,
            jwk_use: self.use_,
            pubkey: RSAPubKey {
                n: BigInt::from_bytes_be(num_bigint::Sign::Plus, &n),
                e: BigInt::from_bytes_be(num_bigint::Sign::Plus, &e),
            },
        })
    }
}

impl RSAJWK {
    pub fn to_jwk(&self) -> Result<String, JWKConvertError> {
        let jwk = RSAPubKeyJWK {
            kid: self.kid.clone(),
            kty: "RSA".to_string(),
            use_: self.jwk_use.clone(),
            n: base64_url::encode(&self.pubkey.n.to_bytes_be().1),
            e: base64_url::encode(&self.pubkey.e.to_bytes_be().1),
        };
        serde_json::to_string(&jwk).map_err(JWKConvertError::JSONParseError)
    }
}

impl RSAPubKey {
    pub fn to_der(&self) -> Result<Vec<u8>, JWKConvertError> {
        let pubkey_asn1 = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Integer(0, self.n.clone()),
                ASN1Block::Integer(0, self.e.clone()),
            ],
        );
        let pubkey_der = simple_asn1::to_der(&pubkey_asn1)?;
        let asn1 = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Sequence(
                    0,
                    vec![
                        ASN1Block::ObjectIdentifier(0, RSA_OID.clone()),
                        ASN1Block::Null(0),
                    ],
                ),
                ASN1Block::BitString(0, pubkey_der.len() * 8, pubkey_der),
            ],
        );

        Ok(simple_asn1::to_der(&asn1)?)
    }

    pub fn to_pem(&self) -> Result<String, JWKConvertError> {
        let der = self.to_der()?;
        let pem = pem::Pem {
            tag: "PUBLIC KEY".to_string(),
            contents: der,
        };
        Ok(pem::encode(&pem))
    }
}

/// Load a Json Web Key from bytes slice
pub fn load_jwk(data: &[u8]) -> Result<RSAJWK, JWKConvertError> {
    let jwk: RSAPubKeyJWK = serde_json::from_slice(data)?;
    Ok(jwk.try_into()?)
}

/// Load an RSA public key from DER format
pub fn load_der(data: &[u8]) -> Result<RSAPubKey, JWKConvertError> {
    let ans1_block_vec = simple_asn1::from_der(data)?;
    if ans1_block_vec.len() != 1 {
        return Err(JWKConvertError::PubKeyParse(
            "Invalid number of sequence: 1",
        ));
    }
    let ans1_seq = if let ASN1Block::Sequence(_, d) = &ans1_block_vec[0] {
        d
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 2"));
    };
    if ans1_seq.len() != 2 {
        return Err(JWKConvertError::PubKeyParse(
            "Invalid number of sequence: 3",
        ));
    }
    //println!("pubkey der: {:?}", ans1_seq);

    let oid_seq = if let ASN1Block::Sequence(_, s) = &ans1_seq[0] {
        s
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 3"));
    };
    let oid = if let ASN1Block::ObjectIdentifier(_, o) = &oid_seq[0] {
        o
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 4"));
    };
    if oid != *RSA_OID {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 5"));
    }

    let bit_string = if let ASN1Block::BitString(_, _, s) = &ans1_seq[1] {
        s
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 6"));
    };

    let parsed_der =
        simple_asn1::from_der(&bit_string).map_err(JWKConvertError::ANS1DecodeError)?;
    if parsed_der.len() != 1 {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 7"));
    }
    let pubkey_seq = if let ASN1Block::Sequence(_, s) = &parsed_der[0] {
        s
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 8"));
    };
    if pubkey_seq.len() != 2 {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 9"));
    }
    let n = if let ASN1Block::Integer(_, n) = &pubkey_seq[0] {
        n
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 10"));
    };
    let e = if let ASN1Block::Integer(_, e) = &pubkey_seq[1] {
        e
    } else {
        return Err(JWKConvertError::PubKeyParse("Invalid format: 11"));
    };

    let rsa_pub_key = RSAPubKey {
        e: e.clone(),
        n: n.clone(),
    };

    Ok(rsa_pub_key)
}

/// Load an RSA public key from PEM format
pub fn load_pem(data: &[u8]) -> Result<RSAPubKey, JWKConvertError> {
    let data = pem::parse(data)?;
    load_der(&data.contents)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::str;

    #[test]
    fn load_jwk1() -> Result<(), Box<dyn std::error::Error>> {
        let mut reader = File::open("testfiles/test1.json")?;
        let data: RSAPubKeyJWK = serde_json::from_reader(&mut reader)?;

        assert_eq!(
            data,
            RSAPubKeyJWK {
                kid: Some("fe41cf0f-7901-489f-9d4e-1437d6c1aa1f".to_string()),
                kty: "RSA".to_string(),
                use_: None,
                n: "rAINWn65QjweP2o9mzZF0dj1V_qlyBs9anRd_OA_iJUk2vTXU9FrzPl1AT8xT570ZGq7UW_dLE-ANUcL10Xr2I-bzVL9IL6aYnjO9L_lqbilfScfJSfT81Oho-vnj5FJH1LaD6s90vStEcSH49kwNoDDK9BXYovFEtxFeFx-H0eRoxHdxo7_91YBPyez4JjBYrBs29Sro2DbVSRxaW384HWXhEYNtGp2Z3Qf22t2o4tUkfxs_fuaU24mwKCWykfnQ5Cq8V7NAIqgWxhVsubjy9yCZ0kFxCNf_cs9hkWIYtVNSDjFg9P30bwy1-37Y01Lb4KVBW6fN7whCq_y-NlJWQ".to_string(),
                e: "AQAB".to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn load_jwk2() -> Result<(), Box<dyn std::error::Error>> {
        let mut reader = File::open("testfiles/test2.json")?;
        let data: RSAPubKeyJWK = serde_json::from_reader(&mut reader)?;

        assert_eq!(
            data,
            RSAPubKeyJWK {
                kid: Some("ctFNPw6mrKynlD3atDovZGBlbWRXj7IK0IBODJ_hqeI".to_string()),
                kty: "RSA".to_string(),
                use_: Some("sig".to_string()),
                n: "r3tms5oOWdyOO-XqMdNkLdp7tm5Eb7kY2ENPCCt-bpU6pC1-QOO3dfTs9LeiyeyonZpqD93ghW1pe5LB49rt1e2BqPNZdndGJZWmtAlv9YXCkLKat6GaG2e7gNzuq7Ls-my-vAYmS6B71KpkBTze2S3KcTjTEP6tPbJzgqZ6vPNK3EYbdCPZHi-QujRmGWUBeUdwsOnGWslaVlmkd4nIeqWYjV-mFD07WwB1y-pWBlC39A_RY4XUGP8WFxd0RSFNy3EoJw1yDK6_-1_xZZfzlRn0JpZsl6p-8zI8FgvMpQmXTSiAgfhYJGhBRZuvOPUrHBhwNE0GeqYYbUiOsXQHiw".to_string(),
                e: "AQAB".to_string()
            }
        );
        Ok(())
    }

    #[test]
    fn test_parse_der1() -> Result<(), JWKConvertError> {
        let pem_data = include_bytes!("../testfiles/test1.pem");
        let pem_rsa = load_pem(&pem_data[..])?;
        let jwk_data = include_bytes!("../testfiles/test1.json");
        let jwk_rsa = load_jwk(&jwk_data[..])?;
        assert_eq!(pem_rsa, jwk_rsa.pubkey);

        let generated_pem = jwk_rsa.pubkey.to_pem()?;
        assert_eq!(generated_pem, str::from_utf8(&pem_data[..]).unwrap());

        let jwk_parsed: RSAPubKeyJWK =
            serde_json::from_slice(jwk_data).map_err(JWKConvertError::JSONParseError)?;
        let pem_jwk: RSAPubKeyJWK = serde_json::from_str(
            &RSAJWK {
                pubkey: pem_rsa,
                kid: jwk_rsa.kid.clone(),
                jwk_use: jwk_rsa.jwk_use,
            }
            .to_jwk()?,
        )
        .map_err(JWKConvertError::JSONParseError)?;
        assert_eq!(jwk_parsed, pem_jwk);
        Ok(())
    }

    #[test]
    fn test_parse_der2() -> Result<(), JWKConvertError> {
        let pem_data = include_bytes!("../testfiles/test2.pem");
        let pem_rsa = load_pem(&pem_data[..])?;
        let jwk_data = include_bytes!("../testfiles/test2.json");
        let jwk_rsa = load_jwk(&jwk_data[..])?;
        assert_eq!(pem_rsa, jwk_rsa.pubkey);

        let generated_pem = jwk_rsa.pubkey.to_pem()?;
        assert_eq!(generated_pem, str::from_utf8(&pem_data[..]).unwrap());

        let jwk_parsed: RSAPubKeyJWK = serde_json::from_slice(jwk_data)?;
        let pem_jwk: RSAPubKeyJWK = serde_json::from_str(
            &RSAJWK {
                pubkey: pem_rsa,
                kid: jwk_rsa.kid.clone(),
                jwk_use: jwk_rsa.jwk_use,
            }
            .to_jwk()?,
        )?;
        assert_eq!(jwk_parsed, pem_jwk);

        Ok(())
    }
}
