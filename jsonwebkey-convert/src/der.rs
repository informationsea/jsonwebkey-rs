use super::*;
use lazy_static::lazy_static;
use num_bigint::ToBigInt;
use simple_asn1::{oid, ASN1Block, BigUint, OID};

lazy_static! {
    static ref RSA_OID: simple_asn1::OID = oid!(1, 2, 840, 113549, 1, 1, 1);
}

pub trait ToPem {
    fn to_der(&self) -> Result<Vec<u8>, Error>;
    fn to_pem(&self) -> Result<String, Error> {
        let der = self.to_der()?;
        let pem = pem::Pem {
            tag: "PUBLIC KEY".to_string(),
            contents: der,
        };
        Ok(pem::encode(&pem))
    }
}

impl ToPem for RSAPublicKey {
    fn to_der(&self) -> Result<Vec<u8>, Error> {
        let pubkey_asn1 = ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Integer(0, self.n.big_uint.to_bigint().unwrap()),
                ASN1Block::Integer(0, self.e.big_uint.to_bigint().unwrap()),
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
}

pub trait FromPem: Sized {
    fn from_pem<T: AsRef<[u8]>>(pem: T) -> Result<Self, Error> {
        let data = pem::parse(pem)?;
        Self::from_der(&data.contents)
    }
    fn from_der(der: &[u8]) -> Result<Self, Error>;
}

impl FromPem for RSAPublicKey {
    fn from_der(der: &[u8]) -> Result<Self, Error> {
        let ans1_block_vec = simple_asn1::from_der(der)?;
        if ans1_block_vec.len() != 1 {
            return Err(Error::PubKeyParse(
                "Invalid number of sequence: length of 1ans1_block_vec is not 1",
            ));
        }
        let ans1_seq = if let ASN1Block::Sequence(_, d) = &ans1_block_vec[0] {
            d
        } else {
            return Err(Error::PubKeyParse("Invalid format: 2"));
        };
        if ans1_seq.len() != 2 {
            return Err(Error::PubKeyParse("Invalid number of sequence: 3"));
        }
        //println!("pubkey der: {:?}", ans1_seq);

        let oid_seq = if let ASN1Block::Sequence(_, s) = &ans1_seq[0] {
            s
        } else {
            return Err(Error::PubKeyParse("Invalid format: 3"));
        };
        let oid = if let ASN1Block::ObjectIdentifier(_, o) = &oid_seq[0] {
            o
        } else {
            return Err(Error::PubKeyParse("Invalid format: 4"));
        };
        if oid != *RSA_OID {
            return Err(Error::PubKeyParse("Invalid format: 5"));
        }

        let bit_string = if let ASN1Block::BitString(_, _, s) = &ans1_seq[1] {
            s
        } else {
            return Err(Error::PubKeyParse("Invalid format: 6"));
        };

        let parsed_der = simple_asn1::from_der(&bit_string).map_err(Error::ANS1DecodeError)?;
        if parsed_der.len() != 1 {
            return Err(Error::PubKeyParse("Invalid format: 7"));
        }
        let pubkey_seq = if let ASN1Block::Sequence(_, s) = &parsed_der[0] {
            s
        } else {
            return Err(Error::PubKeyParse("Invalid format: 8"));
        };
        if pubkey_seq.len() != 2 {
            return Err(Error::PubKeyParse("Invalid format: 9"));
        }
        let n = if let ASN1Block::Integer(_, n) = &pubkey_seq[0] {
            n
        } else {
            return Err(Error::PubKeyParse("Invalid format: 10"));
        };
        let e = if let ASN1Block::Integer(_, e) = &pubkey_seq[1] {
            e
        } else {
            return Err(Error::PubKeyParse("Invalid format: 11"));
        };

        let rsa_pub_key = RSAPublicKey {
            generic: Generic {
                kty: KeyType::Rsa,
                use_: None,
                key_ops: None,
                alg: None,
                kid: None,
                x5u: None,
                x5c: None,
                x5t: None,
                x5t_s256: None,
            },
            e: e.to_biguint().unwrap().into(),
            n: n.to_biguint().unwrap().into(),
        };

        Ok(rsa_pub_key)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_convert_to_pem1() {
        let jwk: RSAPublicKey =
            serde_json::from_str(include_str!("../testfiles/test1.json")).unwrap();
        let pem = jwk.to_pem().unwrap();
        let pem_expected = include_str!("../testfiles/test1.pem");
        assert_eq!(pem, pem_expected);
    }

    #[test]
    fn test_convert_to_pem2() {
        let jwk: RSAPublicKey =
            serde_json::from_str(include_str!("../testfiles/test2.json")).unwrap();
        let pem = jwk.to_pem().unwrap();
        let pem_expected = include_str!("../testfiles/test2.pem");
        assert_eq!(pem, pem_expected);
    }

    #[test]
    fn test_convert_from_pem1() {
        let pem = include_str!("../testfiles/test1.pem");
        let mut jwk = RSAPublicKey::from_pem(pem).unwrap();
        jwk.generic.kid = Some("fe41cf0f-7901-489f-9d4e-1437d6c1aa1f".to_string());
        let jwk_expected: RSAPublicKey =
            serde_json::from_str(include_str!("../testfiles/test1.json")).unwrap();
        assert_eq!(jwk, jwk_expected);
    }
}
