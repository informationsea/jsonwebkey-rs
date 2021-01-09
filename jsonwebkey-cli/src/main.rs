use clap::{crate_authors, crate_version, App, AppSettings, Arg, SubCommand};
use jsonwebkey_convert::der::*;
use jsonwebkey_convert::*;
use std::fs;

fn main() -> Result<(), Error> {
    let matches = App::new("Json Web Key CLI")
        .version(crate_version!())
        .author(crate_authors!())
        .about("Convert an RSA public key between Json Web Key and DER/PEM format")
        .setting(AppSettings::SubcommandRequiredElseHelp)
        .subcommand(
            SubCommand::with_name("jwk-to-pem")
                .arg(
                    Arg::with_name("jwk")
                        .takes_value(true)
                        .required(true)
                        .help("[INPUT] Json Web Key file"),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .takes_value(true)
                        .required(true)
                        .help("[OUTPUT] PEM output"),
                ),
        )
        .subcommand(
            SubCommand::with_name("pem-to-jwk")
                .arg(
                    Arg::with_name("pem")
                        .takes_value(true)
                        .required(true)
                        .help("[INPUT] PEM file"),
                )
                .arg(
                    Arg::with_name("output")
                        .short("o")
                        .long("output")
                        .takes_value(true)
                        .required(true)
                        .help("[OUTPUT] json web key output"),
                )
                .arg(
                    Arg::with_name("kid")
                        .short("k")
                        .long("kid")
                        .takes_value(true)
                        .help("[OPTION] kid entry in JWK"),
                )
                .arg(
                    Arg::with_name("use")
                        .short("u")
                        .long("use")
                        .takes_value(true)
                        .help("[OPTION] use entry in JWK"),
                ),
        )
        .get_matches();

    if let Some(jwk_to_pem) = matches.subcommand_matches("jwk-to-pem") {
        let jwk_path = jwk_to_pem.value_of("jwk").unwrap();
        let output_path = jwk_to_pem.value_of("output").unwrap();
        let data = fs::read(jwk_path).unwrap();
        let jwk: RSAPublicKey = serde_json::from_slice(&data[..])?;
        let pem = jwk.to_pem()?;
        fs::write(output_path, &pem).unwrap();
    } else if let Some(pem_to_jwk) = matches.subcommand_matches("pem-to-jwk") {
        let pem_path = pem_to_jwk.value_of("pem").unwrap();
        let output_path = pem_to_jwk.value_of("output").unwrap();
        let kid = pem_to_jwk.value_of("kid").map(|x| x.to_string());
        let jwk_use = pem_to_jwk.value_of("use").map(|x| x.to_string());
        let data = fs::read(pem_path).unwrap();
        let mut jwk = RSAPublicKey::from_pem(&data)?;
        jwk.generic.kid = kid;
        jwk.generic.use_ = jwk_use.map(|x| match x.as_str() {
            "enc" => KeyUse::Encryption,
            "sig" => KeyUse::Signature,
            _ => {
                eprintln!("Unknown key use: {}", x);
                KeyUse::Encryption
            }
        });
        let jwk_bytes = serde_json::to_vec(&jwk)?;
        fs::write(output_path, &jwk_bytes).unwrap();
    } else {
        unreachable!()
    }
    Ok(())
}
