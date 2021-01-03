# jsonwebkey-cli
Convert an RSA public key between Json Web Key and DER/PEM format.

## Usage

```
Json Web Key CLI 0.1.1
Okamura Yasunobu <okamura@informationsea.info>
Convert an RSA public key between Json Web Key and DER/PEM format

USAGE:
    jsonwebkey-cli <SUBCOMMAND>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    help          Prints this message or the help of the given subcommand(s)
    jwk-to-pem    
    pem-to-jwk
```

```
jsonwebkey-cli-jwk-to-pem 

USAGE:
    jsonwebkey-cli jwk-to-pem <jwk> --output <output>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -o, --output <output>    [OUTPUT] PEM output

ARGS:
    <jwk>    [INPUT] Json Web Key file
```

```
jsonwebkey-cli-pem-to-jwk 

USAGE:
    jsonwebkey-cli pem-to-jwk [OPTIONS] <pem> --output <output>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -k, --kid <kid>          [OPTION] kid entry in JWK
    -o, --output <output>    [OUTPUT] json web key output
    -u, --use <use>          [OPTION] use entry in JWK

ARGS:
    <pem>    [INPUT] PEM file

```