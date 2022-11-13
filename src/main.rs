extern crate clap;

use clap::{App, Arg};
use signature_module::ed25519_module::*;

fn main() {
    let app = App::new("ed25519")
        .version("1.0.0")
        .about("A simple CLI signer for ed25519 signatures")
        .author("Maksym Ostapenko");

    let operation_name = Arg::with_name("operation_type")
        .long("operation")
        .short("o")
        .takes_value(true)
        .required(true)
        .help("Operation type: generate/sign/verify");

    let file_name = Arg::with_name("file_name")
        .long("file")
        .short("f")
        .takes_value(true)
        .required(true)
        .default_value("key")
        .help("File names for public and private keys. (They will be created '[file].pub' and '[file]') respectively");

    let signature_path = Arg::with_name("signature")
        .long("signature")
        .short("s")
        .takes_value(false)
        .required(true)
        .default_value("signature.pem")
        .help("Flag whether the signature file should be used (for verification)");

    let app = app.args(&[operation_name, file_name, signature_path]);

    let matches = app.get_matches();

    match matches.value_of("operation_type").unwrap() {
        "generate" => {
            println!("Keys generation");
            let generated_keypair = generate_keys();
            let keys_path = matches.value_of("file_name").unwrap();
            write_keys_to_file(generated_keypair, keys_path);
            println!("Keys were successfully generated");
        }
        "sign" => {
            println!("Signing");
            let keys_path = matches.value_of("file_name").unwrap();
            sign_message(keys_path);
            println!("Signature was successfully generated");
        }
        "verify" => {
            println!("Verifying");
            let keys_path = matches.value_of("file_name").unwrap();
            let signature_path = matches.value_of("signature").unwrap();
            let is_verified = verify_signature(signature_path, keys_path);
            println!("Verification result - {}", is_verified);
        }
        _ => panic!("Unknown operation!"),
    }
}
