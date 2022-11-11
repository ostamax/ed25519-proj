extern crate clap;
extern crate ed25519_dalek;
extern crate rand;

use std::fs;
use std::io::Read;

use clap::{Arg, App};
use ed25519_dalek::Keypair;
use ed25519_dalek::PublicKey;
use ed25519_dalek::SecretKey;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use rand::rngs::OsRng;

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH};

pub fn generate_keys() -> Keypair {
    let mut csprng = OsRng {};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    keypair
}

pub fn write_keys_to_file(keypair: Keypair, keys_path: &str) {
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = keypair.public.to_bytes();

    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair.secret.to_bytes();
    println!("{:?}", public_key_bytes.len());
    println!("{:?}", secret_key_bytes.len());
    fs::write(format!("{keys_path}.pub"), public_key_bytes).unwrap();
    fs::write(format!("{keys_path}"), secret_key_bytes).unwrap();
}

pub fn read_message_from_file() -> String {
    let mut file = fs::File::open("message.txt").expect("Unable to open message.txt file");
    let mut message = String::new();
    file.read_to_string(&mut message)
        .expect("Error while reading file");
    message
}

pub fn read_secret_key_from_file(secret_key_path: &str) -> SecretKey {
    let mut file = fs::File::open(secret_key_path).expect("Unable to open private key file");

    let mut secret_key_bytes = vec![];
    file.read_to_end(&mut secret_key_bytes).unwrap();
    println!("{:?}", secret_key_bytes);
    let secret: SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
    println!("{:?}", secret);
    secret
}

pub fn read_public_key_from_file(public_key_path: &str) -> PublicKey {
    let mut file = fs::File::open(public_key_path).expect("Unable to open public key file");
    let mut public_key_bytes = vec![];
    file.read_to_end(&mut public_key_bytes).unwrap();
    let public_k: PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
    public_k
}

pub fn sign_message(
    keys_path: &str
) -> Signature {
    let secret_key = read_secret_key_from_file(&format!("{keys_path}"));
    let public_key = read_public_key_from_file(&format!("{keys_path}.pub"));
    let keypair = Keypair {
        public: public_key,
        secret: secret_key,
    };
    let message_string = read_message_from_file();
    let message: &[u8] = message_string.as_bytes();
    let signature = keypair.sign(message);
    println!("{:?}", signature);
    write_signature_to_file(signature);
    signature
}

pub fn write_signature_to_file(signature: Signature) {
    let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
    fs::write("signature.pem", signature_bytes).unwrap();
}

pub fn read_signature_from_file(signature_path: &str) -> Signature {
    let mut file = fs::File::open(signature_path).expect("Unable to open signature file");
    let mut signature_bytes = vec![];
    file.read_to_end(&mut signature_bytes).unwrap();
    let signature: Signature = Signature::from_bytes(&signature_bytes).unwrap();
    signature
}

pub fn verify_signature(
    signature_path: &str,
    keys_path: &str,
) -> bool {
    let message_string = read_message_from_file();
    let public_key = read_public_key_from_file(&format!("{keys_path}.pub"));
    let signature = read_signature_from_file(signature_path);
    let message: &[u8] = message_string.as_bytes();
    public_key.verify(message, &signature).is_ok()
}

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
        .help("Path of the signature file (for verification)");

    let app = app.args(&[operation_name, file_name, signature_path]);

    let matches = app.get_matches();

    match matches.value_of("operation_type").unwrap() {
        "generate" => {
            let generated_keypair = generate_keys();
            let keys_path = matches.value_of("file_name").unwrap();
            write_keys_to_file(generated_keypair, keys_path);
        }
        "sign" => {
            println!("Signing");
            let keys_path = matches.value_of("file_name").unwrap();
            let signature = sign_message(keys_path);
            println!("{:?}", signature);
        }
        "verify" => {
            println!("Verifying");
            let keys_path = matches.value_of("file_name").unwrap();
            let signature_path = matches.value_of("signature").unwrap();
            let is_verified = verify_signature(signature_path, keys_path);
            println!("{}", is_verified);
        }
        _ => panic!("Unknown operation!")
    }
    
}
