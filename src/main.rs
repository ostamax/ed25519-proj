extern crate clap;
extern crate rand;
extern crate ed25519_dalek;

use std::fs;
use std::io::Read;

use clap::Parser;
use ed25519_dalek::SecretKey;
use rand::rngs::OsRng;
use ed25519_dalek::Keypair;
use ed25519_dalek::Signature;
use ed25519_dalek::Signer;
use ed25519_dalek::Verifier;
use ed25519_dalek::PublicKey;

use ed25519_dalek::{PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, KEYPAIR_LENGTH, SIGNATURE_LENGTH};


pub fn generate_keys() -> Keypair {
    let mut csprng = OsRng{};
    let keypair: Keypair = Keypair::generate(&mut csprng);
    keypair
}

pub fn write_keys_to_file(keypair: Keypair){
    let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = keypair.public.to_bytes();

    let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair.secret.to_bytes();
    println!("{:?}", public_key_bytes.len());
    println!("{:?}", secret_key_bytes.len());
    fs::write("pk.txt", public_key_bytes).unwrap();
    fs::write("sk.txt", secret_key_bytes).unwrap();

}

pub fn read_message_from_file() -> String {
    let mut file = fs::File::open("message.txt").expect("Unable to open");
    let mut message = String::new();
    file.read_to_string(&mut message).expect("Error while reading file");
    message  
}

pub fn read_secret_key_from_file(secret_key_path: &str) -> SecretKey {
    let mut file = fs::File::open(secret_key_path).expect("Unable to open");
    
    let mut secret_key_bytes = vec![];
    file.read_to_end(&mut secret_key_bytes).unwrap();
    println!("{:?}", secret_key_bytes);
    let secret: SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
    println!("{:?}", secret);
    secret
}

pub fn read_public_key_from_file(public_key_path: &str) -> PublicKey {
    let mut file = fs::File::open(public_key_path).expect("Unable to open");
    let mut public_key_bytes = vec![];
    file.read_to_end(&mut public_key_bytes).unwrap();
    let public_k: PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
    public_k

}

pub fn sign_message(message_string: String, secret_key_path: &str, public_key_path: &str) -> Signature {
    let secret_key = read_secret_key_from_file(secret_key_path);
    let public_key = read_public_key_from_file(public_key_path);
    let keypair  = Keypair{public:public_key, secret:secret_key};
    let message: &[u8] = message_string.as_bytes();
    let signature = keypair.sign(message);
    println!("{:?}", signature);
    write_signature_to_file(signature);
    signature
}

pub fn write_signature_to_file(signature: Signature) {
    let signature_bytes: [u8; SIGNATURE_LENGTH] = signature.to_bytes();
    fs::write("signature.txt", signature_bytes).unwrap();
}

pub fn read_signature_from_file(signature_path: &str) -> Signature {
    let mut file = fs::File::open(signature_path).expect("Unable to open");
    let mut signature_bytes = vec![];
    file.read_to_end(&mut signature_bytes).unwrap();
    let signature: Signature = Signature::from_bytes(&signature_bytes).unwrap();
    signature
}

pub fn verify_signature(message_string: String, signature_path: &str, public_key_path: &str) -> bool {
    let public_key = read_public_key_from_file(public_key_path);
    let signature = read_signature_from_file(signature_path);
    let message: &[u8] = message_string.as_bytes();
    public_key.verify(message, &signature).is_ok()
}

#[derive(Parser,Default,Debug)]
struct Args {
   operation_type: String,
   message: Option<String>,
   key_path: Option<String>,
}

fn main() {

    let args = Args::parse();
    println!("{}", args.operation_type);

    match args.operation_type.as_str() {
        "generate" => {
            let generated_keypair = generate_keys();
            write_keys_to_file(generated_keypair);
        },
        "sign" => {
            println!("Signing");
            let message = read_message_from_file();
            println!("{:?}", message);
            sign_message(String::from("f"), "sk.txt", "pk.txt");
        },
        "verify" => {
            println!("Verifying");
            println!("{}", verify_signature(String::from("f"), "signature.txt", "pk.txt"));

        },
        _ => panic!("unknown operation"),
    }

}
