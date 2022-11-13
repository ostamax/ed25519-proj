extern crate ed25519_dalek;
extern crate rand;

pub mod ed25519_module {
    use ed25519_dalek::{
        Keypair, PublicKey, SecretKey, Signature, Signer, Verifier, PUBLIC_KEY_LENGTH,
        SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
    };
    use rand::rngs::OsRng;
    use std::fs;
    use std::io::Read;

    pub fn generate_keys() -> Keypair {
        let mut csprng = OsRng {};
        let keypair: Keypair = Keypair::generate(&mut csprng);
        keypair
    }

    pub fn write_keys_to_file(keypair: Keypair, keys_path: &str) {
        let public_key_bytes: [u8; PUBLIC_KEY_LENGTH] = keypair.public.to_bytes();
        let secret_key_bytes: [u8; SECRET_KEY_LENGTH] = keypair.secret.to_bytes();
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
        let secret: SecretKey = SecretKey::from_bytes(&secret_key_bytes).unwrap();
        secret
    }

    pub fn read_public_key_from_file(public_key_path: &str) -> PublicKey {
        let mut file = fs::File::open(public_key_path).expect("Unable to open public key file");
        let mut public_key_bytes = vec![];
        file.read_to_end(&mut public_key_bytes).unwrap();
        let public_k: PublicKey = PublicKey::from_bytes(&public_key_bytes).unwrap();
        public_k
    }

    pub fn sign_message(keys_path: &str) -> Signature {
        let secret_key = read_secret_key_from_file(&format!("{keys_path}"));
        let public_key = read_public_key_from_file(&format!("{keys_path}.pub"));
        let keypair = Keypair {
            public: public_key,
            secret: secret_key,
        };
        let message_string = read_message_from_file();
        let message: &[u8] = message_string.as_bytes();
        let signature = keypair.sign(message);
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

    pub fn verify_signature(signature_path: &str, keys_path: &str) -> bool {
        let message_string = read_message_from_file();
        let public_key = read_public_key_from_file(&format!("{keys_path}.pub"));
        let signature = read_signature_from_file(signature_path);
        let message: &[u8] = message_string.as_bytes();
        public_key.verify(message, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use crate::ed25519_module::*;

    #[test]
    fn test_keys_generation() {
        let keypair = generate_keys();
        write_keys_to_file(keypair, "key");
        let is_public_exists = std::path::Path::new("key.pub").exists();
        let is_secret_exists = std::path::Path::new("key").exists();
        assert_eq!(is_public_exists, true);
        assert_eq!(is_secret_exists, true)
    }

    #[test]
    fn test_message_signing() {
        sign_message("key");
        let is_signature_file_exists = std::path::Path::new("signature.pem").exists();
        assert_eq!(is_signature_file_exists, true)
    }

    #[test]
    fn test_signature_verification() {
        let verification_result = verify_signature("signature.pem", "key");
        assert_eq!(verification_result, true);
    }
}
