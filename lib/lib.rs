use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use blake3::hash;

use lazy_static::lazy_static;

use num_bigint_dig::RandPrime;

use secp256k1::{
    ecdh::SharedSecret, ecdsa::Signature, All, Error, Message, PublicKey, Secp256k1, SecretKey,
};

use serde::{Deserialize, Serialize};

lazy_static! {
    static ref CURVE: Secp256k1<All> = Secp256k1::new();
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    pub public_key: PublicKey,
    pub shared_key: [u8; 32],
}

#[derive(Debug, Clone)]
pub struct ECC {
    private_key: SecretKey,
    public_key: PublicKey,
    user: HashMap<String, User>,
}

impl ECC {
    pub fn new() -> Self {
        let secp = Secp256k1::new();
        let rand = &rand::thread_rng().gen_prime(256).to_bytes_be();
        let seckey = SecretKey::from_slice(rand).unwrap();
        Self {
            public_key: PublicKey::from_secret_key(&secp, &seckey),
            private_key: seckey,
            user: HashMap::new(),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        let secp = Secp256k1::new();
        let rand = slice;
        let seckey = SecretKey::from_slice(rand).unwrap();
        Self {
            public_key: PublicKey::from_secret_key(&secp, &seckey),
            private_key: seckey,
            user: HashMap::new(),
        }
    }

    pub fn private_key(&self) -> [u8; 32] {
        self.private_key.secret_bytes()
    }

    pub fn public_key(&self) -> [u8; 33] {
        self.public_key.serialize()
    }

    pub fn to_pem(&self, path: &str) {
        match fs::write(path, &self.private_key()) {
            Ok(bytes_written) => println!("{:?} bytes written to {}", bytes_written, path),
            Err(e) => println!("Failed to write data: {:?}", e),
        }
    }

    pub fn from_pem(path: &str) -> Self {
        let secp = Secp256k1::new();
        let rand = &fs::read(path).expect("Error reading PEM file")[..];
        let seckey = SecretKey::from_slice(rand).unwrap();
        Self {
            public_key: PublicKey::from_secret_key(&secp, &seckey),
            private_key: seckey,
            user: HashMap::new(),
        }
    }

    pub fn save_users_data(&self, path: &str) {
        match fs::write(path, bincode::serialize(&self.user).unwrap()) {
            Ok(bytes_written) => println!("{:?} bytes written to {}", bytes_written, path),
            Err(e) => println!("Failed to write data: {:?}", e),
        }
    }

    pub fn load_users_data(&mut self, path: &str) {
        let data = match fs::read(path) {
            Ok(bytes) => bytes,
            Err(e) => panic!("Failed to write data: {}", e),
        };
        self.user = bincode::deserialize(&data[..]).unwrap();
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        CURVE
            .sign_ecdsa(
                &Message::from_slice(hash(data).as_bytes()).unwrap(),
                &self.private_key,
            )
            .serialize_compact()
    }

    pub fn verify(&self, data: &[u8], sign: &[u8], user: &str) -> Result<(), Error> {
        CURVE.verify_ecdsa(
            &Message::from_slice(hash(data).as_bytes()).unwrap(),
            &Signature::from_compact(&sign).unwrap(),
            &self.user[user].public_key,
        )
    }

    pub fn encrypt(&self, data: &[u8], user: &str) -> Vec<u8> {
        Aes256Gcm::new(GenericArray::from_slice(&self.user[user].shared_key))
            .encrypt(Nonce::from_slice(b"unique nonce"), data)
            .unwrap()
    }

    pub fn decrypt(&self, data: &[u8], user: &str) -> Vec<u8> {
        Aes256Gcm::new(GenericArray::from_slice(&self.user[user].shared_key))
            .decrypt(Nonce::from_slice(b"unique nonce"), data)
            .unwrap()
    }

    pub fn add_user(&mut self, name: &str, key: [u8; 33]) {
        let public = PublicKey::from_slice(&key).unwrap();
        self.user.insert(
            name.to_owned(),
            User {
                shared_key: SharedSecret::new(&public, &self.private_key).secret_bytes(),
                public_key: public,
            },
        );
    }

    pub fn remove_user(&mut self, name: &str) {
        self.user.remove(name);
    }
}

// use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};
// use aes_gcm::{Aes256Gcm, Nonce};
// use blake3::hash;
// #[allow(unused)]
// use hex::{decode, encode, FromHex, ToHex};
// use secp256k1::ecdh::SharedSecret;
// use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey};

// fn king<T>(_: T) {
//     println!("{}", std::any::type_name::<T>())
// }

// #[rustfmt::skip]
// fn main() {
//     ///////////////////////////////////////////////////////////////////////////////////////////////////
//     // sign and verify msg
//     let secp = Secp256k1::new();
//     let rand = &rand::random::<[u8; 32]>();

//     let seckey = SecretKey::from_slice(rand).unwrap();
//     let pubkey = PublicKey::from_secret_key(&secp, &seckey);

//     let data = hash(b"Hello, world!");
//     let msg = Message::from_slice(data.as_bytes()).unwrap();
//     let sig = secp.sign_ecdsa(&msg, &seckey);
//     let signature = sig.serialize_compact();
//     println!("{}", sig.to_string());

//     let data2 = hash(b"Hello, world!");
//     let msg2 = Message::from_slice(data2.as_bytes()).unwrap();
//     let sig2 = Signature::from_compact(&signature).unwrap();
//     match secp.verify_ecdsa(&msg2, &sig2, &pubkey) {
//         Ok(()) => println!("CorrectSignature"),
//         Err(e) => println!("{:?}", e),
//     }
//     ///////////////////////////////////////////////////////////////////////////////////////////////////
//     // Encrypt data using the public key
//     let rand1 = &rand::random::<[u8; 32]>();
//     let rand2 = &rand::random::<[u8; 32]>();

//     let seckey1 = SecretKey::from_slice(rand1).unwrap();
//     let pubkey1 = PublicKey::from_secret_key(&secp, &seckey1);

//     let seckey2 = SecretKey::from_slice(rand2).unwrap();
//     let pubkey2 = PublicKey::from_secret_key(&secp, &seckey2);

//     let shared1 = SharedSecret::new(&pubkey1, &seckey2).secret_bytes();
//     let shared2 = SharedSecret::new(&pubkey2, &seckey1).secret_bytes();

//     println!("{:?}", shared1);
//     println!("{:?}", shared2);

//     ///////////////////////////////////////////////////////////////////////////////////////////////////
//     /// Encrypt using symmetric key

//     let key = GenericArray::from_slice(&[0u8; 32]);
//     let cipher = Aes256Gcm::new(key);
//     let nonce = Nonce::from_slice(b"unique nonce");
//     let ciphertext = cipher
//         .encrypt(nonce, b"plaintext message".as_ref())
//         .unwrap();
//     let plaintext = cipher.decrypt(nonce, ciphertext.as_ref()).unwrap();
//     println!("{}", String::from_utf8(plaintext).unwrap());
//     println!("{:?}", key);

// }
