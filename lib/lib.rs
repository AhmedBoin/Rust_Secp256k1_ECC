use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;

// importing crates used for encryption standers
use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

// hashing algorithms
use blake3::hash;
use sha3::{Digest, Keccak256};

// requires for handling errors and static variables
use anyhow::Result;
use lazy_static::lazy_static;

// asymmetric encryption, digital signature, and diffi-hellman key exchange (Secp256k1)
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{ecdh::SharedSecret, All, Message, PublicKey, Secp256k1, SecretKey};

use serde::{Deserialize, Serialize};

// Secp256k1 elliptic curve
lazy_static! {
    static ref CURVE: Secp256k1<All> = Secp256k1::new();
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub enum ECCError {
    UserNotFound(String),
    InvalidData,
    InvalidPublicKey,
    InvalidSignature,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    pub address: String,
    pub shared_key: [u8; 32],
}

// Elliptic curve Point (user point)
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ECC {
    private_key: SecretKey,
    public_key: PublicKey,
    address: String,
    user: HashMap<String, User>,
}

impl ECC {
    #[rustfmt::skip]
    pub fn new() -> Self {
        let private_key = SecretKey::from_slice(hash(&rand::random::<[u8; 32]>()).as_bytes()).unwrap();
        let public_key = PublicKey::from_secret_key(&CURVE, &private_key);
        Self {
            address: address(&public_key.serialize_uncompressed()).unwrap(),
            public_key,
            private_key,
            user: HashMap::new(),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let private_key = SecretKey::from_slice(slice)?;
        let public_key = PublicKey::from_secret_key(&CURVE, &private_key);
        Ok(Self {
            address: address(&public_key.serialize_uncompressed()).unwrap(),
            public_key,
            private_key,
            user: HashMap::new(),
        })
    }

    pub fn from_hex(key: &str) -> Result<Self> {
        let private_key = SecretKey::from_slice(&hex::decode(key)?)?;
        let public_key = PublicKey::from_secret_key(&CURVE, &private_key);
        Ok(Self {
            address: address(&public_key.serialize_uncompressed()).unwrap(),
            public_key,
            private_key,
            user: HashMap::new(),
        })
    }

    pub fn private_key(&self) -> [u8; 32] {
        self.private_key.secret_bytes()
    }

    pub fn public_key(&self) -> [u8; 33] {
        self.public_key.serialize()
    }

    pub fn address(&self) -> String {
        self.address.clone()
    }

    pub fn address_of(&self, user: &str) -> Option<&str> {
        match self.user.get(user) {
            Some(user) => Some(&user.address),
            None => None,
        }
    }

    pub fn user_shared_key(&self, user: &str) -> Option<&[u8]> {
        match self.user.get(user) {
            Some(user) => Some(user.shared_key.as_slice()),
            None => None,
        }
    }

    pub fn to_pem(&self, path: &str) -> Result<()> {
        fs::write(path, &self.private_key())?;
        Ok(())
    }

    pub fn load_pem(&mut self, path: &str) -> Result<()> {
        self.private_key = SecretKey::from_slice(&fs::read(path)?[..]).unwrap();
        self.public_key = PublicKey::from_secret_key(&CURVE, &self.private_key);
        Ok(())
    }

    pub fn save_status(&self, path: &str) -> Result<()> {
        fs::write(path, bincode::serialize(&self)?)?;
        Ok(())
    }

    pub fn load_status(path: &str) -> Result<Self> {
        Ok(Self {
            ..bincode::deserialize(&fs::read(path)?)?
        })
    }

    pub fn save_users_data(&self, path: &str) -> Result<()> {
        fs::write(path, bincode::serialize(&self.user)?)?;
        Ok(())
    }

    pub fn load_users_data(&mut self, path: &str) -> Result<()> {
        self.user = bincode::deserialize(&fs::read(path)?)?;
        Ok(())
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 65] {
        let (id, sign) = CURVE
            .sign_ecdsa_recoverable(
                &Message::from_slice(hash(data).as_bytes()).unwrap(),
                &self.private_key,
            )
            .serialize_compact();
        let mut id = (id.to_i32() as u8).to_be_bytes().to_vec();
        id.extend(&sign);
        id.try_into().unwrap()
    }

    pub fn verify(&self, data: &[u8], sign: &[u8], user: &str) -> Result<(), ECCError> {
        match recover(data, sign) {
            Ok(add) => match address(&add) {
                Ok(address) => match &self.user.get(user) {
                    Some(user) => {
                        if address == user.address {
                            Ok(())
                        } else {
                            Err(ECCError::InvalidSignature)
                        }
                    }
                    None => Err(ECCError::UserNotFound(user.to_owned())),
                },
                Err(e) => Err(e),
            },
            Err(e) => Err(e),
        }
    }

    pub fn encrypt(&self, data: &[u8], user: &str) -> Result<Vec<u8>, ECCError> {
        match self.user.get(user) {
            Some(user) => {
                match Aes256Gcm::new(GenericArray::from_slice(&user.shared_key))
                    .encrypt(Nonce::from_slice(b"unique nonce"), data)
                {
                    Ok(enc) => Ok(enc),
                    Err(_) => Err(ECCError::InvalidData),
                }
            }
            None => Err(ECCError::UserNotFound(user.to_owned())),
        }
    }

    pub fn decrypt(&self, data: &[u8], user: &str) -> Result<Vec<u8>, ECCError> {
        match self.user.get(user) {
            Some(user) => {
                match Aes256Gcm::new(GenericArray::from_slice(&user.shared_key))
                    .decrypt(Nonce::from_slice(b"unique nonce"), data)
                {
                    Ok(enc) => Ok(enc),
                    Err(_) => Err(ECCError::InvalidData),
                }
            }
            None => Err(ECCError::UserNotFound(user.to_owned())),
        }
    }

    pub fn add_user(&mut self, name: &str, key: &[u8]) -> Result<()> {
        let public = PublicKey::from_slice(key)?;
        self.user.insert(
            name.to_owned(),
            User {
                shared_key: SharedSecret::new(&public, &self.private_key).secret_bytes(),
                address: address(&public.serialize_uncompressed()).unwrap(),
            },
        );
        Ok(())
    }

    pub fn remove_user(&mut self, name: &str) {
        self.user.remove(name);
    }
}

pub fn to_uncompressed(key: &[u8]) -> Result<[u8; 65], ECCError> {
    match PublicKey::from_slice(key) {
        Ok(key) => Ok(key.serialize_uncompressed()),
        Err(_) => Err(ECCError::InvalidPublicKey),
    }
}

pub fn to_compressed(key: &[u8]) -> Result<[u8; 33], ECCError> {
    match PublicKey::from_slice(key) {
        Ok(key) => Ok(key.serialize()),
        Err(_) => Err(ECCError::InvalidPublicKey),
    }
}

pub fn address(key: &[u8]) -> Result<String, ECCError> {
    match PublicKey::from_slice(key) {
        Ok(key) => {
            let key = key.serialize_uncompressed();
            let hash = Keccak256::digest(key[1..].to_vec());
            let mut addr = hex::encode(&hash[12..32]);
            addr.insert_str(0, "0x");
            Ok(addr)
        }
        Err(_) => Err(ECCError::InvalidPublicKey),
    }
}

pub fn recover(data: &[u8], sign: &[u8]) -> Result<[u8; 33], ECCError> {
    if let Some(&id) = sign.get(0) {
        let id = RecoveryId::from_i32(id as i32).unwrap();
        Ok(CURVE
            .recover_ecdsa(
                &Message::from_slice(hash(data).as_bytes()).unwrap(),
                &RecoverableSignature::from_compact(&sign[1..], id).unwrap(),
            )
            .unwrap()
            .serialize())
    } else {
        Err(ECCError::InvalidSignature)
    }
}

#[allow(unused)]
#[cfg(test)]
pub mod test {
    use crate::{recover, to_compressed, to_uncompressed, ECC};

    #[test]
    pub fn public_key_recovery() {
        let x = ECC::new();
        let msg = b"Hello, World!";
        let sign = x.sign(msg);
        assert_eq!(x.public_key(), recover(msg, &sign).unwrap())
    }

    #[test]
    pub fn sign_and_verify() {
        let mut x = ECC::new();
        let mut y = ECC::new();
        x.add_user("y", &y.public_key());
        y.add_user("x", &x.public_key());

        let msg = b"Hello, World!";
        let sign = x.sign(msg);
        let verify = match y.verify(msg, &sign, "x") {
            Ok(()) => true,
            Err(_) => false,
        };
        assert!(verify);
    }

    #[test]
    pub fn enc_and_dec() {
        let mut x = ECC::new();
        let mut y = ECC::new();
        x.add_user("y", &y.public_key());
        y.add_user("x", &x.public_key());

        let msg = b"Hello, World!";
        let enc = x.encrypt(msg, "y").unwrap();
        let dec = y.decrypt(&enc, "x").unwrap();
        assert_eq!(msg.to_vec(), dec.to_vec());
    }

    #[test]
    pub fn pem() {
        let mut x = ECC::new();
        let mut y = ECC::new();
        x.to_pem("x.pem");
        y.load_pem("x.pem");
        assert_eq!(x.private_key(), y.private_key());
    }

    #[test]
    pub fn users_data() {
        let mut x = ECC::new();
        let mut y = ECC::new();

        x.add_user("y", &y.public_key());
        x.save_users_data("x_users.bin");
        y.load_users_data("x_users.bin");

        assert_eq!(x.user_shared_key("y"), y.user_shared_key("y"));
        assert_eq!(x.address_of("y"), y.address_of("y"));
    }

    #[test]
    pub fn compress_and_decompress_public_key() {
        let x = ECC::new();
        let key = to_uncompressed(&x.public_key()).unwrap();
        let key = to_compressed(&key).unwrap();
        assert_eq!(x.public_key(), key);
    }
}
