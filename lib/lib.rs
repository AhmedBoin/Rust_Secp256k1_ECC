use std::collections::HashMap;
use std::fmt::Debug;
use std::fs;

use aes_gcm::aead::{generic_array::GenericArray, Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};

use blake3::hash;

use anyhow::Result;
use lazy_static::lazy_static;

// use hex::{FromHex, ToHex};
use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};
use secp256k1::{ecdh::SharedSecret, All, Message, PublicKey, Secp256k1, SecretKey};
use sha3::{Digest, Keccak256};

use serde::{Deserialize, Serialize};

lazy_static! {
    static ref CURVE: Secp256k1<All> = Secp256k1::new();
}

#[derive(Debug, Deserialize, Serialize, Clone)]
struct User {
    pub address: String,
    pub shared_key: [u8; 32],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ECC {
    private_key: SecretKey,
    public_key: PublicKey,
    user: HashMap<String, User>,
}

impl ECC {
    pub fn new() -> Self {
        let private_key = SecretKey::from_slice(&rand::random::<[u8; 32]>()).unwrap();
        Self {
            public_key: PublicKey::from_secret_key(&CURVE, &private_key),
            private_key,
            user: HashMap::new(),
        }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        let private_key = SecretKey::from_slice(slice)?;
        Ok(Self {
            public_key: PublicKey::from_secret_key(&CURVE, &private_key),
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

    pub fn verify(&self, data: &[u8], sign: &[u8], user: &str) -> Result<bool, String> {
        match &self.recover(data, sign) {
            Ok(add) => match address(add) {
                Ok(address) => match &self.user.get(user) {
                    Some(user) => {
                        if address == user.address {
                            Ok(true)
                        } else {
                            Ok(false)
                        }
                    }
                    None => Err(format!("there is no user {}", user)),
                },
                Err(e) => Err(e.to_owned()),
            },
            Err(e) => Err(e.to_string()),
        }
    }

    pub fn recover(&self, data: &[u8], sign: &[u8]) -> Result<[u8; 33], &str> {
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
            Err("invalid signature")
        }
    }

    pub fn encrypt(&self, data: &[u8], user: &str) -> Result<Vec<u8>, &str> {
        match self.user.get(user) {
            Some(user) => {
                match Aes256Gcm::new(GenericArray::from_slice(&user.shared_key))
                    .encrypt(Nonce::from_slice(b"unique nonce"), data)
                {
                    Ok(enc) => Ok(enc),
                    Err(_) => Err("couldn't encrypt this data!"),
                }
            }
            None => Err("user not found!"),
        }
    }

    pub fn decrypt(&self, data: &[u8], user: &str) -> Result<Vec<u8>, &str> {
        match self.user.get(user) {
            Some(user) => {
                match Aes256Gcm::new(GenericArray::from_slice(&user.shared_key))
                    .decrypt(Nonce::from_slice(b"unique nonce"), data)
                {
                    Ok(enc) => Ok(enc),
                    Err(_) => Err("couldn't encrypt this data!"),
                }
            }
            None => Err("user not found!"),
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

pub fn to_uncompressed(key: &[u8]) -> Result<[u8; 65], &str> {
    match PublicKey::from_slice(key) {
        Ok(key) => Ok(key.serialize_uncompressed()),
        Err(_) => Err("public key is invalid"),
    }
}

pub fn to_compressed(key: &[u8]) -> Result<[u8; 33], &str> {
    match PublicKey::from_slice(key) {
        Ok(key) => Ok(key.serialize()),
        Err(_) => Err("public key is invalid"),
    }
}

pub fn address(key: &[u8]) -> Result<String, &str> {
    match PublicKey::from_slice(key) {
        Ok(key) => {
            let key = key.serialize_uncompressed();
            let hash = Keccak256::digest(key[1..].to_vec());
            let mut addr = hex::encode(&hash[12..32]);
            addr.insert_str(0, "0x");
            Ok(addr)
        }
        Err(_) => Err("public key is invalid"),
    }
}
