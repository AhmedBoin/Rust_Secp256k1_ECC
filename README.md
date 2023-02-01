# Rust_Secp256k1_ECC
Secp256k1 as a module for encryption, decryption, signing and verifying

```rust
use std::thread;

use crossbeam_channel::unbounded;
use encryption::*;

fn main() {
    let (x_tx, x_rx) = unbounded::<Vec<u8>>();
    let (y_tx, y_rx) = unbounded::<Vec<u8>>();

    let th1 = thread::spawn(move || {
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Signing
        let mut x = ECC::new();
        // let mut x = ECC::from_pem("x.pem");
        // x.load_users_data("x_users.bin");
        x_tx.send(x.public_key().to_vec()).unwrap();
        match y_rx.recv() {
            Ok(key) => x.add_user("y", key.try_into().unwrap()),
            Err(e) => println!("{:?}", e),
        }
        // let data = bincode::serialize("Hello, world!").unwrap();
        let data = "Hello, world!".as_bytes();
        x_tx.send(data.to_vec()).unwrap();
        let sign = x.sign(&data);
        x_tx.send(sign.to_vec()).unwrap();

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Encryption
        x_tx.send(x.encrypt(&data, "y")).unwrap();
        // x.to_pem("x.pem")
        // x.save_users_data("x_users.bin")
    });

    let th2 = thread::spawn(move || {
        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Verifying
        let mut y = ECC::new();
        // let mut y = ECC::from_pem("y.pem");
        // y.load_users_data("y_users.bin");
        y_tx.send(y.public_key().to_vec()).unwrap();
        match x_rx.recv() {
            Ok(key) => y.add_user("x", key.try_into().unwrap()),
            Err(e) => println!("{:?}", e),
        }
        let data = x_rx.recv().unwrap();
        let sign = x_rx.recv().unwrap();
        match y.verify(&data, &sign, "x") {
            Ok(()) => println!("Correct key"),
            Err(e) => println!("{e:?}"),
        }

        //////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Decryption
        let data = x_rx.recv().unwrap();
        println!("{data:?}");
        let data = y.decrypt(&data, "x");
        // println!("{}", bincode::deserialize::<&str>(&data).unwrap());
        println!("{}", String::from_utf8(data).unwrap());
        // y.to_pem("y.pem")
        // y.save_users_data("y_users.bin")
    });

    th1.join().unwrap();
    th2.join().unwrap();
}

```
