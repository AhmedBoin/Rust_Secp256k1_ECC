use encryption::*;

#[allow(unused)]
#[rustfmt::skip]
fn main() {
    // initiate some users
    let mut x = ECC::new();
    let mut y = ECC::from_hex("98a1441d38b21a6d3e4ced37425a3ef88b1a7c20dc38f64c8cada67b66b59641").unwrap();
    let mut z = ECC::from_slice(&rand::random::<[u8; 32]>()).unwrap();

    // add users information to each other
    x.add_user("y", &y.public_key());
    x.add_user("z", &z.public_key());  //
    y.add_user("x", &x.public_key());
    y.add_user("z", &z.public_key());  //
    z.add_user("x", &x.public_key());
    z.add_user("y", &y.public_key());  //

    // signing and verification
    let msg = b"Hello, World!";
    let sig = x.sign(msg);

    assert_eq!(x.public_key(), recover(msg, &sig).unwrap());
    assert!(y.verify(msg, &sig, "x").unwrap());
    assert!(z.verify(msg, &sig, "x").unwrap());

    // Encryption and Decryption
    let enc1 = x.encrypt(msg, "y").unwrap();
    let enc2 = x.encrypt(msg, "z").unwrap();
    assert_ne!(enc1, enc2);

    let dec1 = y.decrypt(&enc1, "x").unwrap();
    let dec2 = z.decrypt(&enc2, "x").unwrap();
    assert_eq!(dec1, dec2);
}
