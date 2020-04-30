use xxtea_nostd::{decrypt, encrypt};

fn main() {
    let key = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0,
        0x80,
    ];
    let mut data = [0xff, 0xfe, 0xfc, 0xf8, 0xf0, 0xe0, 0xc0, 0x80];
    println!("Original: {:?}", data);
    encrypt(&key, &mut data);
    println!("Encrypted: {:?}", data); // Should be 8c3707c01c7fccc4.
    decrypt(&key, &mut data);
    println!("Decrypted: {:?}", data);
}