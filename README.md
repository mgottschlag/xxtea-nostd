
# xxtea-nostd

xxtea-nostd is an implementation of the XXTEA encryption algorithm designed for
`no-std` environments. The code uses native endianess to interpret the byte
slices passed to the library as 4-byte words.

This code implements a raw block cipher. **Do not use it directly, implement a
more secure mode such as cipher block chaining (CBC) on top of it instead**.

## Example

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

## Disclaimer

I am no cryptography expert. Use this code at your own risk. If you use this
code, your program might kill cute little kittens. You have been warned.

## License

The code is licensed under the CC0 1.0. See [LICENSE](LICENSE) or
https://creativecommons.org/publicdomain/zero/1.0/ for more information.

