#![no_std]

#[cfg(test)]
#[macro_use]
extern crate std;

use core::slice;

// The code is based on the public domain implementation at
// https://github.com/mycelium-com/entropy/blob/master/lib/xxtea.c

fn as_u32_slice<'a>(x: &'a [u8]) -> &'a [u32] {
    // Safe, because the length is rounded down.
    unsafe { slice::from_raw_parts(x.as_ptr() as *const u32, x.len() / 4) }
}

fn as_u32_slice_mut<'a>(x: &'a mut [u8]) -> &'a mut [u32] {
    // Safe, because the length is rounded down.
    unsafe { slice::from_raw_parts_mut(x.as_mut_ptr() as *mut u32, x.len() / 4) }
}

pub fn encrypt(key: &[u8], block: &mut [u8]) {
    assert!(key.len() == 16);
    assert!((block.len() & 3) == 0);

    let key = as_u32_slice(key);
    let block = as_u32_slice_mut(block);

    let rounds = 6 + 52 / block.len();
    let n = block.len() - 1;

    let mut sum = 0u32;
    let mut z = block[n]; // left neighbour for the first round
    for _ in 0..rounds {
        // cycle
        sum = sum.wrapping_add(0x9e3779b9);
        let e = sum >> 2;
        for r in 0..block.len() {
            // round
            let y = block[(r + 1) % block.len()]; // right neighbour
            block[r] = block[r].wrapping_add(
                (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
                    ^ ((sum ^ y).wrapping_add(key[(r ^ e as usize) & 3] ^ z)),
            );
            z = block[r]; // left neighbour for the next round
        }
    }
}

pub fn decrypt(key: &[u8], block: &mut [u8]) {
    assert!(key.len() == 16);
    assert!((block.len() & 3) == 0);

    let key = as_u32_slice(key);
    let block = as_u32_slice_mut(block);

    let rounds = 6 + 52 / block.len();

    let mut sum = (rounds as u32).wrapping_mul(0x9e3779b9);
    let mut y = block[0];
    for _ in 0..rounds {
        // cycle
        let e = sum >> 2;
        for r in (0..block.len()).rev() {
            // round
            let z = block[(r + block.len() - 1) % block.len()];
            block[r] = block[r].wrapping_sub(
                (((z >> 5) ^ (y << 2)).wrapping_add((y >> 3) ^ (z << 4)))
                    ^ ((sum ^ y).wrapping_add(key[(r ^ e as usize) & 3] ^ z)),
            );
            y = block[r];
        }
        sum = sum.wrapping_sub(0x9e3779b9);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::num::ParseIntError;
    use std::vec::Vec;

    pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
            .collect()
    }

    #[test]
    fn test_vectors() {
        const TEST_VECTORS: [(&str, &str, &str); 20] = [
            (
                "00000000000000000000000000000000",
                "0000000000000000",
                "ab043705808c5d57",
            ),
            (
                "0102040810204080fffefcf8f0e0c080",
                "0000000000000000",
                "d1e78be2c746728a",
            ),
            (
                "9e3779b99b9773e9b979379e6b695156",
                "ffffffffffffffff",
                "67ed0ea8e8973fc5",
            ),
            (
                "0102040810204080fffefcf8f0e0c080",
                "fffefcf8f0e0c080",
                "8c3707c01c7fccc4",
            ),
            (
                "ffffffffffffffffffffffffffffffff",
                "157c13a850ba5e57306d7791",
                "b2601cefb078b772abccba6a",
            ),
            (
                "9e3779b99b9773e9b979379e6b695156",
                "157c13a850ba5e57306d7791",
                "579016d143ed6247ac6710dd",
            ),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "0102040810204080fffefcf8f0e0c080",
                "c0a19f06ebb0d63925aa27f74cc6b2d0",
            ),
            (
                "9e3779b99b9773e9b979379e6b695156",
                "0102040810204080fffefcf8f0e0c080",
                "01b815fd2e4894d13555da434c9d868a",
            ),
            (
                "0102040810204080fffefcf8f0e0c080",
                "157c13a850ba5e57306d77916fa2c37be1949616",
                "51f0ffeb46012a245e0c6c4fa097db27caec698d",
            ),
            (
                "9e3779b99b9773e9b979379e6b695156",
                "690342f45054a708c475c91db77761bc01b815fd2e4894d1",
                "759e5b212ee58be734d610248e1daa1c9d0647d428b4f95a",
            ),
            (
                "9e3779b99b9773e9b979379e6b695156",
                "3555da434c9d868a1431e73e73372fc0688e09ce11d00b6fd936a764",
                "8e63ae7d8a119566990eb756f16abf94ff87359803ca12fbaa03fdfb",
            ),
            (
                "0102040810204080fffefcf8f0e0c080",
                "db9af3c96e36a30c643c6e97f4d75b7a4b51a40e9d8759e581e3c40b341b4436",
                "5ef1b6e010a2227ba337374b59beffc5263503054745fb513000641e2c7dd107",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4100000000000000",
                "014e7a34874eeb29",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142000000000000",
                "e9d39f636e9ed090",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142430000000000",
                "d20ec51c06feaf0e",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142434400000000",
                "b1551d6ffcd4b61b",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142434445000000",
                "0ff91e518b9837e3",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142434445460000",
                "7003fc98b6788a77",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142434445464700",
                "93951ad360650022",
            ),
            (
                "6a6f686e636b656e64616c6c6a6f686e",
                "4142434445464748",
                "cdeb72b9c903ce52",
            ),
        ];

        for (key, plaintext, ciphertext) in &TEST_VECTORS {
            let key = decode_hex(key).unwrap();
            let good_plaintext = decode_hex(plaintext).unwrap();
            let good_ciphertext = decode_hex(ciphertext).unwrap();

            let mut buffer = good_plaintext.clone();
            encrypt(&key, &mut buffer);

            assert_eq!(good_ciphertext, buffer);

            decrypt(&key, &mut buffer);

            assert_eq!(good_plaintext, buffer);
        }
    }
}
