extern crate rc6;

use cipher::array::Array;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use rc6::RC6;

// test vetors taken from https://web.archive.org/web/20181223080309/http://people.csail.mit.edu/rivest/rc6.pdf

#[test]
fn test_vector_1() {
    let plain_text = [0u8; 16];
    let key = [0u8; 16];

    let cipher = [
        0x8f, 0xc3, 0xa5, 0x36, 0x56, 0xb1, 0xf7, 0x78, 0xc1, 0x29, 0xdf, 0x4e, 0x98, 0x48, 0xa4,
        0x1e,
    ];

    let mut block = *Array::from_slice(&plain_text);

    let rc6 = RC6::new_from_slice(&key).expect("Failed to create RC6");
    rc6.encrypt_block(&mut block);

    assert_eq!(cipher, block[..]);

    rc6.decrypt_block(&mut block);
    assert_eq!(plain_text, block[..]);
}

#[test]
fn test_vector_2() {
    let plain_text = [
        0x02, 0x13, 0x24, 0x35, 0x46, 0x57, 0x68, 0x79, 0x8a, 0x9b, 0xac, 0xbd, 0xce, 0xdf, 0xe0,
        0xf1,
    ];
    let key = [
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67,
        0x78,
    ];

    let cipher = [
        0x52, 0x4e, 0x19, 0x2f, 0x47, 0x15, 0xc6, 0x23, 0x1f, 0x51, 0xf6, 0x36, 0x7e, 0xa4, 0x3f,
        0x18,
    ];

    let mut block = *Array::from_slice(&plain_text);

    let rc6 = RC6::new_from_slice(&key).expect("Failed to create RC6");
    rc6.encrypt_block(&mut block);

    assert_eq!(cipher, block[..]);

    rc6.decrypt_block(&mut block);
    assert_eq!(plain_text, block[..]);
}
