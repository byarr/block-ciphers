extern crate rc6;

use cipher::array::Array;
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use rc6::RC6;
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
