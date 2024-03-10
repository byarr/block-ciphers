extern crate rc6;

use cipher::array::Array;
use cipher::consts::{U16, U20, U24, U32};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use hex_literal::hex;
use rc6::RC6;

macro_rules! rc6_test_case {
    ($name:ident, $rounds:ident, $key_size:ident, $plain:expr, $key:expr, $cipher:expr) => {
        #[test]
        fn $name() {
            let plain_text = hex!($plain);
            let key = hex!($key);
            let cipher = hex!($cipher);
            let mut block = *Array::from_slice(&plain_text);

            let rc6 = <RC6<u32, $rounds, $key_size> as KeyInit>::new_from_slice(&key).unwrap();
            rc6.encrypt_block(&mut block);

            assert_eq!(cipher, block[..]);

            rc6.decrypt_block(&mut block);
            assert_eq!(plain_text, block[..]);
        }
    };
}

// test vectors taken from https://web.archive.org/web/20181223080309/http://people.csail.mit.edu/rivest/rc6.pdf
rc6_test_case!(
    vector_1,
    U20,
    U16,
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "8f c3 a5 36 56 b1 f7 78 c1 29 df 4e 98 48 a4 1e"
);
rc6_test_case!(
    vector_2,
    U20,
    U16,
    "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
    "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78",
    "52 4e 19 2f 47 15 c6 23 1f 51 f6 36 7e a4 3f 18"
);

rc6_test_case!(
    vector_3,
    U20,
    U24,
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "6c d6 1b cb 19 0b 30 38 4e 8a 3f 16 86 90 ae 82"
);

rc6_test_case!(
    vector_4,
    U20,
    U24,
    "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
    "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0",
    "68 83 29 d0 19 e5 05 04 1e 52 e9 2a f9 52 91 d4"
);

rc6_test_case!(
    vector_5,
        U20,
    U32,
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
    "8f 5f bd 05 10 d1 5f a8 93 fa 3f da 6e 85 7e c2"
);

rc6_test_case!(
    vector_6,
        U20,
    U32,
    "02 13 24 35 46 57 68 79 8a 9b ac bd ce df e0 f1",
    "01 23 45 67 89 ab cd ef 01 12 23 34 45 56 67 78 89 9a ab bc cd de ef f0 10 32 54 76 98 ba dc fe",
    "c8 24 18 16 f0 d7 e4 89 20 ad 16 a1 67 4e 5d 48"
);


rc6_test_case!(
    RC6_32_20_16,
        U20,
    U16,
    "000102030405060708090A0B0C0D0E0F",
    "000102030405060708090A0B0C0D0E0F",
    "3A96F9C7F6755CFE46F00E3DCD5D2A3C"
);