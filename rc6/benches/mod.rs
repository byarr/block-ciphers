#![feature(test)]
extern crate test;

use cipher::block_decryptor_bench;
use cipher::block_encryptor_bench;
use cipher::consts::{U16, U32};
use rc6::RC6;

block_encryptor_bench!(
    Key: RC6<U16>,
    rc6_32_20_16_encrypt_block,
    rc6_32_20_16_encrypt_blocks,
);

block_decryptor_bench!(
    Key: RC6<U16>,
    rc6_32_20_16_decrypt_block,
    rc6_32_20_16_decrypt_blocks,
);


block_encryptor_bench!(
    Key: RC6<U32>,
    rc6_32_20_32_encrypt_block,
    rc6_32_20_32_encrypt_blocks,
);

block_decryptor_bench!(
    Key: RC6<U32>,
    rc6_32_20_32_decrypt_block,
    rc6_32_20_32_decrypt_blocks,
);
