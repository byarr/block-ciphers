#![feature(test)]
extern crate test;

use cipher::block_decryptor_bench;
use cipher::block_encryptor_bench;
use rc6::RC6;

block_encryptor_bench!(
    Key: RC6,
    rc6_encrypt_block,
    rc6_encrypt_blocks,
);

block_decryptor_bench!(
    Key: RC6,
    rc6_decrypt_block,
    rc6_decrypt_blocks,
);
