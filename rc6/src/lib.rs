#![no_std]

mod primitives;
use primitives::Word;

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use cipher::array::Array;
use cipher::consts::{U1, U2, U4};
use cipher::inout::InOut;

use cipher::{
    array::ArraySize, typenum::Unsigned, AlgorithmName, Block, BlockCipherDecBackend,
    BlockCipherDecClosure, BlockCipherDecrypt, BlockCipherEncBackend, BlockCipherEncClosure,
    BlockCipherEncrypt, BlockSizeUser, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
};
use core::cmp::max;
use core::fmt::Formatter;
use core::marker::PhantomData;

use crate::primitives::{BlockSize, ExpandedKeyTable, ExpandedKeyTableSize};
use cipher::crypto_common::BlockSizes;
use cipher::typenum::Prod;
use core::ops::{Add, Mul};

pub struct RC6<W: Word, R: ArraySize, B: ArraySize>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    key: ExpandedKeyTable<W, R>,
    key_size: PhantomData<B>,
}

impl<W: Word, R: ArraySize, B: ArraySize> RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    pub fn encrypt(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let w_bytes = W::Bytes::to_usize();
        let mut a = W::from_le_bytes(block.get_in()[..w_bytes].try_into().unwrap());
        let mut b = W::from_le_bytes(block.get_in()[w_bytes..2 * w_bytes].try_into().unwrap());
        let mut c = W::from_le_bytes(block.get_in()[2 * w_bytes..3 * w_bytes].try_into().unwrap());
        let mut d = W::from_le_bytes(block.get_in()[3 * w_bytes..].try_into().unwrap());

        b = b.wrapping_add(self.key[0]);
        d = d.wrapping_add(self.key[1]);
        for i in 1..=R::to_usize() {
            let t = b
                .wrapping_mul(b.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);
            let u = d
                .wrapping_mul(d.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);

            a = (a.bitxor(t)).rotate_left(u).wrapping_add(self.key[2 * i]);
            c = (c.bitxor(u))
                .rotate_left(t)
                .wrapping_add(self.key[2 * i + 1]);

            let ta = a;
            a = b;
            b = c;
            c = d;
            d = ta;
        }
        a = a.wrapping_add(self.key[2 * R::to_usize() + 2]);
        c = c.wrapping_add(self.key[2 * R::to_usize() + 3]);

        block.get_out()[0..w_bytes].copy_from_slice(&a.to_le_bytes());
        block.get_out()[w_bytes..2 * w_bytes].copy_from_slice(&b.to_le_bytes());
        block.get_out()[2 * w_bytes..3 * w_bytes].copy_from_slice(&c.to_le_bytes());
        block.get_out()[3 * w_bytes..].copy_from_slice(&d.to_le_bytes());
    }

    pub fn decrypt(&self, mut block: InOut<'_, '_, Block<Self>>) {
        let w_bytes = W::Bytes::to_usize();
        let mut a = W::from_le_bytes(block.get_in()[..w_bytes].try_into().unwrap());
        let mut b = W::from_le_bytes(block.get_in()[w_bytes..2 * w_bytes].try_into().unwrap());
        let mut c = W::from_le_bytes(block.get_in()[2 * w_bytes..3 * w_bytes].try_into().unwrap());
        let mut d = W::from_le_bytes(block.get_in()[3 * w_bytes..].try_into().unwrap());

        c = c.wrapping_sub(self.key[2 * R::to_usize() + 3]);
        a = a.wrapping_sub(self.key[2 * R::to_usize() + 2]);

        for i in (1..=R::to_usize()).rev() {
            {
                let temp_a = a;
                a = d;
                d = c;
                c = b;
                b = temp_a;
            }

            let u = d
                .wrapping_mul(d.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);
            let t = b
                .wrapping_mul(b.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);

            c = c
                .wrapping_sub(self.key[2 * i + 1])
                .rotate_right(t)
                .bitxor(u);
            a = a.wrapping_sub(self.key[2 * i]).rotate_right(u).bitxor(t);
        }

        d = d.wrapping_sub(self.key[1]);
        b = b.wrapping_sub(self.key[0]);

        block.get_out()[0..w_bytes].copy_from_slice(&a.to_le_bytes());
        block.get_out()[w_bytes..2 * w_bytes].copy_from_slice(&b.to_le_bytes());
        block.get_out()[2 * w_bytes..3 * w_bytes].copy_from_slice(&c.to_le_bytes());
        block.get_out()[3 * w_bytes..].copy_from_slice(&d.to_le_bytes());
    }
}

impl<W: Word, R: ArraySize, B: ArraySize> KeySizeUser for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type KeySize = B;
}

impl<W: Word, R: ArraySize, B: ArraySize> BlockSizeUser for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}
impl<W: Word, R: ArraySize, B: ArraySize> KeyInit for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let expanded_key = key_expansion::<W, R, B>(key);
        Self {
            key: expanded_key,
            key_size: PhantomData,
        }
    }
}

impl<W: Word, R: ArraySize, B: ArraySize> AlgorithmName for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn write_alg_name(f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "RC6 {}/{}/{}", W::Bytes::to_u8(), R::to_u8(), B::U8)
    }
}

impl<W: Word, R: ArraySize, B: ArraySize> BlockCipherEncrypt for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn encrypt_with_backend(&self, f: impl BlockCipherEncClosure<BlockSize = Self::BlockSize>) {
        let mut backend: RC6EncBackend<W, R, B> = RC6EncBackend { enc_dec: self };
        f.call(&mut backend)
    }
}

struct RC6EncBackend<'a, W: Word, R: ArraySize, B: ArraySize>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    enc_dec: &'a RC6<W, R, B>,
}

impl<'a, W: Word, R: ArraySize, B: ArraySize> ParBlocksSizeUser for RC6EncBackend<'a, W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<'a, W: Word, R: ArraySize, B: ArraySize> BlockSizeUser for RC6EncBackend<'a, W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<'a, W: Word, R: ArraySize, B: ArraySize> BlockCipherEncBackend for RC6EncBackend<'_, W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn encrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        self.enc_dec.encrypt(block)
    }
}

impl<'a, W: Word, R: ArraySize, B: ArraySize> BlockCipherDecBackend for RC6DecBackend<'a, W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn decrypt_block(&self, block: InOut<'_, '_, Block<Self>>) {
        self.enc_dec.decrypt(block)
    }
}

impl<W: Word, R: ArraySize, B: ArraySize> BlockCipherDecrypt for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn decrypt_with_backend(&self, f: impl BlockCipherDecClosure<BlockSize = Self::BlockSize>) {
        let mut backend: RC6DecBackend<W, R, B> = RC6DecBackend { enc_dec: self };
        f.call(&mut backend)
    }
}

struct RC6DecBackend<'a, W: Word, R: ArraySize, B: ArraySize>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    enc_dec: &'a RC6<W, R, B>,
}

impl<'a, W: Word, R: ArraySize, B: ArraySize> ParBlocksSizeUser for RC6DecBackend<'a, W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<'a, W: Word, R: ArraySize, B: ArraySize> BlockSizeUser for RC6DecBackend<'a, W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

fn key_expansion<W: Word, R: ArraySize, B: ArraySize>(key: &Array<u8, B>) -> ExpandedKeyTable<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    // b bytes into c words
    let bytes_per_word = W::Bytes::to_usize();
    let c = (B::to_usize() + bytes_per_word - 1) / bytes_per_word;

    let b = B::to_usize();

    let mut l: Vec<W> = vec![W::default(); c];
    for i in (0..b).rev() {
        l[i / bytes_per_word] = (l[i / bytes_per_word].rotate_left(8.into())) | (W::from(key[i]));
    }

    let mut s: ExpandedKeyTable<W, R> = Array::from_fn(|_| W::default());
    s[0] = W::P;

    for i in 1..s.len() {
        s[i] = s[i - 1].wrapping_add(W::Q);
    }

    let mut a = W::default();
    let mut b = W::default();
    let mut i = 0;
    let mut j = 0;

    let v = 3 * max(c, s.len());
    for _s in 1..=v {
        a = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3.into());
        s[i] = a;
        b = (l[j].wrapping_add(a).wrapping_add(b)).rotate_left(a.wrapping_add(b));
        l[j] = b;
        i = (i + 1) % (s.len());
        j = (j + 1) % c;
    }

    s
}
