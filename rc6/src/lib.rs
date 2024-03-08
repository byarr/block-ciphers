#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use cipher::array::Array;
use cipher::consts::{U1, U16, U44};
use cipher::inout::InOut;

use cipher::{
    AlgorithmName, ArraySize, Block, BlockBackend, BlockCipher, BlockCipherDecrypt,
    BlockCipherEncrypt, BlockClosure, BlockSizeUser, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
    Unsigned,
};
use core::cmp::max;
use core::fmt::Formatter;
use core::marker::PhantomData;

use cipher::zeroize::DefaultIsZeroes;
use core::ops::{BitAnd, BitOr, BitXor, Shl};

// This should be parameterised but hard code for now
// W - word size (bits) - 32
// R - number of rounds - 20
// B - key length in bytes - 16

// word size in bits
const LG_W: u32 = 5;

// number of rounds
const R: usize = 20;

pub struct RC6<B: ArraySize> {
    key: Array<u32, U44>,
    key_size: PhantomData<B>,
}

impl<B: ArraySize> BlockCipher for RC6<B> {}

impl<B: ArraySize> KeySizeUser for RC6<B> {
    type KeySize = B;
}

impl<B: ArraySize> BlockSizeUser for RC6<B> {
    type BlockSize = U16;
}
impl<B: ArraySize> KeyInit for RC6<B> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        let expanded_key = key_expansion(key);
        Self {
            key: expanded_key,
            key_size: PhantomData,
        }
    }
}

impl<B: ArraySize> AlgorithmName for RC6<B> {
    fn write_alg_name(f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "RC6 32/20/{}", B::U8)
    }
}

impl<B: ArraySize> BlockCipherEncrypt for RC6<B> {
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut RC6EncBackend {
            expanded_key: self.key,
        })
    }
}

struct RC6EncBackend {
    expanded_key: Array<u32, U44>,
}

impl ParBlocksSizeUser for RC6EncBackend {
    type ParBlocksSize = U1;
}

impl BlockSizeUser for RC6EncBackend {
    type BlockSize = U16;
}

impl BlockBackend for RC6EncBackend {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut a = u32::from_le_bytes(block.get_in()[..4].try_into().unwrap());
        let mut b = u32::from_le_bytes(block.get_in()[4..8].try_into().unwrap());
        let mut c = u32::from_le_bytes(block.get_in()[8..12].try_into().unwrap());
        let mut d = u32::from_le_bytes(block.get_in()[12..16].try_into().unwrap());

        b = b.wrapping_add(self.expanded_key[0]);
        d = d.wrapping_add(self.expanded_key[1]);
        for i in 1..=R {
            let t = b
                .wrapping_mul(b.wrapping_mul(2).wrapping_add(1))
                .rotate_left(LG_W);
            let u = d
                .wrapping_mul(d.wrapping_mul(2).wrapping_add(1))
                .rotate_left(LG_W);

            a = (a.bitxor(t))
                .rotate_left(u.bitand(0b11111))
                .wrapping_add(self.expanded_key[2 * i]);
            c = (c.bitxor(u))
                .rotate_left(t.bitand(0b11111))
                .wrapping_add(self.expanded_key[2 * i + 1]);

            let ta = a;
            a = b;
            b = c;
            c = d;
            d = ta;
        }
        a = a.wrapping_add(self.expanded_key[2 * R + 2]);
        c = c.wrapping_add(self.expanded_key[2 * R + 3]);

        block.get_out()[0..4].copy_from_slice(&a.to_le_bytes());
        block.get_out()[4..8].copy_from_slice(&b.to_le_bytes());
        block.get_out()[8..12].copy_from_slice(&c.to_le_bytes());
        block.get_out()[12..16].copy_from_slice(&d.to_le_bytes());
    }
}

impl<B: ArraySize> BlockCipherDecrypt for RC6<B> {
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        f.call(&mut RC6DecBackend {
            expanded_key: self.key,
        })
    }
}

struct RC6DecBackend {
    expanded_key: Array<u32, U44>,
}

impl ParBlocksSizeUser for RC6DecBackend {
    type ParBlocksSize = U1;
}

impl BlockSizeUser for RC6DecBackend {
    type BlockSize = U16;
}

impl BlockBackend for RC6DecBackend {
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut a = u32::from_le_bytes(block.get_in()[..4].try_into().unwrap());
        let mut b = u32::from_le_bytes(block.get_in()[4..8].try_into().unwrap());
        let mut c = u32::from_le_bytes(block.get_in()[8..12].try_into().unwrap());
        let mut d = u32::from_le_bytes(block.get_in()[12..16].try_into().unwrap());

        c = c.wrapping_sub(self.expanded_key[2 * R + 3]);
        a = a.wrapping_sub(self.expanded_key[2 * R + 2]);

        for i in (1..=R).rev() {
            {
                let temp_a = a;
                a = d;
                d = c;
                c = b;
                b = temp_a;
            }

            let u = d
                .wrapping_mul(d.wrapping_mul(2).wrapping_add(1))
                .rotate_left(LG_W);
            let t = b
                .wrapping_mul(b.wrapping_mul(2).wrapping_add(1))
                .rotate_left(LG_W);

            c = c
                .wrapping_sub(self.expanded_key[2 * i + 1])
                .rotate_right(t & 0b11111)
                .bitxor(u);
            a = a
                .wrapping_sub(self.expanded_key[2 * i])
                .rotate_right(u & 0b11111)
                .bitxor(t);
        }

        d = d.wrapping_sub(self.expanded_key[1]);
        b = b.wrapping_sub(self.expanded_key[0]);

        block.get_out()[0..4].copy_from_slice(&a.to_le_bytes());
        block.get_out()[4..8].copy_from_slice(&b.to_le_bytes());
        block.get_out()[8..12].copy_from_slice(&c.to_le_bytes());
        block.get_out()[12..16].copy_from_slice(&d.to_le_bytes());
    }
}

trait Word:
    Shl<Output = Self>
    + From<u8>
    + BitOr<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + DefaultIsZeroes
{
    const P: Self;
    const Q: Self;

    const BITS: u32;

    fn wrapping_add(self, rhs: Self) -> Self;

    fn wrapping_mul(self, rhs: Self) -> Self;

    fn rotate_left(self, rhs: Self) -> Self;
}

macro_rules! impl_word_for_primitive {
    ($primitive:ident, $P:expr, $Q:expr) => {
        impl Word for $primitive {
            const P: Self = $P;
            const Q: Self = $Q;

            const BITS: u32 = $primitive::BITS;

            fn wrapping_add(self, rhs: Self) -> Self {
                self.wrapping_add(rhs)
            }

            fn wrapping_mul(self, rhs: Self) -> Self {
                self.wrapping_mul(rhs)
            }

            fn rotate_left(self, rhs: Self) -> Self {
                self.rotate_left(rhs)
            }
        }
    };
}

impl_word_for_primitive!(u32, 0xB7E15163, 0x9E3779B9);

fn key_expansion<W: Word, B: ArraySize>(key: &Array<u8, B>) -> Array<W, U44> {
    // output size only depends on the number of rounds
    assert_eq!(2 * R + 4, U44::to_usize());

    // b bytes into c words
    let bytes_per_word = W::BITS as usize / 8;
    let c = (B::to_usize() + bytes_per_word - 1) / bytes_per_word;

    let b = B::to_usize();

    let mut l: Vec<W> = vec![W::default(); c];
    for i in (0..=(b - 1)).rev() {
        l[i / bytes_per_word] = (l[i / bytes_per_word] << 8.into()) | (W::from(key[i]));
    }

    let mut s: Array<W, U44> = Array::from_fn(|_| W::default());
    s[0] = W::P;

    for i in 1..s.len() {
        s[i] = s[i - 1].wrapping_add(W::Q);
    }

    let mut a = W::default();
    let mut b = W::default();
    let mut i = 0;
    let mut j = 0;

    let v = 3 * max(c, 2 * R + 4);
    for _s in 1..=v {
        a = s[i].wrapping_add(a).wrapping_add(b).rotate_left(3.into());
        s[i] = a;
        b = (l[j].wrapping_add(a).wrapping_add(b))
            .rotate_left(a.wrapping_add(b).bitand(0b11111.into()));
        l[j] = b;
        i = (i + 1) % (2 * R + 4);
        j = (j + 1) % c;
    }

    s
}
