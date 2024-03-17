#![no_std]

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use cipher::array::Array;
use cipher::consts::{U1, U2, U4};
use cipher::inout::InOut;

use cipher::{
    AlgorithmName, ArraySize, Block, BlockBackend, BlockCipher, BlockCipherDecrypt,
    BlockCipherEncrypt, BlockClosure, BlockSizeUser, Key, KeyInit, KeySizeUser, ParBlocksSizeUser,
    Unsigned,
};
use core::cmp::max;
use core::fmt::Formatter;
use core::marker::PhantomData;

use cipher::crypto_common::BlockSizes;
use cipher::typenum::{Prod, Sum};
use cipher::zeroize::DefaultIsZeroes;
use core::ops::{Add, BitAnd, BitOr, BitXor, Mul, Shl};

// for r rounds we need 2 * r + 4 e.g. 20 rounds is 44 round keys
pub type ExpandedKeyTableSize<R> = Sum<Prod<R, U2>, U4>;
pub type ExpandedKeyTable<W, R> = Array<W, ExpandedKeyTableSize<R>>;

pub type BlockSize<W> = Prod<<W as Word>::Bytes, U4>;

// This should be parameterised but hard code for now
// W - word size (bits) - 32
// R - number of rounds - 20
// B - key length in bytes - 16

// number of rounds
const R: usize = 20;

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

impl<W: Word, R: ArraySize, B: ArraySize> BlockCipher for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
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
        write!(f, "RC6 {}/20/{}", W::Bytes::to_u8(), B::U8)
    }
}

impl<W: Word, R: ArraySize, B: ArraySize> BlockCipherEncrypt for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn encrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend: RC6EncBackend<W, R> = RC6EncBackend {
            expanded_key: self.key.clone(),
        };
        f.call(&mut backend)
    }
}

struct RC6EncBackend<W: Word, R: ArraySize>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    expanded_key: ExpandedKeyTable<W, R>,
}

impl<W: Word, R: ArraySize> ParBlocksSizeUser for RC6EncBackend<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<W: Word, R: ArraySize> BlockSizeUser for RC6EncBackend<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<W: Word, R: ArraySize> BlockBackend for RC6EncBackend<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut a = W::from_le_bytes(block.get_in()[..4].try_into().unwrap());
        let mut b = W::from_le_bytes(block.get_in()[4..8].try_into().unwrap());
        let mut c = W::from_le_bytes(block.get_in()[8..12].try_into().unwrap());
        let mut d = W::from_le_bytes(block.get_in()[12..16].try_into().unwrap());

        b = b.wrapping_add(self.expanded_key[0]);
        d = d.wrapping_add(self.expanded_key[1]);
        for i in 1..=R {
            let t = b
                .wrapping_mul(b.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);
            let u = d
                .wrapping_mul(d.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);

            a = (a.bitxor(t))
                .rotate_left(u.bitand(0b11111.into()))
                .wrapping_add(self.expanded_key[2 * i]);
            c = (c.bitxor(u))
                .rotate_left(t.bitand(0b11111.into()))
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

impl<W: Word, R: ArraySize, B: ArraySize> BlockCipherDecrypt for RC6<W, R, B>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn decrypt_with_backend(&self, f: impl BlockClosure<BlockSize = Self::BlockSize>) {
        let mut backend: RC6DecBackend<W, R> = RC6DecBackend {
            expanded_key: self.key.clone(),
        };
        f.call(&mut backend)
    }
}

struct RC6DecBackend<W: Word, R: ArraySize>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    expanded_key: ExpandedKeyTable<W, R>,
}

impl<W: Word, R: ArraySize> ParBlocksSizeUser for RC6DecBackend<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type ParBlocksSize = U1;
}

impl<W: Word, R: ArraySize> BlockSizeUser for RC6DecBackend<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    type BlockSize = BlockSize<W>;
}

impl<W: Word, R: ArraySize> BlockBackend for RC6DecBackend<W, R>
where
    BlockSize<W>: BlockSizes,
    R: Mul<U2>,
    Prod<R, U2>: Add<U4>,
    ExpandedKeyTableSize<R>: ArraySize,
{
    fn proc_block(&mut self, mut block: InOut<'_, '_, Block<Self>>) {
        let mut a = W::from_le_bytes(block.get_in()[..4].try_into().unwrap());
        let mut b = W::from_le_bytes(block.get_in()[4..8].try_into().unwrap());
        let mut c = W::from_le_bytes(block.get_in()[8..12].try_into().unwrap());
        let mut d = W::from_le_bytes(block.get_in()[12..16].try_into().unwrap());

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
                .wrapping_mul(d.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);
            let t = b
                .wrapping_mul(b.wrapping_mul(2.into()).wrapping_add(1.into()))
                .rotate_left(W::LG_W);

            c = c
                .wrapping_sub(self.expanded_key[2 * i + 1])
                .rotate_right(t.bitand(0b11111.into()))
                .bitxor(u);
            a = a
                .wrapping_sub(self.expanded_key[2 * i])
                .rotate_right(u.bitand(0b11111.into()))
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

pub trait Word:
    Shl<Output = Self>
    + From<u8>
    + BitOr<Self, Output = Self>
    + BitXor<Self, Output = Self>
    + BitAnd<Self, Output = Self>
    + DefaultIsZeroes
{
    type Bytes: ArraySize + Mul<U4>;
    const P: Self;
    const Q: Self;

    const BITS: u32;

    const LG_W: Self;

    fn wrapping_add(self, rhs: Self) -> Self;
    fn wrapping_sub(self, rhs: Self) -> Self;

    fn wrapping_mul(self, rhs: Self) -> Self;
    fn rotate_left(self, rhs: Self) -> Self;
    fn rotate_right(self, rhs: Self) -> Self;
    fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self;
    fn to_le_bytes(self) -> Array<u8, Self::Bytes>;
}

macro_rules! impl_word_for_primitive {
    ($primitive:ident, $bytes:ty, $lgw:expr, $P:expr, $Q:expr) => {
        impl Word for $primitive {
            type Bytes = $bytes;
            const P: Self = $P;
            const Q: Self = $Q;

            const BITS: u32 = $primitive::BITS;

            const LG_W: Self = $lgw;

            #[inline(always)]
            fn wrapping_add(self, rhs: Self) -> Self {
                $primitive::wrapping_add(self, rhs)
            }

            #[inline(always)]
            fn wrapping_sub(self, rhs: Self) -> Self {
                $primitive::wrapping_sub(self, rhs)
            }

            #[inline(always)]
            fn wrapping_mul(self, rhs: Self) -> Self {
                $primitive::wrapping_mul(self, rhs)
            }

            #[inline(always)]
            fn rotate_left(self, rhs: Self) -> Self {
                $primitive::rotate_left(self, rhs)
            }

            #[inline(always)]
            fn rotate_right(self, rhs: Self) -> Self {
                $primitive::rotate_right(self, rhs)
            }

            #[inline(always)]
            fn from_le_bytes(bytes: &Array<u8, Self::Bytes>) -> Self {
                $primitive::from_le_bytes(bytes.as_slice().try_into().unwrap())
            }

            #[inline(always)]
            fn to_le_bytes(self) -> Array<u8, Self::Bytes> {
                $primitive::to_le_bytes(self).into()
            }
        }
    };
}

impl_word_for_primitive!(u32, U4, 5, 0xB7E15163, 0x9E3779B9);

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
        l[i / bytes_per_word] = (l[i / bytes_per_word] << 8.into()) | (W::from(key[i]));
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
        b = (l[j].wrapping_add(a).wrapping_add(b))
            .rotate_left(a.wrapping_add(b).bitand(0b11111.into()));
        l[j] = b;
        i = (i + 1) % (s.len());
        j = (j + 1) % c;
    }

    s
}
