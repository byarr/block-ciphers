use cipher::array::ArraySize;
use cipher::consts::{U1, U2, U4, U8};
use cipher::typenum::{Prod, Sum};
use cipher::zeroize::DefaultIsZeroes;
use cipher::Array;
use core::ops::{BitAnd, BitOr, BitXor, Mul, Shl};

// for r rounds we need 2 * r + 4 e.g. 20 rounds is 44 round keys
pub type ExpandedKeyTableSize<R> = Sum<Prod<R, U2>, U4>;
pub type ExpandedKeyTable<W, R> = Array<W, ExpandedKeyTableSize<R>>;

pub type BlockSize<W> = Prod<<W as Word>::Bytes, U4>;
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
    ($primitive:ident, $bytes:ty, $P:expr, $Q:expr) => {
        impl Word for $primitive {
            type Bytes = $bytes;
            const P: Self = $P;
            const Q: Self = $Q;

            const BITS: u32 = $primitive::BITS;

            const LG_W: Self = $primitive::BITS.ilog2() as $primitive;

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
                let mask = (1 << (Self::LG_W)) - 1;
                $primitive::rotate_left(self, rhs.bitand(mask) as u32)
            }

            #[inline(always)]
            fn rotate_right(self, rhs: Self) -> Self {
                let mask = (1 << (Self::LG_W)) - 1;
                $primitive::rotate_right(self, rhs.bitand(mask) as u32)
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

impl_word_for_primitive!(u8, U1, 0xB7, 0x9F);
impl_word_for_primitive!(u16, U2, 0xB7E1, 0x9E37);
impl_word_for_primitive!(u32, U4, 0xB7E15163, 0x9E3779B9);
impl_word_for_primitive!(u64, U8, 0xb7e151628aed2a6b, 0x9e3779b97f4a7c15);
