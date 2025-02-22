//! Binary formats represented using `binrw` library.

pub mod bcert;
pub mod device;
pub mod pssh;
pub mod xmr_license;

use binrw::{BinRead, BinResult, BinWrite, Endian};
use core::fmt;
use std::{
    io::{Read, Seek, Write},
    iter::from_fn,
    ops::{Deref, DerefMut},
};

pub trait StructTag {
    const TAG: u16;
}

trait StructRawSize {
    fn get_raw_size(&self) -> usize;
}

impl StructRawSize for u8 {
    fn get_raw_size(&self) -> usize {
        std::mem::size_of::<u8>()
    }
}

impl StructRawSize for u16 {
    fn get_raw_size(&self) -> usize {
        std::mem::size_of::<u16>()
    }
}

impl StructRawSize for u32 {
    fn get_raw_size(&self) -> usize {
        std::mem::size_of::<u32>()
    }
}

impl<T: StructRawSize, const C: usize> StructRawSize for [T; C] {
    fn get_raw_size(&self) -> usize {
        self.iter().map(|x| x.get_raw_size()).sum()
    }
}

impl<T: StructRawSize> StructRawSize for Vec<T> {
    fn get_raw_size(&self) -> usize {
        self.iter().map(|x| x.get_raw_size()).sum()
    }
}

/// Returns the smallest multiple of `align` greater than or equal to `self.size()`.
///
/// This can return at most `isize::MAX + 1`
/// because the original size is at most `isize::MAX`.
///
/// Copied from core/alloc/layout.rs.
#[inline]
const fn size_rounded_up_to_custom_align(size: usize, align: usize) -> usize {
    // SAFETY:
    // Rounded up value is:
    //   size_rounded_up = (size + align - 1) & !(align - 1);
    //
    // The arithmetic we do here can never overflow:
    //
    // 1. align is guaranteed to be > 0, so align - 1 is always
    //    valid.
    //
    // 2. size is at most `isize::MAX`, so adding `align - 1` (which is at
    //    most `isize::MAX`) can never overflow a `usize`.
    //
    // 3. masking by the alignment can remove at most `align - 1`,
    //    which is what we just added, thus the value we return is never
    //    less than the original `size`.
    //
    // (Size 0 Align MAX is already aligned, so stays the same, but things like
    // Size 1 Align MAX or Size isize::MAX Align 2 round up to `isize::MAX + 1`.)
    unsafe {
        let align_m1 = usize::unchecked_sub(align, 1);
        usize::unchecked_add(size, align_m1) & !align_m1
    }
}

fn until_exact_number_of_bytes<Reader, T, Arg, Ret>(
    byte_count_limit: u64,
) -> impl Fn(&mut Reader, Endian, Arg) -> BinResult<Ret>
where
    T: for<'a> BinRead<Args<'a> = Arg>,
    Reader: Read + Seek,
    Arg: Clone,
    Ret: FromIterator<T>,
{
    move |reader, endian, args| {
        let mut last = false;
        let start_position = reader.stream_position().unwrap();

        from_fn(|| {
            if last {
                None
            } else {
                match T::read_options(reader, endian, args.clone()) {
                    Ok(value) => {
                        if reader.stream_position().unwrap() - start_position >= byte_count_limit {
                            last = true;
                        }
                        Some(Ok(value))
                    }
                    err => Some(err),
                }
            }
        })
        .fuse()
        .collect()
    }
}

#[derive(Clone)]
pub struct ValueAndRaw<T> {
    pub val: T,
    pub raw: Vec<u8>,
    pub use_raw: bool,
}

impl<T: BinRead> BinRead for ValueAndRaw<T> {
    type Args<'a> = T::Args<'a>;

    fn read_options<R: Read + Seek>(
        reader: &mut R,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<Self> {
        let beg = reader.stream_position()?;
        let val = T::read_options(reader, endian, args)?;
        let end = reader.stream_position()?;

        let len = usize::try_from(end - beg).unwrap();
        let mut raw = vec![0u8; len];
        reader.seek(std::io::SeekFrom::Start(beg))?;
        reader.read_exact(&mut raw)?;

        Ok(ValueAndRaw {
            val,
            raw,
            use_raw: false,
        })
    }
}

impl<T: BinWrite> BinWrite for ValueAndRaw<T> {
    type Args<'a> = T::Args<'a>;

    fn write_options<W: Write + Seek>(
        &self,
        writer: &mut W,
        endian: Endian,
        args: Self::Args<'_>,
    ) -> BinResult<()> {
        match self.use_raw {
            true => self.raw.write_options(writer, endian, ()),
            false => self.val.write_options(writer, endian, args),
        }
    }
}

impl<T> Deref for ValueAndRaw<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.val
    }
}

impl<T> DerefMut for ValueAndRaw<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.val
    }
}

impl<T: fmt::Debug> std::fmt::Debug for ValueAndRaw<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.val.fmt(f)
    }
}

impl<T> From<T> for ValueAndRaw<T> {
    fn from(value: T) -> Self {
        Self {
            val: value,
            raw: Vec::new(),
            use_raw: false,
        }
    }
}

impl<T> From<(T, Vec<u8>)> for ValueAndRaw<T> {
    fn from(value: (T, Vec<u8>)) -> Self {
        Self {
            val: value.0,
            raw: value.1,
            use_raw: false,
        }
    }
}
