//! Binary formats represented using `binrw` library.

pub mod bcert;
pub mod device;
pub mod pssh;
pub mod xmr_license;

use binrw::{BinRead, BinResult, Endian};
use std::{
    io::{Read, Seek},
    iter::from_fn,
};

pub trait StructTag {
    const TAG: u16;
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
