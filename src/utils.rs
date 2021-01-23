use std::ffi::{self, CStr};
use std::os::raw::c_char;

/// Takes two u8's and forms one u16 where the higher order bits are the first
/// u8 and the lower order bits the second u8.
///
/// minwindef::MAKEWORD already does this, but I felt it was worth being
/// educative by writing it manually. See
/// https://stackoverflow.com/a/50244328/4883095 for a fuller explanation with
/// ASCII art.
///
/// The process is basically this. To make the higher order byte of a u16
/// number, we take our u8, cast it to a u16 value (which means whatever binary
/// number there was, is now left-padded by 8 leading 0's), then when left shift
/// it by 8 digits so that the u8 is encoded on the significant side of the u16,
/// that is, it's now right-padded by 8 trailing 0's.
///
/// We can then just OR this with our lower order byte (converting it first to
/// u16), and the net result is we'll have a single binary number where the
/// first 8 bits are the higher order u8, and the last 8 bits are the lower
/// order u8.
/// ```
/// let x: u8 = 3;
/// assert_eq!(x, 0b00000011);
/// let x = (x as u16) << 8; // This is equivalent to 0b0000000000000011
/// assert_eq!(x, 0b0000001100000000);
/// ```
pub const fn two_u8_to_u16(high: u8, low: u8) -> u16 {
    (high as u16) << 8 | low as u16
}

/// Gets the underlying representation of f32. You'll have to print it in binary
/// format to see it though, as otherwise it will of course be interpreted as a
/// u32 number.
///
/// NOTE: This has nothing to do with this network app, but was educative for me
/// to write!
pub fn f32_to_binary(f: f32) -> u32 {
    let f = unsafe { std::mem::transmute::<f32, [u8; 4]>(f) };
    u32::from_le_bytes(f)
}

/// Takes a buffer of c_chars, and attempts to form a string up to the first
/// null terminator. This means it will never result in an interior null error.
///
/// c_char can be either i8 or u8, it is implementation dependent. We will
/// assume it is i8 here, and because of that, this may not work! :)
pub fn read_c_char_buf(buf: &[c_char]) -> Result<&CStr, ffi::FromBytesWithNulError> {
    // If no null character is found we just slice into the whole array, which
    // will yield an error through from_bytes_with_nul. It would be more
    // performant to manually construct the NotNulTerminated error here and
    // return it in that case.
    let mut last_idx_to_read = buf.len() - 1;
    for i in 0..buf.len() {
        if buf[i] == 0 {
            last_idx_to_read = i;
            break;
        }
    }

    let buf: &[u8] = unsafe { std::mem::transmute(buf) };

    CStr::from_bytes_with_nul(&buf[0..=last_idx_to_read])
}
