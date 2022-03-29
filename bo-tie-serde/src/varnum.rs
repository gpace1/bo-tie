//! Variable length number support
//!
//! Numbers can be encoded with a variable length so long as some of the encoding data is used to
//! indicate how many serialization bytes make up the number. This scheme in this module uses the
//! first byte to mark both how the number is encoded. The maximum number of bytes required is
//! always one more than the size of the number type (e.g. a `u32` can require up to five bytes to
//! encode). This scheme works well when expected values are much less than the maximum value of the
//! number type.
//!
//! This is roughly modeled after this [varint](https://sqlite.org/src4/doc/trunk/www/varint.wiki)
//! implementation.

const U32_VARINT_SIZE: usize = core::mem::size_of::<u32>() + 1;
const USIZE_VARINT_SIZE: usize = core::mem::size_of::<usize>() + 1;

macro_rules! impl_into_iter {
    ($ty:ty, $size:ident) => {
        impl IntoIterator for $ty {
            type Item = u8;
            type IntoIter = core::iter::Take<<[u8; $size] as IntoIterator>::IntoIter>;

            fn into_iter(self) -> Self::IntoIter {
                self.0.into_iter().take(self.1)
            }
        }
    };
}

/// Variant indexing
///
/// A variable length number is used for encoding a variant. The encoding scheme is weighted to only
/// use one or two bytes when encoding most variants.
///
/// # Encoding for a Variant Index
/// In serde a variant index is provided to the serializer as a `u32`. The bo-tie serializer uses
/// the following markings of the first byte to encode a variant index.
///
/// | First Byte (B0)  | Encoding Size | Number Range        | Equation                         | Endianness |
/// | ---------------- | ------------- | ------------------- | -------------------------------- | ---------- |
/// | 0..=0xE0         | 1             | 0..=224             | N = B0                           | N/A        |
/// | 0xE1..=0xFC      | 2             | 225..=7391          | N = 224 + 256 * (B0 - 225) + B1  | big        |
/// | 0xFD             | 3             | 7392..=65,535       | N = \[B1, B2\]                   | little     |
/// | 0xFE             | 4             | 65,536..=16,777,215 | N = \[B1, B2, B3\]               | little     |
/// | 0xFF             | 5             | 16,777,216..        | N = \[B1, B2, B3, B4\]           | little     |
///
/// where:
/// * B# is the encoding byte number
/// * N is the value of the integer
/// * \[B0, B1, ..\] is an array of the bytes containing the number
/// * `..=` is the same as rust's [inclusive range](https://doc.rust-lang.org/core/ops/struct.RangeInclusive.html)
///
/// ### Number Serialization Size
/// The number ranges for serializing the first two bytes are guessed at based on how many
/// enumeration are in a typical `enum` while keeping the encoding and decoding math fast.
/// Enums tend to have the most types of variants (every enumeration is a variant) in rust and they
/// most do not contain more than two hundred of them.
pub struct VariantIndex([u8; U32_VARINT_SIZE], usize);

impl_into_iter!(VariantIndex, U32_VARINT_SIZE);

impl VariantIndex {
    pub fn new(v: u32) -> Self {
        let mut buffer = [0u8; U32_VARINT_SIZE];

        let size = Self::encode(&mut buffer, v);

        Self(buffer, size)
    }

    /// Shortcut to [EncodeU32::encode]
    #[inline]
    fn encode(buffer: &mut [u8; U32_VARINT_SIZE], v: u32) -> usize {
        <Self as EncodeU32>::encode(buffer, v)
    }
}

impl EncodingThresholdsU32 for VariantIndex {
    const S5: u32 = 0x0100_0000;
    const E5: u32 = 0xFFFF_FFFF;

    const S4: u32 = 0x01_0000;
    const E4: u32 = 0xFF_FFFF;

    const S3: u32 = 7392;
    const E3: u32 = 0xFFFF;

    const SF: u32 = 225;
    const EF: u32 = 7391;

    const SMF: u8 = 0xE1;
    const EMF: u8 = 0xFC;

    const EE: u32 = 0xE0;
}

/// String lengths
///
/// Lengths of strings are encoded as a variable length number. This encoding emphasises the use of
/// only one byte to encode a string length.
///
/// # Encoding of a String Length
///
/// | First Byte (B0)  | Encoding Size | Number Range        | Equation                               | Endianness |
/// | ---------------- | ------------- | ------------------- | -------------------------------------- | ---------- |
/// | 0..=0xF8         | 1             | 0..=252             | N = B0                                 | N/A        |
/// | 0xF9             | 3             | 252..=65,535        | N = \[B1, B2\]                         | little     |
/// | 0xFA             | 4             | 65,536..=16,777,215 | N = \[B1, B2, B3\]                     | little     |
/// | 0xFB             | 5             | 16,777,216..2^32    | N = \[B1, B2, B3, B4\]                 | little     |
/// | 0xFC             | 6             | 2^32..2^40          | N = \[B1, B2, B3, B4, B5\]             | little     |
/// | 0xFD             | 7             | 2^40..2^48          | N = \[B1, B2, B3, B4, B5, B6\]         | little     |
/// | 0xFE             | 8             | 2^48..2^56          | N = \[B1, B2, B3, B4, B5, B6, B7\]     | little     |
/// | 0xFF             | 9             | 2^56..2^64          | N = \[B1, B2, B3, B4, B5, B6, B7, B8\] | little     |
///
/// where:
/// * B# is the encoding byte number
/// * N is the value of the integer
/// * \[B0, B1, ..\] is an array of the bytes containing the number
/// * `..=` is the same as rust's [inclusive range](https://doc.rust-lang.org/core/ops/struct.RangeInclusive.html)
pub struct StringLen([u8; USIZE_VARINT_SIZE], usize);

impl_into_iter!(StringLen, USIZE_VARINT_SIZE);

impl StringLen {
    pub fn new(v: usize) -> Self {
        let mut buffer = [0u8; USIZE_VARINT_SIZE];

        let size = Self::encode(&mut buffer, v);

        Self(buffer, size)
    }

    /// Shortcut to [EncodeUsize::encode]
    #[inline]
    fn encode(buffer: &mut [u8; USIZE_VARINT_SIZE], v: usize) -> usize {
        <Self as EncodeUsize>::encode(buffer, v)
    }
}

impl EncodingThresholdsUsize for StringLen {
    const S9: usize = 0x10_0000_0000_0000;
    const E9: usize = 0xFFFF_FFFF_FFFF_FFFF;
    const S8: usize = 0x1_0000_0000_0000;
    const E8: usize = 0xFF_FFFF_FFFF_FFFF;
    const S7: usize = 0x100_0000_0000;
    const E7: usize = 0xFFFF_FFFF_FFFF;
    const S6: usize = 0x1_0000_0000;
    const E6: usize = 0xFF_FFFF_FFFF;
    const S5: usize = 0x10_0000;
    const E5: usize = 0xFFFF_FFFF;
    const S4: usize = 0x1_0000;
    const E4: usize = 0xFF_FFFF;
    const S3: usize = 0xFA;
    const E3: usize = 0xFFFF;
    const SF: usize = 0; // flex not used
    const EF: usize = 0; // flex not used
    const SMF: u8 = 0; // flex not used
    const EMF: u8 = 0; // flex not used
    const EE: usize = 0xF9;
}

/// Byte array length
///
/// This is just an alias to [`StringLen`]
pub type BytesLen = StringLen;

/// Sequence length
///
/// This is just an alias to [`StringLen`]
pub type SequenceLen = StringLen;

/// Map length
///
/// This is just an alias to ['StringLen']
pub type MapLen = StringLen;

/// Encoding threshold values for a `u32`
///
/// There are five different types of thresholds
/// 1) The equivalent thresholds is when the value of the number is the value of the marker
/// 2) The flex thresholds use a combination of the marker and the second byte to encode the number
/// 3) Three byte encoding, where the second and third bytes contain the value
/// 4) Four byte encoding, where the second, third, and fourth bytes contain the value
/// 5) Five byte encoding, where the second, third, fourth, and fifth bytes contain the value
pub(crate) trait EncodingThresholdsU32 {
    /// The starting value for five byte encoding
    const S5: u32;

    /// The ending value for five byte encoding
    const E5: u32 = <u32>::MAX;

    /// The marker for five byte encoding
    const M5: u8 = 0xFF;

    /// The starting value for four byte encoding
    const S4: u32;

    /// the ending value for four byte encoding
    const E4: u32;

    /// The marker for four byte encoding
    const M4: u8 = 0xFE;

    /// The starting value for three byte encoding
    const S3: u32;

    /// The ending value for three byte encoding
    const E3: u32;

    /// The marker for three byte encoding
    const M3: u8 = 0xFD;

    /// The starting value for flex encoding
    const SF: u32;

    /// The ending value for flex encoding
    const EF: u32;

    /// The starting marker value for flex encoding
    const SMF: u8;

    /// The ending marker value for flex encoding
    const EMF: u8;

    /// The starting value for equivalent encoding
    const SE: u32 = 0;

    /// The ending value for equivalent encoding
    const EE: u32;
}

/// Encoding threshold values for a `usize`
///
/// There are nine different types of thresholds, limited by the size of a `usize`. For 16 bit
/// only up to 3 byte encoding is used, for 32 bit up to five bytes are used, and for 64 bit up to
/// nine bytes are used.
/// 1) The equivalent thresholds is when the value of the number is the value of the marker
/// 2) The flex thresholds use a combination of the marker and the second byte to encode the number
/// 3) Three byte encoding, where the second and third bytes contain the value
/// 4) Four byte encoding, where the second, third, and fourth bytes contain the value
/// 5) Five byte encoding, where the second, third, fourth, and fifth bytes contain the value
/// 6) Six byte encoding, where the second, third, fourth, fifth, and sixth bytes contain the value
/// 7) Seven byte encoding, where the second, third, fourth, fifth, sixth, and seventh bytes contain the value
/// 8) Eight byte encoding, where the second, third, fourth, fifth, sixth, seventh, and eight bytes contain the value
/// 9) Nine byte encoding, where the second, third, fourth, fifth, sixth, seventh, eighth, and ninth contain the value
pub(crate) trait EncodingThresholdsUsize {
    /// The starting value for nine byte encoding
    #[cfg(target_pointer_width = "64")]
    const S9: usize;

    /// The ending value for nine byte encoding
    #[cfg(target_pointer_width = "64")]
    const E9: usize;

    /// The marker value for nine byte encoding
    #[cfg(target_pointer_width = "64")]
    const M9: u8 = 0xFF;

    /// The starting value for eight byte encoding
    #[cfg(target_pointer_width = "64")]
    const S8: usize;

    /// The ending value for eight byte encoding
    #[cfg(target_pointer_width = "64")]
    const E8: usize;

    /// The marker value for eight byte encoding
    #[cfg(target_pointer_width = "64")]
    const M8: u8 = 0xFE;

    /// The starting value for seven byte encoding
    #[cfg(target_pointer_width = "64")]
    const S7: usize;

    /// The ending value for seven byte encoding
    #[cfg(target_pointer_width = "64")]
    const E7: usize;

    /// The marker for seven byte encoding
    #[cfg(target_pointer_width = "64")]
    const M7: u8 = 0xFD;

    /// The starting value for six byte encoding
    #[cfg(target_pointer_width = "64")]
    const S6: usize;

    /// The ending value for six byte encoding
    #[cfg(target_pointer_width = "64")]
    const E6: usize;

    /// The marker for six byte encoding
    #[cfg(target_pointer_width = "64")]
    const M6: u8 = 0xFC;

    /// The starting value for five byte encoding
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
    const S5: usize;

    /// The ending value for five byte encoding
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
    const E5: usize;

    /// The marker for five byte encoding
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
    const M5: u8 = 0xFB;

    /// The starting value for four byte encoding
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
    const S4: usize;

    /// the ending value for four byte encoding
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
    const E4: usize;

    /// The marker for four byte encoding
    #[cfg(any(target_pointer_width = "64", target_pointer_width = "32"))]
    const M4: u8 = 0xFA;

    /// The starting value for three byte encoding
    const S3: usize;

    /// The ending value for three byte encoding
    const E3: usize;

    /// The marker for three byte encoding
    const M3: u8 = 0xF9;

    /// The starting value for flex encoding
    const SF: usize;

    /// The ending value for flex encoding
    const EF: usize;

    /// The starting marker value for flex encoding
    const SMF: u8;

    /// The ending marker value for flex encoding
    const EMF: u8;

    /// The starting value for equivalent encoding
    const SE: usize = 0;

    /// The ending value for equivalent encoding
    const EE: usize;
}

macro_rules! encode_out_of_marker {
    ($marker:expr, $value:expr, $buffer:expr, $size:expr) => {{
        let le_bytes = $value.to_le_bytes();
        $buffer[0] = $marker;
        $buffer[1..$size].copy_from_slice(&le_bytes[..($size - 1)]);
        $size
    }};
}

macro_rules! impl_encode {
    (
        $value:expr, $buffer:expr,
        $start_equivalent:path => $end_equivalent:path,
        $start_flex:path => $end_flex:path,
        $start_3:path => $end_3:path : $marker_3:path,
        $($start:path => $end:path : $marker:path | $size:expr ),* $(,)?
    ) => {{
        if ($start_equivalent..=$end_equivalent).contains(&$value) {
            $buffer[0] = $value as u8;
            1
        } else if ($start_flex..=$end_flex).contains(&$value) {
            let adjust = $value - $end_equivalent;

            $buffer[0] = ((adjust >> 8) + $start_flex) as u8;
            $buffer[1] = (adjust & 0xFF) as u8;
            2
        } else if ($start_3..=$end_3).contains(&$value) {
            encode_out_of_marker!($marker_3, $value, $buffer, 3)
        }

        $(
            else if ($start..=$end).contains(&$value) {
                encode_out_of_marker!($marker, $value, $buffer, $size)
            }
        )*

        else {
            unreachable!()
        }
    }}
}

/// Trait for encoding a u32 variable length value
trait EncodeU32: EncodingThresholdsU32 {
    /// Encodes the value and return the size of the encoded number
    fn encode(buffer: &mut [u8; U32_VARINT_SIZE], v: u32) -> usize {
        impl_encode! {
            v, buffer,
            Self::SE => Self::EE,
            Self::SF => Self::EF,
            Self::S3 => Self::E3 : Self::M3,
            Self::S4 => Self::E4 : Self::M4 | 4,
            Self::S5 => Self::E5 : Self::M5 | 5,
        }
    }
}

impl<T> EncodeU32 for T where T: EncodingThresholdsU32 {}

macro_rules! decode_out_of_marker {
    ($encoding:expr, $size:expr, $decode_type:ty ) => {
        if $encoding.len() >= $size {
            let mut buffer = [0u8; core::mem::size_of::<$decode_type>()];

            buffer.copy_from_slice(&$encoding[1..$size]);

            Ok((<$decode_type>::from_le_bytes(buffer), $size))
        } else {
            Err(VariantNumberError::IncorrectEncoding)
        }
    };
}

macro_rules! impl_decode {
    (
        $decode_type:ty,
        $encoding:expr,
        $start_equivalent:path => $end_equivalent:path,
        $start_flex:path => $end_flex:path,
        $($marker:path | $size:expr),* $(,)?
    ) => {{
        let marker = $encoding.get(0).ok_or(VariantNumberError::EmptyBuffer)?;

        $(
            if $marker.eq(marker) {
                decode_out_of_marker!($encoding, $size, $decode_type)
            } else
        )*

        if ($start_flex..=$end_flex).contains(marker) {
            let b1 = *$encoding.get(1).ok_or(VariantNumberError::IncorrectEncoding)?;

            Ok(($end_equivalent + ((*marker as $decode_type) - $start_equivalent) << 8 + (b1 as $decode_type), 2))
        } else {
            $encoding
                .get(0)
                .map(|v| (<$decode_type>::from(*v), 1))
                .ok_or(VariantNumberError::IncorrectEncoding)
        }
    }};
}

/// Trait for decoding a u32 variable length value
pub(crate) trait DecodeU32: EncodingThresholdsU32 {
    /// Try to decode a slice containing a variable length integer into a u32 value
    ///
    /// If the number is successfully decoded then the value is returned along with the the number
    /// of bytes that too to encode the value.
    ///
    /// Input `encoding` must start with a u32 variant number, but it may contain more bytes than
    /// needed to contain the integer.
    ///
    /// # Error
    /// `var` must be equal to or greater than the number of bytes as indicated by the marker byte.
    /// Any bytes in `var` after the encoded number are ignored.
    fn try_decode(encoding: &[u8]) -> Result<(u32, usize), VariantNumberError> {
        impl_decode!(
            u32, encoding,
            Self::SF => Self::EF,
            Self::SMF => Self::EMF,
            Self::M3 | 3,
            Self::M4 | 4,
            Self::M5 | 5,
        )
    }
}

impl<T> DecodeU32 for T where T: EncodingThresholdsU32 {}

trait EncodeUsize: EncodingThresholdsUsize {
    /// Encodes the value and return the size of the encoded number
    fn encode(buffer: &mut [u8; USIZE_VARINT_SIZE], v: usize) -> usize {
        #[cfg(target_pointer_width = "64")]
        impl_encode! {
            v, buffer,
            Self::SE => Self::EE,
            Self::SF => Self::EF,
            Self::S3 => Self::E3 : Self::M3,
            Self::S4 => Self::E4 : Self::M4 | 4,
            Self::S5 => Self::E5 : Self::M5 | 5,
            Self::S6 => Self::E6 : Self::M6 | 6,
            Self::S7 => Self::E7 : Self::M7 | 7,
            Self::S8 => Self::E8 : Self::M8 | 8,
            Self::S9 => Self::E9 : Self::M9 | 9,
        }

        #[cfg(target_pointer_width = "32")]
        impl_encode! {
            v, buffer,
            Self::SE => Self::EE,
            Self::SF => Self::EF,
            Self::S3 => Self::E3 : Self::M3,
            Self::S4 => Self::E4 : Self::M4 | 4,
            Self::S5 => Self::E5 : Self::M5 | 5,
        }

        #[cfg(target_pointer_width = "16")]
        impl_encode! {
            v, buffer,
            Self::SE => Self::EE,
            Self::SF => Self::EF,
            Self::S3 => Self::E3 : Self::M3,
        }
    }
}

impl<T> EncodeUsize for T where T: EncodingThresholdsUsize {}

pub(crate) trait DecodeUsize: EncodingThresholdsUsize {
    /// Try to decode a slice containing a variable length integer into a usize value
    ///
    /// If the number is successfully decoded then the value is returned along with the the number
    /// of bytes that too to encode the value.
    ///
    /// Input `encoding` must start with a usize variant number, but it may contain more bytes than
    /// needed to contain the integer.
    ///
    /// # Error
    /// `var` must be equal to or greater than the number of bytes as indicated by the marker byte.
    /// Any bytes in `var` after the encoded number are ignored.
    fn try_decode(encoding: &[u8]) -> Result<(usize, usize), VariantNumberError> {
        #[cfg(target_pointer_width = "64")]
        impl_decode! {
            usize, encoding,
            Self::SF => Self::EF,
            Self::SMF => Self::EMF,
            Self::M3 | 3,
            Self::M4 | 4,
            Self::M5 | 5,
            Self::M6 | 6,
            Self::M7 | 7,
            Self::M8 | 8,
            Self::M9 | 9,
        }

        #[cfg(target_pointer_width = "32")]
        impl_decode! {
            usize, encoding,
            Self::SF => Self::EF,
            Self::SMF => Self::EMF,
            Self::M3 | 3,
            Self::M4 | 4,
            Self::M5 | 5,
        }

        #[cfg(target_pointer_width = "16")]
        impl_decode! {
            usize, encoding,
            Self::SF => Self::EF,
            Self::SMF => Self::EMF,
            Self::M3 | 3,
        }
    }
}

impl<T> DecodeUsize for T where T: EncodingThresholdsUsize {}

#[derive(Debug, thiserror::Error)]
pub enum VariantNumberError {
    #[error("incorrect encoding for variant")]
    IncorrectEncoding,
    #[error("buffer is empty")]
    EmptyBuffer,
}
