//! Local name data type
//!
//! The local name is the name for the Bluetooth device. The data for the local name structure is
//! just a sequence of utf-8 characters. However the name of the device may be too long for a
//! transport payload to contain so there is two versions of a local name. The complete local name
//! is the full local name of the device. This should be the same name as reported by other methods
//! to get the full name. The shortened local name is an alternative name or abbreviation of the
//! device name that should be easily relatable to the complete local name.
//!
//! The type [`LocalName`] is used as a local name. It is created with the string for the local name
//! and a shortening policy. The shortening policy is a fallback to use alternative shortened names
//! when the full local name is too large. A local name can be shortened to an alternative name or
//! an abbreviated size. The shortener will use the first shortened name that fits.
//!
//! # Name Shortener
//! A name shortener must implement the trait [`shorts::NameShortener`]. More often this trait is
//! not deliberately implemented, and instead a `NameShortener` is derived from the a type that
//! implements [`shorts::IntoNameShortener`]. This trait is implemented for a number of types that
//! get converted into one of the structs in `shorts` that already implement `NameShortener`.
//!
//! ## Alternative Names
//! When creating a `LocalName` a list of strings can be used to provide alternative names. A slice
//! or array of strings (any type that implements [`Borrow<str>`](core::borrow::Borrow)) will be
//! converted into the name shortener [`shorts::Alternatives`]. `Alternatives` will iterate
//! through the alternative names and pick the first one that will fit.
//!
//! ```
//! # use bo_tie_gap::assigned::local_name::LocalName;
//! # use bo_tie_gap::assigned::{AssignedTypes, Sequence};
//! # use core::str;
//! // Create a `LocalName` with the alternatives "example local name" and "example"
//! let local_name = LocalName::new("example local name of a device", ["example local name", "🙈 🙉 🙊", "example"]);
//!
//! let complete_buffer = &mut [0u8; 40];
//!
//! let mut complete_sequence = Sequence::new(complete_buffer);
//!
//! complete_sequence.try_add(&local_name).unwrap();
//!
//! let complete_structure = complete_sequence.into_inner();
//!
//! assert_eq!(AssignedTypes::CompleteLocalName.val(), complete_structure[1]);
//!
//! assert_eq!("example local name of a device", str::from_utf8(&complete_structure[2..32]).unwrap());
//!
//! // This is a buffer that will exactly fit the local
//! // name data structure containing "example".
//! //
//! // Note: "🙈 🙉 🙊" is skipped because each emoji
//! // is actually represented in utf-8 with four bytes.
//! let short_buffer = &mut [0u8; 9];
//!
//! let mut short_sequence = Sequence::new(short_buffer);
//!
//! short_sequence.try_add(&local_name).unwrap();
//!
//! let short_structure = short_sequence.into_inner();
//!
//! assert_eq!(AssignedTypes::ShortenedLocalName.val(), short_structure[1]);
//!
//! assert_eq!("example", str::from_utf8(&short_structure[2..]).unwrap() )
//! ```
//!
//! ## Abbreviations
//! A list of positive integers can be used to abbreviate a local name. This list is converted into
//! a [`shorts::Abbreviations`] when creating a new `LocalName`. Each integer is used as the number
//! of *characters* to abbreviate the name to
//!
//! ```
//! # use bo_tie_gap::assigned::local_name::LocalName;
//! # use bo_tie_gap::assigned::{AssignedTypes, Sequence};
//! # use core::str;
//! let local_name = LocalName::new("LocalName abbreviations example", [23, 9]);
//!
//! let buffer = &mut [0u8; 11];
//!
//! let mut sequence = Sequence::new(buffer);
//!
//! sequence.try_add(&local_name).unwrap();
//!
//! assert_eq!("LocalName", str::from_utf8(&sequence.into_inner()[2..]).unwrap());
//! ```
//! As a shortcut for a single abbreviation, a single number can be used to create the name
//! shortener [`shorts::SingleAbbreviation`].
//!
//! ```
//! # use bo_tie_gap::assigned::local_name::LocalName;
//! let local_name = LocalName::new("My Device", 6);
//! ```
//!
//! ## Complete Name Only
//! Using `None` when creating a `LocalName` will cause the local name to never shorten nor further
//! shorten the name.
//!
//! ```
//! # use bo_tie_gap::assigned::local_name::LocalName;
//! # use bo_tie_gap::assigned::{ConvertError, Sequence};
//! let local_name = LocalName::new("My Full Device Name", None);
//!
//! let buffer = &mut [0u8; 13];
//!
//! let mut sequence = Sequence::new(buffer);
//!
//! // buffer is too small to fit the local name
//! assert!(sequence.try_add(&local_name).is_err());
//!
//! # // just a hidden unit test of the error :)
//! # assert_eq!(Err(ConvertError { required: 21, remaining: 13 }), sequence.try_add(&local_name));
//! ```
pub mod shorts;

use super::*;
use core::borrow::Borrow;
use shorts::{HowToShort, IntoNameShortener, NameShortener};

/// A Local Name
///
/// See the [module] level documentation for details.
///
/// [module]: self
pub struct LocalName<N, S> {
    name: N,
    is_complete: bool,
    short: S,
}

impl<N, S> LocalName<N, S>
where
    N: Borrow<str>,
{
    /// Create a new local name
    ///
    /// Create a `LocalName` where `complete_name` is the full local name.
    pub fn new<T>(complete_name: N, name_shortener: T) -> Self
    where
        T: IntoNameShortener<IntoShorter = S>,
    {
        let name = complete_name;

        let short = name_shortener.into_shorter();

        let is_complete = true;

        Self {
            name,
            is_complete,
            short,
        }
    }

    /// Create a shortened local name
    ///
    /// Create a `LocalName` from an already shortened local name. Input `further_shortener` is used
    /// to further shorten the name in the event where `shortened_name` is still too large.
    pub fn new_short<T>(shortened_name: N, further_shortener: T) -> Self
    where
        T: IntoNameShortener<IntoShorter = S>,
    {
        let name = shortened_name;

        let is_complete = false;

        let short = further_shortener.into_shorter();

        Self {
            name,
            is_complete,
            short,
        }
    }

    /// Get the string slice for the name
    pub fn as_str(&self) -> &str {
        self.name.borrow()
    }

    /// Convert this `LocalName` into its name type
    pub fn into_name(self) -> N {
        self.name
    }

    /// Check if the name is complete
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Change the name shortener
    ///
    /// Change the name shortener to a different shortener. This is useful when a `LocalName` is
    /// created from a raw structure as [`TryFromStruct`] is only implemented for a `LocalName` with
    /// the shortener [`NeverShorten`].
    ///
    /// [`TryFromStruct`]: super::TryFromStruct
    /// [`NeverShorten`]: shorts::NeverShorten
    pub fn change_shortener<T, R>(self, new_shortener: T) -> LocalName<N, R>
    where
        T: IntoNameShortener<IntoShorter = R>,
    {
        let name = self.name;

        let short = new_shortener.into_shorter();

        let is_complete = self.is_complete;

        LocalName {
            name,
            is_complete,
            short,
        }
    }

    /// Short the name by a specific size
    ///
    /// This shortens the local name to have a length of `size`. It will try to insert the shortened
    /// name into `interim`, but if the shortened local name is too large to be put within
    /// `interim` then `Err` is returned.
    ///
    /// If `short_by_size` fails it will return an error of the number of bytes that were required
    /// of the buffer to create the structure.
    fn short_by_size(&self, size: usize, interim: &mut StructIntermediate) -> Result<(), usize> {
        let byte_count: usize = self.name.borrow().chars().take(size).map(|c| c.len_utf8()).sum();

        (byte_count <= interim.remaining_len())
            .then(|| {
                self.name
                    .borrow()
                    .chars()
                    .take(size)
                    .for_each(|c| interim.encode_utf8(c))
            })
            .ok_or(byte_count)
    }

    /// Short the name by an alternative name
    ///
    /// This uses an alternative name as a shortened name. It will try to insert the shortened name
    /// into `interim`, but if the shortened local name is too large to be put within `interim`
    /// then `Err` is returned.
    ///
    /// If `short_by_alt` fails it will return an error of the number of bytes that were required of
    /// the buffer to create the structure.
    fn short_by_alt(&self, alt: &str, interim: &mut StructIntermediate) -> Result<(), usize> {
        let byte_count = alt.bytes().len();

        (byte_count <= interim.remaining_len())
            .then(|| alt.chars().for_each(|c| interim.encode_utf8(c)))
            .ok_or(byte_count)
    }

    /// Short the name
    ///
    /// This will short the name and try to insert it into `interim`. However if the shortened name
    /// is still too large to be put within `interim` then `Err` is returned.
    ///
    /// If `short_by` fails it will return an error of the number of bytes that were required of the
    /// buffer to create the structure.  
    fn short_by<Z>(&self, by: HowToShort<&Z>, interim: &mut StructIntermediate) -> Result<(), usize>
    where
        Z: ?Sized + Borrow<str>,
    {
        match by {
            HowToShort::Abbreviation(size) => self.short_by_size(size, interim),
            HowToShort::AlternativeName(alt) => self.short_by_alt(alt.borrow(), interim),
        }
    }
}

impl<N, S> AsRef<str> for LocalName<N, S>
where
    N: AsRef<str>,
{
    fn as_ref(&self) -> &str {
        self.name.as_ref()
    }
}

impl<N, S> core::ops::Deref for LocalName<N, S>
where
    N: core::ops::Deref<Target = str>,
{
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.name.deref()
    }
}

#[cfg(feature = "alloc")]
impl<N, S> alloc::string::ToString for LocalName<N, S>
where
    N: alloc::string::ToString,
{
    fn to_string(&self) -> alloc::string::String {
        self.name.to_string()
    }
}

impl<N, S> IntoStruct for LocalName<N, S>
where
    N: Borrow<str>,
    S: NameShortener,
    S::StrAlt: core::fmt::Debug,
{
    fn data_len(&self) -> Result<usize, usize> {
        match self.short.can_shorten() {
            true => Err(self.name.borrow().len()),
            false => Ok(self.name.borrow().len()),
        }
    }

    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, ConvertError> {
        let len = self.name.borrow().bytes().len() + HEADER_SIZE;

        let max_size = core::cmp::min(b.len(), DATA_MAX_LEN);

        if self.is_complete && len <= max_size {
            let mut interm = StructIntermediate::new(b, AssignedTypes::CompleteLocalName.val())?;

            self.name.borrow().bytes().for_each(|src| *interm.next().unwrap() = src);

            Ok(interm.finish())
        } else {
            let mut interim = StructIntermediate::new(b, AssignedTypes::ShortenedLocalName.val())?;

            let remaining_len = interim.remaining_len();

            let mut min_required = <usize>::MAX;

            // Iterate through the alternatives
            self.short
                .iter()
                .map(|alt| self.short_by(alt, &mut interim))
                .find_map(|shorted| match shorted {
                    Ok(_) => Some(()),
                    Err(how_many) => {
                        min_required = core::cmp::min(min_required, how_many);

                        None
                    }
                })
                .map(|_| interim.finish())
                .ok_or(ConvertError::OutOfSpace {
                    required: min_required,
                    remaining: remaining_len,
                })
        }
    }
}

impl<'a> TryFromStruct<'a> for LocalName<&'a str, shorts::NeverShorten> {
    fn try_from_struct(r#struct: EirOrAdStruct<'a>) -> Result<Self, Error> {
        use core::str::from_utf8;

        const SHORT: u8 = AssignedTypes::ShortenedLocalName.val();

        const COMPLETE: u8 = AssignedTypes::CompleteLocalName.val();

        let name = from_utf8(r#struct.get_data()).map_err(|e| Error::UTF8Error(e))?;

        let short = shorts::NeverShorten;

        let is_complete = match r#struct.get_type() {
            COMPLETE => Ok(true),
            SHORT => Ok(false),
            _ => Err(Error::IncorrectAssignedType),
        };

        is_complete.map(|is_complete| Self {
            name,
            is_complete,
            short,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_raw_test() {
        // data containing invalid utf8 (any value > 0x7F in a byte is invalid)
        let raw_name_1 = &[5, AssignedTypes::CompleteLocalName.val(), 3, 12, 11, 0x80];

        // 'hello world' as a complete local name
        let raw_name_2 = &[
            12,
            AssignedTypes::CompleteLocalName.val(),
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x20,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
        ];

        // 'hello wo' as a shorted local name
        let raw_name_3 = &[
            9,
            AssignedTypes::ShortenedLocalName.val(),
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x20,
            0x77,
            0x6f,
        ];

        // Wrong AD type
        let raw_name_4 = &[5, AssignedTypes::Flags.val(), 0x68, 0x65, 0x6c, 0x6c];

        let test_name_1 = EirOrAdStruct::try_new(raw_name_1).unwrap().unwrap().0;

        let test_name_2 = EirOrAdStruct::try_new(raw_name_2).unwrap().unwrap().0;

        let test_name_3 = EirOrAdStruct::try_new(raw_name_3).unwrap().unwrap().0;

        let test_name_4 = EirOrAdStruct::try_new(raw_name_4).unwrap().unwrap().0;

        assert!(LocalName::try_from_struct(test_name_1).is_err());

        let local_name_2 = LocalName::try_from_struct(test_name_2).unwrap();

        assert_eq!("hello world", local_name_2.as_str());

        let local_name_3 = LocalName::try_from_struct(test_name_3).unwrap();

        assert_eq!("hello wo", local_name_3.as_str());

        assert!(LocalName::try_from_struct(test_name_4).is_err());
    }

    fn err_ptr(at: usize, data: &[u8]) -> impl core::fmt::Display + '_ {
        use core::fmt;

        struct ErrPointer<'a> {
            at: usize,
            data: &'a [u8],
        }

        impl fmt::Display for ErrPointer<'_> {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                for (cnt, byte) in self.data.iter().enumerate() {
                    if cnt != self.at {
                        match *byte {
                            0..=9 => f.write_str("  ")?,
                            10..=99 => f.write_str("   ")?,
                            _ => f.write_str("    ")?,
                        }
                    } else {
                        match *byte {
                            0..=9 => write!(f, "{:^2}", '^')?,
                            10..=99 => write!(f, "{:^3}", '^')?,
                            _ => write!(f, "{:^4}", '^')?,
                        }
                    }

                    if cnt != self.data.len() - 1 {
                        f.write_str(" ")?;
                    }
                }

                Ok(())
            }
        }

        ErrPointer { at, data }
    }

    #[track_caller]
    fn short_name_test<N, S>(buffer: &mut [u8], local_name: &LocalName<N, S>, expected_bytes: impl Iterator<Item = u8>)
    where
        LocalName<N, S>: IntoStruct,
    {
        let mut sequencer = Sequence::new(buffer);

        sequencer.try_add(local_name).unwrap();

        let data = sequencer.into_inner();

        for (at, (e, r)) in expected_bytes.zip(data.iter()).enumerate() {
            assert_eq!(e, *r, "\n{:?}\n{}\n", data, err_ptr(at, data))
        }
    }

    #[test]
    fn substitute_short_name() {
        let local_name = LocalName::new("substitute_short_name", ["not short enough", "shorter name", "name"]);

        short_name_test(
            &mut [0u8; 23],
            &local_name,
            [
                "substitute_short_name".len() as u8 + 1,
                AssignedTypes::CompleteLocalName.val(),
            ]
            .into_iter()
            .chain("substitute_short_name".bytes()),
        );

        short_name_test(
            &mut [0u8; 20],
            &local_name,
            [
                "not short enough".len() as u8 + 1,
                AssignedTypes::ShortenedLocalName.val(),
            ]
            .into_iter()
            .chain("not short enough".bytes()),
        );

        short_name_test(
            &mut [0u8; 17],
            &local_name,
            ["shorter name".len() as u8 + 1, AssignedTypes::ShortenedLocalName.val()]
                .into_iter()
                .chain("shorter name".bytes()),
        );

        short_name_test(
            &mut [0u8; 10],
            &local_name,
            ["name".len() as u8 + 1, AssignedTypes::ShortenedLocalName.val()]
                .into_iter()
                .chain("name".bytes()),
        );
    }

    #[test]
    fn alt_size_short_name() {
        let local_name = LocalName::new("alt size short name", [14, 8]);

        short_name_test(
            &mut [0u8; 22],
            &local_name,
            [
                "alt size short name".len() as u8 + 1,
                AssignedTypes::CompleteLocalName.val(),
            ]
            .into_iter()
            .chain("alt size short name".bytes()),
        );

        short_name_test(
            &mut [0u8; 17],
            &local_name,
            [
                "alt size short".len() as u8 + 1,
                AssignedTypes::ShortenedLocalName.val(),
            ]
            .into_iter()
            .chain("alt size short".bytes()),
        );

        short_name_test(
            &mut [0u8; 10],
            &local_name,
            ["alt size".len() as u8 + 1, AssignedTypes::ShortenedLocalName.val()]
                .into_iter()
                .chain("alt size".bytes()),
        )
    }
}
