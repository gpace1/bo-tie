//! Local name data type
use super::*;
use core::borrow::Borrow;
use name_short::{HowToShort, IntoNameShortener, NameShortener};

/// An advertised Local Name
///
/// Local names are either complete or incomplete within the advertising packet. As part of the
/// format of the local name, there is a flag to indicate if the name has been shortened from its
/// full length. A `LocalName` can be crated with this flag deliberately set or have it
/// automatically set if the size of the name is larger than the remaining bytes in an advertising
/// payload.
///
/// # Automatic Sizing
/// When the local name is to be automatically sized, it is sized down to the remaining bytes
/// available within an advertising payload. There is no limit to this size, so it can be sized down
/// to zero characters.
///
/// # Deliberate Sizing
/// When the size is deliberately set, the full length of the name that is assigned as part of the
/// creation of a `LocalName` must fit in the remaining bytes of an advertising payload.
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
    /// Create a `LocalName` from the complete name for the device and a name shortener.
    ///
    /// When this `LocalName` is to be added to a buffer for EIR or AD structures, the complete name
    /// will try to be put into the buffer. However, if there is not enough room then the
    /// [`NameShortener`](name_short::NameShortener) `S` will be referred to to create a
    /// shortened local name to put into the buffer.
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
    /// Create a `LocalName` from an already shortened local name and a further shortener. As this
    /// is already a shortened name the local name will always have the EIR or AD tag for a
    /// shortened local name.
    ///
    /// When this `LocalName` is to be added to a buffer for EIR or AD structures, the complete name
    /// will try to be put into the buffer. However, if there is not enough room then the
    /// [`NameShortener`](name_short::NameShortener) `S` will be referred to to create a *further*
    /// shortened local name to put into the buffer.
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

    /// Get the local name
    pub fn get_name(&self) -> &str {
        self.name.borrow()
    }

    /// Check if the name is complete
    pub fn is_complete(&self) -> bool {
        self.is_complete
    }

    /// Change the name shortener
    ///
    /// This returns a `LocalName` with the same name contained within it but with a new name
    /// shortener.
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
        let byte_count = alt.borrow().bytes().len();

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
            HowToShort::Size(size) => self.short_by_size(size, interim),
            HowToShort::AltName(alt) => self.short_by_alt(alt.borrow(), interim),
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
                .ok_or(ConvertError {
                    required: min_required,
                    remaining: remaining_len,
                })
        }
    }
}

impl<'a> TryFromStruct<'a> for LocalName<&'a str, name_short::BaseNameNameOnly> {
    fn try_from_struct(r#struct: EirOrAdStruct<'a>) -> Result<Self, Error> {
        use core::str::from_utf8;

        const SHORT: u8 = AssignedTypes::ShortenedLocalName.val();

        const COMPLETE: u8 = AssignedTypes::CompleteLocalName.val();

        let name = from_utf8(r#struct.get_data()).map_err(|e| Error::UTF8Error(e))?;

        let short = name_short::BaseNameNameOnly;

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

/// Traits and types for shortening a local name
///
/// When converting a [`LocalName`] into an EIR or AD structure, the data of the structure needs
/// to be placed within a buffer. These buffers have limited space and may be unable to or have no
/// more room to contain a specific complete local name. As an alternative, a name is allowed to be
/// shortened from its full representation. How names are shortened is the point of this module.
///
/// The trait `NameShortener` is used to indicate how a name should be shortened.
pub mod name_short {
    use core::borrow::Borrow;

    /// How to short a local name
    ///
    /// A name can either be shortened by a size or an alternative name.
    #[derive(Debug)]
    pub enum HowToShort<S> {
        Size(usize),
        AltName(S),
    }

    /// A trait for shortening a local name
    ///
    /// See the [module] level documentation for details.
    ///
    /// [module]: self
    pub trait NameShortener {
        type StrAlt: ?Sized + Borrow<str>;
        type Alternatives<'a>: Iterator<Item = HowToShort<&'a Self::StrAlt>>
        where
            Self: 'a;

        /// Iterate over the
        fn iter(&self) -> Self::Alternatives<'_>;

        /// Check if this shortener shorten the name
        ///
        /// If the local name can be shortened then this method will return true.
        ///
        /// # Note
        /// If this returns `false` then `minimum` should return `None` or the length of the
        /// complete name.
        fn can_shorten(&self) -> bool;
    }

    /// A trait for creating a name shortener
    pub trait IntoNameShortener {
        type StrAlt: ?Sized + Borrow<str>;
        type IntoShorter: NameShortener<StrAlt = Self::StrAlt>;

        fn into_shorter(self) -> Self::IntoShorter;
    }

    impl<T> IntoNameShortener for T
    where
        T: NameShortener,
    {
        type StrAlt = T::StrAlt;
        type IntoShorter = T;

        fn into_shorter(self) -> Self::IntoShorter {
            self
        }
    }

    /// Marker for a only using only the assigned name
    ///
    /// The string for the local name will not be shortened if it is a complete name nor further
    /// shortened if it is an already shortened name.
    ///
    /// This is used whenever a [`LocalName`](super::LocalName) is derived from an EIR or AD struct
    /// through the implementation of [`TryFromStruct`](crate::assigned::TryFromStruct).
    pub struct BaseNameNameOnly;

    impl NameShortener for BaseNameNameOnly {
        type StrAlt = str;
        type Alternatives<'a> = core::iter::Empty<HowToShort<&'a Self::StrAlt>>;

        fn iter(&self) -> Self::Alternatives<'_> {
            core::iter::empty()
        }

        fn can_shorten(&self) -> bool {
            false
        }
    }

    impl IntoNameShortener for Option<()> {
        type StrAlt = str;
        type IntoShorter = BaseNameNameOnly;

        fn into_shorter(self) -> Self::IntoShorter {
            BaseNameNameOnly
        }
    }

    /// Shorten a local name to a minimum size
    ///
    /// This name shortener will not return any suggested sizes, instead it will only contain the
    /// minimum size a name can be. When a local name is converted into an EIR or AD structure it
    /// will greedily use as many characters of the name as the structure generator can fit within
    /// the data buffer.
    pub struct MinimumSize(usize);

    impl NameShortener for MinimumSize {
        type StrAlt = str;
        type Alternatives<'a> = core::iter::Once<HowToShort<&'a Self::StrAlt>>;

        fn iter(&self) -> Self::Alternatives<'_> {
            core::iter::once(HowToShort::Size(self.0))
        }

        fn can_shorten(&self) -> bool {
            true
        }
    }

    impl IntoNameShortener for usize {
        type StrAlt = str;
        type IntoShorter = MinimumSize;

        fn into_shorter(self) -> Self::IntoShorter {
            MinimumSize(self)
        }
    }

    /// This is a name shortener containing suggested sizes
    ///
    /// This is an iterator over suggested shortened sizes of a local name. If none of the suggested
    /// sizes can be used then the local name cannot be turned into a struct.
    pub struct SuggestedSizes<T>(T);

    /// Iterator for `SuggestedSizes`
    pub struct SuggestedSizesIter<'a, T>(T, core::marker::PhantomData<&'a ()>);

    impl<'a, T> Iterator for SuggestedSizesIter<'a, T>
    where
        T: Iterator<Item = usize>,
    {
        type Item = HowToShort<&'a str>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(|size| HowToShort::Size(size))
        }
    }

    impl<T> NameShortener for SuggestedSizes<T>
    where
        T: Clone + Iterator<Item = usize> + ExactSizeIterator,
    {
        type StrAlt = str;
        type Alternatives<'a> = SuggestedSizesIter<'a, T> where Self: 'a;

        fn iter(&self) -> Self::Alternatives<'_> {
            SuggestedSizesIter(self.0.clone(), core::marker::PhantomData)
        }

        fn can_shorten(&self) -> bool {
            self.0.len() != 0
        }
    }

    impl<'a> IntoNameShortener for &'a [usize] {
        type StrAlt = str;
        type IntoShorter = SuggestedSizes<core::iter::Copied<core::slice::Iter<'a, usize>>>;

        fn into_shorter(self) -> Self::IntoShorter {
            SuggestedSizes(self.iter().copied())
        }
    }

    impl<'a, const SIZE: usize> IntoNameShortener for &'a [usize; SIZE] {
        type StrAlt = str;
        type IntoShorter = SuggestedSizes<core::iter::Copied<core::slice::Iter<'a, usize>>>;

        fn into_shorter(self) -> Self::IntoShorter {
            SuggestedSizes(self.iter().copied())
        }
    }

    impl<const SIZE: usize> IntoNameShortener for [usize; SIZE] {
        type StrAlt = str;
        type IntoShorter = SuggestedSizes<core::array::IntoIter<usize, SIZE>>;

        fn into_shorter(self) -> Self::IntoShorter {
            SuggestedSizes(self.into_iter())
        }
    }

    /// Substitute names
    ///
    /// This is a list of other names to be used when the local name must be shortened.
    pub struct Substitutions<T>(T);

    /// Iterator for [`Substitutions`]
    pub struct SubstitutionsIter<T>(T);

    impl<T, N> Iterator for SubstitutionsIter<T>
    where
        T: Iterator<Item = N>,
    {
        type Item = HowToShort<N>;

        fn next(&mut self) -> Option<Self::Item> {
            self.0.next().map(|n| HowToShort::AltName(n))
        }
    }

    macro_rules! impl_substitutions {
        ($for_ty:ty) => {
            impl IntoNameShortener for &[$for_ty] {
                type StrAlt = $for_ty;
                type IntoShorter = Substitutions<Self>;

                fn into_shorter(self) -> Self::IntoShorter {
                    Substitutions(self)
                }
            }

            impl NameShortener for Substitutions<&[$for_ty]> {
                type StrAlt = $for_ty;
                type Alternatives<'a> = SubstitutionsIter<core::slice::Iter<'a, $for_ty>> where Self: 'a;

                fn iter(&self) -> Self::Alternatives<'_> {
                    SubstitutionsIter(self.0.iter())
                }

                fn can_shorten(&self) -> bool {
                    self.0.len() != 0
                }
            }

            impl IntoNameShortener for &[&$for_ty] {
                type StrAlt = $for_ty;
                type IntoShorter = Substitutions<Self>;

                fn into_shorter(self) -> Self::IntoShorter {
                    Substitutions(self)
                }
            }

            impl NameShortener for Substitutions<&[&$for_ty]> {
                type StrAlt = $for_ty;
                type Alternatives<'a> = SubstitutionsIter<core::iter::Copied<core::slice::Iter<'a, &'a $for_ty>>> where Self: 'a;

                fn iter(&self) -> Self::Alternatives<'_> {
                    SubstitutionsIter(self.0.iter().copied())
                }

                fn can_shorten(&self) -> bool {
                    self.0.len() != 0
                }
            }

            impl<const SIZE: usize> IntoNameShortener for &[$for_ty; SIZE] {
                type StrAlt = $for_ty;
                type IntoShorter = Substitutions<Self>;

                fn into_shorter(self) -> Self::IntoShorter {
                    Substitutions(self)
                }
            }

            impl<const SIZE: usize> NameShortener for Substitutions<&[$for_ty; SIZE]> {
                type StrAlt = $for_ty;
                type Alternatives<'a> = SubstitutionsIter<core::slice::Iter<'a, $for_ty>> where Self: 'a;

                fn iter(&self) -> Self::Alternatives<'_> {
                    SubstitutionsIter(self.0.into_iter())
                }

                fn can_shorten(&self) -> bool {
                    self.0.len() != 0
                }
            }

            impl<const SIZE: usize> IntoNameShortener for &[&$for_ty; SIZE] {
                type StrAlt = $for_ty;
                type IntoShorter = Substitutions<Self>;

                fn into_shorter(self) -> Self::IntoShorter {
                    Substitutions(self)
                }
            }

            impl<const SIZE: usize> NameShortener for Substitutions<&[&$for_ty; SIZE]> {
                type StrAlt = $for_ty;
                type Alternatives<'a> = SubstitutionsIter<core::iter::Copied<core::slice::Iter<'a, &'a $for_ty>>> where Self: 'a;

                fn iter(&self) -> Self::Alternatives<'_> {
                    SubstitutionsIter(self.0.iter().copied())
                }

                fn can_shorten(&self) -> bool {
                    self.0.len() != 0
                }
            }

            impl<const SIZE: usize> IntoNameShortener for [$for_ty; SIZE] {
                type StrAlt = $for_ty;
                type IntoShorter = Substitutions<Self>;

                fn into_shorter(self) -> Self::IntoShorter {
                    Substitutions(self)
                }
            }

            impl<const SIZE: usize> NameShortener for Substitutions<[$for_ty; SIZE]> {
                type StrAlt = $for_ty;
                type Alternatives<'a> = SubstitutionsIter<core::slice::Iter<'a, $for_ty>> where Self: 'a;

                fn iter(&self) -> Self::Alternatives<'_> {
                    SubstitutionsIter(self.0.iter())
                }

                fn can_shorten(&self) -> bool {
                    self.0.len() != 0
                }
            }

            impl<const SIZE: usize> IntoNameShortener for [&$for_ty; SIZE] {
                type StrAlt = $for_ty;
                type IntoShorter = Substitutions<Self>;

                fn into_shorter(self) -> Self::IntoShorter {
                    Substitutions(self)
                }
            }

            impl<const SIZE: usize> NameShortener for Substitutions<[&$for_ty; SIZE]> {
                type StrAlt = $for_ty;
                type Alternatives<'a> = SubstitutionsIter<core::array::IntoIter<&'a $for_ty, SIZE>> where Self: 'a;

                fn iter(&self) -> Self::Alternatives<'_> {
                    SubstitutionsIter(self.0.into_iter())
                }

                fn can_shorten(&self) -> bool {
                    self.0.len() != 0
                }
            }
        };
    }

    impl_substitutions!(alloc::string::String);
    impl_substitutions!(alloc::boxed::Box<str>);
    impl_substitutions!(alloc::borrow::Cow<'static, str>);
    impl_substitutions!(&'static str);
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

        assert_eq!("hello world", local_name_2.get_name());

        let local_name_3 = LocalName::try_from_struct(test_name_3).unwrap();

        assert_eq!("hello wo", local_name_3.get_name());

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
