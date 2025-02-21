//! Traits and types for shortening a local name
//!
//! See the parent [module] for details
//!
//! [module]: super

use core::borrow::Borrow;

/// How to short a local name
///
/// A name can either be shortened by either an Abbreviation or an Alternative name.
///
/// # Note
/// This enumeration is output by the iterator returned by method [`iter`] of `NameShortener`.
///
/// [`iter`]: NameShortener::iter
#[derive(Debug)]
pub enum HowToShort<S> {
    Abbreviation(usize),
    AlternativeName(S),
}

/// A trait for shortening a local name
///
/// See the [local_name module] level documentation for details.
///
/// [local_name module]: super
pub trait NameShortener {
    type StrAlt: ?Sized + Borrow<str>;
    type Shorts<'a>: Iterator<Item = HowToShort<&'a Self::StrAlt>>
    where
        Self: 'a;

    /// Iterate over how to short the name
    ///
    /// This returns an iterator that returns a [`HowToShort`] on each iteration.
    fn iter(&self) -> Self::Shorts<'_>;

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
///
/// This is used to convert a type into a [`NameShortener`]. See the [local_name module] level
/// documentation for details
///
/// [local_name module]: super
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

/// Never shortening a local name
///
/// This is used whenever the local name is to never be shortened nor further shortened.
pub struct NeverShorten;

impl NameShortener for NeverShorten {
    type StrAlt = str;
    type Shorts<'a> = core::iter::Empty<HowToShort<&'a Self::StrAlt>>;

    fn iter(&self) -> Self::Shorts<'_> {
        core::iter::empty()
    }

    fn can_shorten(&self) -> bool {
        false
    }
}

impl IntoNameShortener for Option<()> {
    type StrAlt = str;
    type IntoShorter = NeverShorten;

    fn into_shorter(self) -> Self::IntoShorter {
        NeverShorten
    }
}

/// Name shortener for a single abbreviation
///
/// This has one abbreviation size for shortening a local name.
pub struct SingleAbbreviation(usize);

impl NameShortener for SingleAbbreviation {
    type StrAlt = str;
    type Shorts<'a> = core::iter::Once<HowToShort<&'a Self::StrAlt>>;

    fn iter(&self) -> Self::Shorts<'_> {
        core::iter::once(HowToShort::Abbreviation(self.0))
    }

    fn can_shorten(&self) -> bool {
        true
    }
}

impl IntoNameShortener for usize {
    type StrAlt = str;
    type IntoShorter = SingleAbbreviation;

    fn into_shorter(self) -> Self::IntoShorter {
        SingleAbbreviation(self)
    }
}

/// Abbreviating name shortener
///
/// This contains a list of sizes to abbreviate a local name with.
pub struct Abbreviations<T>(T);

/// Iterator for `SuggestedSizes`
pub struct AbbreviationsIter<'a, T>(T, core::marker::PhantomData<&'a ()>);

impl<'a, T> Iterator for AbbreviationsIter<'a, T>
where
    T: Iterator<Item = usize>,
{
    type Item = HowToShort<&'a str>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|size| HowToShort::Abbreviation(size))
    }
}

impl<T> NameShortener for Abbreviations<T>
where
    T: Clone + Iterator<Item = usize> + ExactSizeIterator,
{
    type StrAlt = str;
    type Shorts<'a>
        = AbbreviationsIter<'a, T>
    where
        Self: 'a;

    fn iter(&self) -> Self::Shorts<'_> {
        AbbreviationsIter(self.0.clone(), core::marker::PhantomData)
    }

    fn can_shorten(&self) -> bool {
        self.0.len() != 0
    }
}

impl<'a> IntoNameShortener for &'a [usize] {
    type StrAlt = str;
    type IntoShorter = Abbreviations<core::iter::Copied<core::slice::Iter<'a, usize>>>;

    fn into_shorter(self) -> Self::IntoShorter {
        Abbreviations(self.iter().copied())
    }
}

impl<'a, const SIZE: usize> IntoNameShortener for &'a [usize; SIZE] {
    type StrAlt = str;
    type IntoShorter = Abbreviations<core::iter::Copied<core::slice::Iter<'a, usize>>>;

    fn into_shorter(self) -> Self::IntoShorter {
        Abbreviations(self.iter().copied())
    }
}

impl<const SIZE: usize> IntoNameShortener for [usize; SIZE] {
    type StrAlt = str;
    type IntoShorter = Abbreviations<core::array::IntoIter<usize, SIZE>>;

    fn into_shorter(self) -> Self::IntoShorter {
        Abbreviations(self.into_iter())
    }
}

/// Alternative names name shortener
///
/// This is a list of other names to shorten a local name by.
pub struct Alternatives<T>(T);

/// Iterator for [`Alternatives`]
pub struct AlternativesIter<T>(T);

impl<T, N> Iterator for AlternativesIter<T>
where
    T: Iterator<Item = N>,
{
    type Item = HowToShort<N>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|n| HowToShort::AlternativeName(n))
    }
}

macro_rules! impl_substitutions {
    ($for_ty:ty) => {
        impl IntoNameShortener for &[$for_ty] {
            type StrAlt = $for_ty;
            type IntoShorter = Alternatives<Self>;

            fn into_shorter(self) -> Self::IntoShorter {
                Alternatives(self)
            }
        }

        impl NameShortener for Alternatives<&[$for_ty]> {
            type StrAlt = $for_ty;
            type Shorts<'a>
                = AlternativesIter<core::slice::Iter<'a, $for_ty>>
            where
                Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
                AlternativesIter(self.0.iter())
            }

            fn can_shorten(&self) -> bool {
                self.0.len() != 0
            }
        }

        impl IntoNameShortener for &[&$for_ty] {
            type StrAlt = $for_ty;
            type IntoShorter = Alternatives<Self>;

            fn into_shorter(self) -> Self::IntoShorter {
                Alternatives(self)
            }
        }

        impl NameShortener for Alternatives<&[&$for_ty]> {
            type StrAlt = $for_ty;
            type Shorts<'a>
                = AlternativesIter<core::iter::Copied<core::slice::Iter<'a, &'a $for_ty>>>
            where
                Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
                AlternativesIter(self.0.iter().copied())
            }

            fn can_shorten(&self) -> bool {
                self.0.len() != 0
            }
        }

        impl<const SIZE: usize> IntoNameShortener for &[$for_ty; SIZE] {
            type StrAlt = $for_ty;
            type IntoShorter = Alternatives<Self>;

            fn into_shorter(self) -> Self::IntoShorter {
                Alternatives(self)
            }
        }

        impl<const SIZE: usize> NameShortener for Alternatives<&[$for_ty; SIZE]> {
            type StrAlt = $for_ty;
            type Shorts<'a>
                = AlternativesIter<core::slice::Iter<'a, $for_ty>>
            where
                Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
                AlternativesIter(self.0.into_iter())
            }

            fn can_shorten(&self) -> bool {
                self.0.len() != 0
            }
        }

        impl<const SIZE: usize> IntoNameShortener for &[&$for_ty; SIZE] {
            type StrAlt = $for_ty;
            type IntoShorter = Alternatives<Self>;

            fn into_shorter(self) -> Self::IntoShorter {
                Alternatives(self)
            }
        }

        impl<const SIZE: usize> NameShortener for Alternatives<&[&$for_ty; SIZE]> {
            type StrAlt = $for_ty;
            type Shorts<'a>
                = AlternativesIter<core::iter::Copied<core::slice::Iter<'a, &'a $for_ty>>>
            where
                Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
                AlternativesIter(self.0.iter().copied())
            }

            fn can_shorten(&self) -> bool {
                self.0.len() != 0
            }
        }

        impl<const SIZE: usize> IntoNameShortener for [$for_ty; SIZE] {
            type StrAlt = $for_ty;
            type IntoShorter = Alternatives<Self>;

            fn into_shorter(self) -> Self::IntoShorter {
                Alternatives(self)
            }
        }

        impl<const SIZE: usize> NameShortener for Alternatives<[$for_ty; SIZE]> {
            type StrAlt = $for_ty;
            type Shorts<'a>
                = AlternativesIter<core::slice::Iter<'a, $for_ty>>
            where
                Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
                AlternativesIter(self.0.iter())
            }

            fn can_shorten(&self) -> bool {
                self.0.len() != 0
            }
        }

        impl<const SIZE: usize> IntoNameShortener for [&$for_ty; SIZE] {
            type StrAlt = $for_ty;
            type IntoShorter = Alternatives<Self>;

            fn into_shorter(self) -> Self::IntoShorter {
                Alternatives(self)
            }
        }

        impl<const SIZE: usize> NameShortener for Alternatives<[&$for_ty; SIZE]> {
            type StrAlt = $for_ty;
            type Shorts<'a>
                = AlternativesIter<core::array::IntoIter<&'a $for_ty, SIZE>>
            where
                Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
                AlternativesIter(self.0.into_iter())
            }

            fn can_shorten(&self) -> bool {
                self.0.len() != 0
            }
        }
    };
}

#[cfg(feature = "alloc")]
impl_substitutions!(alloc::string::String);
#[cfg(feature = "alloc")]
impl_substitutions!(alloc::boxed::Box<str>);
#[cfg(feature = "alloc")]
impl_substitutions!(alloc::borrow::Cow<'static, str>);
impl_substitutions!(&'static str);
