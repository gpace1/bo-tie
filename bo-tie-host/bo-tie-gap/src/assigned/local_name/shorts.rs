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

/// Marker for a only using only the full local name
///
/// The string for the local name will not be shortened if it is a complete name nor further
/// shortened if it is an already shortened name.
///
/// # Note
/// This is used whenever a [`LocalName`](super::LocalName) is derived from an EIR or AD struct
/// through the implementation of [`TryFromStruct`](crate::assigned::TryFromStruct).
pub struct BaseNameOnly;

impl NameShortener for BaseNameOnly {
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
    type IntoShorter = BaseNameOnly;

    fn into_shorter(self) -> Self::IntoShorter {
        BaseNameOnly
    }
}

/// A single Abbreviation
///
/// This name shortener is normally created when a `usize` is used for creating a [`LocalName`].
///
/// [`LocalName`]: super::LocalName
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

/// Abbreviations shortener
///
/// This is an iterator over suggested shortened sizes of a local name. If none of the suggested
/// sizes can be used then the local name cannot be turned into a struct.
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
    type Shorts<'a> = AbbreviationsIter<'a, T> where Self: 'a;

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
        self.0.next().map(|n| HowToShort::AlternativeName(n))
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
            type Shorts<'a> = SubstitutionsIter<core::slice::Iter<'a, $for_ty>> where Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
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
            type Shorts<'a> = SubstitutionsIter<core::iter::Copied<core::slice::Iter<'a, &'a $for_ty>>> where Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
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
            type Shorts<'a> = SubstitutionsIter<core::slice::Iter<'a, $for_ty>> where Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
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
            type Shorts<'a> = SubstitutionsIter<core::iter::Copied<core::slice::Iter<'a, &'a $for_ty>>> where Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
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
            type Shorts<'a> = SubstitutionsIter<core::slice::Iter<'a, $for_ty>> where Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
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
            type Shorts<'a> = SubstitutionsIter<core::array::IntoIter<&'a $for_ty, SIZE>> where Self: 'a;

            fn iter(&self) -> Self::Shorts<'_> {
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
