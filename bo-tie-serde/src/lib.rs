//! Support for Serialization and Deserialization
//!
//! There is nothing within the Bluetooth specification about serialization and deserializaiton of
//! data. The main purpose of this library is for formatting user data within the various headers
//! and for asynchronous flow control.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod de;
mod error;
mod ser;
mod varnum;

pub use de::{
    deserialize, deserialize_seeded, DeserializerHint, HintedDeserialize, HintedDeserializeSeed, HintedDeserializer,
    HintedVisitor,
};
use error::Error;
pub use ser::{serialize, serialize_sized, HintedSerialize, HintedSerializer, SerializerHint};

/// A static buffer
///
/// This is a buffer that is allocated with the stack instead of in dynamic memory. Its a byte
/// buffer that can buffer up to `SIZE` number of elements, and will panic if pushed beyond its
/// capacity.
#[derive(Clone)]
struct StaticBuffer<const SIZE: usize> {
    buffer: [u8; SIZE],
    size: usize,
}

impl<const SIZE: usize> Default for StaticBuffer<SIZE> {
    fn default() -> Self {
        StaticBuffer {
            buffer: [0; SIZE],
            size: 0,
        }
    }
}

impl<const SIZE: usize> PartialEq for StaticBuffer<SIZE> {
    fn eq(&self, other: &Self) -> bool {
        self.buffer[..self.size].eq(&other.buffer[..other.size])
    }
}

/// A trait for trying to extending
///
/// # Note
/// This is auto-implemented for things that already implement Extend
trait TryExtend<A> {
    fn try_extend<T: IntoIterator<Item = A>>(&mut self, iter: T) -> Result<(), Error>
    where
        T::IntoIter: ExactSizeIterator;
}

impl<T, A> TryExtend<A> for T
where
    T: Extend<A>,
{
    fn try_extend<I: IntoIterator<Item = A>>(&mut self, iter: I) -> Result<(), Error>
    where
        I::IntoIter: ExactSizeIterator,
    {
        self.extend(iter);

        Ok(())
    }
}

impl<const SIZE: usize> TryExtend<u8> for StaticBuffer<SIZE> {
    fn try_extend<T: IntoIterator<Item = u8>>(&mut self, iter: T) -> Result<(), Error>
    where
        T::IntoIter: ExactSizeIterator,
    {
        let iterator = iter.into_iter();

        if iterator.len() > SIZE - self.size {
            Err(Error::StaticMessage("Insufficient buffer size for serialization"))
        } else {
            iterator.for_each(|i| {
                self.buffer[self.size] = i;
                self.size += 1;
            });

            Ok(())
        }
    }
}

impl<'a, const SIZE: usize> TryExtend<&'a u8> for StaticBuffer<SIZE> {
    fn try_extend<T: IntoIterator<Item = &'a u8>>(&mut self, iter: T) -> Result<(), Error>
    where
        T::IntoIter: ExactSizeIterator,
    {
        self.try_extend(iter.into_iter().cloned())
    }
}

impl<const SIZE: usize> core::ops::Deref for StaticBuffer<SIZE> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer[..self.size]
    }
}
