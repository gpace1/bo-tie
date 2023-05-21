//! Buffer Utilities
//!
//! `bo-tie` needs to deal with different kinds of buffer types in order to (eventually) support
//! environments where allocations are supported and environments where allocations are not
//! supported. `buffer` contains traits for supporting the 'filling' and 'emptying' of a type of
//! buffer.
//!
use core::fmt::{Debug, Display};
use core::ops::DerefMut;

#[cfg(feature = "alloc")]
pub mod de_vec;
pub mod stack;

/// The Buffer type
///
/// Buffers within the HCI are used for passing between the various protocols on the Bluetooth
/// stack. A type that implements `Buffer` must act like a double ended vector, although with finite
/// capacity maximums. Various protocol implementations needs to push and pop bytes to both the
/// front and back of a buffer. Generally protocols push and pop header byes from the front of the
/// buffer, and push and pop payload bytes to the back of the buffer. This is
/// because a HCI packet ends up being a nesting of multiple different protocols. Bytes of protocol
/// header information are pushed to the front of a buffer while payload data is pushed to the end
/// of the buffer.
pub trait Buffer:
    Unpin + DerefMut<Target = [u8]> + TryExtend<u8> + TryRemove<u8> + TryFrontExtend<u8> + TryFrontRemove<u8>
{
    /// Create a Buffer with the front and back capacities
    fn with_capacity(front: usize, back: usize) -> Self
    where
        Self: Sized;

    /// Clear the buffer and set new capacity thresholds
    ///
    /// A buffer will be cleared of all data and set the capacity of both the `front` and `back` to
    /// be at least as large as the input values. It is up to the implementation if the buffer
    /// capacity is to downsize to the provided values (it may do nothing).
    fn clear_with_capacity(&mut self, front: usize, back: usize);
}

/// Extension methods for types that implement [`Buffer`]
pub trait BufferExt: Buffer {
    /// Create a new buffer
    ///
    /// This creates a new buffer with both the front and back capacities of zero
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(0, 0)
    }

    /// Create a new buffer with the provided `front` capacity
    fn with_front_capacity(front: usize) -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(front, 0)
    }

    /// Create a new buffer with the provided `back` capacity
    fn with_back_capacity(back: usize) -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(0, back)
    }

    /// Clear the buffer
    ///
    /// The front and back capacity may be set to zero or left as they were previously.
    fn clear_uncapped(&mut self) {
        self.clear_with_capacity(0, 0)
    }

    fn clear_with_front_capacity(&mut self, front: usize) {
        self.clear_with_capacity(front, 0)
    }

    fn clear_with_back_capacity(&mut self, back: usize) {
        self.clear_with_capacity(0, back)
    }
}

impl<T> BufferExt for T where T: Buffer {}

/// Try to extend a collection with an iterator
///
/// This is the try equivalent to [`Extend`](core::iter::Extend)
///
/// # Note
/// `TryExtend` is auto-implemented for anything that already implements
/// [`Extend`](core::iter::Extend)
pub trait TryExtend<A> {
    type Error: Debug + Display;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>;

    fn try_extend_one(&mut self, item: A) -> Result<(), Self::Error> {
        self.try_extend(core::iter::once(item))
    }
}

impl<T> TryExtend<u8> for T
where
    T: Extend<u8>,
{
    type Error = core::convert::Infallible;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = u8>,
    {
        self.extend(iter);

        Ok(())
    }
}

/// Try to remove items
///
/// This trait is used to remove items from the end of the collection and return them.
pub trait TryRemove<A> {
    type Error: Debug + Display;
    type RemoveIter<'a>: Iterator<Item = A>
    where
        Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error>;

    fn try_pop(&mut self) -> Option<A> {
        self.try_remove(1).ok().and_then(|mut i| i.next())
    }
}

/// Try to extend the front of a collection with an iterator
pub trait TryFrontExtend<A> {
    type Error: Debug + Display;

    /// Try to extend the collection by the iterator `iter`
    ///
    /// This will extend the front of the iterator by the contents produced by `iter`. The front of
    /// the collection is extended *in order* in which they are pushed to the front. This means that
    /// for something like a `Vec` this results in the items within `iter` being placed in reverse
    /// order at the front.
    fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>;

    /// Reverses `iter` before extending the front of the collection
    ///
    /// This reverses the iterator `iter` before front extending the collection. The main purpose of
    /// this is to put items onto the front in the order in which they appear. In something like a
    /// `Vec` when calling `try_rev_front_extend` the first item in `iter` would become the first
    /// item in the vector.
    fn try_rev_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>,
        T::IntoIter: DoubleEndedIterator,
    {
        let iter = iter.into_iter();

        self.try_front_extend(iter.rev())
    }

    fn try_front_extend_one(&mut self, item: A) -> Result<(), Self::Error> {
        self.try_front_extend(core::iter::once(item))
    }
}

/// Try to remove items from the front of a collection
///
/// This is used for trying to removing items at the front of a collection. In order for a
/// collection to implement this trait it must have a capacity at the front. Removing items from the
/// front must also increase this capacity.
pub trait TryFrontRemove<A> {
    type Error: Debug + Display;
    type FrontRemoveIter<'a>: Iterator<Item = A>
    where
        Self: 'a;

    /// Try to take a number of items from the front of the collection
    ///
    /// The return is an iterator over the items
    /// # Error
    /// `how_many` must not be larger than the length of the implementation.
    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error>;

    /// Try to pop the front item
    ///
    /// The first item is returned so long as the item is not empty.
    fn try_front_pop(&mut self) -> Option<A> {
        self.try_front_remove(1).ok()?.next()
    }
}

impl<A> TryRemove<A> for &'_ [A]
where
    A: Copy,
{
    type Error = BufferError;
    type RemoveIter<'a> = core::iter::Copied<core::slice::Iter<'a, A>> where Self: 'a, A: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        if self.len() >= how_many {
            let (new_this, to_iter) = self.split_at(self.len() - how_many);

            *self = new_this;

            Ok(to_iter.iter().copied())
        } else {
            Err(BufferError::LengthOfBuffer)
        }
    }
}

impl<A> TryFrontRemove<A> for &'_ [A]
where
    A: Copy,
{
    type Error = BufferError;
    type FrontRemoveIter<'a> = core::iter::Copied<core::slice::Iter<'a, A>> where Self: 'a, A: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        if self.len() >= how_many {
            let (to_iter, new_this) = self.split_at(how_many);

            *self = new_this;

            Ok(to_iter.iter().copied())
        } else {
            Err(BufferError::LengthOfBuffer)
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BufferError {
    LengthOfBuffer,
    FrontReserveSize,
}

impl Display for BufferError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            BufferError::LengthOfBuffer => f.write_str("buffer is too small"),
            BufferError::FrontReserveSize => f.write_str("front reserve is too small"),
        }
    }
}
