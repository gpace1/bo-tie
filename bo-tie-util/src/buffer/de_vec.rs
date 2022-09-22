//! A dynamically allocated double ended vector
//!
//! See the doc for [`DeVec`] for details.

use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A very basic double ended vector
///
/// This is a vector that also able to add and remove items from the front. This is not a circle
/// buffer like [`VecDeque`], so it can be de-referenced to a slice or a [`Vec`]. A `DeVec` has a
/// 'reserve' space in both the front and back, so items can be pushed to the front and back. This
/// is not an ideal implementation of a double ended vector. It is intended for usage with this
/// library where the front capacity is known upon creation or erasure of a `DeVec`.
///
/// ## Front push
/// A `DeVec` may only push if there is front reserve space as a `DeVec` does not reallocate if the
/// front reserve is empty. This is mainly used for unwrapping protocol packets from protocol
/// packets within this library so there is not much need for pushing with the exception of
/// 'restoring' a protocol's header.
///
/// [`VecDeque`]: std::collections::VecDeque,
/// [`Vec`]: std::vector::Vec
/// [`Deref`]: std::ops::Deref
#[derive(Debug)]
pub struct DeVec<T> {
    start: usize,
    vec: Vec<T>,
}

impl<T> DeVec<T> {
    pub fn new() -> Self
    where
        T: Default + Copy,
    {
        Self::with_capacity(0, 0)
    }

    /// Create a `DeVec` with the specified front and back reserves
    ///
    /// # Note
    /// The total capacity is `front + back`
    pub fn with_capacity(front: usize, back: usize) -> Self
    where
        T: Default + Copy,
    {
        let mut vec = alloc::vec![Default::default(); front + back];

        vec.truncate(front);

        Self { start: front, vec }
    }
}

impl crate::buffer::Buffer for DeVec<u8> {
    fn with_capacity(front: usize, back: usize) -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(front, back)
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        self.vec.clear();

        self.vec.reserve(front + back);

        self.start = front
    }
}

impl<T> core::ops::Deref for DeVec<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.vec[self.start..]
    }
}

impl<T> core::ops::DerefMut for DeVec<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.vec[self.start..]
    }
}

impl<A> crate::buffer::TryExtend<A> for DeVec<A> {
    type Error = core::convert::Infallible;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>,
    {
        self.vec.extend(iter);

        Ok(())
    }
}

impl<A> crate::buffer::TryRemove<A> for DeVec<A> {
    type Error = crate::buffer::BufferError;
    type RemoveIter<'a> = alloc::vec::Drain<'a, A> where A: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        if self.len() >= how_many {
            let start = self.vec.len() - how_many;

            Ok(self.vec.drain(start..))
        } else {
            Err(crate::buffer::BufferError::LengthOfBuffer)
        }
    }
}

impl<A> crate::buffer::TryFrontExtend<A> for DeVec<A> {
    type Error = crate::buffer::BufferError;

    fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = A>,
    {
        for item in iter {
            self.start
                .checked_sub(1)
                .map(|new_offset| {
                    self.start = new_offset;

                    self.vec[self.start] = item;
                })
                .ok_or(crate::buffer::BufferError::FrontReserveSize)?;
        }

        Ok(())
    }
}

impl<A> crate::buffer::TryFrontRemove<A> for DeVec<A>
where
    A: Copy,
{
    type Error = crate::buffer::BufferError;
    type FrontRemoveIter<'a> = DeVecDrain<'a, A> where A: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        if self.len() >= how_many {
            let removed = &mut self.vec[self.start..(self.start + how_many)];

            self.start += how_many;

            Ok(DeVecDrain { removed, cnt: 0 })
        } else {
            Err(crate::buffer::BufferError::LengthOfBuffer)
        }
    }
}

/// Drain iterator for a `DeVec`
pub struct DeVecDrain<'a, T> {
    removed: &'a mut [T],
    cnt: usize,
}

impl<T> Iterator for DeVecDrain<'_, T>
where
    T: Copy,
{
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        let next = self.cnt;

        self.cnt += 1;

        self.removed.get(next).copied()
    }
}

/// A dynamic reserve of buffers
///
/// This reserve uses dynamic allocation for creating the buffers. The buffers are part of a vector
/// of other reclaimed buffers. This reserve acts like a stack so buffers that are reclaimed are
/// pushed to the inner vector and buffers take are popped from it.
#[derive(Debug)]
pub struct DynBufferReserve<T>(Vec<T>);

impl<T> DynBufferReserve<T> {
    pub fn new(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }

    pub fn take(&mut self, front_capacity: usize) -> TakeDynReserveFuture<T>
    where
        T: crate::buffer::Buffer,
    {
        use crate::buffer::BufferExt;

        if let Some(buffer) = self.0.pop() {
            TakeDynReserveFuture(Some(buffer))
        } else {
            TakeDynReserveFuture(Some(T::with_front_capacity(front_capacity)))
        }
    }

    pub fn reclaim(&mut self, buffer: T) {
        if self.0.capacity() != self.0.len() {
            self.0.push(buffer);
        }
    }
}

/// A future for taking buffers from a `VecBufferReserve`
pub struct TakeDynReserveFuture<T>(Option<T>);

impl<T: Unpin> Future for TakeDynReserveFuture<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.get_mut().0.take().unwrap())
    }
}
