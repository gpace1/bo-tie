//! This is the buffer that is sent to the driver from the interface async task

use bo_tie_core::buffer::{Buffer, TryExtend, TryFrontExtend, TryFrontRemove, TryRemove};
use core::fmt::{Display, Formatter};
use core::ops::{Deref, DerefMut};

pub(crate) enum DriverBuffer<A, B> {
    Cmd(A),
    Data(B),
}

impl<A, B> Buffer for DriverBuffer<A, B>
where
    A: Buffer,
    B: Buffer,
{
    fn with_capacity(_: usize, _: usize) -> Self
    where
        Self: Sized,
    {
        unreachable!()
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        match self {
            DriverBuffer::Cmd(a) => a.clear_with_capacity(front, back),
            DriverBuffer::Data(b) => b.clear_with_capacity(front, back),
        }
    }
}

impl<A, B> TryFrontRemove<u8> for DriverBuffer<A, B>
where
    A: TryFrontRemove<u8>,
    B: TryFrontRemove<u8>,
{
    type Error = DriverBufferError;
    type FrontRemoveIter<'a> = DriverBufferIter<A::FrontRemoveIter<'a>, B::FrontRemoveIter<'a>> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        match self {
            DriverBuffer::Cmd(a) => a
                .try_front_remove(how_many)
                .map(|a| DriverBufferIter::A(a))
                .map_err(|_| DriverBufferError::TryFrontRemove),
            DriverBuffer::Data(b) => b
                .try_front_remove(how_many)
                .map(|b| DriverBufferIter::B(b))
                .map_err(|_| DriverBufferError::TryFrontRemove),
        }
    }
}

impl<A, B> TryFrontExtend<u8> for DriverBuffer<A, B>
where
    A: TryFrontExtend<u8>,
    B: TryFrontExtend<u8>,
{
    type Error = DriverBufferError;

    fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        match self {
            DriverBuffer::Cmd(a) => a.try_front_extend(iter).map_err(|_| DriverBufferError::TryFrontExtend),
            DriverBuffer::Data(b) => b.try_front_extend(iter).map_err(|_| DriverBufferError::TryFrontExtend),
        }
    }
}

impl<A, B> TryRemove<u8> for DriverBuffer<A, B>
where
    A: TryRemove<u8>,
    B: TryRemove<u8>,
{
    type Error = DriverBufferError;
    type RemoveIter<'a> = DriverBufferIter<A::RemoveIter<'a>, B::RemoveIter<'a>> where Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        match self {
            DriverBuffer::Cmd(a) => a
                .try_remove(how_many)
                .map(|a| DriverBufferIter::A(a))
                .map_err(|_| DriverBufferError::TryRemove),
            DriverBuffer::Data(b) => b
                .try_remove(how_many)
                .map(|b| DriverBufferIter::B(b))
                .map_err(|_| DriverBufferError::TryRemove),
        }
    }
}

impl<A, B> TryExtend<u8> for DriverBuffer<A, B>
where
    A: TryExtend<u8>,
    B: TryExtend<u8>,
{
    type Error = DriverBufferError;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        match self {
            DriverBuffer::Cmd(a) => a.try_extend(iter).map_err(|_| DriverBufferError::TryExtend),
            DriverBuffer::Data(b) => b.try_extend(iter).map_err(|_| DriverBufferError::TryExtend),
        }
    }
}

impl<A, B> Deref for DriverBuffer<A, B>
where
    A: Buffer,
    B: Buffer,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        match self {
            DriverBuffer::Cmd(a) => a.deref(),
            DriverBuffer::Data(b) => b.deref(),
        }
    }
}

impl<A, B> DerefMut for DriverBuffer<A, B>
where
    A: Buffer,
    B: Buffer,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            DriverBuffer::Cmd(a) => a.deref_mut(),
            DriverBuffer::Data(b) => b.deref_mut(),
        }
    }
}

#[derive(Debug)]
pub enum DriverBufferError {
    TryExtend,
    TryRemove,
    TryFrontExtend,
    TryFrontRemove,
}

impl Display for DriverBufferError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            DriverBufferError::TryExtend => f.write_str("failed to extend buffer"),
            DriverBufferError::TryRemove => f.write_str("failed to remove from buffer"),
            DriverBufferError::TryFrontExtend => f.write_str("failed to extend front of buffer"),
            DriverBufferError::TryFrontRemove => f.write_str("failed to remove from front of buffer"),
        }
    }
}

pub enum DriverBufferIter<A, B> {
    A(A),
    B(B),
}

impl<A, B, C> Iterator for DriverBufferIter<A, B>
where
    A: Iterator<Item = C>,
    B: Iterator<Item = C>,
{
    type Item = C;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            DriverBufferIter::A(a) => a.next(),
            DriverBufferIter::B(b) => b.next(),
        }
    }
}
