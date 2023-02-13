//! Implementations of the `AccessValue` trait

use crate::server::{AccessReadOnly, AccessValue};
use std::any::Any;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The trivial implementation of [`AccessValue`] or [`AccessReadOnly`]
///
/// When adding attributes to a [`ServerAttributes`] or a [`Server`] via the method `push` or
/// `push_read_only`, the  attribute value is wrapped within a `Trivial` before being added to the
/// list of attributes.
///
/// [`ServerAttributes`]: super::ServerAttributes
/// [`Server`]: super::Server
pub(crate) struct Trivial<V: ?Sized>(pub V);

/// The trivially accessible value
///
/// A `Trivial` should be used whenever the value is not shared between other Attribute Server
/// instances and there is no special requirements for reading and/or writing the value.  
///
/// # Attribute Value Access
/// When directly accessing the value of an attribute containing a `Trivial`, the methods
/// [`get_value`] and [`get_mut_value`] of `ServerAttributes` should use the type `V` instead of
/// `Trivial<V>`.
///
/// [`get_value`]: crate::server::ServerAttributes::get_value
/// [`get_mut_value`]: crate::server::ServerAttributes::get_mut_value
impl<V: Unpin + Send + Sync + 'static> AccessValue for Trivial<V> {
    type ReadValue = V;
    type ReadGuard<'a> = &'a V where V: 'a;
    type Read<'a> = ReadReady<&'a V> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = WriteReady<'a, Self::WriteValue> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadReady(&self.0)
    }

    fn write(&mut self, val: Self::WriteValue) -> Self::Write<'_> {
        WriteReady::new(&mut self.0, val)
    }

    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        &mut self.0
    }
}

impl<V: ?Sized + Send + Sync> AccessReadOnly for Trivial<V> {
    type Value = V;
    type ReadGuard<'a> = &'a V where Self: 'a;
    type Read<'a> = ReadReady<&'a V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadReady(&self.0)
    }
}

/// A copy on write accessor
pub(crate) struct CowAccess<D>(pub D);

impl<D> AccessValue for CowAccess<D>
where
    D: core::ops::Deref + From<<D::Target as ToOwned>::Owned> + Unpin + Send + Sync + 'static,
    D::Target: ToOwned + Send + Sync,
    <D::Target as ToOwned>::Owned: Unpin + Send + Sync,
{
    type ReadValue = D::Target;
    type ReadGuard<'a> = &'a D::Target where Self: 'a;
    type Read<'a> = ReadReady<&'a D::Target> where Self: 'a;
    type WriteValue = <D::Target as ToOwned>::Owned;
    type Write<'a> = OwnedWriteReady<'a, D, Self::WriteValue> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadReady(&*self.0)
    }

    fn write(&mut self, val: Self::WriteValue) -> Self::Write<'_> {
        OwnedWriteReady::new(&mut self.0, val)
    }

    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        &mut self.0
    }
}

/// Future that always returns `Poll::Ready(T)`
pub struct ReadReady<T>(T);

impl<T> ReadReady<T> {
    pub fn new(t: T) -> Self {
        ReadReady(t)
    }
}

impl<T: Copy + Unpin> Future for ReadReady<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.get_mut().0)
    }
}

/// Future that immediately writes to the value
pub struct WriteReady<'a, T>(&'a mut T, Option<T>);

impl<'a, T> WriteReady<'a, T> {
    pub fn new(dest: &'a mut T, src: T) -> Self {
        WriteReady(dest, Some(src))
    }
}

impl<T: Unpin> Future for WriteReady<'_, T> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(val) = this.1.take() {
            *this.0 = val
        }

        Poll::Ready(())
    }
}

/// Future that immediately writes the owned value
pub struct OwnedWriteReady<'a, T, O>(&'a mut T, Option<O>);

impl<'a, T, O> OwnedWriteReady<'a, T, O> {
    pub fn new(dest: &'a mut T, src: O) -> Self {
        OwnedWriteReady(dest, Some(src))
    }
}

impl<T: Unpin + From<O>, O: Unpin> Future for OwnedWriteReady<'_, T, O> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if let Some(val) = this.1.take() {
            *this.0 = T::from(val);
        }

        Poll::Ready(())
    }
}

#[cfg(feature = "tokio")]
impl<V> AccessValue for std::sync::Arc<tokio::sync::Mutex<V>>
where
    V: Unpin + Send + Sync,
{
    type ReadValue = V;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move {
            *self.lock().await = v;
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(feature = "tokio")]
impl<V> AccessValue for std::sync::Arc<tokio::sync::RwLock<V>>
where
    V: Unpin + Send + Sync,
{
    type ReadValue = V;
    type ReadGuard<'a> = tokio::sync::RwLockReadGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(tokio::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move {
            *tokio::sync::RwLock::write(self).await = v;
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(feature = "tokio")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<tokio::sync::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }
}

#[cfg(feature = "tokio")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<tokio::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a> = tokio::sync::RwLockReadGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(tokio::sync::RwLock::read(self))
    }
}

#[cfg(feature = "futures-rs")]
impl<V> AccessValue for std::sync::Arc<futures::lock::Mutex<V>>
where
    V: Unpin + Send + Sync,
{
    type ReadValue = V;
    type ReadGuard<'a> = futures::lock::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = futures::lock::MutexLockFuture<'a, V> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Write<futures::lock::MutexLockFuture<'a, Self::WriteValue>, Self::WriteValue> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        self.lock()
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Write(self.lock(), Some(v))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(feature = "futures-rs")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<futures::lock::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = futures::lock::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = futures::lock::MutexLockFuture<'a, V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        self.lock()
    }
}

#[cfg(feature = "futures-rs")]
pub struct Write<F, V>(F, Option<V>);

#[cfg(feature = "futures-rs")]
impl<V> Future for Write<futures::lock::MutexLockFuture<'_, V>, V> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            let this = self.get_unchecked_mut();

            Pin::new_unchecked(&mut this.0)
                .poll(cx)
                .map(|mut guard| *guard = this.1.take().unwrap())
        }
    }
}

#[cfg(feature = "async-std")]
impl<V> AccessValue for std::sync::Arc<async_std::sync::Mutex<V>>
where
    V: Unpin + Send + Sync,
{
    type ReadValue = V;
    type ReadGuard<'a> = async_std::sync::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move { *self.lock().await = v })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(feature = "async-std")]
impl<V> AccessValue for std::sync::Arc<async_std::sync::RwLock<V>>
where
    V: Unpin + Send + Sync,
{
    type ReadValue = V;
    type ReadGuard<'a> = async_std::sync::RwLockReadGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async_std::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move { *async_std::sync::RwLock::write(self).await = v })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(feature = "async-std")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<async_std::sync::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = async_std::sync::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }
}

#[cfg(feature = "async-std")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<async_std::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a> = async_std::sync::RwLockReadGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async_std::sync::RwLock::read(self))
    }
}
