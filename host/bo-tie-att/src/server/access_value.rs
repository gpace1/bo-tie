//! Implementations of the `AccessValue` trait

use crate::server::{AccessReadOnly, AccessValue};
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
pub struct Trivial<V: ?Sized>(pub V);

/// The trivial implementation for ServerAttributeValue
impl<V: Unpin + Send + Sync> AccessValue for Trivial<V> {
    type Value<'a> = V;
    type ReadGuard<'a> = &'a V where V: 'a;
    type Read<'a> = ReadReady<&'a V> where Self: 'a;
    type Write<'a> = WriteReady<'a, V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadReady(&self.0)
    }

    fn write(&mut self, val: V) -> Self::Write<'_> {
        WriteReady(&mut self.0, Some(val))
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

/// Future that immediately writes to the value upon being polled
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

#[cfg(feature = "tokio")]
impl<V: Send + Sync> AccessValue for std::sync::Arc<tokio::sync::Mutex<V>> {
    type Value<'a> = V;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::Value<'_>) -> Self::Write<'_> {
        Box::pin(async move {
            *self.lock().await = v;
        })
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
impl<V: Send + Sync> AccessValue for std::sync::Arc<tokio::sync::RwLock<V>> {
    type Value<'a> = V;
    type ReadGuard<'a> = tokio::sync::RwLockReadGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(tokio::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::Value<'_>) -> Self::Write<'_> {
        Box::pin(async move {
            *tokio::sync::RwLock::write(self).await = v;
        })
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
impl<V: Send + Sync> AccessValue for std::sync::Arc<futures::lock::Mutex<V>> {
    type Value<'a> = V;
    type ReadGuard<'a> = futures::lock::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = futures::lock::MutexLockFuture<'a, V> where Self: 'a;
    type Write<'a> = Write<futures::lock::MutexLockFuture<'a, V>, V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        self.lock()
    }

    fn write(&mut self, v: Self::Value<'_>) -> Self::Write<'_> {
        Write(self.lock(), Some(v))
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
impl<V: Send + Sync> AccessValue for std::sync::Arc<async_std::sync::Mutex<V>> {
    type Value<'a> = V;
    type ReadGuard<'a> = async_std::sync::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::Value<'_>) -> Self::Write<'_> {
        Box::pin(async move { *self.lock().await = v })
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
impl<V: Send + Sync> AccessValue for std::sync::Arc<async_std::sync::RwLock<V>> {
    type Value<'a> = V;
    type ReadGuard<'a> = async_std::sync::RwLockReadGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async_std::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::Value<'_>) -> Self::Write<'_> {
        Box::pin(async move { *async_std::sync::RwLock::write(self).await = v })
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
