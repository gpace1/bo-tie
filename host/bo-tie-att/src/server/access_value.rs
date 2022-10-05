//! Implementations of the `AccessValue` trait

use crate::server::AccessValue;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

/// The trivial implementation of [`AccessValue`]
///
/// When adding attributes to a [`ServerAttributes`] or a [`Server`] via the method `push` the
/// value attribute value is wrapped within a `Trivial` before being added to the list of
/// attributes.
///
/// [`ServerAttributes`]: super::ServerAttributes
/// [`Server`]: super::Server
pub struct Trivial<V>(pub V);

/// The trivial implementation for ServerAttributeValue
impl<V> AccessValue for Trivial<V>
where
    V: Unpin + Send + Sync,
{
    type Value = V;

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

/// Future that always returns `Poll::Ready(T)`
pub struct ReadReady<T>(T);

impl<T: Copy + Unpin> Future for ReadReady<T> {
    type Output = T;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.get_mut().0)
    }
}

/// Future that immediately writes to the value upon being polled
pub struct WriteReady<'a, T>(&'a mut T, Option<T>);

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
    type Value = V;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::Value) -> Self::Write<'_> {
        Box::pin(async move {
            *self.lock().await = v;
        })
    }
}

#[cfg(feature = "tokio")]
impl<V: Send + Sync> AccessValue for std::sync::Arc<tokio::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a> = tokio::sync::RwLockReadGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(tokio::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::Value) -> Self::Write<'_> {
        Box::pin(async move {
            *tokio::sync::RwLock::write(self).await = v;
        })
    }
}

#[cfg(feature = "futures-rs")]
impl<V: Send + Sync> AccessValue for std::sync::Arc<futures::lock::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = futures::lock::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = futures::lock::MutexLockFuture<'a, V> where Self: 'a;
    type Write<'a> = Write<futures::lock::MutexLockFuture<'a, V>, V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        self.lock()
    }

    fn write(&mut self, v: Self::Value) -> Self::Write<'_> {
        Write(self.lock(), Some(v))
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
    type Value = V;
    type ReadGuard<'a> = async_std::sync::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::Value) -> Self::Write<'_> {
        Box::pin(async move { *self.lock().await = v })
    }
}

#[cfg(feature = "async-std")]
impl<V: Send + Sync> AccessValue for std::sync::Arc<async_std::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a> = async_std::sync::RwLockReadGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a;
    type Write<'a> = Pin<Box<dyn Future<Output = ()> + Send + Sync + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async_std::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::Value) -> Self::Write<'_> {
        Box::pin(async move { *async_std::sync::RwLock::write(self).await = v })
    }
}
