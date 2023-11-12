//! Implementations of the `AccessValue` trait

use crate::server::{Comparable, PinnedFuture, ServerAttribute};
use crate::{pdu, TransferFormatInto, TransferFormatTryFrom};
use core::any::Any;
use core::future::{Future, Ready};
use core::pin::Pin;
use core::task::{Context, Poll};

/// A value accessor
///
/// In order to share a value between connections, the value must be behind an accessor. An accessor
/// ensures that reads and writes are atomic to all clients that have access to the value.
///
/// The intention of this trait is to be implemented for async mutex-like synchronization
/// primitives. Although the implementations must be enabled by features, `AccessValue` is
/// implemented for the mutex types of the crates [async-std], [futures], and [tokio].
///
/// [async-std]: https://docs.rs/async-std/latest/async_std/index.html
/// [futures]: https://docs.rs/futures/latest/futures/index.html
/// [tokio]: https://docs.rs/tokio/latest/tokio/index.html
pub trait AccessValue: Send {
    type ReadValue: ?Sized + Send;

    type ReadGuard<'a>: core::ops::Deref<Target = Self::ReadValue>
    where
        Self: 'a;

    type Read<'a>: Future<Output = Self::ReadGuard<'a>> + Send
    where
        Self: 'a;

    type WriteValue: Unpin + Send;

    type Write<'a>: Future<Output = Result<(), pdu::Error>> + Send
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_>;

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_>;

    fn as_any(&self) -> &dyn core::any::Any;

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any;
}

#[cfg(feature = "tokio")]
impl<V> AccessValue for std::sync::Arc<tokio::sync::Mutex<V>>
where
    V: Unpin + Send + 'static,
{
    type ReadValue = V;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move {
            *self.lock().await = v;

            Ok(())
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
    V: Unpin + Send + Sync + 'static,
{
    type ReadValue = V;
    type ReadGuard<'a> = tokio::sync::RwLockReadGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(tokio::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move {
            *tokio::sync::RwLock::write(self).await = v;

            Ok(())
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

#[cfg(feature = "futures-rs")]
impl<V> AccessValue for std::sync::Arc<futures::lock::Mutex<V>>
where
    V: Unpin + Send + 'static,
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

#[cfg(feature = "async-std")]
impl<V> AccessValue for std::sync::Arc<async_std::sync::Mutex<V>>
where
    V: Unpin + Send + 'static,
{
    type ReadValue = V;
    type ReadGuard<'a> = async_std::sync::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move {
            *self.lock().await = v;
            Ok(())
        })
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
    V: Unpin + Send + Sync + 'static,
{
    type ReadValue = V;
    type ReadGuard<'a> = async_std::sync::RwLockReadGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async_std::sync::RwLock::read(self))
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async move {
            *async_std::sync::RwLock::write(self).await = v;
            Ok(())
        })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

/// Extension method for `AccessValue`
trait AccessValueExt: AccessValue {
    /// Read the value and call `f` with a reference to it.
    fn read_and<F, T>(&self, f: F) -> ReadAnd<Self::Read<'_>, F>
    where
        F: FnOnce(&Self::ReadValue) -> T + Unpin + Send,
    {
        let read = self.read();

        ReadAnd {
            reader: read,
            job: Some(f),
        }
    }
}

impl<S: AccessValue> AccessValueExt for S {}

/// Trait `AccessValue` with `async fn`
///
/// This is equivalent to `AccessValue` with the exception that it uses `async fn` instead of having
/// associated types for the read and write futures. Anything that implements `AsyncAccessValue`
/// also implements `AccessValue`.
///
/// # Note
/// Right now this trait is gated behind the `async-trait` feature as it depends on the
/// `async-trait` crate.
#[cfg(feature = "async-trait")]
#[async_trait::async_trait]
pub trait AsyncAccessValue: Send {
    type ReadValue: ?Sized + Send;

    type ReadGuard<'a>: core::ops::Deref<Target = Self::ReadValue>
    where
        Self: 'a;

    type WriteValue: Unpin + Send;

    async fn read(&self) -> Self::ReadGuard<'_>;

    async fn write(&mut self, v: Self::WriteValue) -> Result<(), pdu::Error>;

    fn as_any(&self) -> &dyn core::any::Any;

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any;
}

#[cfg(feature = "async-trait")]
impl<T: AsyncAccessValue> AccessValue for T {
    type ReadValue = T::ReadValue;
    type ReadGuard<'a> = T::ReadGuard<'a> where Self: 'a;
    type Read<'a> =  Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;
    type WriteValue = T::WriteValue;
    type Write<'a> = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>> where Self: 'a ;

    fn read(&self) -> Self::Read<'_> {
        AsyncAccessValue::read(self)
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        AsyncAccessValue::write(self, v)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        AsyncAccessValue::as_any(self)
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        AsyncAccessValue::as_mut_any(self)
    }
}

/// Wrapper type for an type that implements [`AccessValue`]
pub(super) struct AccessibleValue<A: AccessValue>(pub(super) A);

impl<A> ServerAttribute for AccessibleValue<A>
where
    A: AccessValue + 'static,
    A::ReadValue: TransferFormatInto + Comparable,
    A::WriteValue: TransferFormatTryFrom,
{
    fn read(&self) -> PinnedFuture<Vec<u8>> {
        Box::pin(self.0.read_and(|v| TransferFormatInto::into(v)))
    }

    fn read_response(&self) -> PinnedFuture<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>> {
        Box::pin(self.0.read_and(|v| pdu::read_response(TransferFormatInto::into(v))))
    }

    fn single_read_by_type_response(&mut self, handle: u16) -> PinnedFuture<pdu::ReadTypeResponse<Vec<u8>>> {
        Box::pin(self.0.read_and(move |v| {
            let tf = TransferFormatInto::into(v);

            pdu::ReadTypeResponse::new(handle, tf)
        }))
    }

    fn try_set_value_from_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'a, Result<(), pdu::Error>> {
        Box::pin(async move {
            self.0
                .write(TransferFormatTryFrom::try_from(raw).map_err(|e| e.pdu_err)?)
                .await
        })
    }

    fn value_transfer_format_size(&mut self) -> PinnedFuture<usize> {
        let read_and_fut = self.0.read_and(|v: &A::ReadValue| v.len_of_into());

        Box::pin(async move { read_and_fut.await })
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'_, bool> {
        let read_fut = self.read();

        Box::pin(async { read_fut.await.cmp_tf_data(raw) })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self.0.as_any()
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        self.0.as_mut_any()
    }
}

/// Read only access
///
/// This is the same as [`AccessValue`] except this cannot be written to and the associated type
/// `Value` may be a dynamically sized type. The value types only need to implement
/// [`TransferFormatInto`] and not [`TransferFormatTryFrom`].
///
/// An attribute value that implements this trait can only be read from. The server will return a
/// permissions error to the client for all *write* requests send to this attribute.
pub trait AccessReadOnly: Send {
    type Value: ?Sized + Send;

    type ReadGuard<'a>: core::ops::Deref<Target = Self::Value>
    where
        Self: 'a;

    type Read<'a>: Future<Output = Self::ReadGuard<'a>> + Send
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_>;
}

#[cfg(feature = "tokio")]
impl<V: ?Sized + Send> AccessReadOnly for std::sync::Arc<tokio::sync::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }
}

#[cfg(feature = "tokio")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<tokio::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a> = tokio::sync::RwLockReadGuard<'a, V> where V: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(tokio::sync::RwLock::read(self))
    }
}

#[cfg(feature = "futures-rs")]
impl<V: ?Sized + Send> AccessReadOnly for std::sync::Arc<futures::lock::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = futures::lock::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = futures::lock::MutexLockFuture<'a, V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        self.lock()
    }
}

#[cfg(feature = "async-std")]
impl<V: ?Sized + Send> AccessReadOnly for std::sync::Arc<async_std::sync::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a> = async_std::sync::MutexGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.lock())
    }
}

#[cfg(feature = "async-std")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<async_std::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a> = async_std::sync::RwLockReadGuard<'a, V> where Self: 'a;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + 'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async_std::sync::RwLock::read(self))
    }
}

pub(super) trait AccessReadOnlyExt: AccessReadOnly {
    /// Read the value and call `f` with a reference to it.
    fn read_and<F, T>(&self, f: F) -> ReadAnd<Self::Read<'_>, F>
    where
        F: FnOnce(&Self::Value) -> T + Unpin + Send,
    {
        let read = self.read();

        ReadAnd {
            reader: read,
            job: Some(f),
        }
    }
}

impl<T: AccessReadOnly> AccessReadOnlyExt for T {}

/// Wrapper around a type that implements `AccessReadOnly`
///
/// # Downcasting
/// The methods `as_any` and `as_mut_any` always return a reference to the inner value of
/// `ReadAccess`. The type used for downcasting the return of these methods is `R` and not
/// `ReadOnly<R>`.
///
/// # Note
/// This type must only be used with read only attribute permissions.
pub(super) struct ReadOnly<R: AccessReadOnly>(pub(super) R);

impl<R> ServerAttribute for ReadOnly<R>
where
    R: AccessReadOnly + 'static,
    R::Value: TransferFormatInto + Comparable,
{
    fn read(&self) -> PinnedFuture<Vec<u8>> {
        Box::pin(self.0.read_and(|v| TransferFormatInto::into(v)))
    }

    fn read_response(&self) -> PinnedFuture<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>> {
        Box::pin(self.0.read_and(|v| pdu::read_response(TransferFormatInto::into(v))))
    }

    fn single_read_by_type_response(&mut self, handle: u16) -> PinnedFuture<pdu::ReadTypeResponse<Vec<u8>>> {
        Box::pin(self.0.read_and(move |v| {
            let tf = TransferFormatInto::into(v);

            pdu::ReadTypeResponse::new(handle, tf)
        }))
    }

    fn try_set_value_from_transfer_format<'a>(&'a mut self, _: &'a [u8]) -> PinnedFuture<'a, Result<(), pdu::Error>> {
        unreachable!()
    }

    fn value_transfer_format_size(&mut self) -> PinnedFuture<usize> {
        let read_and_fut = self.0.read_and(|v: &R::Value| v.len_of_into());

        Box::pin(async move { read_and_fut.await })
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'a, bool> {
        let read_fut = self.read();

        Box::pin(async move { read_fut.await.cmp_tf_data(raw) })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        &self.0
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        &mut self.0
    }
}

/// Future for reading the value and performing an operation
pub(super) struct ReadAnd<R, F> {
    reader: R,
    job: Option<F>,
}

impl<R, G, V, F, T> Future for ReadAnd<R, F>
where
    R: Future<Output = G>,
    G: core::ops::Deref<Target = V>,
    F: FnOnce(&V) -> T + Unpin,
    V: ?Sized,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        unsafe {
            let this = self.get_unchecked_mut();

            Pin::new_unchecked(&mut this.reader)
                .poll(cx)
                .map(|val| (this.job.take().unwrap())(&*val))
        }
    }
}

/// The trivial implementation of [`AccessValue`] or [`AccessReadOnly`]
///
/// This is a wrapper for an attribute value type that does not require any async operation to read
/// or write to the value. This is mainly used by either static types or values that are local to
/// the instance of an ATT [`Server`].
///
/// ##
///
/// ## Methods `as_any` and `as_mut_any`
/// The methods `as_any` and `as_mut_any` within `AccessValue` and `AccessReadOnly` are implemented
/// to return a reference to the inner value.
///
/// [`Server`]: crate::server::Server
pub struct TrivialAccessor<V: ?Sized>(pub V);

impl<V> TrivialAccessor<V> {
    pub fn new(value: V) -> Self {
        TrivialAccessor(value)
    }
}

impl<V: Unpin + Send + Sync + 'static> AccessValue for TrivialAccessor<V> {
    type ReadValue = V;
    type ReadGuard<'a> = &'a V where V: 'a;
    type Read<'a> = Ready<&'a V> where Self: 'a;
    type WriteValue = V;
    type Write<'a> = Ready<Result<(), pdu::Error>>;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(&self.0)
    }

    fn write(&mut self, val: Self::WriteValue) -> Self::Write<'_> {
        self.0 = val;

        core::future::ready(Ok(()))
    }

    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        &mut self.0
    }
}

impl<V: ?Sized + Send + Sync> AccessReadOnly for TrivialAccessor<V> {
    type Value = V;
    type ReadGuard<'a> = &'a V where Self: 'a;
    type Read<'a> = Ready<&'a V> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(&self.0)
    }
}

/// A copy on write accessor
pub(crate) struct CowAccess<D>(pub D);

impl<D> AccessValue for CowAccess<D>
where
    D: core::ops::Deref + From<<D::Target as ToOwned>::Owned> + Unpin + Send + 'static,
    D::Target: ToOwned + Send + Sync,
    <D::Target as ToOwned>::Owned: Unpin + Send,
{
    type ReadValue = D::Target;
    type ReadGuard<'a> = &'a D::Target where Self: 'a;
    type Read<'a> = Ready<&'a D::Target> where Self: 'a;
    type WriteValue = <D::Target as ToOwned>::Owned;
    type Write<'a> = Ready<Result<(), pdu::Error>>;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(&*self.0)
    }

    fn write(&mut self, val: Self::WriteValue) -> Self::Write<'_> {
        self.0 = D::from(val);

        core::future::ready(Ok(()))
    }

    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        &mut self.0
    }
}

/// Future used by the implementation of `AccessValue` of `futures-rs`
#[cfg(feature = "futures-rs")]
pub struct Write<F, V>(F, Option<V>);

#[cfg(feature = "futures-rs")]
impl<V> Future for Write<futures::lock::MutexLockFuture<'_, V>, V> {
    type Output = Result<(), pdu::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            let this = self.get_unchecked_mut();

            Pin::new_unchecked(&mut this.0).poll(cx).map(|mut guard| {
                *guard = this.1.take().unwrap();

                Ok(())
            })
        }
    }
}
