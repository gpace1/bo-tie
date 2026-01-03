//! Implementations of the `AccessValue` trait

use crate::server::{Comparable, PinnedFuture, ServerAttribute};
use crate::{pdu, TransferFormatInto, TransferFormatTryFrom};
use core::any::Any;
use core::future::{Future, Ready};
use core::pin::Pin;
use core::task::{Context, Poll};

/// Read guard
///
/// This is the trait bound requirement for the associated type `ReadGuard` of [`AccessValue`]
///
/// The read guard is used for accessing the data within an Attribute value. Unlike writing, an
/// Attribute's value may need to be read for other reasons than for transferring the value to the
/// client. Furthermore reading may occur and the server may determine that the Client will not be
/// sent the value.
///
/// ## Implementing
/// Anything that implements [`Deref`] also implements `ReadGuard`. Most implementations of an
/// `AccessValue` will just use a deref type for its `ReadGuard` associated type. When a
/// de-referential type cannot be used is when the 'value' of an Attribute is implemented to 'take'
/// on a read access.
///
/// If reading *takes* a value from some underlying type, the *Access Value* needs to take ownership
/// of the value until method `access` is called. If the *Read Guard* were to take ownership, it
/// could be possibly dropped without ever being sent to the Client.
///
/// Here is an example where a successive iterator is only proceeded to the next item if
/// ```
/// # use bo_tie_att::server;
/// # use std::iter;
///
/// // This read guard borrows a peekable iterator from
/// // (presumably) a type that implements `AccessValue`.
/// // The value within the peekable iterator is only
/// // dropped if `was_sent` is set to true.
/// struct ReadGuard<'a, F>
/// where
///     F: Fn(usize) -> Option<usize>
/// {
///     was_sent: bool,
///     value: &'a mut iter::Peekable<iter::Successors<usize, F>>
/// };
///
/// impl<F> server::ReadGuard for ReadGuard<'_, F>
/// where
///     F: Fn(usize) -> Option<usize>
/// {
///     type Target = usize;
///
///     fn access(&mut self) -> &Self::Target {
///         self.was_sent = true;
///
///         // For this example, the closure `F` is
///         // expected to always return `Some(_)`.
///         self.value.peek().unwrap()
///     }
///
///     fn access_meta(&self) -> Option<&Self::Target> {
///         self.value.peek()
///     }
/// }
///
/// impl<F> Drop for ReadGuard<'_, F>
/// where
///     F: Fn(usize) -> usize
/// {
///     fn drop(&mut self) {
///         if self.was_sent {
///             self.value.next();
///         }
///     }
/// }
/// ```
pub trait ReadGuard {
    type Target: ?Sized;

    /// Access the value
    ///
    /// This is *only* called when the value is going to be read in order to send the transfer
    /// format of the value to the Client. Method `access` is guaranteed to be called at most once
    /// per read operation, and never called for find operations.
    fn access(&mut self) -> &Self::Target;

    /// Access the value for `Server` purposes
    ///
    /// This is called whenever the `Server` needs to determine something with value, but not send
    /// the value to the `Client`. The operation may call `access` later, or it may not, but either
    /// way `access_meta` will only be called before `access`.
    fn access_meta(&self) -> &Self::Target;
}

impl<T: core::ops::Deref> ReadGuard for T {
    type Target = T::Target;

    fn access(&mut self) -> &Self::Target {
        core::ops::Deref::deref(self)
    }

    fn access_meta(&self) -> &Self::Target {
        core::ops::Deref::deref(self)
    }
}

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

    type ReadGuard<'a>: ReadGuard<Target = Self::ReadValue>
    where
        Self: 'a;

    type Read<'a>: Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send
    where
        Self: 'a;

    type WriteValue: Unpin + Send;

    type Write<'a>: Future<Output = Result<(), pdu::Error>> + Send
    where
        Self: 'a;

    /// Read the Attribute value
    ///
    /// `read` returns a future for accessing the Attribute value in order to read it. This future
    /// either outputs the `ReadGuard` or an ATT PDU `Error` code.
    ///
    /// # `ReadGuard`
    /// The purpose of the `ReadGuard` type is to provide some protection whenever accessing an
    /// Attribute's value. A common example implementation is to assign `ReadGuard` as a mutex
    /// guard.
    ///
    /// Most of the time, something that implements [`Deref`], where the target is equal
    /// to the `ReadValue` associated type, is used as the `ReadGuard`. However, there is some cases
    /// where an accessor specific [`ReadGuard`] type my need to be used. Values that have limited
    /// time access, or abstract over a channel may require a custom gaurd implementation.
    ///
    /// ### *IMPORTANT*: The `ReadGuard` `send_hint`
    /// The trait [`ReadGuard`] is mainly intended for protecting access to a read value, but it
    /// also servers as an indicator for when the value is to be sent to the Client. At times the
    /// `Server` needs to read the value for some other operation other than transferring it to
    /// the client. This consists of either checking the size of the value or comparing the value
    /// to another value provided by the Client.
    ///
    /// To know when the value is going to be read in order to send it to the Client, the
    /// `ReadGuard` trait provides the `send_hint` input to its `access` method. This input is
    /// true whenever the value is being read *to send* it to the Client. Furthermore, this input is
    /// guaranteed to only be true once per processed request.
    ///
    /// # Custom Errors
    /// Any error can be output by the returned `Read` future, but errors that are neither an
    /// [application error] nor a [common error code] have already been checked by the Server.
    ///
    /// [`Deref`]: core::ops::Deref
    /// [application error]: pdu::ErrorConversionError::ApplicationError
    /// [common error coe]: pdu::ErrorConversionError::CommonErrorCode
    fn read(&mut self) -> Self::Read<'_>;

    /// Write an Attribute vale
    ///
    /// `write` returns a future for safely accessing the value in order to write to it. This future
    /// either outputs the `WriteGuard` or an ATT PDU [`Error`] code. Unlike the `ReadGuard` the
    /// only time the `WriteGuard` is dereference is when the value received from the Client is to
    /// be written to the Attribute.
    ///
    /// # Custom Errors
    /// Any error can be output by the returned `Read` future, but errors that are neither an
    /// [application error] nor a [common error code] have already been checked by the Server.
    ///
    /// [application error]: pdu::ErrorConversionError::ApplicationError
    /// [common error coe]: pdu::ErrorConversionError::CommonErrorCode
    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_>;

    fn as_any(&self) -> &dyn Any;

    fn as_mut_any(&mut self) -> &mut dyn Any;
}

#[cfg(feature = "tokio")]
impl<V> AccessValue for std::sync::Arc<tokio::sync::Mutex<V>>
where
    V: Unpin + Send + 'static,
{
    type ReadValue = V;
    type ReadGuard<'a>
        = tokio::sync::MutexGuard<'a, V>
    where
        V: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;
    type WriteValue = V;
    type Write<'a>
        = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        Box::pin(async move { Ok(self.lock().await) })
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
    type ReadGuard<'a>
        = tokio::sync::RwLockReadGuard<'a, V>
    where
        V: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;
    type WriteValue = V;
    type Write<'a>
        = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        Box::pin(async move { Ok(tokio::sync::RwLock::read(self).await) })
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
    type ReadGuard<'a>
        = futures::lock::MutexGuard<'a, V>
    where
        Self: 'a;
    type Read<'a>
        = FuturesRead<futures::lock::MutexLockFuture<'a, V>>
    where
        Self: 'a;
    type WriteValue = V;
    type Write<'a>
        = FuturesWrite<futures::lock::MutexLockFuture<'a, Self::WriteValue>, Self::WriteValue>
    where
        Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        FuturesRead(self.lock())
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        FuturesWrite(self.lock(), Some(v))
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
    type ReadGuard<'a>
        = async_std::sync::MutexGuard<'a, V>
    where
        Self: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;
    type WriteValue = V;
    type Write<'a>
        = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        Box::pin(async move { Ok(self.lock().await) })
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
    type ReadGuard<'a>
        = async_std::sync::RwLockReadGuard<'a, V>
    where
        Self: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;
    type WriteValue = V;
    type Write<'a>
        = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        Box::pin(async move { Ok(async_std::sync::RwLock::read(self).await) })
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

    async fn read(&self) -> Result<Self::ReadGuard<'_>, pdu::Error>;

    async fn write(&mut self, v: Self::WriteValue) -> Result<(), pdu::Error>;

    fn as_any(&self) -> &dyn Any;

    fn as_mut_any(&mut self) -> &mut dyn Any;
}

#[cfg(feature = "async-trait")]
impl<T: AsyncAccessValue> AccessValue for T {
    type ReadValue = T::ReadValue;
    type ReadGuard<'a>
        = T::ReadGuard<'a>
    where
        Self: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;
    type WriteValue = T::WriteValue;
    type Write<'a>
        = Pin<Box<dyn Future<Output = Result<(), pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        AsyncAccessValue::read(self)
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        AsyncAccessValue::write(self, v)
    }

    fn as_any(&self) -> &dyn Any {
        AsyncAccessValue::as_any(self)
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        AsyncAccessValue::as_mut_any(self)
    }
}

/// Wrapper type for a type that implements [`AccessValue`]
pub(super) struct AccessibleValue<A: AccessValue>(pub(super) A);

impl<A> ServerAttribute for AccessibleValue<A>
where
    A: AccessValue + 'static,
    A::ReadValue: TransferFormatInto + Comparable,
    A::WriteValue: TransferFormatTryFrom,
{
    fn read(&mut self) -> PinnedFuture<Result<Vec<u8>, pdu::Error>> {
        let read_fut = self.0.read();

        let task = async move {
            let mut val = read_fut.await?;

            Ok(TransferFormatInto::into(val.access()))
        };

        Box::pin(task)
    }

    fn read_response(&mut self) -> PinnedFuture<Result<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>, pdu::Error>> {
        let read_fut = self.0.read();

        let task = async move {
            let mut val = read_fut.await?;

            Ok(pdu::read_response(TransferFormatInto::into(val.access())))
        };

        Box::pin(task)
    }

    fn read_type_response(
        &mut self,
        handle: u16,
        size: usize,
    ) -> PinnedFuture<'_, Result<Option<pdu::ReadTypeResponse<Vec<u8>>>, pdu::Error>> {
        let read_fut = self.0.read();

        let task = async move {
            let mut val = read_fut.await?;

            let len = TransferFormatInto::len_of_into(val.access_meta());

            let ret = (len == size).then(|| pdu::ReadTypeResponse::new(handle, TransferFormatInto::into(val.access())));

            Ok(ret)
        };

        Box::pin(task)
    }

    fn try_set_value_from_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'a, Result<(), pdu::Error>> {
        Box::pin(async move {
            self.0
                .write(TransferFormatTryFrom::try_from(raw).map_err(|e| e.pdu_err)?)
                .await
        })
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'a, bool> {
        let read_fut = self.read();

        let task = async move {
            let Ok(val) = read_fut.await else { return false };

            val.cmp_tf_data(raw)
        };

        Box::pin(task)
    }

    fn as_any(&self) -> &dyn Any {
        self.0.as_any()
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
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

    type ReadGuard<'a>: ReadGuard<Target = Self::Value>
    where
        Self: 'a;

    type Read<'a>: Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_>;
}

impl<T: ?Sized + Sync> AccessReadOnly for &'static T {
    type Value = &'static T;

    type ReadGuard<'a>
        = &'a &'static T
    where
        Self: 'a;

    type Read<'a>
        = Ready<Result<Self::ReadGuard<'a>, pdu::Error>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(Ok(self))
    }
}

#[cfg(feature = "tokio")]
impl<V: ?Sized + Send> AccessReadOnly for std::sync::Arc<tokio::sync::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a>
        = tokio::sync::MutexGuard<'a, V>
    where
        V: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async move { Ok(self.lock().await) })
    }
}

#[cfg(feature = "tokio")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<tokio::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a>
        = tokio::sync::RwLockReadGuard<'a, V>
    where
        V: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async move { Ok(tokio::sync::RwLock::read(self).await) })
    }
}

#[cfg(feature = "futures-rs")]
impl<V: ?Sized + Send> AccessReadOnly for std::sync::Arc<futures::lock::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a>
        = futures::lock::MutexGuard<'a, V>
    where
        Self: 'a;
    type Read<'a>
        = FuturesRead<futures::lock::MutexLockFuture<'a, V>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        FuturesRead(self.lock())
    }
}

#[cfg(feature = "async-std")]
impl<V: ?Sized + Send> AccessReadOnly for std::sync::Arc<async_std::sync::Mutex<V>> {
    type Value = V;
    type ReadGuard<'a>
        = async_std::sync::MutexGuard<'a, V>
    where
        Self: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async move { Ok(self.lock().await) })
    }
}

#[cfg(feature = "async-std")]
impl<V: ?Sized + Send + Sync> AccessReadOnly for std::sync::Arc<async_std::sync::RwLock<V>> {
    type Value = V;
    type ReadGuard<'a>
        = async_std::sync::RwLockReadGuard<'a, V>
    where
        Self: 'a;
    type Read<'a>
        = Pin<Box<dyn Future<Output = Result<Self::ReadGuard<'a>, pdu::Error>> + Send + 'a>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async move { Ok(async_std::sync::RwLock::read(self).await) })
    }
}

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
    fn read(&mut self) -> PinnedFuture<Result<Vec<u8>, pdu::Error>> {
        let read_fut = self.0.read();

        let task = async move {
            let mut val = read_fut.await?;

            Ok(TransferFormatInto::into(val.access()))
        };

        Box::pin(task)
    }

    fn read_response(&mut self) -> PinnedFuture<Result<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>, pdu::Error>> {
        let read_fut = self.0.read();

        let task = async move {
            let mut val = read_fut.await?;

            Ok(pdu::read_response(TransferFormatInto::into(val.access())))
        };

        Box::pin(task)
    }

    fn read_type_response(
        &mut self,
        handle: u16,
        size: usize,
    ) -> PinnedFuture<'_, Result<Option<pdu::ReadTypeResponse<Vec<u8>>>, pdu::Error>> {
        let read_fut = self.0.read();

        let task = async move {
            let mut val = read_fut.await?;

            let len = TransferFormatInto::len_of_into(val.access_meta());

            let ret = (len == size).then(|| pdu::ReadTypeResponse::new(handle, TransferFormatInto::into(val.access())));

            Ok(ret)
        };

        Box::pin(task)
    }

    fn try_set_value_from_transfer_format<'a>(&'a mut self, _: &'a [u8]) -> PinnedFuture<'a, Result<(), pdu::Error>> {
        unreachable!()
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'a, bool> {
        let read_fut = self.read();

        let task = async move {
            let Ok(val) = read_fut.await else { return false };

            val.cmp_tf_data(&raw)
        };

        Box::pin(task)
    }

    fn as_any(&self) -> &dyn Any {
        &self.0
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
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
    F: FnOnce(&V) -> Result<T, pdu::Error> + Unpin,
    V: ?Sized,
{
    type Output = Result<T, pdu::Error>;

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
    type ReadGuard<'a>
        = &'a V
    where
        V: 'a;
    type Read<'a>
        = Ready<Result<&'a V, pdu::Error>>
    where
        Self: 'a;
    type WriteValue = V;
    type Write<'a> = Ready<Result<(), pdu::Error>>;

    fn read(&mut self) -> Self::Read<'_> {
        core::future::ready(Ok(&self.0))
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
    type ReadGuard<'a>
        = &'a V
    where
        Self: 'a;
    type Read<'a>
        = Ready<Result<&'a V, pdu::Error>>
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(Ok(&self.0))
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
    type ReadGuard<'a>
        = &'a D::Target
    where
        Self: 'a;
    type Read<'a>
        = Ready<Result<&'a D::Target, pdu::Error>>
    where
        Self: 'a;
    type WriteValue = <D::Target as ToOwned>::Owned;
    type Write<'a> = Ready<Result<(), pdu::Error>>;

    fn read(&mut self) -> Self::Read<'_> {
        core::future::ready(Ok(&*self.0))
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

/// Future used by teh implementation of `AccessValue::Read` for `futures-rs`
#[cfg(feature = "futures-rs")]
pub struct FuturesRead<T>(T);

#[cfg(feature = "futures-rs")]
impl<'a, V: ?Sized> Future for FuturesRead<futures::lock::MutexLockFuture<'a, V>> {
    type Output = Result<futures::lock::MutexGuard<'a, V>, pdu::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            let this = self.get_unchecked_mut();

            Pin::new_unchecked(&mut this.0).poll(cx).map(|guard| Ok(guard))
        }
    }
}

/// Future used by the implementation of `AccessValue::Write` for `futures-rs`
#[cfg(feature = "futures-rs")]
pub struct FuturesWrite<T, V>(T, Option<V>);

#[cfg(feature = "futures-rs")]
impl<V> Future for FuturesWrite<futures::lock::MutexLockFuture<'_, V>, V> {
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
