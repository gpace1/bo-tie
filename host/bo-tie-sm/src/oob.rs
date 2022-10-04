//! Security Manager Out Of Band Pairing
//!
//! This contains the setup for enabling the usage of out of band pairing with the Security Manager
//! implementations in this library.

use crate::oob::sealed_receiver_type::OobReceiverTypeVariant;
use core::future::Future;

/// Supported direction of OOB
///
/// Most of the time the user is going to use `BothSendOob` with is used to indicate that both
/// sending and receiving of OOB data is sported. However if one of the methods cannot be done as
/// the OOB data is sent unidirectional, `OnlyResponderSendsOob` is used for OOB data sent from the
/// responder to the initiator, and `OnlyInitiatorSendsOob` is used for the opposite data direction.
#[derive(Debug, Clone, Copy)]
pub(super) enum OobDirection {
    OnlyResponderSendsOob,
    OnlyInitiatorSendsOob,
    BothSendOob,
}

/// Error for method [`OutOfBandMethodBuilder::build`](OutOfBandMethodBuilder::build)
///
/// When initializing bi-directional OOB support for a Security Manager, a method for sending
/// and a method for receiving must be set. If either of these methods are not set, then this error
/// is returned when trying to build a Security Manager.
///
/// # Note
/// If it was the intention not to set the method, then when constructing a Security Manager look
/// for the `build_with
pub enum OobBuildError {
    Send,
    Receive,
}

impl core::fmt::Debug for OobBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        <Self as core::fmt::Display>::fmt(self, f)
    }
}

impl core::fmt::Display for OobBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            OobBuildError::Send => f.write_str("Send method not set for OOB data"),
            OobBuildError::Receive => f.write_str("Receive method not set for OOB data"),
        }
    }
}

/// The trait to used by a Security Manager send data over an out of band (OOB) interface
///
/// This is auto implemented for anything that implements `Fn(&[u8]) -> impl Future`.
pub trait OutOfBandSend<'a> {
    type Future: Future + 'a;

    fn can_send() -> bool;

    fn send(&mut self, data: &'a [u8]) -> Self::Future;
}

impl<'a, S, F> OutOfBandSend<'a> for S
where
    S: FnMut(&'a [u8]) -> F,
    F: Future + 'a,
{
    type Future = F;

    fn can_send() -> bool {
        true
    }

    fn send(&mut self, data: &'a [u8]) -> Self::Future {
        self(data)
    }
}

/// The trait to used by a Security Manager send data over an out of band (OOB) interface
///
/// This is auto implemented for anything that implements `Fn() -> impl Future<Output = Vec<u8>>`.
pub trait OutOfBandReceive {
    type Output: core::borrow::Borrow<[u8]>;
    type Future: Future<Output = Self::Output>;

    fn receive(&mut self) -> Self::Future;
}

impl<R, F, V> OutOfBandReceive for R
where
    R: FnMut() -> F,
    F: Future<Output = V>,
    V: core::borrow::Borrow<[u8]>,
{
    type Output = V;
    type Future = F;

    fn receive(&mut self) -> Self::Future {
        self()
    }
}

/// Future used as the return for an unavailable OOB interface
#[doc(hidden)]
pub struct UnusedOobInterface<V>(core::marker::PhantomData<V>);

impl<V> Future for UnusedOobInterface<V> {
    type Output = V;
    fn poll(self: core::pin::Pin<&mut Self>, _: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        unreachable!()
    }
}

pub(super) mod sealed_receiver_type {

    /// The type of implementor for the `OobReceiverType`. These correspond to the types
    /// `InternalOobReceiver`, `ExternalOobReceiver`, and `()`.
    #[doc(hidden)]
    #[derive(Eq, PartialEq)]
    pub enum OobReceiverTypeVariant {
        Internal,
        External,
        DoesNotExist,
    }

    pub trait SealedTrait {
        #[doc(hidden)]
        fn receiver_type() -> OobReceiverTypeVariant;

        #[doc(hidden)]
        fn can_receive() -> bool {
            match Self::receiver_type() {
                OobReceiverTypeVariant::Internal | OobReceiverTypeVariant::External => true,
                OobReceiverTypeVariant::DoesNotExist => false,
            }
        }

        #[doc(hidden)]
        type Output: core::borrow::Borrow<[u8]>;

        #[doc(hidden)]
        type Future: core::future::Future<Output = Self::Output>;

        #[doc(hidden)]
        fn receive(&mut self) -> Self::Future;
    }
}

/// The trait for receiving out of band data
///
/// Out of band data is received outside of the Bluetooth connection. The method for receiving
/// the data is implemented outside of this library, somehow acquired by a security manager during
/// the process of pairing.
///
/// This trait is sealed, but anything that implements `OutOfBandReceive` will also implement
/// `OobReceiverType`
pub trait OobReceiverType: sealed_receiver_type::SealedTrait {}

impl<F> sealed_receiver_type::SealedTrait for F
where
    F: OutOfBandReceive,
{
    fn receiver_type() -> OobReceiverTypeVariant {
        OobReceiverTypeVariant::Internal
    }

    type Output = F::Output;

    type Future = F::Future;

    fn receive(&mut self) -> Self::Future {
        OutOfBandReceive::receive(self)
    }
}

impl<F> OobReceiverType for F where F: OutOfBandReceive {}

/// Marker type for 'externally' resolving reception of OOB data
///
/// This should be used only when another implementor of [`OobReceiverType`] cannot be used because
/// the data must be explicitly set. The reason  being that this will require a method call to set
/// the received out of band data at the correct time within pairing. Both types of security manager
/// have a method to set the received OOB data that is only available when this type is used.
pub struct ExternalOobReceiver;

impl sealed_receiver_type::SealedTrait for ExternalOobReceiver {
    fn receiver_type() -> OobReceiverTypeVariant {
        sealed_receiver_type::OobReceiverTypeVariant::External
    }

    type Output = [u8; 0];

    type Future = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = Self::Output>>>;

    fn receive(&mut self) -> Self::Future {
        unreachable!("Called receive on external receiver")
    }
}

impl OobReceiverType for ExternalOobReceiver {}

/// A marker type for not supporting out of band data
pub struct Unsupported;

impl<'a> OutOfBandSend<'a> for Unsupported {
    type Future = UnusedOobInterface<()>;

    fn can_send() -> bool {
        false
    }

    fn send(&mut self, _: &'a [u8]) -> Self::Future {
        panic!("Tried to send OOB data on a nonexistent interface")
    }
}

impl sealed_receiver_type::SealedTrait for Unsupported {
    fn receiver_type() -> OobReceiverTypeVariant {
        OobReceiverTypeVariant::DoesNotExist
    }

    type Output = [u8; 0];

    type Future = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = Self::Output>>>;

    fn receive(&mut self) -> Self::Future {
        unreachable!("Called receive on external receiver")
    }
}

impl OobReceiverType for Unsupported {}
