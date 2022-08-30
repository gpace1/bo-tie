//! Security Manager Out Of Band Pairing
//!
//! This contains the setup for enabling the usage of out of band pairing with the Security Manager
//! implementations in this library.

use crate::oob::sealed_receiver_type::OobReceiverTypeVariant;
use alloc::vec::Vec;
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

/// Out of Band pairing method setup
///
/// Security Managers that implement this trait can be used as the out-of-band (OOB) process for
/// pairing. Any communication process that is outside of the direct Bluetooth communication between
/// the two pairing devices can be considered a valid OOB transport if it has acceptable protection
/// against a man in the middle attack.
pub trait BuildOutOfBand: core::ops::DerefMut<Target = Self::Builder> {
    type Builder;
    type SecurityManager;

    fn build(self) -> Self::SecurityManager;
}

/// Out of Band pairing method setup
///
/// Security Managers that implement this trait can be used as the out-of-band (OOB) process for
/// pairing. Any communication process that is outside of the direct Bluetooth communication between
/// the two pairing devices can be considered a valid OOB. However the OOB link must have
/// man in the middle protection in order for the OOB method to be secure form of pairing.
pub struct OutOfBandMethodBuilder<B, S, R> {
    pub(super) builder: B,
    pub(super) send_method: S,
    pub(super) receive_method: R,
}

impl<B, S, R> OutOfBandMethodBuilder<B, S, R> {
    pub(super) fn new(builder: B, send_method: S, receive_method: R) -> Self {
        OutOfBandMethodBuilder {
            builder,
            send_method,
            receive_method,
        }
    }
}

impl<B, S, R> core::ops::Deref for OutOfBandMethodBuilder<B, S, R> {
    type Target = B;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

impl<B, S, R> core::ops::DerefMut for OutOfBandMethodBuilder<B, S, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.builder
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

impl OutOfBandSend<'_> for () {
    type Future = UnusedOobInterface<()>;

    fn can_send() -> bool {
        false
    }

    fn send(&mut self, _: &[u8]) -> Self::Future {
        panic!("Tried to send OOB data on a nonexistent interface")
    }
}

/// The trait to used by a Security Manager send data over an out of band (OOB) interface
///
/// This is auto implemented for anything that implements `Fn() -> impl Future<Output = Vec<u8>>`.
pub trait OutOfBandReceive {
    type Future: Future<Output = Vec<u8>>;

    fn receive(&mut self) -> Self::Future;
}

impl<R, F> OutOfBandReceive for R
where
    R: FnMut() -> F,
    F: Future<Output = Vec<u8>>,
{
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
        type RxType: core::future::Future<Output = alloc::vec::Vec<u8>>;

        #[doc(hidden)]
        fn receive(&mut self) -> Self::RxType;
    }
}

/// The trait for receiving out of band data
///
/// Because out of band data is received outside of the Bluetooth connection , it must be done by
/// the user of this library, but still be done during the process of pairing. So there
/// is two different ways for a security manager to get the out of band data from the other device.
/// The easiest and preferred way is for the Security Manager to directly await the reception of OOB
/// data as it goes about pairing. Essentially set how OOB data is received and forget about it. The
/// other way is to directly set the OOB data with a method in the Security Manager. This is more
/// difficult as it can only be called at the proper time during pairing or else the method will
/// error.
///
/// This is a sealed trait as there are specific types to facilitate the three kinds of OOB data
/// reception. Anything that implements [`OutOfBandReceive`] will work as the preferred method. This
/// method is where the reception occurs within the security manager. The security manager will
/// perform the await the reception of the OOB data at the correct part of the pairing process.
///
/// The type [`ExternalOobReceiver`] should only be used when an `OutOfBandReceive` cannot be used.
/// In this case the Security Managers (initiator and responder) have a separate method that is
/// must be called at the correct time in the pairing process to provide the received OOB data.
/// These methods will error if they are not called at the proper time.
///
/// The last type to implement this trait is not a receiver at all, instead the `()` type is used to
/// indicate that OOB data cannot be received by the Security Manager.
pub trait OobReceiverType: sealed_receiver_type::SealedTrait {}

impl<F> sealed_receiver_type::SealedTrait for F
where
    F: OutOfBandReceive,
{
    fn receiver_type() -> sealed_receiver_type::OobReceiverTypeVariant {
        sealed_receiver_type::OobReceiverTypeVariant::Internal
    }

    type RxType = F::Future;

    fn receive(&mut self) -> Self::RxType {
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

    type RxType = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = alloc::vec::Vec<u8>>>>;

    fn receive(&mut self) -> Self::RxType {
        unreachable!("Called receive on external receiver")
    }
}

impl OobReceiverType for ExternalOobReceiver {}

impl sealed_receiver_type::SealedTrait for () {
    fn receiver_type() -> OobReceiverTypeVariant {
        sealed_receiver_type::OobReceiverTypeVariant::DoesNotExist
    }

    type RxType = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = alloc::vec::Vec<u8>>>>;

    fn receive(&mut self) -> Self::RxType {
        unreachable!("Called receive on external receiver")
    }
}

impl OobReceiverType for () {}
