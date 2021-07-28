//! Security Manager Out Of Band Pairing
//!
//! This contains the setup for enabling the usage of out of band pairing with the Security Manager
//! implementations in this library.

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
/// the two pairing devices can be considered a valid OOB. However the OOB link must have
/// man in the middle protection in order for the OOB method to be secure form of pairing.
///
/// # Bidirectional confirm validation
/// The methods [`set_send_method`](OutOfBandMethodBuilder::set_send_method) and
/// [`set_receive_method`]((OutOfBandMethodBuilder::set_receive_method) determine how data is sent
/// and received through the OOB interface. Both of them must be called before an
/// [`OutOfBandSlaveSecurityManager`] can be built with [`build`]. The method `set_send_method` is
/// used to set a factory function for generating a future to process sending data over the OOB
/// interface. Correspondingly `set_receive_method` is for setting the factory function for
/// generating a future for receiving data over the OOB interface.
///
/// # Single Direction confirm validation
/// If it is desired to only support one direction of OOB data transfer, the methods
/// [`only_send_oob`](OutOfBandMethodBuilder::only_send_oob) and
/// [`only_receive_oob`](OutOfBandMethodBuilder::only_receive_oob) can be used for facilitate this,
/// however it is recommended to only use these methods when the OOB interface only supports a
/// single direction of data transfer. Using these methods will mean that the initiator must support
/// the counterpart direction of data transfer or OOB authentication will fail.
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
///
/// # Bidirectional confirm validation
/// The methods [`set_send_method`](OutOfBandMethodBuilder::set_send_method) and
/// [`set_receive_method`](OutOfBandMethodBuilder::set_receive_method) determine how data is sent
/// and received through the OOB interface. Both of them must be called before an
/// [`OutOfBandSlaveSecurityManager`] can be built with [`build`]. The method `set_send_method` is
/// used to set a factory function for generating a future to process sending data over the OOB
/// interface. Correspondingly `set_receive_method` is for setting the factory function for
/// generating a future for receiving data over the OOB interface.
///
/// # Single Direction confirm validation
/// If it is desired to only support one direction of OOB data transfer, the methods
/// [`only_send_oob`](OutOfBandMethodBuilder::only_send_oob) and
/// [`only_receive_oob`](OutOfBandMethodBuilder::only_receive_oob) can be used for facilitate this,
/// however it is recommended to only use these methods when the OOB interface only supports a
/// single direction of data transfer. Using these methods will mean that the initiator must support
/// the counterpart direction of data transfer or OOB authentication will fail.
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

    fn send(&self, data: &'a [u8]) -> Self::Future;
}

impl<'a, S, F> OutOfBandSend<'a> for S
where
    S: Fn(&'a [u8]) -> F,
    F: Future + 'a,
{
    type Future = F;

    fn can_send() -> bool {
        true
    }

    fn send(&self, data: &'a [u8]) -> Self::Future {
        self(data)
    }
}

impl OutOfBandSend<'_> for () {
    type Future = UnusedOobInterface<()>;

    fn can_send() -> bool {
        false
    }

    fn send(&self, _: &[u8]) -> Self::Future {
        panic!("Tried to send OOB data on a nonexistent interface")
    }
}

/// The trait to used by a Security Manager send data over an out of band (OOB) interface
///
/// This is auto implemented for anything that implements `Fn() -> impl Future<Output = Vec<u8>>`.
pub trait OutOfBandReceive {
    type Future: Future<Output = Vec<u8>>;

    fn can_receive() -> bool;

    fn receive(&self) -> Self::Future;
}

impl<R, F> OutOfBandReceive for R
where
    R: Fn() -> F,
    F: Future<Output = Vec<u8>>,
{
    type Future = F;

    fn can_receive() -> bool {
        true
    }

    fn receive(&self) -> Self::Future {
        self()
    }
}

impl OutOfBandReceive for () {
    type Future = UnusedOobInterface<Vec<u8>>;

    fn can_receive() -> bool {
        false
    }

    fn receive(&self) -> Self::Future {
        panic!("Tried to receive OOB data on a nonexistent interface")
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

mod trait_sealer {
    pub trait SealedTrait {}
}

/// The trait for receiving out of band data
///
/// Because out of band data is received outside of the Bluetooth connection (or whatever other
/// Bluetooth transmission process), it does not quite fit within the process of pairing. So there
/// is two different ways for a security manager to receive the out of band data. The easiest and
/// preferred way is for the Security Manager to directly await the reception of OOB data. The other
/// way is to directly set the OOB data with a method in the Security Manager. This is much harder
/// as it can only be called at the correct time during pairing or else the method will error.
///
/// This is a sealed trait as there are specific types to facilitate the three types of OOB data
/// reception. [`InternalOobReceiver`] is a marker type for the preferred method. Its contains a
/// function used generate a future for awaiting OOB data. This function is internally called at the
/// correct part of the pairing process to await the reception of the OOB data.
/// [`ExternalOobReceiver`] is used when for whatever the internally used function to generate the
/// OOB reception future cannot be used. In this case the Security Managers (initiator and
/// responder) have a separate method that is called to provide the received OOB data to it. This
/// issue is that these methods will error if they're not called at the proper time. This is why
/// `InternalOobReceiver` is preferred as it is idiot proof in this regard. The last type to
/// implement this trait is not a receiver at all, instead the `()` type is used to indicate that
/// OOB data cannot be received by the Security Manager.
pub trait OobReceiverType: trait_sealer::SealedTrait {}

/// Marker type for 'internally' resolving reception of OOB data
///
/// With this marker type, both types of Security Managers (initiator or responder) will call the
/// method for receiving within their methods for pairing. Thus awaiting the reception of OOB data
/// will always occur at the correct time withing the pairing process.
pub struct InternalOobReceiver<F>(pub F);

impl<F> From<F> for InternalOobReceiver<F>
where
    F: OutOfBandReceive,
{
    fn from(f: F) -> Self {
        Self(f)
    }
}

/// Marker type for 'externally' resolving reception of OOB data
///
/// This should be used only when [`InternalOobReceiver`] cannot be used. The reason being that
/// this will require a method call to set the received out of band data at the correct time within
/// pairing. Both types of security manager have a method to set the received OOB data that is only
/// available when this type is used.
pub struct ExternalOobReceiver;
