//! L2CAP Connection types
//!
//! This is not an implementation of `L2CAP`, that can be found within [`bo-tie-l2cap`]. This module
//! contains the types that implement the traits of `bo-tie-l2cap` so they can be used by the L2CAP
//! protocol.

use crate::{Connection, HciAclData};
use bo_tie_hci_util::ConnectionChannelEnds;
use core::cell::Cell;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// A L2CAP connection for LE
pub struct LeL2cap<C: ConnectionChannelEnds> {
    max_mtu: usize,
    mtu: Cell<usize>,
    channel_ends: C,
}

impl<C: ConnectionChannelEnds> TryFrom<Connection<C>> for LeL2cap<C> {
    type Error = Connection<C>;

    fn try_from(c: Connection<C>) -> Result<Self, Self::Error> {
        Connection::<C>::try_into_le(c)
    }
}

impl<C: ConnectionChannelEnds> LeL2cap<C> {
    pub(crate) fn new<T>(max_mtu: usize, initial_mtu: T, channel_ends: C) -> Self
    where
        T: Into<Cell<usize>>,
    {
        let mtu = initial_mtu.into();

        Self {
            max_mtu,
            mtu,
            channel_ends,
        }
    }

    /// Get the receiver
    pub fn get_receiver(&self) -> &C::Receiver {
        self.channel_ends.get_receiver()
    }

    /// Get the sender
    pub fn get_sender(&self) -> C::Sender {
        self.channel_ends.get_sender()
    }

    /// Get the maximum size of an ACl payload
    ///
    /// This returns the maximum size the payload of a HCI ACL data packet can be. Higher layer
    /// protocols must fragment messages to this size.
    ///
    /// # Note
    /// This is the same as the maximum size for a payload of a HCI ACl data packet.
    pub fn get_max_mtu(&self) -> usize {
        self.max_mtu
    }

    /// Get the current maximum transmission size
    ///
    /// Get the currently set maximum transmission unit.
    pub fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    /// Set the current maximum transmission size
    ///
    /// Set the current maximum transmission unit.
    pub fn set_mtu(&mut self, to: usize) {
        self.mtu.set(to)
    }
}

impl<C> bo_tie_l2cap::ConnectionChannel for LeL2cap<C>
where
    C: ConnectionChannelEnds,
{
    type SendBuffer = C::ToBuffer;
    type SendFut<'a> = ConnectionChannelSender<'a, C> where Self: 'a;
    type SendFutErr = <C::Sender as bo_tie_hci_util::Sender>::Error;
    type RecvBuffer = C::FromBuffer;
    type RecvFut<'a> = AclReceiverMap<'a, C> where Self: 'a;

    fn send(&self, data: bo_tie_l2cap::BasicInfoFrame<alloc::vec::Vec<u8>>) -> Self::SendFut<'_> {
        // todo: not sure if this will be necessary when the type of input data is `BasicInfoFrame<Self::Buffer<'_>>`
        let front_capacity = HciAclData::<()>::HEADER_SIZE;

        let channel_ends = &self.channel_ends;

        let iter = SelfSendBufferIter {
            front_capacity,
            channel_ends,
        };

        ConnectionChannelSender {
            sliced_future: data.into_fragments(self.get_mtu(), iter),
        }
    }

    fn set_mtu(&mut self, mtu: u16) {
        self.mtu.set(mtu.into())
    }

    fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    fn max_mtu(&self) -> usize {
        self.max_mtu
    }

    fn min_mtu(&self) -> usize {
        use bo_tie_l2cap::MinimumMtu;

        bo_tie_l2cap::LeU::MIN_MTU
    }

    fn receive(&mut self) -> Self::RecvFut<'_> {
        AclReceiverMap {
            receiver: self.channel_ends.get_mut_receiver(),
            _p: core::marker::PhantomData,
            receive_future: None,
        }
    }
}

/// A self sending buffer
///
/// This is a wrapper around a buffer and a sender. When it is created it is in buffer mode and can
/// be de-referenced as a slice or extended to fill the buffer. It then can be converted into a
/// future to send the message to the interface async task.

struct AclBufferBuilder<C: ConnectionChannelEnds> {
    sender: C::Sender,
    buffer: Option<C::ToBuffer>,
}

impl<C> bo_tie_util::buffer::TryExtend<u8> for AclBufferBuilder<C>
where
    C: ConnectionChannelEnds,
{
    type Error = AclBufferError<C::ToBuffer>;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = u8>,
    {
        self.buffer
            .as_mut()
            .map(|buffer| buffer.try_extend(iter).map_err(|e| AclBufferError::Buffer(e)))
            .transpose()
            .map(|_| ())
    }
}

#[cfg(feature = "unstable-type-alias-impl-trait")]
impl<C> core::future::IntoFuture for AclBufferBuilder<C>
where
    C: ConnectionChannelEnds,
{
    type Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>;
    type IntoFuture = impl Future<Output = Self::Output>;

    fn into_future(mut self) -> Self::IntoFuture {
        use bo_tie_hci_util::Sender;

        let message = bo_tie_hci_util::FromConnectionIntraMessage::Acl(self.buffer.take().unwrap()).into();

        async move { self.sender.send(message).await }
    }
}

#[cfg(not(feature = "unstable-type-alias-impl-trait"))]
impl<C> core::future::IntoFuture for AclBufferBuilder<C>
where
    C: ConnectionChannelEnds,
{
    type Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>;
    type IntoFuture = AclBufferFuture<C>;

    fn into_future(mut self) -> Self::IntoFuture {
        let message = bo_tie_hci_util::FromConnectionIntraMessage::Acl(self.buffer.take().unwrap()).into();

        AclBufferFuture {
            message: Some(message),
            sender_future: None,
            sender: self.sender,
            _p: core::marker::PhantomPinned,
        }
    }
}

/// This is a temporary type until 'type_alias_impl_trait` feature is stable
#[cfg(not(feature = "unstable-type-alias-impl-trait"))]
struct AclBufferFuture<C: ConnectionChannelEnds> {
    message: Option<<C::Sender as bo_tie_hci_util::Sender>::Message>,
    sender_future: Option<
        core::pin::Pin<
            alloc::boxed::Box<dyn Future<Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>>>,
        >,
    >,
    sender: C::Sender,
    _p: core::marker::PhantomPinned,
}

#[cfg(not(feature = "unstable-type-alias-impl-trait"))]
impl<C: ConnectionChannelEnds> Future for AclBufferFuture<C> {
    type Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use alloc::boxed::Box;
        use bo_tie_hci_util::Sender;
        use core::mem::transmute;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.sender_future.as_mut() {
                Some(future) => break Pin::new(future).poll(cx),
                None => {
                    let message = this.message.take().unwrap();

                    let future = Box::pin(this.sender.send(message))
                        as Pin<Box<dyn Future<Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>>>>;

                    // This is 'ok' only because `this` is pinned
                    let sender_future = unsafe {
                        transmute::<
                            _,
                            Pin<Box<dyn Future<Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>>>>,
                        >(future)
                    };

                    this.sender_future = Some(sender_future);
                }
            }
        }
    }
}

/// Error for `TryExtend` implementation of `SelfSendBuffer`

enum AclBufferError<T: bo_tie_util::buffer::TryExtend<u8>> {
    Buffer(T::Error),
}

impl<T: bo_tie_util::buffer::TryExtend<u8>> core::fmt::Debug for AclBufferError<T>
where
    T::Error: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AclBufferError::Buffer(e) => e.fmt(f),
        }
    }
}

impl<T: bo_tie_util::buffer::TryExtend<u8>> core::fmt::Display for AclBufferError<T>
where
    T::Error: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AclBufferError::Buffer(e) => e.fmt(f),
        }
    }
}

struct SelfSendBufferIter<'a, C: ConnectionChannelEnds> {
    front_capacity: usize,
    channel_ends: &'a C,
}

impl<'a, C> Iterator for SelfSendBufferIter<'a, C>
where
    C: ConnectionChannelEnds,
{
    type Item = SelfSendBufferFutureMap<C>;

    fn next(&mut self) -> Option<Self::Item> {
        let take_buffer = self.channel_ends.take_buffer(self.front_capacity);

        let sender = self.channel_ends.get_sender().into();

        Some(SelfSendBufferFutureMap { sender, take_buffer })
    }
}

struct SelfSendBufferFutureMap<C: ConnectionChannelEnds> {
    sender: Option<C::Sender>,
    take_buffer: C::TakeBuffer,
}

impl<C> Future for SelfSendBufferFutureMap<C>
where
    C: ConnectionChannelEnds,
{
    type Output = AclBufferBuilder<C>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        unsafe { Pin::new_unchecked(&mut this.take_buffer) }
            .poll(cx)
            .map(|buffer| {
                let sender = this.sender.take().unwrap();
                let buffer = buffer.into();

                AclBufferBuilder { sender, buffer }
            })
    }
}

pub struct ConnectionChannelSender<'a, C: ConnectionChannelEnds> {
    sliced_future: bo_tie_l2cap::send_future::AsSlicedPacketFuture<
        SelfSendBufferIter<'a, C>,
        alloc::vec::Vec<u8>,
        SelfSendBufferFutureMap<C>,
        AclBufferBuilder<C>,
        <AclBufferBuilder<C> as core::future::IntoFuture>::IntoFuture,
    >,
}

impl<'a, C> Future for ConnectionChannelSender<'a, C>
where
    C: ConnectionChannelEnds,
{
    type Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|this| &mut this.sliced_future) }.poll(cx)
    }
}

pub struct AclReceiverMap<'a, C: ConnectionChannelEnds> {
    // todo: raw pointers (and associated unsafety) can probably be converted to references when rust issue #100135 is closed
    receiver: *mut C::Receiver,
    _p: core::marker::PhantomData<&'a C::Receiver>,
    receive_future: Option<<C::Receiver as bo_tie_hci_util::Receiver>::ReceiveFuture<'a>>,
}

impl<'a, C> Future for AclReceiverMap<'a, C>
where
    C: ConnectionChannelEnds,
{
    type Output = Option<
        Result<
            bo_tie_l2cap::L2capFragment<C::FromBuffer>,
            bo_tie_l2cap::BasicFrameError<<C::FromBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>,
        >,
    >;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use bo_tie_hci_util::{Receiver, ToConnectionIntraMessage};
        use bo_tie_l2cap::BasicFrameError;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.receive_future {
                None => this.receive_future = Some(unsafe { &mut *this.receiver }.recv()),
                Some(ref mut receiver) => match unsafe { Pin::new_unchecked(receiver) }.poll(cx) {
                    Poll::Pending => break Poll::Pending,
                    Poll::Ready(None) => break Poll::Ready(None),
                    Poll::Ready(Some(ToConnectionIntraMessage::Acl(data))) => match HciAclData::try_from_buffer(data) {
                        Ok(data) => {
                            let fragment = bo_tie_l2cap::L2capFragment::from(data);

                            break Poll::Ready(Some(Ok(fragment)));
                        }
                        Err(_) => {
                            break Poll::Ready(Some(Err(BasicFrameError::Other(
                                "Received invalid HCI ACL Data packet",
                            ))))
                        }
                    },
                    Poll::Ready(Some(ToConnectionIntraMessage::Sco(_))) => {
                        break Poll::Ready(Some(Err(BasicFrameError::Other(
                            "synchronous connection data is not implemented",
                        ))))
                    }
                    Poll::Ready(Some(ToConnectionIntraMessage::Iso(_))) => {
                        break Poll::Ready(Some(Err(BasicFrameError::Other(
                            "isochronous connection data is not implemented",
                        ))))
                    }
                    Poll::Ready(Some(ToConnectionIntraMessage::Disconnect(_reason))) => break Poll::Ready(None),
                },
            }
        }
    }
}
