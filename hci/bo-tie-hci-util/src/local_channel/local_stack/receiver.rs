//! A stack local channel's [`Receiver`]
//!
//! [`Receiver`]: crate::Receiver

use crate::local_channel::local_stack::buffered_channel::UnsafeReservedBuffer;
use crate::local_channel::local_stack::channel::LocalChannel;
use crate::local_channel::local_stack::{
    FromConnMsg, FromConnectionChannel, FromHostChannel, ToConnDataMsg, ToConnectionDataChannel, ToHostGenChannel,
    ToHostGenMsg, ToInterfaceMsg, UnsafeFromConnMsg, UnsafeToConnDataMsg, UnsafeToHostGenMsg, UnsafeToInterfaceMsg,
};
use crate::local_channel::{LocalQueueBuffer, LocalQueueBufferReceive, LocalReceiverFuture};
use crate::{Receiver, ToConnectionDataIntraMessage, ToConnectionEventIntraMessage, ToHostCommandIntraMessage};
use bo_tie_core::buffer::stack::{Reservation, UnsafeBufferReservation};
use core::borrow::Borrow;
use core::task::Waker;
use core::task::{Context, Poll};

/// The receiver for a stack local channel
pub struct LocalChannelReceiver<const CHANNEL_SIZE: usize, C, T>(C, core::marker::PhantomData<T>)
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>>;

impl<const CHANNEL_SIZE: usize, C, T> LocalChannelReceiver<CHANNEL_SIZE, C, T>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>>,
{
    pub(super) fn new(c: C) -> Self {
        c.borrow().receiver_exists.set(true);

        Self(c, core::marker::PhantomData)
    }

    /// Forget `self` and return `C`
    ///
    /// This is unsafe as "normally" a field cannot be moved out of a type that implements `Drop`,
    /// but here the intention is to not run `Drop` and return `C`.
    pub(super) unsafe fn forget_and_unwrap(mut self) -> C {
        let c = core::mem::replace(&mut self.0, core::mem::MaybeUninit::uninit().assume_init());

        core::mem::forget(self);

        c
    }
}

impl<const CHANNEL_SIZE: usize, C, T> Clone for LocalChannelReceiver<CHANNEL_SIZE, C, T>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>> + Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), core::marker::PhantomData)
    }
}

impl<const CHANNEL_SIZE: usize, C> LocalQueueBuffer for LocalChannelReceiver<CHANNEL_SIZE, C, ToHostCommandIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage>>,
{
    type Payload = ToHostCommandIntraMessage;

    fn call_waker(&self) {
        self.0.borrow().waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.borrow().waker.set(Some(waker))
    }
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBuffer
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &'a ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Payload = ToHostGenMsg<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;

    fn call_waker(&self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBuffer
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Payload = ToInterfaceMsg<'a, CHANNEL_SIZE, BUFFER_SIZE>;

    fn call_waker(&self) {
        self.0.channel.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.channel.waker.set(Some(waker))
    }
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBuffer
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        Reservation<'a, ToConnectionDataChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Payload = ToConnDataMsg<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;

    fn call_waker(&self) {
        self.0.channel.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.channel.waker.set(Some(waker))
    }
}

impl<const CHANNEL_SIZE: usize, C> LocalQueueBuffer
    for LocalChannelReceiver<CHANNEL_SIZE, C, ToConnectionEventIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToConnectionEventIntraMessage>>,
{
    type Payload = ToConnectionEventIntraMessage;

    fn call_waker(&self) {
        self.0.borrow().waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.borrow().waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBuffer
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &'a FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Payload = FromConnMsg<'a, CHANNEL_SIZE, BUFFER_SIZE>;

    fn call_waker(&self) {
        self.0.channel.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.channel.waker.set(Some(waker))
    }
}

impl<const CHANNEL_SIZE: usize, C> LocalQueueBufferReceive
    for LocalChannelReceiver<CHANNEL_SIZE, C, ToHostCommandIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage>>,
{
    fn has_senders(&self) -> bool {
        self.0.borrow().sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.borrow().message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        self.0.borrow().message_queue.borrow_mut().try_remove().unwrap()
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferReceive
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn has_senders(&self) -> bool {
        self.0.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        let unsafe_payload = self.0.message_queue.borrow_mut().try_remove().unwrap();

        match unsafe_payload {
            UnsafeToHostGenMsg::Event(e) => ToHostGenMsg::Event(e),
            UnsafeToHostGenMsg::NewConnection(c) => {
                let connection_ends = unsafe { c.into() };

                ToHostGenMsg::NewConnection(connection_ends)
            }
        }
    }
}

impl<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferReceive
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn has_senders(&self) -> bool {
        self.0.channel.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.channel.message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        let unsafe_payload = self.0.channel.message_queue.borrow_mut().try_remove().unwrap();

        match unsafe_payload {
            UnsafeToInterfaceMsg::Command(t) => ToInterfaceMsg::Command(unsafe { UnsafeBufferReservation::rebind(t) }),
            UnsafeToInterfaceMsg::Disconnect(h, t) => {
                ToInterfaceMsg::Disconnect(h, unsafe { UnsafeBufferReservation::rebind(t) })
            }
            UnsafeToInterfaceMsg::PacketBufferInfo(i) => ToInterfaceMsg::PacketBufferInfo(i),
            UnsafeToInterfaceMsg::EventRoutingPolicy(p) => ToInterfaceMsg::EventRoutingPolicy(p),
        }
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferReceive
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        Reservation<'_, ToConnectionDataChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn has_senders(&self) -> bool {
        self.0.channel.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.channel.message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        let unsafe_payload = self.0.channel.message_queue.borrow_mut().try_remove().unwrap();

        match unsafe_payload {
            UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Acl(t)) => {
                ToConnDataMsg::Acl(unsafe { UnsafeReservedBuffer::into_res(t) })
            }
            UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Sco(t)) => {
                ToConnDataMsg::Sco(unsafe { UnsafeReservedBuffer::into_res(t) })
            }
            UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Iso(t)) => {
                ToConnDataMsg::Iso(unsafe { UnsafeReservedBuffer::into_res(t) })
            }
            UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Disconnect(e)) => ToConnDataMsg::Disconnect(e),
        }
    }
}

impl<const CHANNEL_SIZE: usize, C> LocalQueueBufferReceive
    for LocalChannelReceiver<CHANNEL_SIZE, C, ToConnectionEventIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToConnectionEventIntraMessage>>,
{
    fn has_senders(&self) -> bool {
        self.0.borrow().sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.borrow().message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        self.0.borrow().message_queue.borrow_mut().try_remove().unwrap()
    }
}

impl<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferReceive
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn has_senders(&self) -> bool {
        self.0.channel.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.channel.message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        let unsafe_payload = self.0.channel.message_queue.borrow_mut().try_remove().unwrap();

        match unsafe_payload {
            UnsafeFromConnMsg::Acl(t) => FromConnMsg::Acl(unsafe { UnsafeBufferReservation::rebind(t) }),
            UnsafeFromConnMsg::Sco(t) => FromConnMsg::Sco(unsafe { UnsafeBufferReservation::rebind(t) }),
            UnsafeFromConnMsg::Iso(t) => FromConnMsg::Iso(unsafe { UnsafeBufferReservation::rebind(t) }),
        }
    }
}

impl<const CHANNEL_SIZE: usize, C> Receiver for LocalChannelReceiver<CHANNEL_SIZE, C, ToHostCommandIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage>>,
{
    type Message = ToHostCommandIntraMessage;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.borrow().waker.set(Some(cx.waker().clone()));

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Receiver
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &'z ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Message = ToHostGenMsg<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.waker.set(Some(cx.waker().clone()));

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<'z, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Receiver
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &'z FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Message = ToInterfaceMsg<'z, CHANNEL_SIZE, BUFFER_SIZE>;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.channel.waker.set(Some(cx.waker().clone()));

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Receiver
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        Reservation<'z, ToConnectionDataChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Message = ToConnDataMsg<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.channel.waker.set(Some(cx.waker().clone()));

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<const CHANNEL_SIZE: usize, C> Receiver for LocalChannelReceiver<CHANNEL_SIZE, C, ToConnectionEventIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToConnectionEventIntraMessage>>,
{
    type Message = ToConnectionEventIntraMessage;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.borrow().waker.set(Some(cx.waker().clone()));

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<'z, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Receiver
    for LocalChannelReceiver<
        CHANNEL_SIZE,
        &'z FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Message = FromConnMsg<'z, CHANNEL_SIZE, BUFFER_SIZE>;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.channel.waker.set(Some(cx.waker().clone()));

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<const CHANNEL_SIZE: usize, C, T> Drop for LocalChannelReceiver<CHANNEL_SIZE, C, T>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>>,
{
    fn drop(&mut self) {
        self.0.borrow().receiver_exists.set(false);
        self.0.borrow().message_queue.borrow_mut().empty()
    }
}
