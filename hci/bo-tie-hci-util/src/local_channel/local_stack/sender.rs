//! A stack local channel [`Sender`]
//!
//! [`Sender`]: crate::Sender

use crate::local_channel::local_stack::buffered_channel::UnsafeReservedBuffer;
use crate::local_channel::local_stack::channel::LocalChannel;
use crate::local_channel::local_stack::{
    FromConnMsg, FromConnectionChannel, FromHostChannel, ToConnDataMsg, ToConnectionDataChannel, ToHostGenChannel,
    ToHostGenMsg, ToInterfaceMsg, UnsafeConnectionEnds, UnsafeFromConnMsg, UnsafeToConnDataMsg, UnsafeToHostGenMsg,
    UnsafeToInterfaceMsg,
};
use crate::local_channel::{LocalQueueBuffer, LocalQueueBufferSend, LocalSendFuture, LocalSendFutureError};
use crate::{Sender, ToConnectionDataIntraMessage, ToConnectionEventIntraMessage, ToHostCommandIntraMessage};
use bo_tie_util::buffer::stack::{BufferReservation, Reservation};
use core::borrow::Borrow;
use core::task::Waker;

/// The sender for a stack local channel
pub struct LocalChannelSender<const CHANNEL_SIZE: usize, C, T>(C, core::marker::PhantomData<T>)
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>>;

impl<const CHANNEL_SIZE: usize, C, T> LocalChannelSender<CHANNEL_SIZE, C, T>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>>,
{
    pub(super) fn new(c: C) -> Self {
        c.borrow().sender_count.set(c.borrow().sender_count.get() + 1);

        Self(c, core::marker::PhantomData)
    }
}

impl<const CHANNEL_SIZE: usize, C, T> Clone for LocalChannelSender<CHANNEL_SIZE, C, T>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>> + Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone(), core::marker::PhantomData)
    }
}

impl<const CHANNEL_SIZE: usize, C> LocalQueueBuffer for LocalChannelSender<CHANNEL_SIZE, C, ToHostCommandIntraMessage>
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
    for LocalChannelSender<
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
    for LocalChannelSender<
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
    for LocalChannelSender<
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
    for LocalChannelSender<CHANNEL_SIZE, C, ToConnectionEventIntraMessage>
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
    for LocalChannelSender<
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

impl<const CHANNEL_SIZE: usize, C> LocalQueueBufferSend
    for LocalChannelSender<CHANNEL_SIZE, C, ToHostCommandIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage>>,
{
    fn is_full(&self) -> bool {
        self.0.borrow().message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.borrow().receiver_exists.get()
    }

    fn push(&self, packet: Self::Payload) {
        self.0.borrow().message_queue.borrow_mut().try_push(packet).unwrap();
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferSend
    for LocalChannelSender<
        CHANNEL_SIZE,
        &ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn is_full(&self) -> bool {
        self.0.message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.receiver_exists.get()
    }

    fn push(&self, packet: Self::Payload) {
        let unsafe_packet = match packet {
            ToHostGenMsg::Event(e) => UnsafeToHostGenMsg::Event(e),
            ToHostGenMsg::NewConnection(c) => {
                let unsafe_ends = unsafe { UnsafeConnectionEnds::from(c) };

                UnsafeToHostGenMsg::NewConnection(unsafe_ends)
            }
        };

        self.0.message_queue.borrow_mut().try_push(unsafe_packet).unwrap();
    }
}

impl<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferSend
    for LocalChannelSender<
        CHANNEL_SIZE,
        &FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn is_full(&self) -> bool {
        self.0.channel.message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.channel.receiver_exists.get()
    }

    fn push(&self, packet: Self::Payload) {
        let unsafe_packet = match packet {
            ToInterfaceMsg::Command(t) => UnsafeToInterfaceMsg::Command(unsafe { BufferReservation::to_unsafe(t) }),
            ToInterfaceMsg::Disconnect(h, t) => {
                UnsafeToInterfaceMsg::Disconnect(h, unsafe { BufferReservation::to_unsafe(t) })
            }
            ToInterfaceMsg::PacketBufferInfo(i) => UnsafeToInterfaceMsg::PacketBufferInfo(i),
            ToInterfaceMsg::EventRoutingPolicy(p) => UnsafeToInterfaceMsg::EventRoutingPolicy(p),
        };

        self.0
            .channel
            .message_queue
            .borrow_mut()
            .try_push(unsafe_packet)
            .unwrap();
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferSend
    for LocalChannelSender<
        CHANNEL_SIZE,
        Reservation<'_, ToConnectionDataChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn is_full(&self) -> bool {
        self.0.channel.message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.channel.receiver_exists.get()
    }

    fn push(&self, packet: Self::Payload) {
        let unsafe_packet = match packet {
            ToConnDataMsg::Iso(t) => UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Iso(unsafe {
                UnsafeReservedBuffer::from_res(t)
            })),
            ToConnDataMsg::Acl(t) => UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Acl(unsafe {
                UnsafeReservedBuffer::from_res(t)
            })),
            ToConnDataMsg::Sco(t) => UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Sco(unsafe {
                UnsafeReservedBuffer::from_res(t)
            })),
            ToConnDataMsg::Disconnect(e) => UnsafeToConnDataMsg(ToConnectionDataIntraMessage::Disconnect(e)),
        };

        self.0
            .channel
            .message_queue
            .borrow_mut()
            .try_push(unsafe_packet)
            .unwrap();
    }
}

impl<const CHANNEL_SIZE: usize, C> LocalQueueBufferSend
    for LocalChannelSender<CHANNEL_SIZE, C, ToConnectionEventIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToConnectionEventIntraMessage>>,
{
    fn is_full(&self) -> bool {
        self.0.borrow().message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.borrow().receiver_exists.get()
    }

    fn push(&self, packet: Self::Payload) {
        self.0.borrow().message_queue.borrow_mut().try_push(packet).unwrap();
    }
}

impl<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> LocalQueueBufferSend
    for LocalChannelSender<
        CHANNEL_SIZE,
        &FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    fn is_full(&self) -> bool {
        self.0.channel.message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.channel.receiver_exists.get()
    }

    fn push(&self, packet: Self::Payload) {
        let unsafe_packet = match packet {
            FromConnMsg::Iso(t) => UnsafeFromConnMsg::Iso(unsafe { BufferReservation::to_unsafe(t) }),
            FromConnMsg::Acl(t) => UnsafeFromConnMsg::Acl(unsafe { BufferReservation::to_unsafe(t) }),
            FromConnMsg::Sco(t) => UnsafeFromConnMsg::Sco(unsafe { BufferReservation::to_unsafe(t) }),
        };

        self.0
            .channel
            .message_queue
            .borrow_mut()
            .try_push(unsafe_packet)
            .unwrap();
    }
}

impl<const CHANNEL_SIZE: usize, C> Sender for LocalChannelSender<CHANNEL_SIZE, C, ToHostCommandIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage>>,
{
    type Error = LocalSendFutureError;
    type Message = ToHostCommandIntraMessage;
    type SendFuture<'a> = LocalSendFuture<'a, Self, Self::Message> where Self: 'a;

    fn send(&mut self, message: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(message),
            local_sender: self,
        }
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Sender
    for LocalChannelSender<
        CHANNEL_SIZE,
        &'z ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Error = LocalSendFutureError;
    type Message = ToHostGenMsg<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;
    type SendFuture<'a> = LocalSendFuture<'a, Self, Self::Message> where Self: 'a;

    fn send(&mut self, message: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(message),
            local_sender: self,
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Sender
    for LocalChannelSender<
        CHANNEL_SIZE,
        &'z FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Error = LocalSendFutureError;
    type Message = ToInterfaceMsg<'z, CHANNEL_SIZE, BUFFER_SIZE>;
    type SendFuture<'a> = LocalSendFuture<'a, Self, Self::Message> where Self: 'a;

    fn send(&mut self, message: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(message),
            local_sender: self,
        }
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Sender
    for LocalChannelSender<
        CHANNEL_SIZE,
        Reservation<'z, ToConnectionDataChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Error = LocalSendFutureError;
    type Message = ToConnDataMsg<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;
    type SendFuture<'a> = LocalSendFuture<'a, Self, Self::Message> where Self: 'a;

    fn send(&mut self, message: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(message),
            local_sender: self,
        }
    }
}

impl<const CHANNEL_SIZE: usize, C> Sender for LocalChannelSender<CHANNEL_SIZE, C, ToConnectionEventIntraMessage>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, ToConnectionEventIntraMessage>>,
{
    type Error = LocalSendFutureError;
    type Message = ToConnectionEventIntraMessage;
    type SendFuture<'a> = LocalSendFuture<'a, Self, Self::Message> where Self: 'a;

    fn send(&mut self, message: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(message),
            local_sender: self,
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Sender
    for LocalChannelSender<
        CHANNEL_SIZE,
        &'z FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >
{
    type Error = LocalSendFutureError;
    type Message = FromConnMsg<'z, CHANNEL_SIZE, BUFFER_SIZE>;
    type SendFuture<'a> = LocalSendFuture<'a, Self, Self::Message> where Self: 'a;

    fn send(&mut self, message: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(message),
            local_sender: self,
        }
    }
}

impl<const CHANNEL_SIZE: usize, C, T> Drop for LocalChannelSender<CHANNEL_SIZE, C, T>
where
    C: Borrow<LocalChannel<CHANNEL_SIZE, T>>,
{
    fn drop(&mut self) {
        self.0.borrow().sender_count.set(self.0.borrow().sender_count.get() - 1);

        if self.0.borrow().sender_count.get() == 0 {
            self.0.borrow().waker.take().map(|waker| waker.wake());
        }
    }
}
