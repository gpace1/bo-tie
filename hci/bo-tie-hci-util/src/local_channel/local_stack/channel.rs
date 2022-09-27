//! Stack local channel
//!
//! This is the implementation of a channel whose queue is allocated on the stack.

use super::sender::LocalChannelSender;
use crate::local_channel::local_stack::receiver::LocalChannelReceiver;
use crate::local_channel::local_stack::{ToHostGenChannel, ToHostGenMsg, UnsafeToHostGenMsg};
use crate::local_channel::LocalSendFutureError;
use crate::{Channel, ToHostCommandIntraMessage};
use bo_tie_util::buffer::stack::QueueBuffer;
use core::cell::{Cell, RefCell};
use core::task::Waker;

/// A stack allocated async channel
///
/// This is a MPSC channel where the queue is allocated on the stack instead of the heap. Using this
/// channel requires borrowing the channel, either the standard rust way with `&` or by using a
/// wrapper structure that carries a lifetime.
///
/// The size of the channel's queue must be known at compile time. The channel is always a fixed
/// sized channel and cannot be reallocated to have a larger or smaller queue. For the fastest
/// implementation, the size of the queue should be a power of two.
pub struct LocalChannel<const CHANNEL_SIZE: usize, T> {
    pub(super) message_queue: RefCell<QueueBuffer<T, CHANNEL_SIZE>>,
    pub(super) sender_count: Cell<usize>,
    pub(super) receiver_exists: Cell<bool>,
    pub(super) waker: Cell<Option<Waker>>,
}

impl<const CHANNEL_SIZE: usize, T> LocalChannel<CHANNEL_SIZE, T> {
    pub(super) fn new() -> Self {
        let message_queue = RefCell::new(QueueBuffer::new());
        let sender_count = Cell::new(0);
        let receiver_exists = Cell::new(false);
        let waker = Cell::new(None);

        Self {
            message_queue,
            sender_count,
            receiver_exists,
            waker,
        }
    }
}

impl<const CHANNEL_SIZE: usize> Channel for &LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage> {
    type SenderError = LocalSendFutureError;
    type Message = ToHostCommandIntraMessage;
    type Sender = LocalChannelSender<CHANNEL_SIZE, Self, ToHostCommandIntraMessage>;
    type Receiver = LocalChannelReceiver<CHANNEL_SIZE, Self, ToHostCommandIntraMessage>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(*self)
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        if self.receiver_exists.get() {
            None
        } else {
            Some(LocalChannelReceiver::new(*self))
        }
    }
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Channel
    for &'a ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type SenderError = LocalSendFutureError;
    type Message = ToHostGenMsg<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;
    type Sender = LocalChannelSender<CHANNEL_SIZE, Self, UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>;
    type Receiver = LocalChannelReceiver<CHANNEL_SIZE, Self, UnsafeToHostGenMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(*self)
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        if self.receiver_exists.get() {
            None
        } else {
            Some(LocalChannelReceiver::new(*self))
        }
    }
}
