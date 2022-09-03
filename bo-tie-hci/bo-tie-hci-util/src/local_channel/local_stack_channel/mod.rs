//! A local channel with statically allocated buffers
//!
//! A static channel contains buffers that are on the stack instead of dynamically allocated. This
//! creates the limitation on the number of entries the channel can buffer, but it doesn't mean the
//! channel will error or panic if the buffer fills to full. Instead the channel will await when the
//! user tries to send when the buffer is full.
//!
//! This is a local channel so it can only be used between async tasks running on the same thread.
//! Furthermore, The channel must be created before the asynchronous tasks are because the buffer is
//! allocated on the stack. Tasks must use the channel through a reference to it in order to
//! guarantee the lifetime of the buffer.

use super::{
    LocalQueueBuffer, LocalQueueBufferReceive, LocalQueueBufferSend, LocalReceiverFuture, LocalSendFuture,
    LocalSendFutureError,
};
use crate::hci::interface::local_channel::local_stack_channel::stack_buffers::{
    Reservation, UnsafeBufferReservation, UnsafeReservation,
};
use crate::hci::interface::{
    Channel, ChannelEnds as ChannelEndsTrait, ChannelReserve, FlowControl, FlowControlId, FlowCtrlReceiver,
    FromIntraMessage, InterfaceReceivers, IntraMessageType, PrepareBufferMsg, Receiver, Sender, TaskId, ToIntraMessage,
};
use crate::hci::BufferReserve;
use core::cell::{Cell, Ref, RefCell};
use core::fmt::{Display, Formatter};
use core::ops::Deref;
use core::task::{Context, Poll, Waker};
use stack_buffers::{BufferReservation, DeLinearBuffer, LinearBuffer, LinearBufferError, QueueBuffer, StackHotel};

mod stack_buffers;

/// A channel for sending data between futures within the same task
///
/// This is a MPSC channel is used for one direction communication between two futures running in
/// the same task. It works the same as any async channel, but the message queue is implemented on
/// the stack. The size of this queue is determined by the constant generic `CHANNEL_SIZE`.
///
/// # Note
/// `SIZE` should be a power of two for the fastest implementation.
pub struct LocalStackChannel<const CHANNEL_SIZE: usize, B, T> {
    // The order of fields `message_queue` and `buffer_reserve` matter.  Dropping `message_queue`
    // before `buffer_reserve` allows for `message_queue` to contain unsafe reservations from
    // `buffer_reserve`.
    message_queue: RefCell<QueueBuffer<T, CHANNEL_SIZE>>,
    buffer_reserve: StackHotel<B, CHANNEL_SIZE>,
    sender_count: Cell<usize>,
    receiver_exists: Cell<bool>,
    waker: Cell<Option<Waker>>,
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStackChannel<CHANNEL_SIZE, B, T> {
    fn new() -> Self {
        let message_queue = RefCell::new(QueueBuffer::new());
        let buffer_reserve = StackHotel::new();
        let sender_count = Cell::new(0);
        let receiver_exists = Cell::new(false);
        let waker = Cell::new(None);

        Self {
            buffer_reserve,
            message_queue,
            sender_count,
            receiver_exists,
            waker,
        }
    }
}

macro_rules! impl_channel {
    ($message_ty:ty, $unsafe_message_ty:ty, $($methods:tt)*) => {
        type SenderError = LocalSendFutureError;
        type Message = $message_ty;
        type Sender =
            LocalStackChannelSender<CHANNEL_SIZE, Self, B, $unsafe_message_ty>;
        type Receiver =
            LocalStackChannelReceiver<CHANNEL_SIZE, Self, B, $unsafe_message_ty>;

        $($methods)*
    };
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> Channel
    for Reservation<
        'z,
        LocalStackChannel<
            CHANNEL_SIZE,
            B,
            FromIntraMessage<
                UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
            >,
        >,
        TASK_COUNT,
    >
where
    B: Unpin,
{
    impl_channel! {
        FromIntraMessage<StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>, ChannelEnds<'z, B, TASK_COUNT, CHANNEL_SIZE>>,
        FromIntraMessage<UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>, UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>>,

        fn get_sender(&self) -> Self::Sender {
            LocalStackChannelSender::new(self.clone())
        }

        fn take_receiver(&self) -> Option<Self::Receiver> {
            Some(LocalStackChannelReceiver::new(self.clone()))
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, B> Channel
    for &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>
where
    B: Unpin,
{
    impl_channel! {
        ToIntraMessage<BufferReservation<'z, B, CHANNEL_SIZE>>,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,

        fn get_sender(&self) -> Self::Sender {
            LocalStackChannelSender::new(*self)
        }

        fn take_receiver(&self) -> Option<Self::Receiver> {
            Some(LocalStackChannelReceiver::new(*self))
        }
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> BufferReserve
    for Reservation<
        'z,
        LocalStackChannel<
            CHANNEL_SIZE,
            B,
            FromIntraMessage<
                UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
            >,
        >,
        TASK_COUNT,
    >
where
    B: crate::hci::Buffer,
{
    type Buffer = StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>;
    type TakeBuffer = LocalStackTakeBuffer<Self>;

    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>,
    {
        LocalStackTakeBuffer::new(self.clone(), front_capacity.into().unwrap_or_default())
    }

    fn reclaim(&mut self, _: Self::Buffer) {}
}

impl<'z, const CHANNEL_SIZE: usize, B> BufferReserve
    for &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>
where
    B: crate::hci::Buffer,
{
    type Buffer = BufferReservation<'z, B, CHANNEL_SIZE>;
    type TakeBuffer = LocalStackTakeBuffer<Self>;

    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>,
    {
        LocalStackTakeBuffer::new(*self, front_capacity.into().unwrap_or_default())
    }

    fn reclaim(&mut self, _: Self::Buffer) {}
}

macro_rules! impl_local_queue_buffer {
    ($message_ty:ty) => {
        type Payload = $message_ty;

        fn call_waker(&self) {
            self.0.waker.take().map(|w| w.wake());
        }

        fn set_waker(&self, waker: Waker) {
            self.0.waker.set(Some(waker))
        }
    };
}

macro_rules! impl_local_queue_buffer_send {
    ($channel_ends:pat, $channel_ends_convert:expr) => {
        fn is_full(&self) -> bool {
            self.0.message_queue.borrow().is_full()
        }

        fn receiver_exists(&self) -> bool {
            self.0.receiver_exists.get()
        }

        fn push(&self, intra_message: Self::Payload) {
            debug_assert!(self.receiver_exists(), "all receivers closed for stack channel");

            let message_type = match intra_message.ty {
                IntraMessageType::Command(m, buffer) => {
                    let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                    IntraMessageType::Command(m, unsafe_buffer)
                }
                IntraMessageType::Acl(buffer) => {
                    let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                    IntraMessageType::Acl(unsafe_buffer)
                }
                IntraMessageType::Sco(buffer) => {
                    let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                    IntraMessageType::Sco(unsafe_buffer)
                }
                IntraMessageType::Iso(buffer) => {
                    let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                    IntraMessageType::Iso(unsafe_buffer)
                }
                IntraMessageType::Event(ed) => IntraMessageType::Event(ed),
                IntraMessageType::Disconnect(r) => IntraMessageType::Disconnect(r),
                IntraMessageType::Connection($channel_ends) => $channel_ends_convert,
            };

            self.0
                .message_queue
                .borrow_mut()
                .try_push(message_type.into())
                .unwrap();
        }
    };
}

/// The sender part of a stack allocated channel
///
/// This implements `Sender` for sending messages to the receiver of its channel.
#[derive(Clone)]
pub struct LocalStackChannelSender<const CHANNEL_SIZE: usize, C, B, T>(C)
where
    C: Deref<Target = LocalStackChannel<CHANNEL_SIZE, B, T>>;

impl<const CHANNEL_SIZE: usize, C, B, T> LocalStackChannelSender<CHANNEL_SIZE, C, B, T>
where
    C: Deref<Target = LocalStackChannel<CHANNEL_SIZE, B, T>>,
{
    fn new(channel: C) -> Self {
        channel.sender_count.set(channel.sender_count.get() + 1);

        Self(channel)
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >
{
    impl_local_queue_buffer!(
        FromIntraMessage<
            StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>,
            ChannelEnds<'z, B, TASK_COUNT, CHANNEL_SIZE>,
        >
    );
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBufferSend
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >
where
    B: Sized,
{
    fn is_full(&self) -> bool {
        self.0.message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.receiver_exists.get()
    }

    fn push(&self, intra_message: Self::Payload) {
        debug_assert!(self.receiver_exists(), "all receivers closed for stack channel");

        let message_type = match intra_message.ty {
            IntraMessageType::Command(m, buffer) => {
                let unsafe_buffer = UnsafeStackFromBuffer::from(buffer);

                IntraMessageType::Command(m, unsafe_buffer)
            }
            IntraMessageType::Acl(buffer) => {
                let unsafe_buffer = UnsafeStackFromBuffer::from(buffer);

                IntraMessageType::Acl(unsafe_buffer)
            }
            IntraMessageType::Sco(buffer) => {
                let unsafe_buffer = UnsafeStackFromBuffer::from(buffer);

                IntraMessageType::Sco(unsafe_buffer)
            }
            IntraMessageType::Iso(buffer) => {
                let unsafe_buffer = UnsafeStackFromBuffer::from(buffer);

                IntraMessageType::Iso(unsafe_buffer)
            }
            IntraMessageType::Event(ed) => IntraMessageType::Event(ed),
            IntraMessageType::Disconnect(r) => IntraMessageType::Disconnect(r),
            IntraMessageType::Connection(channel_ends) => {
                let message = unsafe { UnsafeChannelEnds::from(channel_ends) };

                IntraMessageType::Connection(message)
            }
        };

        self.0.message_queue.borrow_mut().try_push(message_type.into()).unwrap();
    }
}

impl<'z, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
{
    impl_local_queue_buffer!(ToIntraMessage<BufferReservation<'z, B, CHANNEL_SIZE>>);
}

impl<'z, const CHANNEL_SIZE: usize, B> LocalQueueBufferSend
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Sized,
{
    fn is_full(&self) -> bool {
        self.0.message_queue.borrow().is_full()
    }

    fn receiver_exists(&self) -> bool {
        self.0.receiver_exists.get()
    }

    fn push(&self, intra_message: Self::Payload) {
        debug_assert!(self.receiver_exists(), "all receivers closed for stack channel");

        let message_type = match intra_message.ty {
            IntraMessageType::Command(m, buffer) => {
                let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                IntraMessageType::Command(m, unsafe_buffer)
            }
            IntraMessageType::Acl(buffer) => {
                let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                IntraMessageType::Acl(unsafe_buffer)
            }
            IntraMessageType::Sco(buffer) => {
                let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                IntraMessageType::Sco(unsafe_buffer)
            }
            IntraMessageType::Iso(buffer) => {
                let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                IntraMessageType::Iso(unsafe_buffer)
            }
            IntraMessageType::Event(ed) => IntraMessageType::Event(ed),
            IntraMessageType::Disconnect(r) => IntraMessageType::Disconnect(r),
            IntraMessageType::Connection(_) => IntraMessageType::Connection(()),
        };

        self.0.message_queue.borrow_mut().try_push(message_type.into()).unwrap();
    }
}

macro_rules! impl_sender {
    ($message_ty:ty) => {
        type Error = LocalSendFutureError;
        type Message = $message_ty;
        type SendFuture<'a> = LocalSendFuture<'a, Self, $message_ty> where Self: 'a;

        fn send(&self, message: Self::Message) -> Self::SendFuture<'_> {
            LocalSendFuture {
                packet: Some(message),
                local_sender: self,
            }
        }
    };
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> Sender
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >
where
    B: Unpin,
{
    impl_sender!(
        FromIntraMessage<
            StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>,
            ChannelEnds<'z, B, TASK_COUNT, CHANNEL_SIZE>,
        >
    );
}

impl<'z, const CHANNEL_SIZE: usize, B> Sender
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Unpin,
{
    impl_sender!(ToIntraMessage<BufferReservation<'z, B, CHANNEL_SIZE>>);
}

impl<const CHANNEL_SIZE: usize, C, B, T> Drop for LocalStackChannelSender<CHANNEL_SIZE, C, B, T>
where
    C: Deref<Target = LocalStackChannel<CHANNEL_SIZE, B, T>>,
{
    fn drop(&mut self) {
        self.0.sender_count.set(self.0.sender_count.get() - 1);

        if self.0.sender_count.get() == 0 {
            self.0.waker.take().map(|waker| waker.wake());
        }
    }
}

/// A receiver of a message of a `LocalStackChannel`
pub struct LocalStackChannelReceiver<const CHANNEL_SIZE: usize, C, B, T>(C)
where
    C: Deref<Target = LocalStackChannel<CHANNEL_SIZE, B, T>>;

impl<const CHANNEL_SIZE: usize, C, B, T> LocalStackChannelReceiver<CHANNEL_SIZE, C, B, T>
where
    C: Deref<Target = LocalStackChannel<CHANNEL_SIZE, B, T>>,
{
    fn new(c: C) -> Self {
        c.receiver_exists.set(true);

        Self(c)
    }

    /// Forget `self` and return `C`
    ///
    /// This is unsafe as "normally" a field cannot be moved out of a type that implements `Drop`,
    /// but here the intention is to not run `Drop` and return `C`.
    unsafe fn forget_and_unwrap(mut self) -> C {
        let c = core::mem::replace(&mut self.0, core::mem::MaybeUninit::uninit().assume_init());

        core::mem::forget(self);

        c
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >
{
    impl_local_queue_buffer!(
        FromIntraMessage<
            StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>,
            ChannelEnds<'z, B, TASK_COUNT, CHANNEL_SIZE>,
        >
    );
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBufferReceive
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >
where
    B: Sized,
{
    fn has_senders(&self) -> bool {
        self.0.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        let intra_message = self.0.message_queue.borrow_mut().try_remove().unwrap();

        match intra_message.ty {
            IntraMessageType::Command(m, unsafe_buffer) => {
                let buffer = UnsafeStackFromBuffer::into::<'z>(unsafe_buffer);

                IntraMessageType::Command(m, buffer)
            }
            IntraMessageType::Acl(unsafe_buffer) => {
                let buffer = UnsafeStackFromBuffer::into::<'z>(unsafe_buffer);

                IntraMessageType::Acl(buffer)
            }
            IntraMessageType::Sco(unsafe_buffer) => {
                let buffer = UnsafeStackFromBuffer::into::<'z>(unsafe_buffer);

                IntraMessageType::Sco(buffer)
            }
            IntraMessageType::Iso(unsafe_buffer) => {
                let buffer = UnsafeStackFromBuffer::into::<'z>(unsafe_buffer);

                IntraMessageType::Iso(buffer)
            }
            IntraMessageType::Event(ed) => IntraMessageType::Event(ed),
            IntraMessageType::Disconnect(r) => IntraMessageType::Disconnect(r),
            IntraMessageType::Connection(unsafe_channel_ends) => {
                let channel_ends = unsafe { UnsafeChannelEnds::into::<'z>(unsafe_channel_ends) };

                IntraMessageType::Connection(channel_ends)
            }
        }
        .into()
    }
}

impl<'z, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
{
    impl_local_queue_buffer!(ToIntraMessage<BufferReservation<'z, B, CHANNEL_SIZE>>);
}

impl<'z, const CHANNEL_SIZE: usize, B> LocalQueueBufferReceive
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Sized,
{
    fn has_senders(&self) -> bool {
        self.0.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.message_queue.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        let intra_message = self.0.message_queue.borrow_mut().try_remove().unwrap();

        match intra_message.ty {
            IntraMessageType::Command(m, unsafe_buffer) => {
                let buffer = unsafe { UnsafeBufferReservation::rebind(unsafe_buffer) };

                IntraMessageType::Command(m, buffer)
            }
            IntraMessageType::Acl(unsafe_buffer) => {
                let buffer = unsafe { UnsafeBufferReservation::rebind(unsafe_buffer) };

                IntraMessageType::Acl(buffer)
            }
            IntraMessageType::Sco(unsafe_buffer) => {
                let buffer = unsafe { UnsafeBufferReservation::rebind(unsafe_buffer) };

                IntraMessageType::Sco(buffer)
            }
            IntraMessageType::Iso(unsafe_buffer) => {
                let buffer = unsafe { UnsafeBufferReservation::rebind(unsafe_buffer) };

                IntraMessageType::Iso(buffer)
            }
            IntraMessageType::Event(ed) => IntraMessageType::Event(ed),
            IntraMessageType::Disconnect(r) => IntraMessageType::Disconnect(r),
            IntraMessageType::Connection(_) => IntraMessageType::Connection(()),
        }
        .into()
    }
}

macro_rules! impl_receiver {
    ($message_ty: ty) => {
        type Message = $message_ty;
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

        fn recv(&self) -> Self::ReceiveFuture<'_> {
            LocalReceiverFuture(self)
        }
    };
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> Receiver
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >
where
    B: Unpin,
{
    impl_receiver!(
        FromIntraMessage<
            StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>,
            ChannelEnds<'z, B, TASK_COUNT, CHANNEL_SIZE>,
        >
    );
}

impl<'z, const CHANNEL_SIZE: usize, B> Receiver
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Unpin,
{
    impl_receiver!(ToIntraMessage<BufferReservation<'z, B, CHANNEL_SIZE>>);
}

impl<const CHANNEL_SIZE: usize, C, B, T> Drop for LocalStackChannelReceiver<CHANNEL_SIZE, C, B, T>
where
    C: Deref<Target = LocalStackChannel<CHANNEL_SIZE, B, T>>,
{
    fn drop(&mut self) {
        self.0.receiver_exists.set(false);
        self.0.message_queue.borrow_mut().empty()
    }
}

/// The buffer type for messages from the Interface
// note:
// the field order matters here as the `unsafe_buffer`
// field must drop before the field `reservation`.
pub struct StackFromBuffer<'z, B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> {
    unsafe_buffer: UnsafeBufferReservation<B, CHANNEL_SIZE>,
    channel_reservation: Reservation<
        'z,
        LocalStackChannel<
            CHANNEL_SIZE,
            B,
            FromIntraMessage<
                UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
            >,
        >,
        TASK_COUNT,
    >,
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> crate::hci::Buffer
    for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: crate::hci::Buffer,
{
    fn with_capacity(_front: usize, _back: usize) -> Self
    where
        Self: Sized,
    {
        panic!("with_capacity cannot be called on a reserved buffer");
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        self.unsafe_buffer.clear_with_capacity(front, back)
    }
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> Deref for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.unsafe_buffer.deref()
    }
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> core::ops::DerefMut
    for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: core::ops::DerefMut<Target = [u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.unsafe_buffer.deref_mut()
    }
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> crate::TryExtend<u8>
    for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: crate::TryExtend<u8>,
{
    type Error = B::Error;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = u8>,
    {
        self.unsafe_buffer.try_extend(iter)
    }
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> crate::TryRemove<u8>
    for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: crate::TryRemove<u8>,
{
    type Error = B::Error;
    type RemoveIter<'a> = B::RemoveIter<'a> where Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.unsafe_buffer.try_remove(how_many)
    }
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> crate::TryFrontExtend<u8>
    for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: crate::TryFrontExtend<u8>,
{
    type Error = B::Error;

    fn try_front_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = u8>,
    {
        self.unsafe_buffer.try_front_extend(iter)
    }
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> crate::TryFrontRemove<u8>
    for StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: crate::TryFrontRemove<u8>,
{
    type Error = B::Error;
    type FrontRemoveIter<'a> = B::FrontRemoveIter<'a> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.unsafe_buffer.try_front_remove(how_many)
    }
}

pub struct UnsafeStackFromBuffer<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> {
    unsafe_buffer: UnsafeBufferReservation<B, CHANNEL_SIZE>,
    unsafe_channel_reservation: UnsafeReservation<
        LocalStackChannel<
            CHANNEL_SIZE,
            B,
            FromIntraMessage<
                UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
            >,
        >,
        TASK_COUNT,
    >,
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE> {
    fn into<'z>(self) -> StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE> {
        let unsafe_buffer = self.unsafe_buffer;

        let channel_reservation = unsafe { UnsafeReservation::rebind(self.unsafe_channel_reservation) };

        StackFromBuffer {
            unsafe_buffer,
            channel_reservation,
        }
    }

    fn from(buffer: StackFromBuffer<'_, B, TASK_COUNT, CHANNEL_SIZE>) -> Self {
        let unsafe_buffer = buffer.unsafe_buffer;

        let unsafe_channel_reservation = unsafe { Reservation::to_unsafe(buffer.channel_reservation) };

        UnsafeStackFromBuffer {
            unsafe_buffer,
            unsafe_channel_reservation,
        }
    }
}

/// Take buffer for `LocalStackChannel`
///
/// This the type used as the `TakeBuffer` in the implementation of `BufferReserve` for
/// `LocalStackChannel`.
pub struct LocalStackTakeBuffer<C> {
    channel: C,
    front_capacity: usize,
}

impl<C> LocalStackTakeBuffer<C> {
    fn new(channel: C, front_capacity: usize) -> Self {
        Self {
            channel,
            front_capacity,
        }
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> core::future::Future
    for LocalStackTakeBuffer<
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
    >
where
    B: crate::hci::Buffer + 'z,
{
    type Output = StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this.channel.buffer_reserve.take_buffer(this.front_capacity) {
            Some(buffer) => {
                let unsafe_buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                let channel_reservation = this.channel.clone();

                let stack_from_buffer = StackFromBuffer {
                    unsafe_buffer,
                    channel_reservation,
                };

                Poll::Ready(stack_from_buffer)
            }
            None => {
                this.channel.buffer_reserve.set_waker(cx.waker());

                Poll::Pending
            }
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T> core::future::Future
    for LocalStackTakeBuffer<&'z LocalStackChannel<CHANNEL_SIZE, B, T>>
where
    B: crate::hci::Buffer + 'z,
    T: Unpin,
{
    type Output = BufferReservation<'z, B, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this.channel.buffer_reserve.take_buffer(this.front_capacity) {
            Some(buffer) => Poll::Ready(buffer),
            None => {
                this.channel.buffer_reserve.set_waker(cx.waker());

                Poll::Pending
            }
        }
    }
}

/// The `ToChannel` type for [`LocalStackChannelReserve`]
///
/// This is the type used as the channel for sending messages *to* the interface async task.
///
/// # Safety
/// This type uses an `UnsafeBufferReservation` as the reservation for the buffers are
/// self-referential within the channel's message queue. A `LocalStackChannel` is made safe to use
/// by having the sender and receiver implementations of the channel take references to it and all
/// messages within the channel queue are dropped when the receiver is dropped.
type ToChannelType<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> = LocalStackChannel<
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    ToIntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
>;

/// The `FromChannel` type for [`LocalStackChannelReserve`]
///
/// This is the type used as the channel for sending messages *from* the interface async task.
///
/// # Safety
/// This type uses both an [`UnsafeBufferReservation`] and an [`UnsafeStackChannelEnds`]. These
/// types are required as their safe equivalents [`BufferReservation`] and [`StackChannelEnds`]
/// (respectively) both have lifetimes which causes a self-reference issue. These lifetimes are for
/// the `LocalStackChannelReserveData` which holds the stack-allocated data for these types, part of
/// which is used for the queue for the async task message channels. So lifetime-less unsafe structs
/// must be used within these queues as otherwise it creates a compiler error inducing
/// self-referential structure.
///
/// These unsafe types are safe to use so long as the `LocalStackChannelReserveData` they are
/// self-referential to is guaranteed to not be moved while they exist. This is achieved by making
/// sure that a `LocalStackChannelReserve` and all channels are created from a reference to a
/// `LocalStackChannelReserveData`. Whenever a channel's receiver is dropped, then all messages
/// within the channel queue are also dropped, so this guarantees that there will be no unsafe
/// types within the reserve data before rust will allow it to be moved.  
type FromChannelType<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> = LocalStackChannel<
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    FromIntraMessage<
        UnsafeStackFromBuffer<DeLinearBuffer<BUFFER_SIZE, u8>, TASK_COUNT, CHANNEL_SIZE>,
        UnsafeChannelEnds<DeLinearBuffer<BUFFER_SIZE, u8>, TASK_COUNT, CHANNEL_SIZE>,
    >,
>;

struct TaskData<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    channel: Reservation<'a, FromChannelType<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    task_id: TaskId,
    flow_ctrl_id: FlowControlId,
}

/// Ends of channel for a connection async task
pub struct ChannelEnds<'z, B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> {
    sender_channel: &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
    receiver: LocalStackChannelReceiver<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >,
}

pub type ChannelEndsType<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    ChannelEnds<'z, DeLinearBuffer<BUFFER_SIZE, u8>, TASK_COUNT, CHANNEL_SIZE>;

impl<'z, B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> ChannelEndsTrait
    for ChannelEnds<'z, B, TASK_COUNT, CHANNEL_SIZE>
where
    B: crate::hci::Buffer + 'z,
{
    type ToBuffer = BufferReservation<'z, B, CHANNEL_SIZE>;

    type FromBuffer = StackFromBuffer<'z, B, TASK_COUNT, CHANNEL_SIZE>;

    type TakeBuffer = LocalStackTakeBuffer<
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
    >;

    type Sender = LocalStackChannelSender<
        CHANNEL_SIZE,
        &'z LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >;

    type Receiver = LocalStackChannelReceiver<
        CHANNEL_SIZE,
        Reservation<
            'z,
            LocalStackChannel<
                CHANNEL_SIZE,
                B,
                FromIntraMessage<
                    UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
                    UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
                >,
            >,
            TASK_COUNT,
        >,
        B,
        FromIntraMessage<
            UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>,
            UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE>,
        >,
    >;

    fn get_sender(&self) -> Self::Sender {
        self.sender_channel.get_sender()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.sender_channel.take(front_capacity)
    }

    fn get_receiver(&self) -> &Self::Receiver {
        &self.receiver
    }

    fn get_mut_receiver(&mut self) -> &mut Self::Receiver {
        &mut self.receiver
    }
}

/// Unsafe `StackChannelEnds`
///
/// Because `StackChannelEnds` contains a lifetime, it cannot be part of the type
/// `LocalStackChannelReserveData` as it would be self-referential. An `UnsafeStackChannelEnds` is
/// used as the intermediary
pub struct UnsafeChannelEnds<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> {
    sender_channel: *const LocalStackChannel<CHANNEL_SIZE, B, ToIntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
    unsafe_receive_channel: UnsafeReservation<
        LocalStackChannel<CHANNEL_SIZE, B, FromIntraMessage<UnsafeStackFromBuffer<B, TASK_COUNT, CHANNEL_SIZE>, Self>>,
        TASK_COUNT,
    >,
}

impl<B, const TASK_COUNT: usize, const CHANNEL_SIZE: usize> UnsafeChannelEnds<B, TASK_COUNT, CHANNEL_SIZE> {
    unsafe fn from(ends: ChannelEnds<'_, B, TASK_COUNT, CHANNEL_SIZE>) -> Self {
        let sender_channel = ends.sender_channel as *const _;

        let reservation: Reservation<'_, _, TASK_COUNT> = ends.receiver.forget_and_unwrap();

        let unsafe_receive_channel = Reservation::to_unsafe(reservation);

        UnsafeChannelEnds {
            sender_channel,
            unsafe_receive_channel,
        }
    }

    unsafe fn into<'a>(self) -> ChannelEnds<'a, B, TASK_COUNT, CHANNEL_SIZE> {
        let receiver_reservation = UnsafeReservation::rebind(self.unsafe_receive_channel);

        // new is deliberately not called to create the receiver.
        // This method is intended to act like a 'rebuilding' of a
        // StackChannelEnds, not the creation a 'new' StackChannelEnds.
        let receiver = LocalStackChannelReceiver(receiver_reservation);

        let sender_channel = self.sender_channel.as_ref().unwrap();

        ChannelEnds {
            sender_channel,
            receiver,
        }
    }
}

/// [`LocalStackChannelReserve`] data
///
/// This is the data that is allocating on the stack for a LocalStackChannelReserve. The main
/// purpose of a `LocalStackChannelReserveData` is to not hold the data, but to give the
/// [`LocalStackChannelReserve`] something to refer to. This is a limitation of a `StackHotel` as it
/// needs something to put a lifetime to when taking a reservation, and a reserve is made up of
/// multiple `StackHotels`.
pub struct LocalStackChannelReserveData<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    from_channels: StackHotel<FromChannelType<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    cmd_channel: ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    acl_channel: ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    sco_channel: ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    le_acl_channel: ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    le_iso_channel: ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserveData`
    pub fn new() -> Self {
        let to_channels = StackHotel::new();
        let cmd_channel = ToChannelType::new();
        let acl_channel = ToChannelType::new();
        let sco_channel = ToChannelType::new();
        let le_acl_channel = ToChannelType::new();
        let le_iso_channel = ToChannelType::new();

        Self {
            from_channels: to_channels,
            cmd_channel,
            acl_channel,
            sco_channel,
            le_acl_channel,
            le_iso_channel,
        }
    }
}

/// A reserve of static channels for local communication
///
/// These are channels that are buffered through static allocation instead of dynamic allocation.
/// This means both the maximum number of channels and the size of the buffers of each channel must
/// be known at compile time and fully be allocated at runtime (static memory structures cannot
/// "grow" to their maximum size). `LocalStackChannels` is intended to be used only where dynamic
/// allocation is not possible.
pub struct LocalStackChannelReserve<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    data: &'a LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    task_data: RefCell<LinearBuffer<TASK_COUNT, TaskData<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>>,
    flow_ctrl_receiver: FlowCtrlReceiver<
        LocalStackChannelReceiver<
            CHANNEL_SIZE,
            &'a ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
            DeLinearBuffer<BUFFER_SIZE, u8>,
            ToIntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
        >,
    >,
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserve<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserve`
    ///
    /// This creates a new `LocalStackChannelReserve` from the provided `rx_channel` and
    /// `tx_channel`. While these objects may be put on the heap, the references are expected to be
    /// of stack allocated types. Otherwise using a
    /// [`LocalChannelManager`](super::LocalChannelManager) is preferred.
    pub fn new(data: &'a LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>) -> Self {
        let task_data = RefCell::new(LinearBuffer::new());

        let receivers = InterfaceReceivers {
            cmd_receiver: LocalStackChannelReceiver(&data.cmd_channel),
            acl_receiver: LocalStackChannelReceiver(&data.cmd_channel),
            sco_receiver: LocalStackChannelReceiver(&data.cmd_channel),
            le_acl_receiver: LocalStackChannelReceiver(&data.cmd_channel),
            le_iso_receiver: LocalStackChannelReceiver(&data.cmd_channel),
        };

        let flow_ctrl_receiver = FlowCtrlReceiver::new(receivers);

        Self {
            data,
            task_data,
            flow_ctrl_receiver,
        }
    }
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelReserve
    for LocalStackChannelReserve<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Error = LocalStackChannelsError;

    type SenderError = LocalSendFutureError;

    type TryExtendError = LinearBufferError;

    type ToBuffer = StackFromBuffer<'z, DeLinearBuffer<BUFFER_SIZE, u8>, TASK_COUNT, CHANNEL_SIZE>;

    type ToChannel = Reservation<'z, FromChannelType<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>;

    type FromBuffer = BufferReservation<'z, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type FromChannel = &'z ToChannelType<CHANNEL_SIZE, BUFFER_SIZE>;

    type TaskChannelEnds = ChannelEnds<'z, DeLinearBuffer<BUFFER_SIZE, u8>, TASK_COUNT, CHANNEL_SIZE>;

    fn try_remove(&mut self, id: TaskId) -> Result<(), Self::Error> {
        if let Ok(at) = self
            .task_data
            .get_mut()
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
        {
            self.task_data
                .get_mut()
                .try_remove(at)
                .map(|_| ())
                .map_err(|_| unreachable!())
        } else {
            Err(LocalStackChannelsError::ChannelForIdDoesNotExist)
        }
    }

    fn add_new_task(&self, task_id: TaskId, flow_ctrl_id: FlowControlId) -> Result<Self::TaskChannelEnds, Self::Error> {
        use core::ops::Deref;

        let insertion_index = self
            .task_data
            .borrow()
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&task_id))
            .expect_err("task id already associated to another async task");

        let new_channel = self
            .data
            .from_channels
            .take(LocalStackChannel::new())
            .ok_or(LocalStackChannelsError::TaskCountReached)?;

        let new_channel_clone = new_channel.clone();

        let new_task_data = TaskData {
            channel: new_channel,
            task_id,
            flow_ctrl_id,
        };

        self.task_data
            .borrow_mut()
            .try_insert(new_task_data, insertion_index)
            .map_err(|_| LocalStackChannelsError::TaskCountReached)?;

        let receiver = LocalStackChannelReceiver(new_channel_clone);

        let sender_channel = match flow_ctrl_id {
            FlowControlId::Cmd => &self.data.cmd_channel,
            FlowControlId::Acl => &self.data.acl_channel,
            FlowControlId::Sco => &self.data.sco_channel,
            FlowControlId::LeAcl => &self.data.le_acl_channel,
            FlowControlId::LeIso => &self.data.le_iso_channel,
        };

        Ok(ChannelEnds {
            sender_channel,
            receiver,
        })
    }

    fn get(&self, id: TaskId) -> Option<Self::ToChannel> {
        use core::ops::Deref;

        let ref_task_data = self.task_data.borrow();

        ref_task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .and_then(|index| ref_task_data.get(index))
            .map(|TaskData { channel, .. }| channel.clone())
    }

    fn get_flow_control_id(&self, id: TaskId) -> Option<FlowControlId> {
        let ref_task_data = self.task_data.borrow();

        ref_task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .and_then(|index| ref_task_data.get(index))
            .map(|TaskData { flow_ctrl_id, .. }| *flow_ctrl_id)
    }

    fn get_flow_ctrl_receiver(&mut self) -> &mut FlowCtrlReceiver<<Self::FromChannel as Channel>::Receiver> {
        &mut self.flow_ctrl_receiver
    }
}

#[derive(Debug)]
pub enum LocalStackChannelsError {
    TaskCountReached,
    ChannelIdAlreadyUsed,
    ChannelForIdDoesNotExist,
}

impl Display for LocalStackChannelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalStackChannelsError::TaskCountReached => f.write_str("reached maximum channel count"),
            LocalStackChannelsError::ChannelIdAlreadyUsed => f.write_str("id already used"),
            LocalStackChannelsError::ChannelForIdDoesNotExist => {
                f.write_str("no channel is associated with the provided id")
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::*;

    #[test]
    fn local_static_init_usize() {
        let _: LocalStackChannel<20, usize> = LocalStackChannel::new();
    }

    #[test]
    fn local_static_init_ref_mut_usize() {
        let _: LocalStackChannel<20, &mut usize> = LocalStackChannel::new();
    }

    #[tokio::test]
    async fn local_static_add_remove_usize() {
        let ls: LocalStackChannel<5, HciPacket<usize>> = LocalStackChannel::new();

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        generic_send_and_receive(&ls, &test_vals).await
    }

    #[tokio::test]
    async fn local_static_add_remove_usize_single_capacity() {
        let ls: LocalStackChannel<1, HciPacket<usize>> = LocalStackChannel::new();

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        generic_send_and_receive(&ls, &test_vals).await
    }

    #[tokio::test]
    async fn local_static_add_remove_byte_slice() {
        let l: LocalStackChannel<4, HciPacket<&[u8]>> = LocalStackChannel::new();

        let test_vals: &[&[u8]] = &[
            "Hello world".as_bytes(),
            "Where were we last night".as_bytes(),
            "3y2j`kl4hjlhbavucoxy78gy3u2k14hg5 431".as_bytes(),
            "4hbn2341bjkl4j".as_bytes(),
            "more spam".as_bytes(),
            "even more spam".as_bytes(),
            "this is a test of the boring alert system".as_bytes(),
            "who asked for your opinion on my test data?".as_bytes(),
        ];

        generic_send_and_receive(&l, test_vals).await
    }

    #[tokio::test]
    async fn local_add_remove_array() {
        const SIZE: usize = 20;

        let l: LocalStackChannel<4, HciPacket<[usize; SIZE]>> = LocalStackChannel::new();

        let test_vals: &[[usize; SIZE]] = &[
            [0; SIZE], [1; SIZE], [2; SIZE], [3; SIZE], [4; SIZE], [5; SIZE], [6; SIZE], [7; SIZE], [8; SIZE],
            [9; SIZE],
        ];

        generic_send_and_receive(&l, test_vals).await
    }
}
