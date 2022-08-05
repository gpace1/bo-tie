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
use crate::hci::interface::local_channel::local_stack_channel::stack_buffers::{Reservation, UnsafeBufferReservation};
use crate::hci::interface::{
    Channel, ChannelEnds, ChannelReserve, FlowControl, FlowControlId, FlowCtrlReceiver, GetPrepareSend,
    InterfaceReceivers, IntraMessage, Receiver, Sender, TaskId,
};
use crate::hci::BufferReserve;
use core::cell::{Cell, Ref, RefCell};
use core::fmt::{Display, Formatter};
use core::ops::Deref;
use core::task::{Context, Poll, Waker};
use stack_buffers::{BufferReservation, DeLinearBuffer, LinearBuffer, LinearBufferError, QueueBuffer, StackHotel};

mod stack_buffers;

/// A wrapper around a reference to a reservation
///
/// The point of this wrapper is to implement `Deref` to the type that the `Reservation` can
/// dereference to.
pub struct RefReservation<'a, 'z, T, const SIZE: usize>(&'a Reservation<'z, T, SIZE>);

impl<T, const SIZE: usize> Deref for RefReservation<'_, '_, T, SIZE> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

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
    ($($methods:tt)*) => {
        type SenderError = LocalSendFutureError;
        type Message = IntraMessage<BufferReservation<'a, B, CHANNEL_SIZE>>;
        type Sender =
            LocalStackChannelSender<CHANNEL_SIZE, Self, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>;
        type Receiver =
            LocalStackChannelReceiver<CHANNEL_SIZE, Self, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>;

        $($methods)*
    };
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> Channel
    for RefReservation<
        'a,
        '_,
        LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        TASK_COUNT,
    >
where
    B: Unpin,
{
    impl_channel! {
        fn get_sender(&self) -> Self::Sender {
            LocalStackChannelSender::new(RefReservation(self.0))
        }

        fn take_receiver(&self) -> Option<Self::Receiver> {
            Some(LocalStackChannelReceiver::new(RefReservation(self.0)))
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, B> Channel
    for &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>
where
    B: Unpin,
{
    impl_channel! {
        fn get_sender(&self) -> Self::Sender {
            LocalStackChannelSender::new(*self)
        }

        fn take_receiver(&self) -> Option<Self::Receiver> {
            Some(LocalStackChannelReceiver::new(*self))
        }
    }
}

macro_rules! impl_buffer_reserve {
    ($($impl_take:tt)*) => {
        type Buffer = BufferReservation<'a, B, CHANNEL_SIZE>;
        type TakeBuffer = LocalStackTakeBuffer<Self>;

        $($impl_take)*

        fn reclaim(&mut self, _: Self::Buffer) {}
    };
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> BufferReserve
    for RefReservation<'a, '_, LocalStackChannel<CHANNEL_SIZE, B, T>, TASK_COUNT>
where
    B: crate::hci::Buffer + 'a,
    T: Unpin,
{
    impl_buffer_reserve! {
        fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
        where
            S: Into<Option<usize>>,
        {
            LocalStackTakeBuffer::new(RefReservation(self.0), front_capacity.into().unwrap_or_default())
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> BufferReserve for &'a LocalStackChannel<CHANNEL_SIZE, B, T>
where
    B: crate::hci::Buffer + 'a,
    T: Unpin,
{
    impl_buffer_reserve! {
        fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
        where
            S: Into<Option<usize>>,
        {
            LocalStackTakeBuffer::new(*self, front_capacity.into().unwrap_or_default())
        }
    }
}

macro_rules! impl_local_queue_buffer {
    () => {
        type Payload = IntraMessage<BufferReservation<'a, B, CHANNEL_SIZE>>;

        fn call_waker(&self) {
            self.0.waker.take().map(|w| w.wake());
        }

        fn set_waker(&self, waker: Waker) {
            self.0.waker.set(Some(waker))
        }
    };
}

macro_rules! impl_local_queue_buffer_send {
    () => {
        fn is_full(&self) -> bool {
            self.0.message_queue.borrow().is_full()
        }

        fn receiver_exists(&self) -> bool {
            self.0.receiver_exists.get()
        }

        fn push(&self, intra_message: Self::Payload) {
            debug_assert!(self.receiver_exists(), "all receivers closed for stack channel");

            self.0
                .message_queue
                .borrow_mut()
                .try_push(
                    intra_message.map(|buffer_reservation| unsafe { BufferReservation::to_unsafe(buffer_reservation) }),
                )
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

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        RefReservation<
            'a,
            '_,
            LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
            TASK_COUNT,
        >,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
{
    impl_local_queue_buffer!();
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBufferSend
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        RefReservation<
            'a,
            '_,
            LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
            TASK_COUNT,
        >,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Sized,
{
    impl_local_queue_buffer_send!();
}

impl<'a, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
{
    impl_local_queue_buffer!();
}

impl<'a, const CHANNEL_SIZE: usize, B> LocalQueueBufferSend
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Sized,
{
    impl_local_queue_buffer_send!();
}

macro_rules! impl_sender {
    ($lif:lifetime) => {
        type Error = LocalSendFutureError;
        type Message = IntraMessage<BufferReservation<'a, B, CHANNEL_SIZE>>;
        type SendFuture<'z> = LocalSendFuture<'z, Self, IntraMessage<BufferReservation<$lif, B, CHANNEL_SIZE>>> where Self: 'z;

        fn send(&self, message: Self::Message) -> Self::SendFuture<'_> {
            LocalSendFuture {
                packet: Some(message),
                local_sender: self,
            }
        }
    };
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> Sender
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        RefReservation<
            'a,
            '_,
            LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
            TASK_COUNT,
        >,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Unpin,
{
    impl_sender!('a);
}

impl<'a, const CHANNEL_SIZE: usize, B> Sender
    for LocalStackChannelSender<
        CHANNEL_SIZE,
        &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Unpin,
{
    impl_sender!('a);
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

macro_rules! impl_local_queue_buffer_receive {
    () => {
        fn has_senders(&self) -> bool {
            self.0.sender_count.get() != 0
        }

        fn is_empty(&self) -> bool {
            self.0.message_queue.borrow().is_empty()
        }

        fn pop_next(&self) -> Self::Payload {
            self.0
                .message_queue
                .borrow_mut()
                .try_remove()
                .unwrap()
                .map(|u_buffer_reservation| unsafe {
                    // This is rebound to lifetime 'a
                    UnsafeBufferReservation::rebind(u_buffer_reservation)
                })
        }
    };
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
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        RefReservation<
            'a,
            '_,
            LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
            TASK_COUNT,
        >,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
{
    impl_local_queue_buffer!();
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> LocalQueueBufferReceive
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        RefReservation<
            'a,
            '_,
            LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
            TASK_COUNT,
        >,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Sized,
{
    impl_local_queue_buffer_receive!();
}

impl<'a, const CHANNEL_SIZE: usize, B> LocalQueueBuffer
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
{
    impl_local_queue_buffer!();
}

impl<'a, const CHANNEL_SIZE: usize, B> LocalQueueBufferReceive
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Sized,
{
    impl_local_queue_buffer_receive!();
}

macro_rules! impl_receiver {
    () => {
        type Message = IntraMessage<BufferReservation<'a, B, CHANNEL_SIZE>>;
        type ReceiveFuture<'z> = LocalReceiverFuture<'z, Self> where Self: 'z;

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

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B> Receiver
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        RefReservation<
            'a,
            '_,
            LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
            TASK_COUNT,
        >,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Unpin,
{
    impl_receiver!();
}

impl<'a, const CHANNEL_SIZE: usize, B> Receiver
    for LocalStackChannelReceiver<
        CHANNEL_SIZE,
        &'a LocalStackChannel<CHANNEL_SIZE, B, IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>>,
        B,
        IntraMessage<UnsafeBufferReservation<B, CHANNEL_SIZE>>,
    >
where
    B: Unpin,
{
    impl_receiver!();
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

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> core::future::Future
    for LocalStackTakeBuffer<RefReservation<'a, '_, LocalStackChannel<CHANNEL_SIZE, B, T>, TASK_COUNT>>
where
    B: crate::hci::Buffer + 'a,
    T: Unpin,
{
    type Output = BufferReservation<'a, B, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let reservation: &'a Reservation<_, TASK_COUNT> = this.channel.0;

        let opt_buffer: Option<BufferReservation<'a, B, CHANNEL_SIZE>> =
            StackHotel::<B, CHANNEL_SIZE>::take_buffer(&reservation.buffer_reserve, this.front_capacity);

        match opt_buffer {
            Some(buffer) => Poll::Ready(buffer),
            None => {
                this.channel.buffer_reserve.set_waker(cx.waker());

                Poll::Pending
            }
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> core::future::Future
    for LocalStackTakeBuffer<&'a LocalStackChannel<CHANNEL_SIZE, B, T>>
where
    B: crate::hci::Buffer + 'a,
    T: Unpin,
{
    type Output = BufferReservation<'a, B, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let opt_buffer = StackHotel::<B, CHANNEL_SIZE>::take_buffer(&this.channel.buffer_reserve, this.front_capacity);

        match opt_buffer {
            Some(buffer) => Poll::Ready(buffer),
            None => {
                this.channel.buffer_reserve.set_waker(cx.waker());

                Poll::Pending
            }
        }
    }
}

/// The deref [`Channel`](crate::hci::interface::Channel) type for [`LocalStackChannelReserve`]
///
/// This is the non-generic type used for the channel types of the implementation of
/// [`ChannelReserve`](crate::hci::interface::ChannelReserve) for `LocalStackChannelReserve`. The
/// `ToChannel` and `FromChannel` can both be dereferenced to this type.
///
/// # Safety
/// An `UnsafeChannel` does contain `UnsafeBufferReservation`s. An `UnsafeBufferReservation` is
/// the same as a [`BufferReservation`](stack_buffers::BufferReservation) without any lifetime to
/// tie it to the [`StackHotel`](stack_buffers::StackHotel) that created it. It requires that user
/// guarantee that the `UnsafeBufferReservation` is dropped before the `StackHotel` is *moved*. The
/// user must make sure that a `UnsafeBufferReservation` must have all the same safety guarantees
/// around a `StackHotel` that the compiler provides for a `BufferReservation` or
/// [`Reservation`](stack_buffers::Reservation).
///
/// `UnsafeBufferReservation`s are used because it removes an extra indirection from a
/// `LocalStackChannel`. Without it there would need to be another structure to contain the messages
/// and it would have a lifetime back to the `LocalStackChannel` (because it hast the `StackHotel`).
/// This is cumbersome as the message queue is expected to be contained within a mpsc data
/// structure. However, in order to have the message queue as part of the channel
/// `UnsafeBufferReservation` is used as using a `BufferReservation` would create a
/// self-referential struct (which the rust compiler will not allow you to do).
///
/// ## Safety Requirements
/// A `LocalStackChannel` must have the same usage requirements with `UnsafeBufferReservation` as a
/// `BufferReservation` created from it's `buffer_reserve`. It cannot be moved (with the exception
/// of dropping) while any message exists within the field `message_queue` (of `LocalStackChannel`).
/// `message_queue` is a collection of the `UnsafeBufferReservation`s that link back to the
/// `StackHotel` `buffer_reserve` so if an `LocalStackChannel` is moved while any
/// `UnsafeBufferReservation`s exist for `buffer_reserve` UB will occur.
///
/// The requirements for safety are builtin, the user does not need to worry about them. The next
///
/// ## Safety Assurance
/// To make sure that a `ChannelType` is immovable while `message_queue` contains
/// `UnsafeBufferReservation`s, the trait `Channel` is only implemented for types that contain a
/// reference back to a `LocalStackChannel`. Consequently [`LocalStackChannelSender`] and
/// [`LocalStackChannelReceiver`] contain a reference back to the `LocalStackChannel`. These are the
/// sender and receiver types for the implementation of `Channel` for `LocalStackChannel`. Because
/// they contain a reference the compiler will ensure that the `LocalStackChannel` is immovable
/// while either of them exist.
///
/// In order to send a message, a `LocalStackChannelReceiver` and at least one
/// `LocalStackChannelSender` must exist. A `LocalStackChannelSender` will not add a message to the
/// `message_queue` if no receiver exists, and when a `LocalStackChannelReceiver` is dropped the
/// `message_queue` is emptied. The only time the message queue contains a message is when the
/// `LocalStackChannelReceiver` still exists, and because a `LocalStackChannelReceiver` contains a
/// reference to the `UnsafeChannel` the compiler will guarantee that the `LocalStackChannel` is not
/// moved. All this results in the compiler assuring that a `LocalStackChannel` will not move while
/// any message is in `message_queue`, thus making it a safe to use self referential structure.
type ChannelType<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> = LocalStackChannel<
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
>;

struct TaskData<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    channel: Reservation<'a, ChannelType<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    task_id: TaskId,
    flow_ctrl_id: FlowControlId,
}

/// Ends of channel for an async task
pub struct StackChannelEnds<'a, 'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    sender_channel: &'z ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    receiver: LocalStackChannelReceiver<
        CHANNEL_SIZE,
        RefReservation<'a, 'z, ChannelType<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        DeLinearBuffer<BUFFER_SIZE, u8>,
        IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
    >,
}

impl<'a, 'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelEnds
    for StackChannelEnds<'a, 'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type ToBuffer = BufferReservation<'z, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type TakeBuffer = LocalStackTakeBuffer<&'z ChannelType<CHANNEL_SIZE, BUFFER_SIZE>>;

    type Sender = LocalStackChannelSender<
        CHANNEL_SIZE,
        &'z ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
        DeLinearBuffer<BUFFER_SIZE, u8>,
        IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
    >;

    type Receiver = LocalStackChannelReceiver<
        CHANNEL_SIZE,
        RefReservation<'a, 'z, ChannelType<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        DeLinearBuffer<BUFFER_SIZE, u8>,
        IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
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

/// [`LocalStackChannelReserve`] data
///
/// This is the data that is allocating on the stack for a LocalStackChannelReserve. The main
/// purpose of a `LocalStackChannelReserveData` is to not hold the data, but to give the
/// [`LocalStackChannelReserve`] something to refer to. This is a limitation of a `StackHotel` as it
/// needs something to put a lifetime to when taking a reservation, and a reserve is made up of
/// multiple `StackHotels`.
pub struct LocalStackChannelReserveData<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    to_channels: StackHotel<ChannelType<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    cmd_channel: ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    acl_channel: ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    sco_channel: ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    le_acl_channel: ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
    le_iso_channel: ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserveData`
    fn new() -> Self {
        let to_channels = StackHotel::new();
        let cmd_channel = ChannelType::new();
        let acl_channel = ChannelType::new();
        let sco_channel = ChannelType::new();
        let le_acl_channel = ChannelType::new();
        let le_iso_channel = ChannelType::new();

        Self {
            to_channels,
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
    task_data: LinearBuffer<TASK_COUNT, TaskData<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>,
    flow_ctrl_receiver: FlowCtrlReceiver<
        LocalStackChannelReceiver<
            CHANNEL_SIZE,
            &'a ChannelType<CHANNEL_SIZE, BUFFER_SIZE>,
            DeLinearBuffer<BUFFER_SIZE, u8>,
            IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
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
        let task_data = LinearBuffer::new();

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

trait Foo {
    type SenderError;

    type MessageBuffer;

    type ToBuffer<'a>
    where
        Self: 'a;

    type Foo<'a>: BufferReserve<Buffer = Self::ToBuffer<'a>>
        + Channel<SenderError = Self::SenderError, Message = IntraMessage<Self::MessageBuffer>>
    where
        Self: 'a;

    fn get_foo(&self) -> Self::Foo<'_>;
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelReserve
    for LocalStackChannelReserve<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Error = LocalStackChannelsError;

    type SenderError = LocalSendFutureError;

    type TryExtendError = LinearBufferError;

    type ToBuffer<'a> = BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE> where Self: 'a ;

    type ToChannel<'a> = RefReservation<'a, 'z, ChannelType<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT> where Self: 'a;

    type FromBuffer = BufferReservation<'z, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type FromChannel = &'z ChannelType<CHANNEL_SIZE, BUFFER_SIZE>;

    type OtherTaskEnds<'a> = StackChannelEnds<'a, 'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE> where Self: 'a;

    /// Try to remove a channel
    ///
    /// The channel is removed based on the reference to the channel. An error is returned if there
    /// is no channel with the given channel identifier.
    fn try_remove(&mut self, id: TaskId) -> Result<(), Self::Error> {
        if let Ok(at) = self
            .task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
        {
            self.task_data.try_remove(at).map(|_| ()).map_err(|_| unreachable!())
        } else {
            Err(LocalStackChannelsError::ChannelForIdDoesNotExist)
        }
    }

    fn add_new_task(
        &mut self,
        task_id: TaskId,
        flow_ctrl_id: FlowControlId,
    ) -> Result<Self::OtherTaskEnds<'_>, Self::Error> {
        use core::ops::Deref;

        let index = self
            .task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&task_id))
            .expect_err("task id already associated to another async task");

        let channel = self
            .data
            .to_channels
            .take(LocalStackChannel::new())
            .ok_or(LocalStackChannelsError::TaskCountReached)?;

        let new_task_data = TaskData {
            channel,
            task_id,
            flow_ctrl_id,
        };

        self.task_data
            .try_insert(new_task_data, index)
            .map_err(|_| LocalStackChannelsError::TaskCountReached)?;

        let receiver = LocalStackChannelReceiver(RefReservation(&self.task_data[index].channel));

        let sender_channel: &ChannelType<CHANNEL_SIZE, BUFFER_SIZE> = match flow_ctrl_id {
            FlowControlId::Cmd => &self.data.cmd_channel,
            FlowControlId::Acl => &self.data.acl_channel,
            FlowControlId::Sco => &self.data.sco_channel,
            FlowControlId::LeAcl => &self.data.le_acl_channel,
            FlowControlId::LeIso => &self.data.le_iso_channel,
        };

        Ok(StackChannelEnds {
            sender_channel,
            receiver,
        })
    }

    fn get(&self, id: TaskId) -> Option<Self::ToChannel<'_>> {
        use core::ops::Deref;

        self.task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .and_then(|index| self.task_data.get(index))
            .map(|TaskData { channel, .. }| RefReservation(channel))
    }

    fn get_flow_control_id(&self, id: TaskId) -> Option<FlowControlId> {
        self.task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .map(|index| self.task_data[index].flow_ctrl_id)
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
