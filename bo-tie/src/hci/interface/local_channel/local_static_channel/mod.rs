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
use crate::hci::interface::local_channel::local_static_channel::static_buffer::{LinearBufferError, ReservedBuffer};
use crate::hci::interface::{
    Channel, ChannelId, ChannelReserve, ChannelReserveTypes, FlowControl, IntraMessage, Receiver, Sender,
};
use crate::hci::BufferReserve;
use core::cell::{Cell, Ref, RefCell};
use core::fmt::{Display, Formatter};
use core::task::{Poll, Waker};
use static_buffer::{DeLinearBuffer, LinearBuffer, QueueBuffer, StaticBufferReserve};

mod static_buffer;

/// A channel for sending data between futures within the same task
///
/// This is a MPSC channel is used for one direction communication between two futures running in
/// the same task. It works the same as any async channel, but the message queue is implemented on
/// the stack. The size of this queue is determined by the constant generic `CHANNEL_SIZE`.
///
/// # Note
/// `SIZE` should be a power of two for the fastest implementation.
pub struct LocalStaticChannel<const CHANNEL_SIZE: usize, B, T> {
    reserve: StaticBufferReserve<B, CHANNEL_SIZE>,
    circle_buffer: RefCell<QueueBuffer<T, CHANNEL_SIZE>>,
    sender_count: Cell<usize>,
    waker: Cell<Option<Waker>>,
    flow_control: RefCell<FlowControl>,
}

impl<const CHANNEL_SIZE: usize, B, T> LocalStaticChannel<CHANNEL_SIZE, B, T> {
    fn new() -> Self {
        let reserve = StaticBufferReserve::new();
        let sender_count = Cell::new(0);
        let circle_buffer = RefCell::new(QueueBuffer::new());
        let waker = Cell::new(None);
        let flow_control = RefCell::new(FlowControl::default());

        Self {
            reserve,
            circle_buffer,
            sender_count,
            waker,
            flow_control,
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T: Unpin> Channel for Ref<'z, LocalStaticChannel<CHANNEL_SIZE, B, T>> {
    type SenderError = LocalSendFutureError;
    type Message = T;
    type Sender = LocalStaticChannelSender<'z, CHANNEL_SIZE, B, T>;
    type Receiver = LocalStaticChannelReceiver<'z, CHANNEL_SIZE, B, T>;

    fn get_sender(&self) -> Self::Sender {
        LocalStaticChannelSender::new(Ref::clone(self))
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        Some(LocalStaticChannelReceiver(Ref::clone(self)))
    }

    fn on_flow_control<F>(&self, f: F)
    where
        F: FnOnce(&mut FlowControl),
    {
        f(&mut self.flow_control.borrow_mut())
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T> BufferReserve for Ref<'z, LocalStaticChannel<CHANNEL_SIZE, B, T>>
where
    B: crate::hci::Buffer,
    T: Unpin,
{
    type Buffer = ReservedBuffer<'z, B, CHANNEL_SIZE>;
    type TakeBuffer = LocalStaticTakeBuffer<'z, CHANNEL_SIZE, B, T>;

    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>,
    {
        let clone = Ref::clone(self);

        LocalStaticTakeBuffer::new(clone, front_capacity.into().unwrap_or_default())
    }

    fn reclaim<'a>(&'a mut self, buffer: Self::Buffer) {
        drop(buffer)
    }
}

pub struct LocalStaticChannelSender<'a, const CHANNEL_SIZE: usize, B, T>(
    Ref<'a, LocalStaticChannel<CHANNEL_SIZE, B, T>>,
);

impl<const CHANNEL_SIZE: usize, B, T> Clone for LocalStaticChannelSender<'_, CHANNEL_SIZE, B, T> {
    fn clone(&self) -> Self {
        Self(Ref::clone(&self.0))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStaticChannelSender<'a, CHANNEL_SIZE, B, T> {
    fn new(channel: Ref<'a, LocalStaticChannel<CHANNEL_SIZE, B, T>>) -> Self {
        let sender_count = channel.sender_count.get() + 1;

        channel.sender_count.set(sender_count);

        Self(channel)
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBuffer for LocalStaticChannelSender<'a, CHANNEL_SIZE, B, T> {
    type Payload = T;

    fn call_waker(&self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBufferSend for LocalStaticChannelSender<'a, CHANNEL_SIZE, B, T>
where
    T: Sized,
{
    fn is_full(&self) -> bool {
        self.0.circle_buffer.borrow().is_full()
    }

    fn push(&self, packet: Self::Payload) {
        self.0.circle_buffer.borrow_mut().try_push(packet).unwrap();
    }
}

impl<const CHANNEL_SIZE: usize, B, T: Unpin> Sender for LocalStaticChannelSender<'_, CHANNEL_SIZE, B, T> {
    type Error = LocalSendFutureError;
    type Message = T;
    type SendFuture<'a> = LocalSendFuture<'a, Self, T> where Self: 'a;

    fn send(&self, t: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(t),
            local_sender: self,
        }
    }
}

impl<const CHANNEL_SIZE: usize, B, T> Drop for LocalStaticChannelSender<'_, CHANNEL_SIZE, B, T> {
    fn drop(&mut self) {
        let sender_count = self.0.sender_count.get() - 1;

        self.0.sender_count.set(sender_count);

        if self.0.sender_count.get() == 0 {
            self.0.waker.take().map(|waker| waker.wake());
        }
    }
}

/// A receiver of a message of a `LocalStaticChannel`
pub struct LocalStaticChannelReceiver<'a, const CHANNEL_SIZE: usize, B, T>(
    Ref<'a, LocalStaticChannel<CHANNEL_SIZE, B, T>>,
);

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBuffer for LocalStaticChannelReceiver<'a, CHANNEL_SIZE, B, T> {
    type Payload = T;

    fn call_waker(&self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBufferReceive for LocalStaticChannelReceiver<'a, CHANNEL_SIZE, B, T>
where
    T: Sized,
{
    fn has_senders(&self) -> bool {
        self.0.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.circle_buffer.borrow().is_empty()
    }

    fn remove(&self) -> Self::Payload {
        self.0.circle_buffer.borrow_mut().try_remove().unwrap()
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T: Unpin> Receiver for LocalStaticChannelReceiver<'z, CHANNEL_SIZE, B, T> {
    type Message = T;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn recv(&self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

/// This is to satisfy the type `SelfReceiverRef` for the implementation of `ChannelReserve` on
/// `LocalStaticChannelManager`.
impl<'z, const CHANNEL_SIZE: usize, B, T> core::ops::Deref for LocalStaticChannelReceiver<'z, CHANNEL_SIZE, B, T> {
    type Target = Self;

    fn deref(&self) -> &Self::Target {
        &self
    }
}

/// Take buffer for `LocalStaticChannel`
///
/// This the type used as the `TakeBuffer` in the implementation of `BufferReserve` for
/// `LocalStaticChannel`.
pub struct LocalStaticTakeBuffer<'a, const CHANNEL_SIZE: usize, B, T>(
    Ref<'a, LocalStaticChannel<CHANNEL_SIZE, B, T>>,
    usize,
);

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStaticTakeBuffer<'a, CHANNEL_SIZE, B, T> {
    fn new(local_static_channel: Ref<'a, LocalStaticChannel<CHANNEL_SIZE, B, T>>, front_capacity: usize) -> Self {
        Self(local_static_channel, front_capacity)
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> core::future::Future for LocalStaticTakeBuffer<'a, CHANNEL_SIZE, B, T>
where
    B: crate::hci::Buffer,
    T: Unpin,
{
    type Output = ReservedBuffer<'a, B, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let ls_channel = &this.0;

        let ref_reserve = Ref::map(Ref::clone(ls_channel), |channel| &channel.reserve);

        if let Some(buffer) = StaticBufferReserve::<B, CHANNEL_SIZE>::take_buffer(ref_reserve, this.1) {
            Poll::Ready(buffer)
        } else {
            ls_channel.reserve.set_waker(cx.waker());

            Poll::Pending
        }
    }
}

/// The type of buffer for a message of a local static channel
type LocalStaticBuffer<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> =
    ReservedBuffer<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

/// The message type for a local static channel
type LocalStaticMessage<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> =
    IntraMessage<LocalStaticBuffer<'a, BUFFER_SIZE, CHANNEL_SIZE>>;

/// The channel type for a local static channel manager
type LocalStaticChannelType<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> = LocalStaticChannel<
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    LocalStaticMessage<'a, BUFFER_SIZE, CHANNEL_SIZE>,
>;

/// The sender type for a local static channel
type LocalStaticSenderType<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> = LocalStaticChannelSender<
    'a,
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    LocalStaticMessage<'a, BUFFER_SIZE, CHANNEL_SIZE>,
>;

/// The receiver type for a local static channel
type LocalStaticReceiverType<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> = LocalStaticChannelReceiver<
    'a,
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    LocalStaticMessage<'a, BUFFER_SIZE, CHANNEL_SIZE>,
>;

/// A collection of static channels for local communication
///
/// These are channels that are buffered through static allocation instead of dynamic allocation.
/// This means both the maximum number of channels and the size of the buffers of each channel must
/// be known at compile time and fully be allocated at runtime (static memory structures cannot
/// "grow" to their maximum size). `LocalStaticChannels` is intended to be used only where dynamic
/// allocation is not possible.
pub struct LocalStackChannelReserve<'a, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
{
    rx_sender: LocalStaticSenderType<'a, BUFFER_SIZE, CHANNEL_SIZE>,
    rx_receiver: LocalStaticReceiverType<'a, BUFFER_SIZE, CHANNEL_SIZE>,
    tx_channels:
        &'a RefCell<LinearBuffer<CHANNEL_COUNT, (ChannelId, LocalStaticChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>)>>,
}

impl<'a, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserve<'a, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserve`
    ///
    /// This creates a new `LocalStaticChannelReserve` from the provided `rx_channel` and
    /// `tx_channel`. While these objects may be put on the heap, the references are expected to be
    /// of stack allocated types. Otherwise using a
    /// [`LocalChannelManager`](super::LocalChannelManager) is preferred.
    pub fn new(
        rx_channel: &'a RefCell<LocalStaticChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>>,
        tx_channels: &'a RefCell<
            LinearBuffer<CHANNEL_COUNT, (ChannelId, LocalStaticChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>)>,
        >,
    ) -> Self {
        let rx_sender = rx_channel.borrow().get_sender();
        let rx_receiver = rx_channel.borrow().take_receiver().expect("Failed to take ");

        Self {
            rx_sender,
            rx_receiver,
            tx_channels,
        }
    }
}

impl<'z, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelReserveTypes
    for LocalStackChannelReserve<'z, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Error = LocalStaticChannelsError;

    type SenderError = LocalSendFutureError;

    type TryExtendError = LinearBufferError;

    type Sender = <Self::Channel as Channel>::Sender;

    type Receiver = <Self::Channel as Channel>::Receiver;

    type Buffer = LocalStaticBuffer<'z, BUFFER_SIZE, CHANNEL_SIZE>;

    type Channel = Ref<'z, LocalStaticChannelType<'z, BUFFER_SIZE, CHANNEL_SIZE>>;
}

impl<'z, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelReserve
    for LocalStackChannelReserve<'z, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    fn get_self_sender(&self) -> Self::Sender {
        self.rx_sender.clone()
    }

    fn get_self_receiver(&self) -> &Self::Receiver {
        &self.rx_receiver
    }

    /// Try to add a channel
    ///
    /// A channel will be created with the associated `ChannelId` so long as the id is unique and
    /// the `CHANNEL_COUNT` has not been reached.
    fn try_add(&mut self, id: ChannelId) -> Result<Self::Channel, Self::Error> {
        if let Err(at) = self.tx_channels.borrow().binary_search_by(|i| i.0.cmp(&id)) {
            self.tx_channels
                .borrow_mut()
                .try_insert((id, LocalStaticChannel::new()), at)
                .map_err(|_| LocalStaticChannelsError::ChannelCountReached)?;

            Ok(Ref::map(self.tx_channels.borrow(), |channels| {
                &channels.get(at).unwrap().1
            }))
        } else {
            Err(LocalStaticChannelsError::ChannelIdAlreadyUsed)
        }
    }

    /// Try to remove a channel
    ///
    /// The channel is removed based on the reference to the channel. An error is returned if there
    /// is no channel with the given channel identifier.
    fn try_remove(&mut self, id: ChannelId) -> Result<(), Self::Error> {
        if let Ok(at) = self.tx_channels.borrow().binary_search_by(|i| i.0.cmp(&id)) {
            self.tx_channels
                .borrow_mut()
                .try_remove(at)
                .map(|_| ())
                .map_err(|_| unreachable!())
        } else {
            Err(LocalStaticChannelsError::ChannelForIdDoesNotExist)
        }
    }

    fn get(&self, id: ChannelId) -> Option<Self::Channel> {
        self.tx_channels
            .borrow()
            .binary_search_by(|i| i.0.cmp(&id))
            .ok()
            .map(|index| Ref::map(self.tx_channels.borrow(), |channels| &channels.get(index).unwrap().1))
    }
}

#[derive(Debug)]
pub enum LocalStaticChannelsError {
    ChannelCountReached,
    ChannelIdAlreadyUsed,
    ChannelForIdDoesNotExist,
}

impl Display for LocalStaticChannelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalStaticChannelsError::ChannelCountReached => f.write_str("reached maximum channel count"),
            LocalStaticChannelsError::ChannelIdAlreadyUsed => f.write_str("id already used"),
            LocalStaticChannelsError::ChannelForIdDoesNotExist => {
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
        let _: LocalStaticChannel<20, usize> = LocalStaticChannel::new();
    }

    #[test]
    fn local_static_init_ref_mut_usize() {
        let _: LocalStaticChannel<20, &mut usize> = LocalStaticChannel::new();
    }

    #[tokio::test]
    async fn local_static_add_remove_usize() {
        let ls: LocalStaticChannel<5, HciPacket<usize>> = LocalStaticChannel::new();

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        generic_send_and_receive(&ls, &test_vals).await
    }

    #[tokio::test]
    async fn local_static_add_remove_usize_single_capacity() {
        let ls: LocalStaticChannel<1, HciPacket<usize>> = LocalStaticChannel::new();

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        generic_send_and_receive(&ls, &test_vals).await
    }

    #[tokio::test]
    async fn local_static_add_remove_byte_slice() {
        let l: LocalStaticChannel<4, HciPacket<&[u8]>> = LocalStaticChannel::new();

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

        let l: LocalStaticChannel<4, HciPacket<[usize; SIZE]>> = LocalStaticChannel::new();

        let test_vals: &[[usize; SIZE]] = &[
            [0; SIZE], [1; SIZE], [2; SIZE], [3; SIZE], [4; SIZE], [5; SIZE], [6; SIZE], [7; SIZE], [8; SIZE],
            [9; SIZE],
        ];

        generic_send_and_receive(&l, test_vals).await
    }
}
