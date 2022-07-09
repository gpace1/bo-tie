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
use crate::hci::interface::{
    Channel, ChannelEnds, ChannelReserve, FlowControl, IntraMessage, Receiver, Sender, TaskId,
};
use crate::hci::BufferReserve;
use core::cell::{Cell, Ref, RefCell};
use core::fmt::{Display, Formatter};
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
    flow_control: RefCell<FlowControl>,
    reserve: StackHotel<B, CHANNEL_SIZE>,
    circle_buffer: RefCell<QueueBuffer<T, CHANNEL_SIZE>>,
    sender_count: Cell<usize>,
    waker: Cell<Option<Waker>>,
}

impl<const CHANNEL_SIZE: usize, B, T> LocalStackChannel<CHANNEL_SIZE, B, T> {
    fn new() -> Self {
        let flow_control = RefCell::new(FlowControl::default());
        let reserve = StackHotel::new();
        let sender_count = Cell::new(0);
        let circle_buffer = RefCell::new(QueueBuffer::new());
        let waker = Cell::new(None);

        Self {
            flow_control,
            reserve,
            circle_buffer,
            sender_count,
            waker,
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T: Unpin> Channel for Ref<'z, LocalStackChannel<CHANNEL_SIZE, B, T>> {
    type SenderError = LocalSendFutureError;
    type Message = T;
    type Sender = LocalStackChannelSender<'z, CHANNEL_SIZE, B, T>;
    type Receiver = LocalStackChannelReceiver<'z, CHANNEL_SIZE, B, T>;

    fn get_sender(&self) -> Self::Sender {
        LocalStackChannelSender::new(Ref::clone(self))
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        Some(LocalStackChannelReceiver(Ref::clone(self)))
    }

    fn on_flow_control<F>(&self, f: F)
    where
        F: FnOnce(&mut FlowControl),
    {
        f(&mut self.flow_control.borrow_mut())
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T> BufferReserve for Ref<'z, LocalStackChannel<CHANNEL_SIZE, B, T>>
where
    B: crate::hci::Buffer,
    T: Unpin,
{
    type Buffer = BufferReservation<'z, B, CHANNEL_SIZE>;
    type TakeBuffer = LocalStackTakeBuffer<'z, CHANNEL_SIZE, B, T>;

    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>,
    {
        let clone = Ref::clone(self);

        LocalStackTakeBuffer::new(clone, front_capacity.into().unwrap_or_default())
    }

    fn reclaim<'a>(&'a mut self, buffer: Self::Buffer) {
        drop(buffer)
    }
}

pub struct LocalStackChannelSender<'a, const CHANNEL_SIZE: usize, B, T>(Ref<'a, LocalStackChannel<CHANNEL_SIZE, B, T>>);

impl<const CHANNEL_SIZE: usize, B, T> Clone for LocalStackChannelSender<'_, CHANNEL_SIZE, B, T> {
    fn clone(&self) -> Self {
        Self(Ref::clone(&self.0))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStackChannelSender<'a, CHANNEL_SIZE, B, T> {
    fn new(channel: Ref<'a, LocalStackChannel<CHANNEL_SIZE, B, T>>) -> Self {
        let sender_count = channel.sender_count.get() + 1;

        channel.sender_count.set(sender_count);

        Self(channel)
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBuffer for LocalStackChannelSender<'a, CHANNEL_SIZE, B, T> {
    type Payload = T;

    fn call_waker(&self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBufferSend for LocalStackChannelSender<'a, CHANNEL_SIZE, B, T>
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

impl<const CHANNEL_SIZE: usize, B, T: Unpin> Sender for LocalStackChannelSender<'_, CHANNEL_SIZE, B, T> {
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

impl<const CHANNEL_SIZE: usize, B, T> Drop for LocalStackChannelSender<'_, CHANNEL_SIZE, B, T> {
    fn drop(&mut self) {
        let sender_count = self.0.sender_count.get() - 1;

        self.0.sender_count.set(sender_count);

        if self.0.sender_count.get() == 0 {
            self.0.waker.take().map(|waker| waker.wake());
        }
    }
}

/// A receiver of a message of a `LocalStackChannel`
pub struct LocalStackChannelReceiver<'a, const CHANNEL_SIZE: usize, B, T>(
    Ref<'a, LocalStackChannel<CHANNEL_SIZE, B, T>>,
);

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBuffer for LocalStackChannelReceiver<'a, CHANNEL_SIZE, B, T> {
    type Payload = T;

    fn call_waker(&self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBufferReceive for LocalStackChannelReceiver<'a, CHANNEL_SIZE, B, T>
where
    T: Sized,
{
    fn has_senders(&self) -> bool {
        self.0.sender_count.get() != 0
    }

    fn is_empty(&self) -> bool {
        self.0.circle_buffer.borrow().is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        self.0.circle_buffer.borrow_mut().try_remove().unwrap()
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T: Unpin> Receiver for LocalStackChannelReceiver<'z, CHANNEL_SIZE, B, T> {
    type Message = T;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
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
}

/// Take buffer for `LocalStackChannel`
///
/// This the type used as the `TakeBuffer` in the implementation of `BufferReserve` for
/// `LocalStackChannel`.
pub struct LocalStackTakeBuffer<'a, const CHANNEL_SIZE: usize, B, T>(
    Ref<'a, LocalStackChannel<CHANNEL_SIZE, B, T>>,
    usize,
);

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStackTakeBuffer<'a, CHANNEL_SIZE, B, T> {
    fn new(local_static_channel: Ref<'a, LocalStackChannel<CHANNEL_SIZE, B, T>>, front_capacity: usize) -> Self {
        Self(local_static_channel, front_capacity)
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> core::future::Future for LocalStackTakeBuffer<'a, CHANNEL_SIZE, B, T>
where
    B: crate::hci::Buffer,
    T: Unpin,
{
    type Output = BufferReservation<'a, B, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        let ls_channel = &this.0;

        let ref_reserve = Ref::map(Ref::clone(ls_channel), |channel| &channel.reserve);

        if let Some(buffer) = StackHotel::<B, CHANNEL_SIZE>::take_buffer(ref_reserve, this.1) {
            Poll::Ready(buffer)
        } else {
            ls_channel.reserve.set_waker(cx.waker());

            Poll::Pending
        }
    }
}

/// The type of buffer for a message of a local static channel
type LocalStackReservation<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> =
    BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

/// The message type for a local static channel
type LocalStackMessage<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> =
    IntraMessage<LocalStackReservation<'a, BUFFER_SIZE, CHANNEL_SIZE>>;

/// The channel type for a local static channel manager
type LocalStackChannelType<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> =
    LocalStackChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, LocalStackMessage<'a, BUFFER_SIZE, CHANNEL_SIZE>>;

/// The sender type for a local static channel
type LocalStackSenderType<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> = LocalStackChannelSender<
    'a,
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    LocalStackMessage<'a, BUFFER_SIZE, CHANNEL_SIZE>,
>;

/// The receiver type for a local static channel
type LocalStackReceiverType<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> = LocalStackChannelReceiver<
    'a,
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    LocalStackMessage<'a, BUFFER_SIZE, CHANNEL_SIZE>,
>;

/// Channels for communication between an async task and the interface async task
struct TaskChannels<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> {
    id: TaskId,
    interface_rx: LocalStackChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>,
    interface_tx: LocalStackChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>,
}

impl<'a, const BUFFER_SIZE: usize, const CHANNEL_SIZE: usize> TaskChannels<'a, BUFFER_SIZE, CHANNEL_SIZE> {
    /// Create a new [`TaskChannels`]
    fn new(id: TaskId) -> Self {
        let interface_rx = LocalStackChannelType::new();
        let interface_tx = LocalStackChannelType::new();

        Self {
            id,
            interface_rx,
            interface_tx,
        }
    }

    /// Get the channel ends used by the interface async task
    fn get_interface_ends(
        this: Ref<'_, Self>,
    ) -> ChannelEnds<Ref<'_, LocalStackChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>>> {
        let sender = Ref::map(Ref::clone(&this), |this| &this.interface_tx).get_sender();

        let receiver = Ref::map(this, |this| &this.interface_rx).take_receiver().unwrap();

        ChannelEnds::new(sender, receiver)
    }

    /// Get the channel ends used by the associated async task
    fn get_task_ends(
        this: Ref<'_, Self>,
    ) -> ChannelEnds<Ref<'_, LocalStackChannelType<'a, BUFFER_SIZE, CHANNEL_SIZE>>> {
        let sender = Ref::map(Ref::clone(&this), |this| &this.interface_rx).get_sender();

        let receiver = Ref::map(this, |this| &this.interface_tx).take_receiver().unwrap();

        ChannelEnds::new(sender, receiver)
    }
}

/// [`LocalStackChannelReserve`] data
///
/// This is the data that is held by
struct LocalStackChannelReserveData<'a, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>(
    RefCell<StackHotel<RefCell<TaskChannels<'static, BUFFER_SIZE, CHANNEL_SIZE>>, CHANNEL_COUNT>>,
);

impl<const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserveData<'static, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserveData`
    fn new() -> Self {
        Self(RefCell::new(StackHotel::new()))
    }
}

impl<const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> core::ops::Deref
    for LocalStackChannelReserveData<'_, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Target = RefCell<StackHotel<RefCell<TaskChannels<'static, BUFFER_SIZE, CHANNEL_SIZE>>, CHANNEL_COUNT>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// A collection of static channels for local communication
///
/// These are channels that are buffered through static allocation instead of dynamic allocation.
/// This means both the maximum number of channels and the size of the buffers of each channel must
/// be known at compile time and fully be allocated at runtime (static memory structures cannot
/// "grow" to their maximum size). `LocalStackChannels` is intended to be used only where dynamic
/// allocation is not possible.
pub struct LocalStackChannelReserve<'a, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
{
    channels: &'a LocalStackChannelReserveData<'a, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    reserves: LinearBuffer<CHANNEL_COUNT, (TaskId, LocalStackReservation<'a, BUFFER_SIZE, CHANNEL_SIZE>)>,
}

impl<'a, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserve<'a, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserve`
    ///
    /// This creates a new `LocalStackChannelReserve` from the provided `rx_channel` and
    /// `tx_channel`. While these objects may be put on the heap, the references are expected to be
    /// of stack allocated types. Otherwise using a
    /// [`LocalChannelManager`](super::LocalChannelManager) is preferred.
    pub fn new(channels: &'a LocalStackChannelReserveData<'a, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>) -> Self {
        let reserves = LinearBuffer::new();

        Self { reserves, channels }
    }
}

impl<'z, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelReserve
    for LocalStackChannelReserve<'z, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Error = LocalStackChannelsError;

    type SenderError = LocalSendFutureError;

    type TryExtendError = LinearBufferError;

    type ForNewTaskError = LocalStackChannelsError;

    type Sender = <Self::Channel as Channel>::Sender;

    type Receiver = <Self::Channel as Channel>::Receiver;

    type Buffer = LocalStackReservation<'z, BUFFER_SIZE, CHANNEL_SIZE>;

    type Channel = Ref<'z, LocalStackChannelType<'z, BUFFER_SIZE, CHANNEL_SIZE>>;

    /// Try to remove a channel
    ///
    /// The channel is removed based on the reference to the channel. An error is returned if there
    /// is no channel with the given channel identifier.
    fn try_remove(&mut self, id: TaskId) -> Result<(), Self::Error> {
        if let Ok(at) = self.tx_channels.borrow().binary_search_by(|i| i.0.cmp(&id)) {
            self.tx_channels
                .borrow_mut()
                .try_remove(at)
                .map(|_| ())
                .map_err(|_| unreachable!())
        } else {
            Err(LocalStackChannelsError::ChannelForIdDoesNotExist)
        }
    }

    fn add_new_task(&mut self, task_id: TaskId) -> Result<ChannelEnds<Self::Channel>, Self::ForNewTaskError>
    where
        Self::Channel: Sized,
    {
        let index = self
            .reserves
            .binary_search_by(|(id, _)| id.cmp(&task_id))
            .expect("task id already associated to another async task");

        let channel_reservation =
            StackHotel::take_ref(self.channels.borrow()).ok_or(LocalStackChannelsError::ChannelCountReached)?;

        self.reserves.try_insert((task_id, channel_reservation), index)?;

        Ok(TaskChannels::get_task_ends(self.reserves[index].1.borrow()))
    }

    /// Get a channel
    ///
    /// Returns the channel associated by `id`. If there is no channel with that id then `None` is
    /// returned.
    fn get(&self, id: TaskId) -> Option<Self::Channel> {
        self.tx_channels
            .borrow()
            .binary_search_by(|i| i.0.cmp(&id))
            .ok()
            .map(|index| Ref::map(self.tx_channels.borrow(), |channels| &channels.get(index).unwrap().1))
    }
}

#[derive(Debug)]
pub enum LocalStackChannelsError {
    ChannelCountReached,
    ChannelIdAlreadyUsed,
    ChannelForIdDoesNotExist,
}

impl Display for LocalStackChannelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalStackChannelsError::ChannelCountReached => f.write_str("reached maximum channel count"),
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
