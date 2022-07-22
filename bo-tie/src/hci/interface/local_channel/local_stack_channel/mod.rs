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
    // `buffer_reserve` (Note: this does not make any other unsafe reservations safe to use). The
    // type `UnsafeChannel` is an example scenario  for this issue.
    message_queue: RefCell<QueueBuffer<T, CHANNEL_SIZE>>,
    buffer_reserve: StackHotel<B, CHANNEL_SIZE>,
    sender_count: Cell<usize>,
    waker: Cell<Option<Waker>>,
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStackChannel<CHANNEL_SIZE, B, T> {
    fn new() -> Self {
        let message_queue = RefCell::new(QueueBuffer::new());
        let buffer_reserve = StackHotel::new();
        let sender_count = Cell::new(0);
        let waker = Cell::new(None);

        Self {
            buffer_reserve,
            message_queue,
            sender_count,
            waker,
        }
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T: Unpin> Channel for &'z LocalStackChannel<CHANNEL_SIZE, B, T> {
    type SenderError = LocalSendFutureError;
    type Message = T;
    type Sender = LocalStackChannelSender<'z, CHANNEL_SIZE, B, T>;
    type Receiver = LocalStackChannelReceiver<'z, CHANNEL_SIZE, B, T>;

    fn get_sender(&self) -> Self::Sender {
        LocalStackChannelSender::new(self)
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        Some(LocalStackChannelReceiver(self))
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T> BufferReserve for &'z LocalStackChannel<CHANNEL_SIZE, B, T>
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
        LocalStackTakeBuffer::new(self, front_capacity.into().unwrap_or_default())
    }

    fn reclaim(&mut self, _: Self::Buffer) {}
}

/// The sender part of a stack allocated channel
///
/// This implements `Sender` for sending messages to the receiver of its channel.
#[derive(Clone)]
pub struct LocalStackChannelSender<'a, const CHANNEL_SIZE: usize, B, T>(&'a LocalStackChannel<CHANNEL_SIZE, B, T>);

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStackChannelSender<'a, CHANNEL_SIZE, B, T> {
    fn new(channel: &'a LocalStackChannel<CHANNEL_SIZE, B, T>) -> Self {
        channel.sender_count.set(channel.sender_count.get() + 1);

        Self(channel)
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBuffer for LocalStackChannelSender<'a, CHANNEL_SIZE, B, T> {
    type Payload = T;

    fn call_waker(&mut self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&mut self, waker: Waker) {
        self.0.waker.set(Some(waker))
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBufferSend for LocalStackChannelSender<'a, CHANNEL_SIZE, B, T>
where
    T: Sized,
{
    fn is_full(&self) -> bool {
        self.0.message_queue.borrow().is_full()
    }

    fn push(&mut self, packet: Self::Payload) {
        self.0.message_queue.borrow_mut().try_push(packet).unwrap();
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
        self.0.sender_count.set(self.0.sender_count.get() - 1);

        if self.0.sender_count.get() == 0 {
            self.0.waker.take().map(|waker| waker.wake());
        }
    }
}

/// A receiver of a message of a `LocalStackChannel`
pub struct LocalStackChannelReceiver<'a, const CHANNEL_SIZE: usize, B, T>(&'a LocalStackChannel<CHANNEL_SIZE, B, T>);

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalQueueBuffer for LocalStackChannelReceiver<'a, CHANNEL_SIZE, B, T> {
    type Payload = T;

    fn call_waker(&mut self) {
        self.0.waker.take().map(|w| w.wake());
    }

    fn set_waker(&mut self, waker: Waker) {
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
        self.0.message_queue.borrow().is_empty()
    }

    fn pop_next(&mut self) -> Self::Payload {
        self.0.message_queue.borrow_mut().try_remove().unwrap()
    }
}

impl<'z, const CHANNEL_SIZE: usize, B, T: Unpin> Receiver for LocalStackChannelReceiver<'z, CHANNEL_SIZE, B, T> {
    type Message = T;
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

/// Take buffer for `LocalStackChannel`
///
/// This the type used as the `TakeBuffer` in the implementation of `BufferReserve` for
/// `LocalStackChannel`.
pub struct LocalStackTakeBuffer<'a, const CHANNEL_SIZE: usize, B, T> {
    channel: &'a LocalStackChannel<CHANNEL_SIZE, B, T>,
    front_capacity: usize,
}

impl<'a, const CHANNEL_SIZE: usize, B, T> LocalStackTakeBuffer<'a, CHANNEL_SIZE, B, T> {
    fn new(channel: &'a LocalStackChannel<CHANNEL_SIZE, B, T>, front_capacity: usize) -> Self {
        Self {
            channel,
            front_capacity,
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, B, T> core::future::Future for LocalStackTakeBuffer<'a, CHANNEL_SIZE, B, T>
where
    B: crate::hci::Buffer,
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

/// The [`Channel`](crate::hci::interface::Channel) type for a [`LocalStackChannelReserve`]
///
/// This is an alias for the `Channel` in the `ChannelReserve` implementation of a
/// [`LocalStackChannelReserve`].
///
/// # unsafety
/// This type must be carefully be used as it is makes a `LocalStackChannel` self-referential. An
/// `UnsafeChannel` cannot be moved while there is messages within the mpsc buffer for the channel,
/// with the only exception being that it is safe to drop an `UnsafeChannel`
type UnsafeChannel<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> = LocalStackChannel<
    CHANNEL_SIZE,
    DeLinearBuffer<BUFFER_SIZE, u8>,
    IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
>;

struct TaskData<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    channel: Reservation<'a, UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    task_id: TaskId,
    flow_ctrl_id: FlowControlId,
}

/// Ends of channel for an async task
pub struct StackChannelEnds<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    sender_channel: &'a UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    receiver: LocalStackChannelReceiver<
        'a,
        CHANNEL_SIZE,
        DeLinearBuffer<BUFFER_SIZE, u8>,
        IntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>,
    >,
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelEnds
    for StackChannelEnds<'a, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Channel = &'a UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>;

    fn get_prep_send(
        &self,
        front_capacity: usize,
    ) -> GetPrepareSend<<Self::Channel as Channel>::Sender, <Self::Channel as BufferReserve>::TakeBuffer> {
        GetPrepareSend::new(&self.sender_channel, front_capacity)
    }

    fn get_receiver(&self) -> &<Self::Channel as Channel>::Receiver {
        &self.receiver
    }

    fn get_mut_receiver(&mut self) -> &mut <Self::Channel as Channel>::Receiver {
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
    to_channels: StackHotel<UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    cmd_channel: UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    acl_channel: UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    sco_channel: UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    le_acl_channel: UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    le_iso_channel: UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>,
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserveData`
    fn new() -> Self {
        let to_channels = StackHotel::new();
        let cmd_channel = UnsafeChannel::new();
        let acl_channel = UnsafeChannel::new();
        let sco_channel = UnsafeChannel::new();
        let le_acl_channel = UnsafeChannel::new();
        let le_iso_channel = UnsafeChannel::new();

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
            'a,
            CHANNEL_SIZE,
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
        let to_channel_reservations = LinearBuffer::new();

        let receivers = InterfaceReceivers {
            cmd_receiver: (&data.cmd_channel).take_receiver().unwrap(),
            acl_receiver: (&data.cmd_channel).take_receiver().unwrap(),
            sco_receiver: (&data.cmd_channel).take_receiver().unwrap(),
            le_acl_receiver: (&data.cmd_channel).take_receiver().unwrap(),
            le_iso_receiver: (&data.cmd_channel).take_receiver().unwrap(),
        };

        let flow_ctrl_receiver = FlowCtrlReceiver::new(receivers);

        Self {
            data,
            task_data: to_channel_reservations,
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

    type MessageBuffer = UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type Sender = <Self::Channel as Channel>::Sender;

    type Receiver = <Self::Channel as Channel>::Receiver;

    type Buffer = BufferReservation<'z, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type Channel = &'z UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE>;

    type ChannelEnds = StackChannelEnds<'z, CHANNEL_SIZE, BUFFER_SIZE>;

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

    fn add_new_task(&mut self, task_id: TaskId, flow_ctrl_id: FlowControlId) -> Result<Self::ChannelEnds, Self::Error>
    where
        Self::Channel: Sized,
    {
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

        let task_data_ref = self.task_data.deref().get(index).unwrap();

        let receiver = (&*task_data_ref.channel).take_receiver().unwrap();

        let sender_channel: &UnsafeChannel<CHANNEL_SIZE, BUFFER_SIZE> = match flow_ctrl_id {
            FlowControlId::Cmd => &self.data.cmd_channel,
            FlowControlId::Acl => &self.data.acl_channel,
            FlowControlId::Sco => &self.data.sco_channel,
            FlowControlId::LeAcl => &self.data.le_acl_channel,
            FlowControlId::LeIso => &self.data.le_iso_channel,
        };

        let new_task_channel_ends: StackChannelEnds<'z, CHANNEL_SIZE, BUFFER_SIZE> = StackChannelEnds {
            sender_channel,
            receiver,
        };

        Ok(new_task_channel_ends)
    }

    fn get_and<F, R>(&self, id: TaskId, f: F) -> Option<R>
    where
        F: FnOnce(&Self::Channel) -> R,
    {
        self.task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .map(|index| f(&&*self.task_data[index].channel))
    }

    fn get_flow_control_id(&self, id: TaskId) -> Option<FlowControlId> {
        self.task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .map(|index| self.task_data[index].flow_ctrl_id)
    }

    fn get_flow_ctrl_receiver(&mut self) -> &mut FlowCtrlReceiver<Self::Receiver> {
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
