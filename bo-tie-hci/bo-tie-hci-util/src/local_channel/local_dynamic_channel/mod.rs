//! A local channel with dynamically allocated buffers
//!
//! This is a local channel where the buffer is allocated dynamically upon creation. However, the
//! channel will not reallocate its buffer if it fills up. Both the send and receive are
//! asynchronous so if the channel cannot accept any more messages the sender will await until a
//! message is removed by the receiver.
//!
//! This is a local channel so it can only be used between async tasks running on the same thread.

mod dyn_buffer;

use super::{
    LocalQueueBuffer, LocalQueueBufferReceive, LocalQueueBufferSend, LocalReceiverFuture, LocalSendFuture,
    LocalSendFutureError,
};
use crate::{
    Channel, ChannelEnds, ChannelReserve, FlowControlId, FlowCtrlReceiver, FromIntraMessage, InterfaceReceivers,
    Receiver, Sender, TaskId, ToIntraMessage,
};
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use bo_tie_util::buffer::BufferReserve;
use core::cell::RefCell;
use core::fmt::{Display, Formatter};
use core::task::{Context, Poll, Waker};
use dyn_buffer::DeVec;
use dyn_buffer::{DynBufferReserve, TakeDynReserveFuture};

/// The sender for a local channel
pub struct LocalChannelSender<B, T>(Rc<RefCell<LocalChannelInner<B, T>>>);

impl<B, T> LocalChannelSender<B, T> {
    fn new(ref_cell_inner: &Rc<RefCell<LocalChannelInner<B, T>>>) -> Self {
        ref_cell_inner.borrow_mut().sender_count += 1;

        Self(ref_cell_inner.clone())
    }
}

impl<B, T> Clone for LocalChannelSender<B, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<B, T> LocalQueueBuffer for LocalChannelSender<B, T> {
    type Payload = T;

    fn call_waker(&self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<B, T> LocalQueueBufferSend for LocalChannelSender<B, T> {
    fn is_full(&self) -> bool {
        let local_channel = self.0.borrow();

        local_channel.channel_buffer.len() == local_channel.channel_buffer.capacity()
    }

    fn receiver_exists(&self) -> bool {
        self.0.borrow().receiver_exists
    }

    fn push(&self, packet: Self::Payload) {
        self.0.borrow_mut().channel_buffer.push_back(packet)
    }
}

impl<B: Unpin, T: Unpin> Sender for LocalChannelSender<B, T> {
    type Error = LocalSendFutureError;
    type Message = T;
    type SendFuture<'a> = LocalSendFuture<'a, Self, T> where Self: 'a;

    fn send<'a>(&'a self, t: Self::Message) -> Self::SendFuture<'a> {
        LocalSendFuture::new(self, t)
    }
}

impl<B, T> Drop for LocalChannelSender<B, T> {
    fn drop(&mut self) {
        let mut sender = self.0.borrow_mut();

        sender.sender_count -= 1;

        if sender.sender_count == 0 {
            sender.waker.take().map(|waker| waker.wake());
        }
    }
}

/// The receiver for a local channel
pub struct LocalChannelReceiver<B, T>(Rc<RefCell<LocalChannelInner<B, T>>>);

impl<B, T> Clone for LocalChannelReceiver<B, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<B, T> LocalQueueBuffer for LocalChannelReceiver<B, T> {
    type Payload = T;

    fn call_waker(&self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<B, T> LocalQueueBufferReceive for LocalChannelReceiver<B, T> {
    fn has_senders(&self) -> bool {
        self.0.borrow().sender_count != 0
    }

    fn is_empty(&self) -> bool {
        self.0.borrow().channel_buffer.is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        self.0.borrow_mut().channel_buffer.pop_front().unwrap()
    }
}

impl<B: Unpin, T: Unpin> Receiver for LocalChannelReceiver<B, T> {
    type Message = T;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a,;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.borrow_mut().waker = Some(cx.waker().clone());

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

/// A local channel
///
/// This is a channel for sending messages between async tasks running on the same thread. A local
/// channel is not `Send` safe
pub struct LocalChannel<B, T>(Rc<RefCell<LocalChannelInner<B, T>>>);

impl<B, T> Clone for LocalChannel<B, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

struct LocalChannelInner<B, T> {
    reserve: DynBufferReserve<B>,
    sender_count: usize,
    receiver_exists: bool,
    channel_buffer: VecDeque<T>,
    waker: Option<Waker>,
}

impl<B, T> LocalChannelInner<B, T> {
    fn new(capacity: usize) -> Self {
        let reserve = DynBufferReserve::new(capacity);
        let senders_count = 0;
        let receiver_exists = false;
        let buffer = VecDeque::with_capacity(capacity);
        let waker = None;

        LocalChannelInner {
            reserve,
            sender_count: senders_count,
            receiver_exists,
            channel_buffer: buffer,
            waker,
        }
    }
}

impl<B, T> LocalChannel<B, T> {
    fn new(capacity: usize) -> Self {
        Self(Rc::new(RefCell::new(LocalChannelInner::new(capacity))))
    }
}

impl<B: Unpin, T: Unpin> Channel for LocalChannel<B, T> {
    type SenderError = LocalSendFutureError;
    type Message = T;
    type Sender = LocalChannelSender<B, T>;
    type Receiver = LocalChannelReceiver<B, T>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(&self.0)
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        Some(LocalChannelReceiver(self.0.clone()))
    }
}

impl<B, T> BufferReserve for LocalChannel<B, T>
where
    B: bo_tie_util::buffer::Buffer,
{
    type Buffer = B;
    type TakeBuffer = TakeDynReserveFuture<B>;

    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>,
    {
        self.0
            .borrow_mut()
            .reserve
            .take(front_capacity.into().unwrap_or_default())
    }

    fn reclaim(&mut self, buffer: Self::Buffer) {
        self.0.borrow_mut().reserve.reclaim(buffer)
    }
}

#[derive(Clone)]
pub struct DynChannelEnds {
    send_channel: LocalChannel<DeVec<u8>, ToIntraMessage<DeVec<u8>>>,
    receiver: LocalChannelReceiver<DeVec<u8>, FromIntraMessage<DeVec<u8>, Self>>,
}

impl ChannelEnds for DynChannelEnds {
    type ToBuffer = DeVec<u8>;

    type FromBuffer = DeVec<u8>;

    type TakeBuffer = <LocalChannel<DeVec<u8>, ToIntraMessage<DeVec<u8>>> as BufferReserve>::TakeBuffer;

    type Sender = LocalChannelSender<DeVec<u8>, ToIntraMessage<DeVec<u8>>>;

    type Receiver = LocalChannelReceiver<DeVec<u8>, FromIntraMessage<DeVec<u8>, Self>>;

    fn get_sender(&self) -> Self::Sender {
        self.send_channel.get_sender()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.send_channel.take(front_capacity)
    }

    fn get_receiver(&self) -> &Self::Receiver {
        &self.receiver
    }

    fn get_mut_receiver(&mut self) -> &mut Self::Receiver {
        &mut self.receiver
    }
}

/// Task information
struct TaskData {
    sender_channel: LocalChannel<DeVec<u8>, FromIntraMessage<DeVec<u8>, DynChannelEnds>>,
    task_id: TaskId,
    flow_control_id: FlowControlId,
}

/// Task sender channels
///
/// These are the senders used by other async tasks for communicating with the interface task
struct FromOtherTaskChannels<C> {
    cmd_channel: C,
    acl_channel: C,
    sco_channel: C,
    le_acl_channel: C,
    le_iso_channel: C,
}

/// A Channel Manager for local channels
///
/// This is a manager of local channels that are dynamically allocated at runtime. These channels
/// are not `Send` safe as the internal buffers are borrowed by both users of the channel.
///
/// The channels of a `LocalChannelManager` are allocated when they are needed. A channel consists
/// of a [`VecDeque`](std::collections::VecDeque) for the message buffer which is shared by the
/// sender and receiver. These channel buffers are allocated with an initial capacity that is also
/// the maximum capacity of the channel. If a channel's buffer reaches maximum capacity, then any
/// further sends will pend.
pub struct LocalChannelManager {
    channel_size: usize,
    other_task_data: RefCell<alloc::vec::Vec<TaskData>>,
    task_senders: FromOtherTaskChannels<LocalChannel<DeVec<u8>, ToIntraMessage<DeVec<u8>>>>,
    flow_control_receiver: FlowCtrlReceiver<LocalChannelReceiver<DeVec<u8>, ToIntraMessage<DeVec<u8>>>>,
}

impl LocalChannelManager {
    pub fn new(channel_size: usize) -> Self {
        let other_task_data = RefCell::new(alloc::vec::Vec::new());

        let cmd_channel = LocalChannel::new(channel_size);
        let acl_channel = LocalChannel::new(channel_size);
        let sco_channel = LocalChannel::new(channel_size);
        let le_acl_channel = LocalChannel::new(channel_size);
        let le_iso_channel = LocalChannel::new(channel_size);

        let interface_receivers = InterfaceReceivers {
            cmd_receiver: cmd_channel.take_receiver().unwrap(),
            acl_receiver: acl_channel.take_receiver().unwrap(),
            sco_receiver: sco_channel.take_receiver().unwrap(),
            le_acl_receiver: le_acl_channel.take_receiver().unwrap(),
            le_iso_receiver: le_iso_channel.take_receiver().unwrap(),
        };

        let flow_control_receiver = FlowCtrlReceiver::new(interface_receivers);

        let task_senders = FromOtherTaskChannels {
            cmd_channel,
            acl_channel,
            sco_channel,
            le_acl_channel,
            le_iso_channel,
        };

        Self {
            channel_size,
            other_task_data,
            task_senders,
            flow_control_receiver,
        }
    }
}

impl ChannelReserve for LocalChannelManager {
    type Error = LocalChannelManagerError;

    type SenderError = LocalSendFutureError;

    type TryExtendError = core::convert::Infallible;

    type ToBuffer = Self::FromBuffer;

    type ToChannel = LocalChannel<DeVec<u8>, FromIntraMessage<DeVec<u8>, DynChannelEnds>>;

    type FromBuffer = DeVec<u8>;

    type FromChannel = LocalChannel<DeVec<u8>, ToIntraMessage<DeVec<u8>>>;

    type TaskChannelEnds = DynChannelEnds;

    fn try_remove(&mut self, id: TaskId) -> Result<(), Self::Error> {
        if let Ok(index) = self
            .other_task_data
            .get_mut()
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
        {
            self.other_task_data.get_mut().remove(index);

            Ok(())
        } else {
            Err(LocalChannelManagerError::ChannelIdDoesNotExist)
        }
    }

    fn add_new_task(
        &self,
        task_id: TaskId,
        flow_control_id: FlowControlId,
    ) -> Result<Self::TaskChannelEnds, Self::Error> {
        let from_new_task_channel = match flow_control_id {
            FlowControlId::Cmd => self.task_senders.cmd_channel.clone(),
            FlowControlId::Acl => self.task_senders.acl_channel.clone(),
            FlowControlId::Sco => self.task_senders.sco_channel.clone(),
            FlowControlId::LeAcl => self.task_senders.le_acl_channel.clone(),
            FlowControlId::LeIso => self.task_senders.le_iso_channel.clone(),
        };

        let to_new_task_channel = LocalChannel::new(self.channel_size);

        let new_task_ends = DynChannelEnds {
            send_channel: from_new_task_channel,
            receiver: to_new_task_channel.take_receiver().unwrap(),
        };

        let index = self
            .other_task_data
            .borrow()
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&task_id))
            .expect_err("task id already associated to another async task");

        let channel_data = TaskData {
            sender_channel: to_new_task_channel,
            task_id,
            flow_control_id,
        };

        self.other_task_data.borrow_mut().insert(index, channel_data);

        Ok(new_task_ends)
    }

    fn get(&self, id: TaskId) -> Option<Self::ToChannel> {
        let ref_other_task_data = self.other_task_data.borrow();

        ref_other_task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .and_then(|index| ref_other_task_data.get(index))
            .map(|TaskData { sender_channel, .. }| sender_channel.clone())
    }

    fn get_flow_control_id(&self, id: TaskId) -> Option<FlowControlId> {
        let ref_other_task_data = self.other_task_data.borrow();

        ref_other_task_data
            .binary_search_by(|TaskData { task_id, .. }| task_id.cmp(&id))
            .ok()
            .and_then(|index| ref_other_task_data.get(index))
            .map(|TaskData { flow_control_id, .. }| *flow_control_id)
    }

    fn get_flow_ctrl_receiver(&mut self) -> &mut FlowCtrlReceiver<<Self::FromChannel as Channel>::Receiver> {
        &mut self.flow_control_receiver
    }
}

#[derive(Debug)]
pub enum LocalChannelManagerError {
    ChannelIdAlreadyUsed,
    ChannelIdDoesNotExist,
}

impl Display for LocalChannelManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalChannelManagerError::ChannelIdAlreadyUsed => f.write_str("channel id already used"),
            LocalChannelManagerError::ChannelIdDoesNotExist => f.write_str("channel for id does not exist"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bo_tie_hci_interface::test::*;

    #[test]
    fn local_init_usize() {
        let _: LocalChannel<usize, usize> = LocalChannel::new(20);
    }

    #[test]
    fn local_init_ref_mut_usize() {
        let _: LocalChannel<&mut usize, &mut usize> = LocalChannel::new(20);
    }

    #[tokio::test]
    async fn local_add_remove_usize() {
        let l: LocalChannel<HciPacket<usize>> = LocalChannel::new(5);

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        generic_send_and_receive(&l, &test_vals).await
    }

    #[tokio::test]
    async fn local_add_remove_usize_single_capacity() {
        let l: LocalChannel<HciPacket<usize>> = LocalChannel::new(1);

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        generic_send_and_receive(&l, &test_vals).await
    }

    #[tokio::test]
    async fn local_add_remove_byte_slice() {
        let l: LocalChannel<HciPacket<&[u8]>> = LocalChannel::new(4);

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

        let l: LocalChannel<HciPacket<[usize; SIZE]>> = LocalChannel::new(4);

        let test_vals: &[[usize; SIZE]] = &[
            [0; SIZE], [1; SIZE], [2; SIZE], [3; SIZE], [4; SIZE], [5; SIZE], [6; SIZE], [7; SIZE], [8; SIZE],
            [9; SIZE],
        ];

        generic_send_and_receive(&l, test_vals).await
    }
}
