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
use crate::hci::interface::local_channel::local_dynamic_channel::dyn_buffer::{DynBufferReserve, TakeDynReserveFuture};
use crate::hci::interface::{
    Channel, ChannelId, ChannelReserve, ChannelReserveTypes, FlowControl, IntraMessage, Receiver, Sender,
};
use crate::hci::BufferReserve;
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use core::cell::RefCell;
use core::fmt::{Display, Formatter};
use core::task::Waker;
use dyn_buffer::DeVec;

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

    fn remove(&self) -> Self::Payload {
        self.0.borrow_mut().channel_buffer.pop_front().unwrap()
    }
}

impl<B: Unpin, T: Unpin> Receiver for LocalChannelReceiver<B, T> {
    type Message = T;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a,;

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
    channel_buffer: VecDeque<T>,
    waker: Option<Waker>,
    flow_control: FlowControl,
}

impl<B, T> LocalChannel<B, T> {
    fn new(capacity: usize) -> Self {
        let reserve = DynBufferReserve::new(capacity);
        let senders_count = 0;
        let buffer = VecDeque::with_capacity(capacity);
        let waker = None;
        let flow_control = Default::default();

        LocalChannel(Rc::new(RefCell::new(LocalChannelInner {
            reserve,
            sender_count: senders_count,
            channel_buffer: buffer,
            waker,
            flow_control,
        })))
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

    fn on_flow_control<F>(&self, f: F)
    where
        F: FnOnce(&mut FlowControl),
    {
        f(&mut self.0.borrow_mut().flow_control)
    }
}

impl<B, T> BufferReserve for LocalChannel<B, T>
where
    B: crate::hci::Buffer,
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
    rx_sender: LocalChannelSender<DeVec<u8>, IntraMessage<DeVec<u8>>>,
    rx_receiver: LocalChannelReceiver<DeVec<u8>, IntraMessage<DeVec<u8>>>,
    tx_channels: alloc::vec::Vec<(ChannelId, LocalChannel<DeVec<u8>, IntraMessage<DeVec<u8>>>)>,
}

impl LocalChannelManager {
    pub fn new(channel_size: usize) -> Self {
        let rx_channel = LocalChannel::new(channel_size);

        let rx_sender = rx_channel.get_sender();
        let rx_receiver = rx_channel.take_receiver().unwrap();

        let tx_channels = alloc::vec::Vec::new();

        Self {
            channel_size,
            rx_sender,
            rx_receiver,
            tx_channels,
        }
    }
}

impl ChannelReserveTypes for LocalChannelManager {
    type Error = LocalChannelManagerError;

    type SenderError = LocalSendFutureError;

    type TryExtendError = core::convert::Infallible;

    type Sender = LocalChannelSender<DeVec<u8>, IntraMessage<DeVec<u8>>>;

    type Receiver = LocalChannelReceiver<DeVec<u8>, IntraMessage<DeVec<u8>>>;

    type Buffer = DeVec<u8>;

    type Channel = LocalChannel<DeVec<u8>, IntraMessage<DeVec<u8>>>;
}

impl ChannelReserve for LocalChannelManager {
    fn get_self_sender(&self) -> Self::Sender {
        self.rx_sender.clone()
    }

    fn get_self_receiver(&self) -> &Self::Receiver {
        &self.rx_receiver
    }

    fn try_add(&mut self, id: ChannelId) -> Result<Self::Channel, Self::Error> {
        if let Err(index) = self.tx_channels.binary_search_by(|c| c.0.cmp(&id)) {
            let local_channel = LocalChannel::new(self.channel_size);

            self.tx_channels.insert(index, (id, local_channel));

            Ok(self.tx_channels[index].1.clone())
        } else {
            Err(LocalChannelManagerError::ChannelIdAlreadyUsed)
        }
    }

    fn try_remove(&mut self, id: ChannelId) -> Result<(), Self::Error> {
        if let Ok(index) = self.tx_channels.binary_search_by(|c| c.0.cmp(&id)) {
            self.tx_channels.remove(index);

            Ok(())
        } else {
            Err(LocalChannelManagerError::ChannelIdDoesNotExist)
        }
    }

    fn get(&self, id: ChannelId) -> Option<Self::Channel> {
        self.tx_channels
            .binary_search_by(|i| i.0.cmp(&id))
            .ok()
            .and_then(|index| self.tx_channels.get(index))
            .map(|(_, channel)| channel)
            .cloned()
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
    use crate::test::*;

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
