//! A local channel with dynamically allocated buffers
//!
//! This is a local channel where the buffer is allocated dynamically upon creation. However, the
//! channel will not reallocate its buffer if it fills up. Both the send and receive are
//! asynchronous so if the channel cannot accept any more messages the sender will await until a
//! message is removed by the receiver.
//!
//! This is a local channel so it can only be used between async tasks running on the same thread.

use super::{
    LocalQueueBuffer, LocalQueueBufferReceive, LocalQueueBufferSend, LocalReceiverFuture, LocalSendFuture,
    LocalSendFutureError,
};
use crate::hci::interface::{Channel, ChannelId, ChannelsManagement, Receiver, Sender};
use alloc::collections::VecDeque;
use core::cell::RefCell;
use core::fmt::{Display, Formatter};
use core::task::Waker;

struct LocalChannelInner<T> {
    sender_count: usize,
    buffer: VecDeque<T>,
    waker: Option<Waker>,
}

/// A local channel
///
/// This is a channel for sending messages between async tasks running on the same thread. A local
/// channel is not `Send` safe
pub struct LocalChannel<T>(RefCell<LocalChannelInner<T>>);

impl<T> LocalChannel<T> {
    fn new(capacity: usize) -> Self {
        let senders_count = 0;
        let buffer = VecDeque::with_capacity(capacity);
        let waker = None;

        LocalChannel(RefCell::new(LocalChannelInner {
            sender_count: senders_count,
            buffer,
            waker,
        }))
    }
}

pub struct LocalChannelSender<'a, T>(&'a RefCell<LocalChannelInner<T>>);

impl<'a, T> LocalChannelSender<'a, T> {
    fn new(ref_cell_inner: &'a RefCell<LocalChannelInner<T>>) -> Self {
        ref_cell_inner.borrow_mut().sender_count += 1;

        Self(ref_cell_inner)
    }
}

impl<T> LocalQueueBuffer for LocalChannelSender<'_, T> {
    type Payload = T;

    fn call_waker(&mut self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&mut self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<T> LocalQueueBufferSend for LocalChannelSender<'_, T> {
    fn is_full(&self) -> bool {
        let local_channel = self.0.borrow();

        local_channel.buffer.len() == local_channel.buffer.capacity()
    }

    fn push(&mut self, packet: Self::Payload) {
        self.0.borrow_mut().buffer.push_back(packet)
    }
}

impl<'z, T> Sender for LocalChannelSender<'z, T> {
    type Error = LocalSendFutureError;
    type Message = T;
    type SendFuture<'a>

    = LocalSendFuture<'a, Self, T>    where
    T: 'a,
    'z: 'a,;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture::new(self, t)
    }
}

impl<T> Drop for LocalChannelSender<'_, T> {
    fn drop(&mut self) {
        let mut sender = self.0.borrow_mut();

        sender.sender_count -= 1;

        if sender.sender_count == 0 {
            sender.waker.take().map(|waker| waker.wake());
        }
    }
}

pub struct LocalChannelReceiver<'a, T>(&'a RefCell<LocalChannelInner<T>>);

impl<T> LocalQueueBuffer for LocalChannelReceiver<'_, T> {
    type Payload = T;

    fn call_waker(&mut self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&mut self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<T> LocalQueueBufferReceive for LocalChannelReceiver<'_, T> {
    fn has_senders(&self) -> bool {
        self.0.borrow().sender_count != 0
    }

    fn is_empty(&self) -> bool {
        self.0.borrow().buffer.is_empty()
    }

    fn remove(&mut self) -> Self::Payload {
        self.0.borrow_mut().buffer.pop_front().unwrap()
    }
}

impl<'z, T> Receiver for LocalChannelReceiver<'z, T> {
    type Message = T;
    type ReceiveFuture<'a>

    = LocalReceiverFuture<'a, Self>    where
    T: 'a,
    'z: 'a,;

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<T> Channel for LocalChannel<T> {
    type Sender<'a>

    = LocalChannelSender<'a, T>    where
    T: 'a,;
    type Receiver<'a>

    = LocalChannelReceiver<'a, T>    where
    T: 'a,;

    fn get_sender(&self) -> Self::Sender<'_> {
        LocalChannelSender::new(&self.0)
    }

    fn get_receiver(&self) -> Self::Receiver<'_> {
        LocalChannelReceiver(&self.0)
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
pub struct LocalChannelManager<T> {
    channel_size: usize,
    rx_channel: LocalChannel<T>,
    tx_channels: alloc::vec::Vec<(ChannelId, LocalChannel<T>)>,
}

impl<T> LocalChannelManager<T> {
    pub fn new(channel_size: usize) -> Self {
        let rx_channel = LocalChannel::new(channel_size);
        let tx_channels = alloc::vec::Vec::new();

        Self {
            channel_size,
            tx_channels,
            rx_channel,
        }
    }
}

impl<T> ChannelsManagement for LocalChannelManager<T> {
    type Channel = LocalChannel<T>;
    type Error = LocalChannelManagerError;

    fn get_rx_channel<'a>(&'a self) -> &Self::Channel {
        &self.rx_channel
    }

    fn try_add(&mut self, id: ChannelId) -> Result<usize, Self::Error> {
        if let Err(index) = self.tx_channels.binary_search_by(|c| c.0.cmp(&id)) {
            self.tx_channels
                .insert(index, (id, LocalChannel::new(self.channel_size)));

            Ok(index)
        } else {
            Err(LocalChannelManagerError::ChannelIdAlreadyUsed)
        }
    }

    fn try_remove(&mut self, id: ChannelId) -> Result<Self::Channel, Self::Error> {
        if let Ok(index) = self.tx_channels.binary_search_by(|c| c.0.cmp(&id)) {
            Ok(self.tx_channels.remove(index).1)
        } else {
            Err(LocalChannelManagerError::ChannelIdDoesNotExist)
        }
    }

    fn get(&self, id: ChannelId) -> Option<&Self::Channel> {
        self.tx_channels
            .binary_search_by(|i| i.0.cmp(&id))
            .ok()
            .and_then(|index| self.tx_channels.get(index))
            .map(|(_, channel)| channel)
    }

    fn get_by_index(&self, index: usize) -> Option<&Self::Channel> {
        self.tx_channels.get(index).map(|(_, channel)| channel)
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
        let _: LocalChannel<usize> = LocalChannel::new(20);
    }

    #[test]
    fn local_init_ref_mut_usize() {
        let _: LocalChannel<&mut usize> = LocalChannel::new(20);
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
