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
use crate::hci::interface::{Channel, ChannelId, ChannelsManagement, Receiver, Sender};
use core::cell::RefCell;
use core::fmt::{Display, Formatter};
use core::task::Waker;
use static_buffer::{LinearBuffer, QueueBuffer};

mod static_buffer;

struct LocalStaticChannelInner<const SIZE: usize, T> {
    circle_buffer: QueueBuffer<T, SIZE>,
    sender_count: usize,
    waker: Option<Waker>,
}

/// A channel for sending data between futures within the same task
///
/// This channel is used for one direction communication between two futures running in parallel
/// on the same task. There is only a single sender and receiver for this channel. Two or more
/// of these `LocalChannel`s are used for sending data to and from the HCI implementation and
/// the interface driver.
///
/// # Note
/// `SIZE` should be a power of two for the fastest implementation.
pub struct LocalStaticChannel<const SIZE: usize, T>(RefCell<LocalStaticChannelInner<SIZE, T>>);

impl<const SIZE: usize, T> LocalStaticChannel<SIZE, T> {
    fn new() -> Self {
        let sender_count = 0;
        let circle_buffer = QueueBuffer::new();
        let waker = None;

        Self(RefCell::new(LocalStaticChannelInner {
            sender_count,
            circle_buffer,
            waker,
        }))
    }
}

impl<const SIZE: usize, T> Channel for LocalStaticChannel<SIZE, T> {
    type Sender<'a>

    = LocalStaticChannelSender<'a, SIZE, T>     where
    T: 'a,;
    type Receiver<'a>

    = LocalStaticChannelReceiver<'a, SIZE, T>     where
    T: 'a,;

    fn get_sender(&self) -> Self::Sender<'_> {
        LocalStaticChannelSender::new(&self.0)
    }

    fn get_receiver(&self) -> Self::Receiver<'_> {
        LocalStaticChannelReceiver(&self.0)
    }
}

pub struct LocalStaticChannelSender<'a, const SIZE: usize, T>(&'a RefCell<LocalStaticChannelInner<SIZE, T>>);

impl<'a, const SIZE: usize, T> LocalStaticChannelSender<'a, SIZE, T> {
    fn new(ref_cell_inner: &'a RefCell<LocalStaticChannelInner<SIZE, T>>) -> Self {
        ref_cell_inner.borrow_mut().sender_count += 1;

        Self(ref_cell_inner)
    }
}

impl<'a, const SIZE: usize, T> LocalQueueBuffer for LocalStaticChannelSender<'a, SIZE, T> {
    type Payload = T;

    fn call_waker(&mut self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&mut self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<'a, const SIZE: usize, T> LocalQueueBufferSend for LocalStaticChannelSender<'a, SIZE, T>
where
    T: Sized,
{
    fn is_full(&self) -> bool {
        self.0.borrow().circle_buffer.is_full()
    }

    fn push(&mut self, packet: Self::Payload) {
        self.0.borrow_mut().circle_buffer.try_push(packet).unwrap();
    }
}

impl<'z, const SIZE: usize, T> Sender for LocalStaticChannelSender<'z, SIZE, T> {
    type Error = LocalSendFutureError;
    type Message = T;
    type SendFuture<'a>

    = LocalSendFuture<'a, Self, T>    where
    T: 'a,
    'z: 'a,;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture {
            packet: Some(t),
            local_sender: self,
        }
    }
}

impl<const SIZE: usize, T> Drop for LocalStaticChannelSender<'_, SIZE, T> {
    fn drop(&mut self) {
        let mut sender = self.0.borrow_mut();

        sender.sender_count -= 1;

        if sender.sender_count == 0 {
            sender.waker.take().map(|waker| waker.wake());
        }
    }
}

pub struct LocalStaticChannelReceiver<'a, const SIZE: usize, T>(&'a RefCell<LocalStaticChannelInner<SIZE, T>>);

impl<'a, const SIZE: usize, T> LocalQueueBuffer for LocalStaticChannelReceiver<'a, SIZE, T> {
    type Payload = T;

    fn call_waker(&mut self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&mut self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<'a, const SIZE: usize, T> LocalQueueBufferReceive for LocalStaticChannelReceiver<'a, SIZE, T>
where
    T: Sized,
{
    fn has_senders(&self) -> bool {
        self.0.borrow().sender_count != 0
    }

    fn is_empty(&self) -> bool {
        self.0.borrow().circle_buffer.is_empty()
    }

    fn remove(&mut self) -> Self::Payload {
        self.0.borrow_mut().circle_buffer.try_remove().unwrap()
    }
}

impl<'z, const SIZE: usize, T> Receiver for LocalStaticChannelReceiver<'z, SIZE, T> {
    type Message = T;
    type ReceiveFuture<'a>

    = LocalReceiverFuture<'a, Self>    where
    T: 'a,
    'z: 'a,;

    fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a> {
        LocalReceiverFuture(self)
    }
}

/// A collection of static channels for local communication
///
/// These are channels that are buffered through static allocation instead of dynamic allocation.
/// This means both the maximum number of channels and the size of the buffers of each channel must
/// be known at compile time and fully be allocated at runtime (static memory structures cannot
/// "grow" to their maximum size). `LocalStaticChannels` is intended to be used only where dynamic
/// allocation is not possible.
pub struct LocalStaticChannelManager<T, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize> {
    rx_channel: LocalStaticChannel<CHANNEL_SIZE, T>,
    tx_channels: LinearBuffer<CHANNEL_COUNT, (ChannelId, LocalStaticChannel<CHANNEL_SIZE, T>)>,
}

impl<T, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize>
    LocalStaticChannelManager<T, CHANNEL_COUNT, CHANNEL_SIZE>
{
    pub fn new() -> Self {
        let rx_channel = LocalStaticChannel::new();
        let tx_channels = LinearBuffer::new();

        Self {
            rx_channel,
            tx_channels,
        }
    }
}

impl<T, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize> ChannelsManagement
    for LocalStaticChannelManager<T, CHANNEL_COUNT, CHANNEL_SIZE>
{
    type Channel = LocalStaticChannel<CHANNEL_SIZE, T>;
    type Error = LocalStaticChannelsError;

    fn get_rx_channel(&self) -> &Self::Channel {
        &self.rx_channel
    }

    /// Try to add a channel
    ///
    /// A channel will be created with the associated `ChannelId` so long as the id is unique and
    /// the `CHANNEL_COUNT` has not been reached.
    fn try_add(&mut self, id: ChannelId) -> Result<usize, Self::Error> {
        if let Err(at) = self.tx_channels.binary_search_by(|i| i.0.cmp(&id)) {
            self.tx_channels
                .try_insert((id, LocalStaticChannel::new()), at)
                .map(|_| at)
                .map_err(|_| LocalStaticChannelsError::ChannelCountReached)
        } else {
            Err(LocalStaticChannelsError::ChannelIdAlreadyUsed)
        }
    }

    /// Try to remove a channel
    ///
    /// The channel is removed based on the reference to the channel. An error is returned if there
    /// is no channel with the given channel identifier.
    fn try_remove(&mut self, id: ChannelId) -> Result<Self::Channel, Self::Error> {
        if let Ok(at) = self.tx_channels.binary_search_by(|i| i.0.cmp(&id)) {
            self.tx_channels
                .try_remove(at)
                .map(|(_, channel)| channel)
                .map_err(|_| unreachable!())
        } else {
            Err(LocalStaticChannelsError::ChannelForIdDoesNotExist)
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
