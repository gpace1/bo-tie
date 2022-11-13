//! Stack local buffered channel
//!
//! This is a stack local channel with support of buffered data. Both the channel's message queue
//! and the reserve for buffers are on the stack.
//!
//! A buffered channel allows for buffers to be taken from a 'reserve' of buffers associated with
//! the channel.

use super::receiver::LocalChannelReceiver;
use super::sender::LocalChannelSender;
use crate::local_channel::local_stack::channel::LocalChannel;
use crate::local_channel::local_stack::{
    BufferReserve, FromConnMsg, FromConnectionChannel, FromHostChannel, ToConnDataMsg, ToConnectionDataChannel,
    ToInterfaceMsg, UnsafeFromConnMsg, UnsafeToConnDataMsg, UnsafeToInterfaceMsg,
};
use crate::local_channel::LocalSendFutureError;
use crate::Channel;
use bo_tie_util::buffer::stack::{
    BufferReservation, DeLinearBuffer, Reservation, StackHotel, UnsafeBufferReservation, UnsafeReservation,
};
use bo_tie_util::buffer::{Buffer, TryExtend, TryFrontExtend, TryFrontRemove, TryRemove};
use core::borrow::Borrow;
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::task::{Context, Poll};

/// A stack allocated buffered async channel
///
/// This is a MPSC channel where the queue is allocated on the stack instead of the heap. Using this
/// channel requires borrowing the channel, either the standard rust way with `&` or by using a
/// wrapper structure that carries a lifetime.
///
/// The size of the channel's queue must be known at compile time. The channel is always a fixed
/// sized channel and cannot be reallocated to have a larger or smaller queue. For the fastest
/// implementation, the size of the queue should be a power of two.
///
/// # Buffer
/// Buffers are taken from a `reserve`. This reserve is a finite amount equivalent to the
/// `CHANNEL_SIZE` of general purpose buffers that can be filled and used as part of the message.
/// Buffers can be taken through the implementation of [`BufferReserve`].
///
/// [`BufferReserve`]: bo_tie_util::buffer::BufferReserve
pub struct LocalBufferedChannel<const CHANNEL_SIZE: usize, B, T> {
    pub(super) channel: LocalChannel<CHANNEL_SIZE, T>,
    pub(super) buffer_reserve: StackHotel<B, CHANNEL_SIZE>,
}

impl<const CHANNEL_SIZE: usize, B, T> LocalBufferedChannel<CHANNEL_SIZE, B, T> {
    pub(super) fn new() -> Self {
        let channel = LocalChannel::new();
        let buffer_reserve = StackHotel::new();

        Self {
            channel,
            buffer_reserve,
        }
    }
}

impl<const CHANNEL_SIZE: usize, B, T> Borrow<LocalChannel<CHANNEL_SIZE, T>>
    for &LocalBufferedChannel<CHANNEL_SIZE, B, T>
{
    fn borrow(&self) -> &LocalChannel<CHANNEL_SIZE, T> {
        &self.channel
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> Borrow<LocalChannel<CHANNEL_SIZE, T>>
    for Reservation<'_, LocalBufferedChannel<CHANNEL_SIZE, B, T>, TASK_COUNT>
{
    fn borrow(&self) -> &LocalChannel<CHANNEL_SIZE, T> {
        &self.channel
    }
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Channel
    for &'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>
{
    type SenderError = LocalSendFutureError;
    type Message = ToInterfaceMsg<'a, CHANNEL_SIZE, BUFFER_SIZE>;
    type Sender = LocalChannelSender<CHANNEL_SIZE, Self, UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>>;
    type Receiver = LocalChannelReceiver<CHANNEL_SIZE, Self, UnsafeToInterfaceMsg<CHANNEL_SIZE, BUFFER_SIZE>>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(self)
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        if self.channel.receiver_exists.get() {
            None
        } else {
            Some(LocalChannelReceiver::new(*self))
        }
    }
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Channel
    for Reservation<'a, ToConnectionDataChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>
{
    type SenderError = LocalSendFutureError;
    type Message = ToConnDataMsg<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;
    type Sender = LocalChannelSender<CHANNEL_SIZE, Self, UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>;
    type Receiver =
        LocalChannelReceiver<CHANNEL_SIZE, Self, UnsafeToConnDataMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(self.clone())
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        if self.channel.receiver_exists.get() {
            None
        } else {
            Some(LocalChannelReceiver::new(self.clone()))
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> Channel
    for &'a FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>
{
    type SenderError = LocalSendFutureError;
    type Message = FromConnMsg<'a, CHANNEL_SIZE, BUFFER_SIZE>;
    type Sender = LocalChannelSender<CHANNEL_SIZE, Self, UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>>;
    type Receiver = LocalChannelReceiver<CHANNEL_SIZE, Self, UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(self)
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        if self.channel.receiver_exists.get() {
            None
        } else {
            Some(LocalChannelReceiver::new(&*self))
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize, T> BufferReserve
    for &'a LocalBufferedChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, T>
{
    type Buffer = BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;
    type TakeBuffer = TakeBuffer<Self>;

    fn take<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        TakeBuffer::new(
            &*self,
            front_capacity.into().unwrap_or_default(),
            back_capacity.into().unwrap_or_default(),
        )
    }

    fn reclaim(&mut self, _: Self::Buffer) {}
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize, T> BufferReserve
    for Reservation<'a, LocalBufferedChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, T>, TASK_COUNT>
{
    type Buffer = ReservedBuffer<'a, TASK_COUNT, CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, T>;
    type TakeBuffer = TakeBuffer<Self>;

    fn take<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        TakeBuffer::new(
            self.clone(),
            front_capacity.into().unwrap_or_default(),
            back_capacity.into().unwrap_or_default(),
        )
    }

    fn reclaim(&mut self, _: Self::Buffer) {}
}

/// Take buffer for `LocalBufferedChannel`
///
/// This the type used as the [`TakeBuffer`] in the implementation of `BufferReserve` for
/// `LocalStackChannel`.
///
/// [`TakeBuffer`]: bo_tie_util::buffer::BufferReserve::TakeBuffer
pub struct TakeBuffer<C> {
    channel: C,
    front_capacity: usize,
    back_capacity: usize,
}

impl<C> TakeBuffer<C> {
    fn new(channel: C, front_capacity: usize, back_capacity: usize) -> Self {
        Self {
            channel,
            front_capacity,
            back_capacity,
        }
    }
}

impl<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize, T> Future
    for TakeBuffer<&'a LocalBufferedChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, T>>
{
    type Output = BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this
            .channel
            .buffer_reserve
            .take_buffer(this.front_capacity, this.back_capacity)
        {
            Some(buffer) => Poll::Ready(buffer),
            None => {
                this.channel.buffer_reserve.set_waker(cx.waker());

                Poll::Pending
            }
        }
    }
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize, T> Future
    for TakeBuffer<Reservation<'a, LocalBufferedChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, T>, TASK_COUNT>>
{
    type Output = ReservedBuffer<'a, TASK_COUNT, CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, T>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this
            .channel
            .buffer_reserve
            .take_buffer(this.front_capacity, this.back_capacity)
        {
            Some(buffer) => {
                let buffer = unsafe { BufferReservation::to_unsafe(buffer) };

                Poll::Ready(ReservedBuffer::new(this.channel.clone(), buffer))
            }
            None => {
                this.channel.buffer_reserve.set_waker(cx.waker());

                Poll::Pending
            }
        }
    }
}

/// This is a buffer taken from a `Reservation<'_, LocalBufferedChannel<_,_,_>>`
///
/// The buffers returned by the implementation of `BufferReserve` need to contain a reservation
/// to the buffered channel if it is created from a `Reservation`. The implementation of
/// `TakeBuffer<Reservation<_>>` uses a copy of the `Reservation`, so when a buffer is returned when
/// it is polled to completion, the compiler requires the reservation to be cloned in order to meed
/// the lifetime requirements (which is correct as the lifetime of the reservation of the buffered
/// channel must at least last as long as the buffer created from the channel).
pub struct ReservedBuffer<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> {
    source: Reservation<'a, LocalBufferedChannel<CHANNEL_SIZE, B, T>, TASK_COUNT>,
    buffer: UnsafeBufferReservation<B, CHANNEL_SIZE>,
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> ReservedBuffer<'a, TASK_COUNT, CHANNEL_SIZE, B, T> {
    fn new<'b>(
        source: Reservation<'a, LocalBufferedChannel<CHANNEL_SIZE, B, T>, TASK_COUNT>,
        buffer: UnsafeBufferReservation<B, CHANNEL_SIZE>,
    ) -> Self {
        Self { source, buffer }
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> Buffer
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: Buffer,
{
    fn with_capacity(_: usize, _: usize) -> Self
    where
        Self: Sized,
    {
        unimplemented!("with_capacity not implemented for ReservedBuffer")
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        self.buffer.clear_with_capacity(front, back)
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> Deref
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer.deref()
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> DerefMut
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: DerefMut<Target = [u8]>,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.buffer.deref_mut()
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> TryExtend<u8>
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: TryExtend<u8>,
{
    type Error = B::Error;

    fn try_extend<E>(&mut self, iter: E) -> Result<(), Self::Error>
    where
        E: IntoIterator<Item = u8>,
    {
        self.buffer.try_extend(iter)
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> TryRemove<u8>
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: TryRemove<u8>,
{
    type Error = B::Error;
    type RemoveIter<'a> = B::RemoveIter<'a> where Self: 'a ;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.buffer.try_remove(how_many)
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> TryFrontExtend<u8>
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: TryFrontExtend<u8>,
{
    type Error = B::Error;

    fn try_front_extend<E>(&mut self, iter: E) -> Result<(), Self::Error>
    where
        E: IntoIterator<Item = u8>,
    {
        self.buffer.try_front_extend(iter)
    }
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> TryFrontRemove<u8>
    for ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>
where
    B: TryFrontRemove<u8>,
{
    type Error = B::Error;
    type FrontRemoveIter<'a> = B::FrontRemoveIter<'a> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.buffer.try_front_remove(how_many)
    }
}

pub struct UnsafeReservedBuffer<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> {
    source: UnsafeReservation<LocalBufferedChannel<CHANNEL_SIZE, B, T>, TASK_COUNT>,
    buffer: UnsafeBufferReservation<B, CHANNEL_SIZE>,
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, B, T> UnsafeReservedBuffer<TASK_COUNT, CHANNEL_SIZE, B, T> {
    pub(super) unsafe fn from_res(res: ReservedBuffer<'_, TASK_COUNT, CHANNEL_SIZE, B, T>) -> Self {
        let source = Reservation::to_unsafe(res.source);
        let buffer = res.buffer;

        Self { source, buffer }
    }

    pub(super) unsafe fn into_res<'a>(self) -> ReservedBuffer<'a, TASK_COUNT, CHANNEL_SIZE, B, T> {
        let source = UnsafeReservation::rebind(self.source);
        let buffer = self.buffer;

        ReservedBuffer { source, buffer }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::*;
    use crate::{FromConnectionIntraMessage, ToConnectionDataIntraMessage, ToInterfaceIntraMessage};
    use bo_tie_util::errors::Error;

    macro_rules! dup {
        ($to_dup:tt) => {
            ($to_dup, $to_dup)
        };
    }

    macro_rules! create_buffer {
        ($channel:expr, $($vals:expr),* $(,)?) => {
            {
                let mut buffer = (&$channel).take(None).await;

                buffer.try_extend([$($vals),*]).unwrap();

                buffer
            }
        }
    }

    #[tokio::test]
    async fn add_remove_from_connection() {
        const CHANNEL_SIZE: usize = 20;
        const BUFFER_SIZE: usize = 10;

        let lbc: FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE> = LocalBufferedChannel::new();

        let (tx_vals, rx_vals) = dup!([
            FromConnectionIntraMessage::Acl(create_buffer!(lbc, 108, 129, 23, 130, 32, 8, 221, 164, 255, 8)),
            FromConnectionIntraMessage::Sco(create_buffer!(lbc, 52, 107, 46, 72, 130, 116, 93, 79, 87, 156)),
            FromConnectionIntraMessage::Iso(create_buffer!(lbc, 79, 241, 161, 246, 47, 255, 66, 56, 163, 138)),
            FromConnectionIntraMessage::Acl(create_buffer!(lbc, 230, 72, 41, 47, 198, 119, 19, 227, 69, 169)),
            FromConnectionIntraMessage::Acl(create_buffer!(lbc, 208, 180, 111, 74, 54, 49, 157, 23, 18, 227)),
            FromConnectionIntraMessage::Acl(create_buffer!(lbc, 181, 246, 210, 113, 97, 63, 218, 50, 134, 74)),
            FromConnectionIntraMessage::Acl(create_buffer!(lbc, 246, 58, 74, 211, 73, 195, 130, 138, 213, 247)),
            FromConnectionIntraMessage::Disconnect(Error::RemoteUserTerminatedConnection),
        ]);

        channel_send_and_receive(&lbc, tx_vals, rx_vals, |l, r| match (l, r) {
            (FromConnectionIntraMessage::Acl(l), FromConnectionIntraMessage::Acl(r)) => l.deref() == r.deref(),
            (FromConnectionIntraMessage::Sco(l), FromConnectionIntraMessage::Sco(r)) => l.deref() == r.deref(),
            (FromConnectionIntraMessage::Iso(l), FromConnectionIntraMessage::Iso(r)) => l.deref() == r.deref(),
            (FromConnectionIntraMessage::Disconnect(l), FromConnectionIntraMessage::Disconnect(r)) => l == r,
            _ => false,
        })
        .await
    }

    #[tokio::test]
    async fn add_remove_from_host_host() {
        const CHANNEL_SIZE: usize = 20;
        const BUFFER_SIZE: usize = 10;

        let lbc: FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE> = LocalBufferedChannel::new();

        let (tx_vals, rx_vals) = dup!([
            ToInterfaceIntraMessage::Command(create_buffer!(lbc, 105, 220, 84, 248, 217, 99, 255, 92, 142, 27)),
            ToInterfaceIntraMessage::Command(create_buffer!(lbc, 173, 60, 111, 10, 114, 186, 117, 247, 198, 81)),
            ToInterfaceIntraMessage::Command(create_buffer!(lbc, 185, 26, 10, 192, 70, 236, 61, 248, 198, 36)),
        ]);

        channel_send_and_receive(&lbc, tx_vals, rx_vals, |l, r| match (l, r) {
            (ToInterfaceIntraMessage::Command(l), ToInterfaceIntraMessage::Command(r)) => l.deref() == r.deref(),
        })
        .await
    }

    #[tokio::test]
    async fn add_remove_to_connection() {
        const CHANNEL_SIZE: usize = 20;
        const BUFFER_SIZE: usize = 10;

        let hotel = StackHotel::<_, 1>::new();

        let lbc: Reservation<ToConnectionDataChannel<1, CHANNEL_SIZE, BUFFER_SIZE>, 1> =
            hotel.take(LocalBufferedChannel::new()).unwrap();

        let (tx_vals, rx_vals) = dup!([
            ToConnectionDataIntraMessage::Acl(create_buffer!(lbc, 85, 21, 81, 12, 9, 117, 132, 156, 202, 4)),
            ToConnectionDataIntraMessage::Sco(create_buffer!(lbc, 197, 26, 164, 139, 220, 176, 33, 30, 1, 75)),
            ToConnectionDataIntraMessage::Iso(create_buffer!(lbc, 33, 207, 153, 191, 26, 18, 21, 63, 190, 211)),
        ]);

        channel_send_and_receive(lbc, tx_vals, rx_vals, |l, r| match (l, r) {
            (ToConnectionDataIntraMessage::Acl(l), ToConnectionDataIntraMessage::Acl(r)) => l.deref() == r.deref(),
            (ToConnectionDataIntraMessage::Sco(l), ToConnectionDataIntraMessage::Sco(r)) => l.deref() == r.deref(),
            (ToConnectionDataIntraMessage::Iso(l), ToConnectionDataIntraMessage::Iso(r)) => l.deref() == r.deref(),
            (ToConnectionDataIntraMessage::Disconnect(l), ToConnectionDataIntraMessage::Disconnect(r)) => l == r,
            _ => false,
        })
        .await
    }
}
