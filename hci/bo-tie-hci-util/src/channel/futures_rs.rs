//! [futures-rs] channel implementations
//!
//! [futures-rs]: futures

use bo_tie_core::buffer::de_vec::DeVec;
use core::pin::Pin;
use core::task::{Context, Poll};
use futures::channel::mpsc;

impl<T> crate::Sender for mpsc::UnboundedSender<T>
where
    T: Unpin,
{
    type Error = mpsc::SendError;
    type Message = T;
    type SendFuture<'a> = futures::sink::Send<'a, Self, T> where Self: 'a;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        futures::sink::SinkExt::send(self, t)
    }
}

impl<T> crate::Receiver for mpsc::UnboundedReceiver<T>
where
    T: Unpin,
{
    type Message = T;
    type ReceiveFuture<'a> = futures::stream::Next<'a, Self>
    where
        Self: 'a,;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        futures::stream::Stream::poll_next(Pin::new(self), cx)
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        futures::stream::StreamExt::next(self)
    }
}

/// The [`ChannelReserve`] type as implemented by `futures`'s unbounded channels
///
/// [`ChannelReserve`]: crate::channel::ChannelReserve
pub type UnboundedChannelReserve = crate::channel::ChannelReserve<
    mpsc::UnboundedSender<crate::ToHostCommandIntraMessage>,
    mpsc::UnboundedSender<
        crate::ToHostGeneralIntraMessage<
            crate::channel::ConnectionEnds<
                mpsc::UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
                mpsc::UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
                mpsc::UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
            >,
        >,
    >,
    mpsc::UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedSender<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedSender<crate::ToConnectionEventIntraMessage>,
    mpsc::UnboundedReceiver<crate::ToInterfaceIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedReceiver<crate::FromConnectionIntraMessage<DeVec<u8>>>,
    fn() -> (
        mpsc::UnboundedSender<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
        mpsc::UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    ),
    fn() -> (
        mpsc::UnboundedSender<crate::ToConnectionEventIntraMessage>,
        mpsc::UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
    ),
    mpsc::UnboundedSender<crate::ToInterfaceIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedReceiver<crate::ToHostCommandIntraMessage>,
    mpsc::UnboundedReceiver<
        crate::ToHostGeneralIntraMessage<
            crate::channel::ConnectionEnds<
                mpsc::UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
                mpsc::UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
                mpsc::UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
            >,
        >,
    >,
    mpsc::UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
>;

/// The [`HostChannelEnds`] type as implemented by `futures`'s unbounded channels
///
/// [`HostChannelEnds`]: crate::channel::HostChannelEnds
pub type UnboundedHostChannelEnds = crate::channel::HostChannelEnds<
    mpsc::UnboundedSender<crate::ToInterfaceIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedReceiver<crate::ToHostCommandIntraMessage>,
    mpsc::UnboundedReceiver<
        crate::ToHostGeneralIntraMessage<
            crate::channel::ConnectionEnds<
                mpsc::UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
                mpsc::UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
                mpsc::UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
            >,
        >,
    >,
    mpsc::UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    mpsc::UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
>;

/// Create a [`ChannelReserve`] and [`HostChannelEnds`] using [tokio's] unbounded channels
///
/// The created `ChannelReserve` (and `HostChannelEnds`) use tokio's unbounded channels for
/// communication between the async tasks of the HCI implementation.
///
/// The inputs are the maximum sizes of the front and tail packet frame information for the
/// interface. See [`ChannelReserveBuilder::new`].
///
/// [tokio's]: tokio::sync::mpsc
/// [`ChannelReserve`]: crate::ChannelReserve
/// [`HostChannelEnds`]: crate::HostChannelEnds
pub fn futures_unbounded(front_size: usize, tail_size: usize) -> (UnboundedChannelReserve, UnboundedHostChannelEnds) {
    use futures::channel::mpsc::unbounded;

    super::ChannelReserveBuilder::new(front_size, tail_size)
        .set_c1(unbounded)
        .set_c2(unbounded)
        .set_c3(unbounded)
        .set_c4(unbounded)
        .set_c5(unbounded as fn() -> (_, _))
        .set_c6(unbounded as fn() -> (_, _))
        .build()
}
