//! [tokio] channel implementations
//!
//! [tokio]: tokio

use bo_tie_core::buffer::de_vec::DeVec;
use core::fmt::Debug;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use tokio::sync::mpsc::{error, UnboundedReceiver, UnboundedSender};

make_error!(Error, error::SendError, UnboundedSender, UnboundedReceiver);

impl<T> crate::Sender for UnboundedSender<T>
where
    T: Unpin + Debug,
    Error: From<error::SendError<T>>,
{
    type Error = Error;
    type Message = T;
    type SendFuture<'a> = UnboundedSenderFuture<'a, T> where Self: 'a;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        UnboundedSenderFuture(self, t.into())
    }
}

/// Type used as the `SendFuture` of the implementation of [`Sender`] for `UnboundedSender`
///
/// [`Sender`]: crate::Sender
pub struct UnboundedSenderFuture<'a, T>(&'a UnboundedSender<T>, Option<T>);

impl<T> Future for UnboundedSenderFuture<'_, T>
where
    T: Unpin + Debug,
    Error: From<error::SendError<T>>,
{
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        let t = this.1.take().unwrap();

        match UnboundedSender::send(this.0, t) {
            Ok(_) => Poll::Ready(Ok(())),
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }
}

impl<T> crate::Receiver for UnboundedReceiver<T>
where
    T: Unpin + Debug,
{
    type Message = T;
    type ReceiveFuture<'a> = UnboundedReceiverFuture<'a, T> where Self: 'a,;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        self.poll_recv(cx)
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        UnboundedReceiverFuture(self)
    }
}

/// Type used as the `ReceiveFuture` of the implementation of [`Receiver`] for `UnboundedReceiver`
///
/// [`Receiver`]: crate::Receiver
pub struct UnboundedReceiverFuture<'a, T>(&'a mut UnboundedReceiver<T>);

impl<T> Future for UnboundedReceiverFuture<'_, T>
where
    T: Unpin,
{
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.get_mut().0.poll_recv(cx)
    }
}

/// The [`ChannelReserve`] type as implemented by `tokio`'s unbounded channels
///
/// [`ChannelReserve`]: crate::channel::ChannelReserve
pub type UnboundedChannelReserve = crate::channel::ChannelReserve<
    UnboundedSender<crate::ToHostCommandIntraMessage>,
    UnboundedSender<
        crate::ToHostGeneralIntraMessage<
            crate::channel::ConnectionEnds<
                UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
                UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
                UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
            >,
        >,
    >,
    UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
    UnboundedSender<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    UnboundedSender<crate::ToConnectionEventIntraMessage>,
    UnboundedReceiver<crate::ToInterfaceIntraMessage<DeVec<u8>>>,
    UnboundedReceiver<crate::FromConnectionIntraMessage<DeVec<u8>>>,
    fn() -> (
        UnboundedSender<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
        UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    ),
    fn() -> (
        UnboundedSender<crate::ToConnectionEventIntraMessage>,
        UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
    ),
    UnboundedSender<crate::ToInterfaceIntraMessage<DeVec<u8>>>,
    UnboundedReceiver<crate::ToHostCommandIntraMessage>,
    UnboundedReceiver<
        crate::ToHostGeneralIntraMessage<
            crate::channel::ConnectionEnds<
                UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
                UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
                UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
            >,
        >,
    >,
    UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
>;

/// The [`HostChannelEnds`] type as implemented by `tokio`'s unbounded channels
///
/// [`HostChannelEnds`]: crate::channel::HostChannelEnds
pub type UnboundedHostChannelEnds = crate::channel::HostChannelEnds<
    UnboundedSender<crate::ToInterfaceIntraMessage<DeVec<u8>>>,
    UnboundedReceiver<crate::ToHostCommandIntraMessage>,
    UnboundedReceiver<
        crate::ToHostGeneralIntraMessage<
            crate::channel::ConnectionEnds<
                UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
                UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
                UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
            >,
        >,
    >,
    UnboundedSender<crate::FromConnectionIntraMessage<DeVec<u8>>>,
    UnboundedReceiver<crate::ToConnectionDataIntraMessage<DeVec<u8>>>,
    UnboundedReceiver<crate::ToConnectionEventIntraMessage>,
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
/// [`ChannelReserveBuilder::new`]:
pub fn tokio_unbounded(front_size: usize, tail_size: usize) -> (UnboundedChannelReserve, UnboundedHostChannelEnds) {
    use tokio::sync::mpsc::unbounded_channel;

    super::ChannelReserveBuilder::new(front_size, tail_size)
        .set_c1(unbounded_channel)
        .set_c2(unbounded_channel)
        .set_c3(unbounded_channel)
        .set_c4(unbounded_channel)
        .set_c5(unbounded_channel as fn() -> (_, _))
        .set_c6(unbounded_channel as fn() -> (_, _))
        .build()
}
