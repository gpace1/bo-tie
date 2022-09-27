//! [async-std] channel implementation
//!
//! [async-std]: async_std

use async_std::channel::{Receiver, Recv, Send, SendError, Sender};
use core::fmt::Debug;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

make_error!(Error, SendError, Sender, Receiver);

impl<T> crate::Sender for Sender<T>
where
    T: Unpin + Debug,
    Error: From<SendError<T>>,
{
    type Error = Error;
    type Message = T;
    type SendFuture<'a> = SendFuture<'a, T> where Self: 'a;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        SendFuture(Sender::send(self, t))
    }
}

pub struct SendFuture<'a, T>(Send<'a, T>);

impl<T> Future for SendFuture<'_, T>
where
    T: Unpin + Debug,
    Error: From<SendError<T>>,
{
    type Output = Result<(), Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match unsafe { self.map_unchecked_mut(|this| &mut this.0).poll(cx) } {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => Poll::Ready(Ok(())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
        }
    }
}

impl<T> crate::Receiver for Receiver<T>
where
    T: Unpin,
{
    type Message = T;
    type ReceiveFuture<'a> = ReceiverFuture<'a, T> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        async_std::stream::Stream::poll_next(Pin::new(self), cx)
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        ReceiverFuture(Receiver::recv(self))
    }
}

pub struct ReceiverFuture<'a, T>(Recv<'a, T>);

impl<T> Future for ReceiverFuture<'_, T> {
    type Output = Option<T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match unsafe { self.map_unchecked_mut(|this| &mut this.0).poll(cx) } {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(t)) => Poll::Ready(Some(t)),
            Poll::Ready(Err(_)) => Poll::Ready(None),
        }
    }
}

/// Create a [`ChannelReserve`] and [`HostChannelEnds`] using [async-std's] unbounded channels
///
/// The created `ChannelReserve` (and `HostChannelEnds`) use tokio's unbounded channels for
/// communication between the async tasks of the HCI implementation.
///
/// [async-std's]: async_std::channel
/// [`ChannelReserve`]: crate::ChannelReserve
/// [`HostChannelEnds`]: crate::HostChannelEnds
pub fn async_std_unbounded() -> (impl crate::ChannelReserve, impl crate::HostChannelEnds) {
    use async_std::channel::unbounded;

    super::ChannelReserveBuilder::new()
        .set_c1(unbounded)
        .set_c2(unbounded)
        .set_c3(unbounded)
        .set_c4(unbounded)
        .set_c5(unbounded)
        .build()
}
