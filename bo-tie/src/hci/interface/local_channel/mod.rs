//! A channel local to the host
//!
//! When the user wants to have the host, interface driver, and connections async tasks all running
//! within the same thread (essentially all tasks are `!Send`) a local channel is used for
//! communication. This channel consists of statically allocated buffer to store the messages that
//! are sent from the sender to the receiver.

mod local_dynamic_channel;
mod local_static_channel;

use core::fmt::{Display, Formatter};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
pub use local_dynamic_channel::LocalChannelManager;
pub use local_static_channel::LocalStackChannelReserve;

/// Trait for a buffer of the sender of a local channel
///
/// This trait is used for the `LocalSendFuture` and `LocalReceiverFuture` implementations.
pub trait LocalQueueBuffer {
    type Payload;

    /// Call the waker
    ///
    /// # Note
    /// This method will do nothing if no current waker is set
    fn call_waker(&self);

    /// Set the waker
    fn set_waker(&self, waker: Waker);
}

/// Trait for a buffer of the sender of a local channel
///
/// This trait is used for the `LocalSendFuture` and `LocalReceiverFuture` implementations.
trait LocalQueueBufferSend: LocalQueueBuffer {
    /// Check if the buffer is full
    fn is_full(&self) -> bool;

    /// Push an item to the buffer
    ///
    /// # Note
    /// This method is called after `is_full` returns false
    fn push(&self, packet: Self::Payload);
}

/// Trait for a buffer of the receiver of a local channel
///
/// This trait is used for the `LocalSendFuture` and `LocalReceiverFuture` implementations.
trait LocalQueueBufferReceive: LocalQueueBuffer {
    /// Check if there is any Senders associated with this Receiver
    fn has_senders(&self) -> bool;

    /// Check if the buffer is empty
    fn is_empty(&self) -> bool;

    /// Remove an item from the buffer
    ///
    /// # Note
    /// This method is called after `is_empty` returns false
    fn remove(&self) -> Self::Payload;
}

pub struct LocalSendFuture<'a, S, T> {
    packet: Option<T>,
    local_sender: &'a S,
}

impl<'a, S, T> LocalSendFuture<'a, S, T> {
    fn new(local_sender: &'a S, packet: T) -> Self {
        let packet = Some(packet);

        LocalSendFuture { packet, local_sender }
    }
}

#[derive(Debug)]
pub struct LocalSendFutureError;

impl Display for LocalSendFutureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("local send future error")
    }
}

impl<S, T> Future for LocalSendFuture<'_, S, T>
where
    S: LocalQueueBufferSend<Payload = T>,
{
    type Output = Result<(), LocalSendFutureError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        if !this.local_sender.is_full() {
            this.local_sender.push(this.packet.take().unwrap());

            // Wake the receiver if it's awaiting
            this.local_sender.call_waker();

            Poll::Ready(Ok(()))
        } else {
            // Buffer is full, need to await for the receiver to clear a few entries
            this.local_sender.set_waker(cx.waker().clone());

            Poll::Pending
        }
    }
}

pub struct LocalReceiverFuture<'a, S>(&'a S);

impl<S> Future for LocalReceiverFuture<'_, S>
where
    S: LocalQueueBufferReceive,
{
    type Output = Option<S::Payload>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut self.get_mut().0;

        if !this.has_senders() {
            Poll::Ready(None)
        } else if !this.is_empty() {
            let ret = this.remove();

            this.call_waker();

            Poll::Ready(Some(ret))
        } else {
            this.set_waker(cx.waker().clone());

            Poll::Pending
        }
    }
}

#[derive(Debug)]
pub struct LocalReceiverFutureError;

impl Display for LocalReceiverFutureError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.write_str("local receiver future error")
    }
}
