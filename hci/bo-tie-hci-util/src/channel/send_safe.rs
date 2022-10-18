//! Module for guaranteeing Send safety
//!
//! Methods that use `impl Trait` for returning a [`ChannelReserve`] or [`HostChannelEnds`] do not
//! have the necessary `Send` restrictions for use with something like `tokio::send`. To combat
//! this, the traits [`SendSafeChannelReserve`] and [`SendSafeHostChannelEnds`] were created to add
//! the required `Send` bounds on *all* the associated types within the original traits. Instead of
//! returning `impl ChannelReserve` methods will instead return `impl SendSafeChannelReserve` (and
//! the same is true for `HostChannelEnds`).
//!
//! In a practical sense, just using these traits is not enough. Calling   
//!
//! [`ChannelReserve`]: crate::ChannelReserve
//! [`HostChannelEnds`]: crate::HostChannelEnds

use crate::{
    BufferReserve, Channel, ChannelReserve, ConnectionChannelEnds, ConnectionHandle, FlowControlId, FlowCtrlReceiver,
    FromConnectionIntraMessage, FromHostIntraMessage, FromInterface, Receiver, Sender, TaskId,
    ToConnectionIntraMessage, ToHostCommandIntraMessage, ToHostGeneralIntraMessage,
};
use bo_tie_util::buffer::{Buffer, TryExtend, TryFrontExtend, TryFrontRemove, TryRemove};
use core::fmt::Debug;
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

/// A wrapper for `impl SendSafeChannelReserve` or `impl SendSafeHostChannelEnds`
///
/// This wrapper is used to add the `Send` bound to the associated types of the traits
/// [`ChannelReserve`] and [`HostChannelEnds`] without
pub struct SendSafe<T>(T);

impl<T> SendSafe<T> {
    pub fn new(t: T) -> Self {
        SendSafe(t)
    }
}

// impl<T: Send + DerefMut<Target = [u8]>> DerefMut<Target = [u8]> for SendSafe<T> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         self.0.deref_mut()
//     }
// }
//
// impl<T: Send + Deref> Deref for SendSafe<T> {
//     type Target = [u8];
//
//     fn deref(&self) -> &Self::Target {
//         self.0.deref()
//     }
// }
//
// impl<T> TryExtend<u8> for SendSafe<T>
// where
//     T: Send + TryExtend<u8>,
//     T::Error: Send,
// {
//     type Error = T::Error;
//
//     fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
//     where
//         T: IntoIterator<Item = u8>,
//     {
//         self.0.try_extend(iter)
//     }
// }
//
// impl<T> TryRemove<u8> for SendSafe<T>
// where
//     T: Send + TryRemove<u8>,
//     T::Error: Send,
// {
//     type Error = T::Error;
//     type RemoveIter<'a> = T::RemoveIter<'a> where Self: 'a;
//
//     fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
//         self.0.try_remove(how_many)
//     }
// }
//
// impl<T> TryFrontExtend<u8> for SendSafe<T>
// where
//     T: Send + TryFrontExtend<u8>,
//     T::Error: Send,
// {
//     type Error = T::Error;
//
//     fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
//     where
//         T: IntoIterator<Item = u8>,
//     {
//         self.0.try_front_extend(iter)
//     }
// }
//
// impl<T> TryFrontRemove<u8> for SendSafe<T>
// where
//     T: Send + TryFrontRemove<u8>,
//     T::Error: Send,
// {
//     type Error = T::Error;
//     type FrontRemoveIter<'a> = T::FrontRemoveIter<'a> where Self: 'a;
//
//     fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
//         self.0.try_front_remove(how_many)
//     }
// }
//
// impl<T: Send + Buffer> Buffer for SendSafe<T> {
//     fn with_capacity(front: usize, back: usize) -> Self
//     where
//         Self: Sized,
//     {
//         Self(T::with_capacity(front: usize, back: usize))
//     }
//
//     fn clear_with_capacity(&mut self, front: usize, back: usize) {
//         self.0.clear_with_capacity(front, back)
//     }
// }
//
// impl<T> Future for SendSafe<T>
// where
//     T: Future + Send,
// {
//     type Output = T::Output;
//
//     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//         unsafe { self.map_unchecked_mut(|this| &mut this.0).poll(cx) }
//     }
// }
//
// impl<'z, T> Sender for SendSafe<T>
// where
//     T: SendSafeSender<'z>,
// {
//     type Error = T::SendSafeError;
//     type Message = T::SendSafeMessage;
//     type SendFuture<'a> = T::SendSafeSendFuture<'a> where Self: 'a;
//
//     fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
//         self.0.send(t)
//     }
// }
//
// impl<'z, T> Receiver for SendSafe<T>
// where
//     T: SendSafeReceiver<'z>,
// {
//     type Message = T::SendSafeMessage;
//     type ReceiveFuture<'a> = T::SendSafeReceiveFuture<'a> where Self: 'a;
//
//     fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
//         self.0.poll_recv(cx)
//     }
//
//     fn recv(&mut self) -> Self::ReceiveFuture<'_> {
//         self.0.recv()
//     }
// }
//
// impl<T> BufferReserve for SendSafe<T>
// where
//     T: SendSafeBufferReserve,
// {
//     type Buffer = T::SendSafeBuffer;
//     type TakeBuffer = T::SendSafeTakeBuffer;
//
//     fn take<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
//     where
//         F: Into<Option<usize>>,
//         B: Into<Option<usize>>,
//     {
//         self.0.take(front_capacity, back_capacity)
//     }
//
//     fn reclaim(&mut self, buffer: Self::Buffer) {
//         self.0.reclaim(buffer)
//     }
// }
//
// impl<T> Channel for SendSafe<T>
// where
//     T: SendSafeChannel,
// {
//     type SenderError = T::SendSafeSenderError;
//     type Message = T::SendSafeMessage;
//     type Sender = T::SendSafeSenderError;
//     type Receiver = T::SendSafeReceiver;
//
//     fn get_sender(&self) -> Self::Sender {
//         SendSafe(self.0.get_sender())
//     }
//
//     fn take_receiver(&self) -> Option<Self::Receiver> {
//         self.0.take_receiver().map(|rx| SendSafe(rx))
//     }
// }
//
// impl<T> ConnectionChannelEnds for SendSafe<T>
// where
//     T: Sized + SendSafeConnectionChannelEnds,
// {
//     type ToBuffer = T::SendSafeToBuffer;
//     type FromBuffer = T::SendSafeFromBuffer;
//     type TakeBuffer = SendSafe(T::SendSafeTakeBuffer);
//     type Sender = SendSafe(T::SendSafeSender);
//     type Receiver = SendSafe(T::SendSafeReceiver);
//
//     fn get_sender(&self) -> Self::Sender {
//         SendSafe(self.0.get_sender())
//     }
//
//     fn take_buffer<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
//     where
//         F: Into<Option<usize>>,
//         B: Into<Option<usize>>,
//     {
//         SendSafe(self.0.take_buffer(front_capacity, back_capacity))
//     }
//
//     fn get_receiver(&self) -> &Self::Receiver {
//         self.0.get_receiver()
//     }
// }
//
// impl<T> ChannelReserve for SendSafe<T>
// where
//     T: SendSafeChannelReserve,
// {
//     type Error = T::SendSafeError;
//     type SenderError = T::SendSafeSenderError;
//     type ToHostCmdChannel = T::SendSafeToHostCmdChannel;
//     type ToHostGenChannel = T::SendSafeToHostGenChannel;
//     type FromHostChannel = T::SendSafeFromHostChannel;
//     type ToConnectionChannel = T::SendSafeToConnectionChannel;
//     type FromConnectionChannel = T::SendSafeFromConnectionChannel;
//     type ConnectionChannelEnds = T::SendSafeConnectionChannelEnds;
//
//     fn try_remove(&mut self, handle: ConnectionHandle) -> Result<(), Self::Error> {
//         self.0.try_remove(handle)
//     }
//
//     fn add_new_connection(
//         &self,
//         handle: ConnectionHandle,
//         flow_control_id: FlowControlId,
//     ) -> Result<Self::ConnectionChannelEnds, Self::Error> {
//         self.0.add_new_connection(handle, flow_control_id)
//     }
//
//     fn get_channel(
//         &self,
//         id: TaskId,
//     ) -> Option<FromInterface<Self::ToHostCmdChannel, Self::ToHostGenChannel, Self::ToConnectionChannel>> {
//         self.0.get_channel(id)
//     }
//
//     fn get_flow_control_id(&self, handle: ConnectionHandle) -> Option<FlowControlId> {
//         self.0.get_flow_control_id(handle)
//     }
//
//     fn get_flow_ctrl_receiver(
//         &mut self,
//     ) -> &mut FlowCtrlReceiver<
//         <Self::FromHostChannel as Channel>::Receiver,
//         <Self::FromConnectionChannel as Channel>::Receiver,
//     > {
//         self.0.get_flow_ctrl_receiver()
//     }
// }

pub trait SendSafeSender<'z>:
    'z
    + Send
    + Sender<Error = Self::SendSafeError, Message = Self::SendSafeMessage, SendFuture<'z> = Self::SendSafeSendFuture>
{
    type SendSafeError: Send + Debug;
    type SendSafeMessage: Send + Unpin;
    type SendSafeSendFuture: Send + Future<Output = Result<(), Self::SendSafeError>>;
}

impl<'z, T> SendSafeSender<'z> for T
where
    T: 'z + Send + Sender,
    T::Error: Send,
    T::Message: Send,
    T::SendFuture<'z>: Send,
{
    type SendSafeError = T::Error;
    type SendSafeMessage = T::Message;
    type SendSafeSendFuture = T::SendFuture<'z>;
}

pub trait SendSafeReceiver<'z>:
    'z + Send + Receiver<Message = Self::SendSafeMessage, ReceiveFuture<'z> = Self::SendSafeReceiveFuture>
{
    type SendSafeMessage: Send + Unpin;
    type SendSafeReceiveFuture: Send + Future<Output = Option<Self::SendSafeMessage>>;
}

impl<'z, T> SendSafeReceiver<'z> for T
where
    T: 'z + Send + Receiver,
    T::Message: Send,
    T::ReceiveFuture<'z>: Send,
{
    type SendSafeMessage = T::Message;
    type SendSafeReceiveFuture = T::ReceiveFuture<'z>;
}

pub trait SendSafeBufferReserve:
    BufferReserve<Buffer = Self::SendSafeBuffer, TakeBuffer = Self::SendSafeTakeBuffer>
{
    type SendSafeBuffer: Send + Buffer + Unpin;
    type SendSafeTakeBuffer: Future<Output = Self::SendSafeBuffer>;
}

impl<T> SendSafeBufferReserve for T
where
    T: Send + BufferReserve,
    T::Buffer: Send,
    T::TakeBuffer: Send,
{
    type SendSafeBuffer = T::Buffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
}

pub trait SendSafeChannel:
    Send
    + Channel<
        SenderError = Self::SendSafeSenderError,
        Message = Self::SendSafeMessage,
        Sender = Self::SendSafeSender,
        Receiver = Self::SendSafeReceiver,
    >
{
    type SendSafeSenderError: Send + Debug;
    type SendSafeMessage: Send + Unpin;
    type SendSafeSender: for<'z> SendSafeSender<'z>;
    type SendSafeReceiver: for<'z> SendSafeReceiver<'z>;
}

impl<T> SendSafeChannel for T
where
    T: Send + Channel,
    T::SenderError: Send,
    T::Message: Send,
    T::Sender: for<'z> SendSafeSender<'z>,
    T::Receiver: for<'z> SendSafeReceiver<'z>,
{
    type SendSafeSenderError = T::SenderError;
    type SendSafeMessage = T::Message;
    type SendSafeSender = T::Sender;
    type SendSafeReceiver = T::Receiver;
}

pub trait SendSafeConnectionChannelEnds:
    Send
    + ConnectionChannelEnds<
        ToBuffer = Self::SendSafeToBuffer,
        FromBuffer = Self::SendSafeFromBuffer,
        TakeBuffer = Self::SendSafeTakeBuffer,
        Sender = Self::SendSafeSender,
        Receiver = Self::SendSafeReceiver,
    >
{
    type SendSafeToBuffer: Send + Buffer;
    type SendSafeFromBuffer: Send + Buffer;
    type SendSafeTakeBuffer: Send + Future<Output = Self::SendSafeToBuffer>;
    type SendSafeSender: for<'z> SendSafeSender<
        'z,
        SendSafeMessage = FromConnectionIntraMessage<Self::SendSafeToBuffer>,
    >;
    type SendSafeReceiver: for<'z> SendSafeReceiver<
        'z,
        SendSafeMessage = ToConnectionIntraMessage<Self::SendSafeFromBuffer>,
    >;
}

impl<T> SendSafeConnectionChannelEnds for T
where
    T: Send + ConnectionChannelEnds,
    T::ToBuffer: Send,
    T::FromBuffer: Send,
    T::TakeBuffer: Send,
    T::Sender: for<'a> SendSafeSender<'a, SendSafeMessage = FromConnectionIntraMessage<T::ToBuffer>>,
    T::Receiver: for<'a> SendSafeReceiver<'a, SendSafeMessage = ToConnectionIntraMessage<T::FromBuffer>>,
{
    type SendSafeToBuffer = T::ToBuffer;
    type SendSafeFromBuffer = T::FromBuffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
    type SendSafeSender = T::Sender;
    type SendSafeReceiver = T::Receiver;
}

pub trait SendSafeChannelReserve:
    Send
    + ChannelReserve<
        Error = Self::SendSafeError,
        SenderError = Self::SendSafeSenderError,
        ToHostCmdChannel = Self::SendSafeToHostCmdChannel,
        ToHostGenChannel = Self::SendSafeToHostGenChannel,
        FromHostChannel = Self::SendSafeFromHostChannel,
        ToConnectionChannel = Self::SendSafeToConnectionChannel,
        FromConnectionChannel = Self::SendSafeFromConnectionChannel,
        ConnectionChannelEnds = Self::SendSafeConnectionChannelEnds,
    >
{
    type SendSafeError: Debug + Send;
    type SendSafeSenderError: Debug + Send;
    type SendSafeToHostCmdChannel: SendSafeChannel<
        SendSafeSenderError = Self::SendSafeSenderError,
        SendSafeMessage = ToHostCommandIntraMessage,
    >;
    type SendSafeToHostGenChannel: SendSafeChannel<
        SendSafeSenderError = Self::SenderError,
        SendSafeMessage = ToHostGeneralIntraMessage<Self::SendSafeConnectionChannelEnds>,
    >;
    type SendSafeFromHostChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SenderError,
            SendSafeMessage = FromHostIntraMessage<
                <Self::SendSafeFromHostChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;
    type SendSafeToConnectionChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SenderError,
            SendSafeMessage = ToConnectionIntraMessage<
                <Self::SendSafeToConnectionChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;
    type SendSafeFromConnectionChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SenderError,
            SendSafeMessage = FromConnectionIntraMessage<
                <Self::SendSafeFromConnectionChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;
    type SendSafeConnectionChannelEnds: SendSafeConnectionChannelEnds;
}

impl<T> SendSafeChannelReserve for T
where
    T: Send + ChannelReserve,
    T::Error: Send,
    T::SenderError: Send,
    T::ToHostCmdChannel:
        SendSafeChannel<SendSafeSenderError = T::SenderError, SendSafeMessage = ToHostCommandIntraMessage>,
    T::ToHostGenChannel: SendSafeChannel<
        SendSafeSenderError = T::SenderError,
        SendSafeMessage = ToHostGeneralIntraMessage<T::ConnectionChannelEnds>,
    >,
    T::FromHostChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = T::SenderError,
            SendSafeMessage = FromHostIntraMessage<<T::FromHostChannel as SendSafeBufferReserve>::SendSafeBuffer>,
        >,
    T::ToConnectionChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = T::SenderError,
            SendSafeMessage = ToConnectionIntraMessage<
                <T::ToConnectionChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >,
    T::FromConnectionChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = T::SenderError,
            SendSafeMessage = FromConnectionIntraMessage<
                <T::FromConnectionChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >,
    T::ConnectionChannelEnds: SendSafeConnectionChannelEnds,
{
    type SendSafeError = T::Error;
    type SendSafeSenderError = T::SenderError;
    type SendSafeToHostCmdChannel = T::ToHostCmdChannel;
    type SendSafeToHostGenChannel = T::ToHostGenChannel;
    type SendSafeFromHostChannel = T::FromHostChannel;
    type SendSafeToConnectionChannel = T::ToConnectionChannel;
    type SendSafeFromConnectionChannel = T::FromConnectionChannel;
    type SendSafeConnectionChannelEnds = T::ConnectionChannelEnds;
}
