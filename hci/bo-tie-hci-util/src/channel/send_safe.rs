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
use core::fmt::{Debug, Display, Formatter};
use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::pin::Pin;
use std::task::{Context, Poll};

/// Used to make a `impl ChannelReserve` send safe
///
/// The associated type of `impl ChannelReserve`, including the associated types of trait bounds on
/// the associated types, and the associated types on their bounds (and so on), do not have the
/// bound for `Send`. When `impl Trait` is returned by a public function or method any other crate
/// can only interpret the associated types by the direct bounds. [`ChannelReserve`] does not
/// directly bound `Send` to these associated types as it is implemented for types that are not
/// `Send`.  
///
/// The wrapper `SendSafe` is used for binding `Send` to all the associated types and sub associated
/// types within `ChannelReserve`.
pub struct SendSafe<T>(T)
where
    T: Send + ChannelReserve,
    T::Error: Send,
    T::SenderError: Send,
    T::ToHostCmdChannel: Send,
    <T::ToHostCmdChannel as Channel>::Sender: Send,
    <<T::ToHostCmdChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToHostCmdChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToHostCmdChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToHostCmdChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ToHostGenChannel: Send,
    <T::ToHostGenChannel as Channel>::Sender: Send,
    <<T::ToHostGenChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToHostGenChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToHostGenChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToHostGenChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::FromHostChannel: Send,
    <T::FromHostChannel as BufferReserve>::Buffer: Send,
    <T::FromHostChannel as BufferReserve>::TakeBuffer: Send,
    <T::FromHostChannel as Channel>::Sender: Send,
    <<T::FromHostChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::FromHostChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::FromHostChannel as Channel>::Receiver: Send,
    for<'a> <<T::FromHostChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ToConnectionChannel: Send,
    <T::ToConnectionChannel as BufferReserve>::Buffer: Send,
    <T::ToConnectionChannel as BufferReserve>::TakeBuffer: Send,
    <T::ToConnectionChannel as Channel>::Sender: Send,
    <<T::ToConnectionChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToConnectionChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToConnectionChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToConnectionChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::FromConnectionChannel: Send,
    <T::FromConnectionChannel as BufferReserve>::Buffer: Send,
    <T::FromConnectionChannel as BufferReserve>::TakeBuffer: Send,
    <T::FromConnectionChannel as Channel>::Sender: Send,
    <<T::FromConnectionChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::FromConnectionChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::FromConnectionChannel as Channel>::Receiver: Send,
    for<'a> <<T::FromConnectionChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ConnectionChannelEnds: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::ToBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::FromBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::TakeBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender: Send,
    <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender as Sender>::Error: Send,
    for<'a> <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::Receiver: Send,
    for<'a> <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Receiver as Receiver>::ReceiveFuture<'a>: Send;

impl<T> SendSafe<T>
where
    T: Send + ChannelReserve,
    T::Error: Send,
    T::SenderError: Send,
    T::ToHostCmdChannel: Send,
    <T::ToHostCmdChannel as Channel>::Sender: Send,
    <<T::ToHostCmdChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToHostCmdChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToHostCmdChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToHostCmdChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ToHostGenChannel: Send,
    <T::ToHostGenChannel as Channel>::Sender: Send,
    <<T::ToHostGenChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToHostGenChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToHostGenChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToHostGenChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::FromHostChannel: Send,
    <T::FromHostChannel as BufferReserve>::Buffer: Send,
    <T::FromHostChannel as BufferReserve>::TakeBuffer: Send,
    <T::FromHostChannel as Channel>::Sender: Send,
    <<T::FromHostChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::FromHostChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::FromHostChannel as Channel>::Receiver: Send,
    for<'a> <<T::FromHostChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ToConnectionChannel: Send,
    <T::ToConnectionChannel as BufferReserve>::Buffer: Send,
    <T::ToConnectionChannel as BufferReserve>::TakeBuffer: Send,
    <T::ToConnectionChannel as Channel>::Sender: Send,
    <<T::ToConnectionChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToConnectionChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToConnectionChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToConnectionChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::FromConnectionChannel: Send,
    <T::FromConnectionChannel as BufferReserve>::Buffer: Send,
    <T::FromConnectionChannel as BufferReserve>::TakeBuffer: Send,
    <T::FromConnectionChannel as Channel>::Sender: Send,
    <<T::FromConnectionChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::FromConnectionChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::FromConnectionChannel as Channel>::Receiver: Send,
    for<'a> <<T::FromConnectionChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ConnectionChannelEnds: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::ToBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::FromBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::TakeBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender: Send,
    <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender as Sender>::Error: Send,
    for<'a> <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::Receiver: Send,
    for<'a> <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
{
    pub fn new(t: T) -> Self
    where
        T: SendSafeChannelReserve,
    {
        SendSafe(t)
    }
}

impl<T> ChannelReserve for SendSafe<T>
where
    T: Send + ChannelReserve,
    T::Error: Send,
    T::SenderError: Send,
    T::ToHostCmdChannel: Send,
    <T::ToHostCmdChannel as Channel>::Sender: Send,
    <<T::ToHostCmdChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToHostCmdChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToHostCmdChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToHostCmdChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ToHostGenChannel: Send,
    <T::ToHostGenChannel as Channel>::Sender: Send,
    <<T::ToHostGenChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToHostGenChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToHostGenChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToHostGenChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::FromHostChannel: Send,
    <T::FromHostChannel as BufferReserve>::Buffer: Send,
    <T::FromHostChannel as BufferReserve>::TakeBuffer: Send,
    <T::FromHostChannel as Channel>::Sender: Send,
    <<T::FromHostChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::FromHostChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::FromHostChannel as Channel>::Receiver: Send,
    for<'a> <<T::FromHostChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ToConnectionChannel: Send,
    <T::ToConnectionChannel as BufferReserve>::Buffer: Send,
    <T::ToConnectionChannel as BufferReserve>::TakeBuffer: Send,
    <T::ToConnectionChannel as Channel>::Sender: Send,
    <<T::ToConnectionChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::ToConnectionChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ToConnectionChannel as Channel>::Receiver: Send,
    for<'a> <<T::ToConnectionChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::FromConnectionChannel: Send,
    <T::FromConnectionChannel as BufferReserve>::Buffer: Send,
    <T::FromConnectionChannel as BufferReserve>::TakeBuffer: Send,
    <T::FromConnectionChannel as Channel>::Sender: Send,
    <<T::FromConnectionChannel as Channel>::Sender as Sender>::Error: Send,
    for<'a> <<T::FromConnectionChannel as Channel>::Sender as Sender>::SendFuture<'a>: Send,
    <T::FromConnectionChannel as Channel>::Receiver: Send,
    for<'a> <<T::FromConnectionChannel as Channel>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
    T::ConnectionChannelEnds: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::ToBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::FromBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::TakeBuffer: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender: Send,
    <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender as Sender>::Error: Send,
    for<'a> <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Sender as Sender>::SendFuture<'a>: Send,
    <T::ConnectionChannelEnds as ConnectionChannelEnds>::Receiver: Send,
    for<'a> <<T::ConnectionChannelEnds as ConnectionChannelEnds>::Receiver as Receiver>::ReceiveFuture<'a>: Send,
{
    type Error = T::Error;
    type SenderError = T::SenderError;
    type ToHostCmdChannel = T::ToHostCmdChannel;
    type ToHostGenChannel = T::ToHostGenChannel;
    type FromHostChannel = T::FromHostChannel;
    type ToConnectionChannel = T::ToConnectionChannel;
    type FromConnectionChannel = T::FromConnectionChannel;
    type ConnectionChannelEnds = T::ConnectionChannelEnds;

    fn try_remove(&mut self, handle: ConnectionHandle) -> Result<(), Self::Error> {
        self.0.try_remove(handle)
    }

    fn add_new_connection(
        &mut self,
        handle: ConnectionHandle,
        flow_control_id: FlowControlId,
    ) -> Result<Self::ConnectionChannelEnds, Self::Error> {
        self.0.add_new_connection(handle, flow_control_id)
    }

    fn get_channel(
        &self,
        id: TaskId,
    ) -> Option<FromInterface<Self::ToHostCmdChannel, Self::ToHostGenChannel, Self::ToConnectionChannel>> {
        self.0.get_channel(id)
    }

    fn get_flow_control_id(&self, handle: ConnectionHandle) -> Option<FlowControlId> {
        self.0.get_flow_control_id(handle)
    }

    fn get_flow_ctrl_receiver(
        &mut self,
    ) -> &mut FlowCtrlReceiver<
        <Self::FromHostChannel as Channel>::Receiver,
        <Self::FromConnectionChannel as Channel>::Receiver,
    > {
        self.0.get_flow_ctrl_receiver()
    }
}

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
    Send + BufferReserve<Buffer = Self::SendSafeBuffer, TakeBuffer = Self::SendSafeTakeBuffer>
{
    type SendSafeBuffer: Send + Buffer + Unpin;
    type SendSafeTakeBuffer: Send + Future<Output = Self::SendSafeBuffer>;
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
