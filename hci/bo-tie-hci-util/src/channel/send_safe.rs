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
    BufferReserve, Channel, ChannelReserve, ConnectionChannelEnds, FromConnectionIntraMessage, HostChannelEnds,
    Receiver, Sender, ToConnectionDataIntraMessage, ToConnectionEventIntraMessage, ToHostCommandIntraMessage,
    ToHostGeneralIntraMessage, ToInterfaceIntraMessage,
};
use bo_tie_util::buffer::{Buffer, TryExtend, TryFrontExtend, TryFrontRemove, TryRemove};
use core::fmt::{Debug, Display};
use core::future::Future;

pub trait SendSafeBuffer<'a>:
    'static
    + Send
    + Buffer
    + TryExtend<u8, Error = Self::SendSafeTryExtendError>
    + TryRemove<u8, Error = Self::SendSafeTryRemoveError, RemoveIter<'a> = Self::SendSafeTryRemoveIter>
    + TryFrontExtend<u8, Error = Self::SendSafeTryFrontExtendError>
    + TryFrontRemove<
        u8,
        Error = Self::SendSafeTryFrontRemoveError,
        FrontRemoveIter<'a> = Self::SendSafeTryFrontRemoveIter,
    >
{
    type SendSafeTryExtendError: Debug + Display + Send;
    type SendSafeTryRemoveError: Debug + Display + Send;
    type SendSafeTryRemoveIter: Iterator<Item = u8> + Send;
    type SendSafeTryFrontExtendError: Debug + Display + Send;
    type SendSafeTryFrontRemoveError: Debug + Display + Send;
    type SendSafeTryFrontRemoveIter: Iterator<Item = u8> + Send;
}

impl<'a, T> SendSafeBuffer<'a> for T
where
    T: 'static + Send + Buffer,
    <T as TryExtend<u8>>::Error: Send,
    <T as TryRemove<u8>>::Error: Send,
    <T as TryRemove<u8>>::RemoveIter<'a>: Send,
    <T as TryFrontExtend<u8>>::Error: Send,
    <T as TryFrontRemove<u8>>::Error: Send,
    <T as TryFrontRemove<u8>>::FrontRemoveIter<'a>: Send,
{
    type SendSafeTryExtendError = <T as TryExtend<u8>>::Error;
    type SendSafeTryRemoveError = <T as TryRemove<u8>>::Error;
    type SendSafeTryRemoveIter = <T as TryRemove<u8>>::RemoveIter<'a>;
    type SendSafeTryFrontExtendError = <T as TryFrontExtend<u8>>::Error;
    type SendSafeTryFrontRemoveError = <T as TryFrontRemove<u8>>::Error;
    type SendSafeTryFrontRemoveIter = <T as TryFrontRemove<u8>>::FrontRemoveIter<'a>;
}

pub trait SendSafeBufferReserve:
    Send + BufferReserve<Buffer = Self::SendSafeBuffer, TakeBuffer = Self::SendSafeTakeBuffer>
{
    type SendSafeBuffer: for<'a> SendSafeBuffer<'a>;
    type SendSafeTakeBuffer: Send + Future<Output = Self::SendSafeBuffer>;
}

impl<T> SendSafeBufferReserve for T
where
    T: Send + BufferReserve,
    T::Buffer: for<'a> SendSafeBuffer<'a>,
    T::TakeBuffer: Send,
{
    type SendSafeBuffer = T::Buffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
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
        DataReceiver = Self::SendSafeDataReceiver,
        EventReceiver = Self::SendSafeEventReceiver,
    >
{
    type SendSafeToBuffer: for<'a> SendSafeBuffer<'a>;
    type SendSafeFromBuffer: for<'a> SendSafeBuffer<'a>;
    type SendSafeTakeBuffer: Send + Future<Output = Self::SendSafeToBuffer>;
    type SendSafeSender: for<'z> SendSafeSender<
        'z,
        SendSafeMessage = FromConnectionIntraMessage<Self::SendSafeToBuffer>,
    >;
    type SendSafeDataReceiver: for<'z> SendSafeReceiver<
        'z,
        SendSafeMessage = ToConnectionDataIntraMessage<Self::SendSafeFromBuffer>,
    >;
    type SendSafeEventReceiver: for<'z> SendSafeReceiver<'z, SendSafeMessage = ToConnectionEventIntraMessage>;
}

impl<T> SendSafeConnectionChannelEnds for T
where
    T: Send + ConnectionChannelEnds,
    T::ToBuffer: for<'a> SendSafeBuffer<'a>,
    T::FromBuffer: for<'a> SendSafeBuffer<'a>,
    T::TakeBuffer: Send,
    T::Sender: for<'a> SendSafeSender<'a, SendSafeMessage = FromConnectionIntraMessage<T::ToBuffer>>,
    T::DataReceiver: for<'a> SendSafeReceiver<'a, SendSafeMessage = ToConnectionDataIntraMessage<T::FromBuffer>>,
    T::EventReceiver: for<'a> SendSafeReceiver<'a, SendSafeMessage = ToConnectionEventIntraMessage>,
{
    type SendSafeToBuffer = T::ToBuffer;
    type SendSafeFromBuffer = T::FromBuffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
    type SendSafeSender = T::Sender;
    type SendSafeDataReceiver = T::DataReceiver;
    type SendSafeEventReceiver = T::EventReceiver;
}

/// The send safe equivalent of [`ChannelReserve`]
///
/// The main usage of this is with methods and functions that would normally return
/// `impl ChannelReserve` instead return `impl SendSafeChannelReserve`. The "need" to switch arises
/// from the associated types (and the associated types of the associated types (and the associated
/// types of those associated types (...ect))) of `ChannelReserve` not implementing `Send`. This can
/// be fixed by extrapolating the `impl ChannelReserve` to explicitly add the send bound to every
/// associated type, but that requires a massive and ugly `impl Trait` so `SendSafeChannelReserve`
/// was created to be used instead.
///
/// So long as all the associated types `Send` a type that implements `ChannelReserve` will also
/// implement `SendSafeChannelReserve` with one exception. The associated type
/// `SendSafeToConnectionChannel` needs to also implement `Sync`.
///
/// [`ChannelReserve`]: crate::ChannelReserve
pub trait SendSafeChannelReserve:
    Send
    + ChannelReserve<
        Error = Self::SendSafeError,
        SenderError = Self::SendSafeSenderError,
        ToHostCmdChannel = Self::SendSafeToHostCmdChannel,
        ToHostGenChannel = Self::SendSafeToHostGenChannel,
        FromHostChannel = Self::SendSafeFromHostChannel,
        ToConnectionDataChannel = Self::SendSafeToConnectionDataChannel,
        ToConnectionEventChannel = Self::SendSafeToConnectionEventChannel,
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
            SendSafeMessage = ToInterfaceIntraMessage<
                <Self::SendSafeFromHostChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;
    // This probably needs to be send safe as it gets "split"
    // between the interface and host async tasks at runtime.
    type SendSafeToConnectionDataChannel: Sync
        + SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SenderError,
            SendSafeMessage = ToConnectionDataIntraMessage<
                <Self::SendSafeToConnectionDataChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;

    type SendSafeToConnectionEventChannel: SendSafeChannel<
        SendSafeSenderError = Self::SenderError,
        SendSafeMessage = ToConnectionEventIntraMessage,
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
            SendSafeMessage = ToInterfaceIntraMessage<<T::FromHostChannel as SendSafeBufferReserve>::SendSafeBuffer>,
        >,
    T::ToConnectionDataChannel: Sync
        + SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = T::SenderError,
            SendSafeMessage = ToConnectionDataIntraMessage<
                <T::ToConnectionDataChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >,
    T::ToConnectionEventChannel:
        SendSafeChannel<SendSafeSenderError = T::SenderError, SendSafeMessage = ToConnectionEventIntraMessage>,

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
    type SendSafeToConnectionDataChannel = T::ToConnectionDataChannel;
    type SendSafeToConnectionEventChannel = T::ToConnectionEventChannel;
    type SendSafeFromConnectionChannel = T::FromConnectionChannel;
    type SendSafeConnectionChannelEnds = T::ConnectionChannelEnds;
}

/// The send safe equivalent of [`HostChannelEnds`]
///
/// The main usage of this is with methods and functions that would normally return
/// `impl HostChannelEnds` instead return `impl SendSafeHostChannelEnds`. The "need" to switch
/// arises from the associated types (and the associated types of the associated types (and the
/// associated types of those associated types (...ect))) of `HostChannelEnds` not implementing
/// `Send`. This can be fixed by extrapolating the `impl HostChannelEnds` to explicitly add the send
/// bound to associated type, but that requires a massive and ugly `impl Trait` so
/// `SendSafeHostChannelEnds` was created to be used instead.
///
/// So long as all the associated types `Send` a type that implements `HostChannelEnds` will also
/// implement `SendSafeHostChannelEnds`.
///
/// [`HostChannelEnds`]: crate::HostChannelEnds
pub trait SendSafeHostChannelEnds:
    Send
    + HostChannelEnds<
        ToBuffer = Self::SendSafeToBuffer,
        FromBuffer = Self::SendSafeFromBuffer,
        TakeBuffer = Self::SendSafeTakeBuffer,
        Sender = Self::SendSafeSender,
        CmdReceiver = Self::SendSafeCmdReceiver,
        GenReceiver = Self::SendSafeGenReceiver,
        ConnectionChannelEnds = Self::SendSafeConnectionChannelEnds,
    >
{
    type SendSafeToBuffer: for<'a> SendSafeBuffer<'a>;
    type SendSafeFromBuffer: for<'a> SendSafeBuffer<'a>;
    type SendSafeTakeBuffer: Send + Future<Output = Self::ToBuffer>;
    type SendSafeSender: for<'a> SendSafeSender<'a, Message = ToInterfaceIntraMessage<Self::SendSafeToBuffer>>;
    type SendSafeCmdReceiver: for<'a> SendSafeReceiver<'a, Message = ToHostCommandIntraMessage>;
    type SendSafeGenReceiver: for<'a> SendSafeReceiver<
        'a,
        Message = ToHostGeneralIntraMessage<Self::SendSafeConnectionChannelEnds>,
    >;
    type SendSafeConnectionChannelEnds: SendSafeConnectionChannelEnds;
}

impl<T> SendSafeHostChannelEnds for T
where
    T: Send + HostChannelEnds,
    T::ToBuffer: for<'a> SendSafeBuffer<'a>,
    T::FromBuffer: for<'a> SendSafeBuffer<'a>,
    T::TakeBuffer: Send,
    T::Sender: for<'a> SendSafeSender<'a, SendSafeMessage = ToInterfaceIntraMessage<T::ToBuffer>>,
    T::CmdReceiver: for<'a> SendSafeReceiver<'a, SendSafeMessage = ToHostCommandIntraMessage>,
    T::GenReceiver: for<'a> SendSafeReceiver<'a, SendSafeMessage = ToHostGeneralIntraMessage<T::ConnectionChannelEnds>>,
    T::ConnectionChannelEnds: SendSafeConnectionChannelEnds,
{
    type SendSafeToBuffer = T::ToBuffer;
    type SendSafeFromBuffer = T::FromBuffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
    type SendSafeSender = T::Sender;
    type SendSafeCmdReceiver = T::CmdReceiver;
    type SendSafeGenReceiver = T::GenReceiver;
    type SendSafeConnectionChannelEnds = T::ConnectionChannelEnds;
}
