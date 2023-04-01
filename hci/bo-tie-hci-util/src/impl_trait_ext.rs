//! Traits that extend the bounds of traits within this library
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
//! [`ChannelReserve`]: ChannelReserve
//! [`HostChannelEnds`]: HostChannelEnds

use crate::{
    BufferReserve, Channel, ChannelReserve, ConnectionChannelEnds, FromConnectionIntraMessage, HostChannelEnds,
    Receiver, Sender, ToConnectionDataIntraMessage, ToConnectionEventIntraMessage, ToHostCommandIntraMessage,
    ToHostGeneralIntraMessage, ToInterfaceIntraMessage,
};
use bo_tie_util::buffer::{Buffer, TryExtend, TryFrontExtend, TryFrontRemove, TryRemove};
use core::fmt::{Debug, Display};
use core::future::Future;

/// The Send safe equivalent of [`Buffer`]
///
/// [`Buffer`]: Buffer
pub trait SendSafeBuffer:
    'static
    + Send
    + Buffer
    + TryExtend<u8, Error = Self::SendSafeTryExtendError>
    + TryRemove<u8, Error = Self::SendSafeTryRemoveError, RemoveIter<'static> = Self::SendSafeTryRemoveIter>
    + TryFrontExtend<u8, Error = Self::SendSafeTryFrontExtendError>
    + TryFrontRemove<
        u8,
        Error = Self::SendSafeTryFrontRemoveError,
        FrontRemoveIter<'static> = Self::SendSafeTryFrontRemoveIter,
    >
{
    type SendSafeTryExtendError: Debug + Display + Send + 'static;
    type SendSafeTryRemoveError: Debug + Display + Send + 'static;
    type SendSafeTryRemoveIter: Iterator<Item = u8> + Send + 'static;
    type SendSafeTryFrontExtendError: Debug + Display + Send + 'static;
    type SendSafeTryFrontRemoveError: Debug + Display + Send + 'static;
    type SendSafeTryFrontRemoveIter: Iterator<Item = u8> + Send + 'static;
}

impl<T> SendSafeBuffer for T
where
    T: 'static + Send + Buffer,
    <T as TryExtend<u8>>::Error: Send + 'static,
    <T as TryRemove<u8>>::Error: Send + 'static,
    <T as TryRemove<u8>>::RemoveIter<'static>: Send + 'static,
    <T as TryFrontExtend<u8>>::Error: Send + 'static,
    <T as TryFrontRemove<u8>>::Error: Send + 'static,
    <T as TryFrontRemove<u8>>::FrontRemoveIter<'static>: Send + 'static,
{
    type SendSafeTryExtendError = <T as TryExtend<u8>>::Error;
    type SendSafeTryRemoveError = <T as TryRemove<u8>>::Error;
    type SendSafeTryRemoveIter = <T as TryRemove<u8>>::RemoveIter<'static>;
    type SendSafeTryFrontExtendError = <T as TryFrontExtend<u8>>::Error;
    type SendSafeTryFrontRemoveError = <T as TryFrontRemove<u8>>::Error;
    type SendSafeTryFrontRemoveIter = <T as TryFrontRemove<u8>>::FrontRemoveIter<'static>;
}

/// Send safe equivalent of [`BufferReserve`]
///
/// [`BufferReserve`]: crate::BufferReserve
pub trait SendSafeBufferReserve:
    'static + Send + BufferReserve<Buffer = Self::SendSafeBuffer, TakeBuffer = Self::SendSafeTakeBuffer>
{
    type SendSafeBuffer: SendSafeBuffer;
    type SendSafeTakeBuffer: Send + 'static + Future<Output = Self::SendSafeBuffer>;
}

impl<T> SendSafeBufferReserve for T
where
    T: 'static + Send + BufferReserve,
    T::Buffer: SendSafeBuffer,
    T::TakeBuffer: Send + 'static,
{
    type SendSafeBuffer = T::Buffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
}

/// Send safe equivalent of [`Sender`]
///
/// [`Sender`]: crate::Sender
pub trait SendSafeSender: 'static
    + Send
    + Sender<Error = Self::SendSafeError, Message = Self::SendSafeMessage, SendFuture<'static> = Self::SendSafeSendFuture>
{
    type SendSafeError: Send + 'static + Debug;
    type SendSafeMessage: Send + 'static + Unpin;
    type SendSafeSendFuture: Send + 'static + Future<Output = Result<(), Self::SendSafeError>>;
}

impl<T> SendSafeSender for T
where
    T: 'static + Send + Sender,
    T::Error: Send + 'static,
    T::Message: Send + 'static,
    T::SendFuture<'static>: Send + 'static,
{
    type SendSafeError = T::Error;
    type SendSafeMessage = T::Message;
    type SendSafeSendFuture = T::SendFuture<'static>;
}

/// Send safe equivalent of [`Receiver`]
///
/// [`Receiver`]: crate::Receiver
pub trait SendSafeReceiver:
    'static + Send + Receiver<Message = Self::SendSafeMessage, ReceiveFuture<'static> = Self::SendSafeReceiveFuture>
{
    type SendSafeMessage: Send + 'static + Unpin;
    type SendSafeReceiveFuture: Send + 'static + Future<Output = Option<Self::SendSafeMessage>>;
}

impl<T> SendSafeReceiver for T
where
    T: 'static + Send + Receiver,
    T::Message: Send + 'static,
    T::ReceiveFuture<'static>: Send + 'static,
{
    type SendSafeMessage = T::Message;
    type SendSafeReceiveFuture = T::ReceiveFuture<'static>;
}

/// Send safe equivalent of [`Channel`]
///
/// [`Channel`]: crate::Channel
pub trait SendSafeChannel:
    'static
    + Send
    + Channel<
        SenderError = Self::SendSafeSenderError,
        Message = Self::SendSafeMessage,
        Sender = Self::SendSafeSender,
        Receiver = Self::SendSafeReceiver,
    >
{
    type SendSafeSenderError: Send + 'static + Debug;
    type SendSafeMessage: Send + 'static + Unpin;
    type SendSafeSender: SendSafeSender;
    type SendSafeReceiver: SendSafeReceiver;
}

impl<T> SendSafeChannel for T
where
    T: 'static + Send + Channel,
    T::SenderError: Send + 'static,
    T::Message: Send + 'static,
    T::Sender: SendSafeSender,
    T::Receiver: SendSafeReceiver,
{
    type SendSafeSenderError = T::SenderError;
    type SendSafeMessage = T::Message;
    type SendSafeSender = T::Sender;
    type SendSafeReceiver = T::Receiver;
}

/// Send safe equivalent of [`ConnectionChannelEnds`]
///
/// [`ConnectionChannelEnds`]: crate::ConnectionChannelEnds
pub trait SendSafeConnectionChannelEnds:
    'static
    + Send
    + ConnectionChannelEnds<
        ToBuffer = Self::SendSafeToBuffer,
        FromBuffer = Self::SendSafeFromBuffer,
        TakeBuffer = Self::SendSafeTakeBuffer,
        Sender = Self::SendSafeSender,
        DataReceiver = Self::SendSafeDataReceiver,
        EventReceiver = Self::SendSafeEventReceiver,
    >
{
    type SendSafeToBuffer: SendSafeBuffer;
    type SendSafeFromBuffer: SendSafeBuffer;
    type SendSafeTakeBuffer: Send + Future<Output = Self::SendSafeToBuffer>;
    type SendSafeSender: SendSafeSender<SendSafeMessage = FromConnectionIntraMessage<Self::SendSafeToBuffer>>;
    type SendSafeDataReceiver: SendSafeReceiver<
        SendSafeMessage = ToConnectionDataIntraMessage<Self::SendSafeFromBuffer>,
    >;
    type SendSafeEventReceiver: SendSafeReceiver<SendSafeMessage = ToConnectionEventIntraMessage>;
}

impl<T> SendSafeConnectionChannelEnds for T
where
    T: Send + 'static + ConnectionChannelEnds,
    T::ToBuffer: SendSafeBuffer,
    T::FromBuffer: SendSafeBuffer,
    T::TakeBuffer: Send + 'static,
    T::Sender: SendSafeSender<SendSafeMessage = FromConnectionIntraMessage<T::ToBuffer>>,
    T::DataReceiver: SendSafeReceiver<SendSafeMessage = ToConnectionDataIntraMessage<T::FromBuffer>>,
    T::EventReceiver: SendSafeReceiver<SendSafeMessage = ToConnectionEventIntraMessage>,
{
    type SendSafeToBuffer = T::ToBuffer;
    type SendSafeFromBuffer = T::FromBuffer;
    type SendSafeTakeBuffer = T::TakeBuffer;
    type SendSafeSender = T::Sender;
    type SendSafeDataReceiver = T::DataReceiver;
    type SendSafeEventReceiver = T::EventReceiver;
}

/// The Send safe equivalent of [`ChannelReserve`]
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
/// [`ChannelReserve`]: ChannelReserve
pub trait SendSafeChannelReserve:
    Send
    + 'static
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
    type SendSafeError: Debug + Send + 'static;
    type SendSafeSenderError: Debug + Send + 'static;
    type SendSafeToHostCmdChannel: SendSafeChannel<
        SendSafeSenderError = Self::SendSafeSenderError,
        SendSafeMessage = ToHostCommandIntraMessage,
    >;
    type SendSafeToHostGenChannel: SendSafeChannel<
        SendSafeSenderError = Self::SendSafeSenderError,
        SendSafeMessage = ToHostGeneralIntraMessage<Self::SendSafeConnectionChannelEnds>,
    >;
    type SendSafeFromHostChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SendSafeSenderError,
            SendSafeMessage = ToInterfaceIntraMessage<
                <Self::SendSafeFromHostChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;
    type SendSafeToConnectionDataChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SendSafeSenderError,
            SendSafeMessage = ToConnectionDataIntraMessage<
                <Self::SendSafeToConnectionDataChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;

    type SendSafeToConnectionEventChannel: SendSafeChannel<
        SendSafeSenderError = Self::SendSafeSenderError,
        SendSafeMessage = ToConnectionEventIntraMessage,
    >;

    type SendSafeFromConnectionChannel: SendSafeBufferReserve
        + SendSafeChannel<
            SendSafeSenderError = Self::SendSafeSenderError,
            SendSafeMessage = FromConnectionIntraMessage<
                <Self::SendSafeFromConnectionChannel as SendSafeBufferReserve>::SendSafeBuffer,
            >,
        >;
    type SendSafeConnectionChannelEnds: SendSafeConnectionChannelEnds;
}

impl<T> SendSafeChannelReserve for T
where
    T: Send + 'static + ChannelReserve,
    T::Error: Send + 'static,
    T::SenderError: Send + 'static,
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
    T::ToConnectionDataChannel: SendSafeBufferReserve
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

/// The Send safe equivalent of [`HostChannelEnds`]
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
    + 'static
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
    type SendSafeToBuffer: SendSafeBuffer;
    type SendSafeFromBuffer: SendSafeBuffer;
    type SendSafeTakeBuffer: Send + 'static + Future<Output = Self::ToBuffer>;
    type SendSafeSender: SendSafeSender<SendSafeMessage = ToInterfaceIntraMessage<Self::SendSafeToBuffer>>;
    type SendSafeCmdReceiver: SendSafeReceiver<SendSafeMessage = ToHostCommandIntraMessage>;
    type SendSafeGenReceiver: SendSafeReceiver<
        SendSafeMessage = ToHostGeneralIntraMessage<Self::SendSafeConnectionChannelEnds>,
    >;
    type SendSafeConnectionChannelEnds: SendSafeConnectionChannelEnds;
}

impl<T> SendSafeHostChannelEnds for T
where
    T: Send + 'static + HostChannelEnds,
    T::ToBuffer: SendSafeBuffer,
    T::FromBuffer: SendSafeBuffer,
    T::TakeBuffer: Send + 'static,
    T::Sender: SendSafeSender<SendSafeMessage = ToInterfaceIntraMessage<T::ToBuffer>>,
    T::CmdReceiver: SendSafeReceiver<SendSafeMessage = ToHostCommandIntraMessage>,
    T::GenReceiver: SendSafeReceiver<SendSafeMessage = ToHostGeneralIntraMessage<T::ConnectionChannelEnds>>,
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
