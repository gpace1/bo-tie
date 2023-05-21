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
//! [`ChannelReserve`]: crate::ChannelReserve
//! [`HostChannelEnds`]: crate::HostChannelEnds

use crate::{
    BufferReserve, Channel, ChannelReserve, ConnectionChannelEnds, FromConnectionIntraMessage, HostChannelEnds,
    Receiver, Sender, ToConnectionDataIntraMessage, ToConnectionEventIntraMessage, ToHostCommandIntraMessage,
    ToHostGeneralIntraMessage, ToInterfaceIntraMessage,
};
use bo_tie_core::buffer::{Buffer, TryExtend, TryFrontExtend, TryFrontRemove, TryRemove};
use core::fmt::{Debug, Display};
use core::future::Future;

/// Send safe equivalent of [`Buffer`]
///
/// [`Buffer`]: bo_tie_core::buffer::Buffer
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

/// Send and Sync safe equivalent of [`Buffer`]
///
/// [`Buffer`]: bo_tie_core::buffer::Buffer
pub trait SendAndSyncSafeBuffer<'a>:
    'static
    + Send
    + Sync
    + Buffer
    + TryExtend<u8, Error = Self::SendAndSyncSafeTryExtendError>
    + TryRemove<u8, Error = Self::SendAndSyncSafeTryRemoveError, RemoveIter<'a> = Self::SendAndSyncSafeTryRemoveIter>
    + TryFrontExtend<u8, Error = Self::SendAndSyncSafeTryFrontExtendError>
    + TryFrontRemove<
        u8,
        Error = Self::SendAndSyncSafeTryFrontRemoveError,
        FrontRemoveIter<'a> = Self::SendAndSyncSafeTryFrontRemoveIter,
    >
{
    type SendAndSyncSafeTryExtendError: Debug + Display + Send + Sync;
    type SendAndSyncSafeTryRemoveError: Debug + Display + Send + Sync;
    type SendAndSyncSafeTryRemoveIter: Iterator<Item = u8> + Send + Sync;
    type SendAndSyncSafeTryFrontExtendError: Debug + Display + Send + Sync;
    type SendAndSyncSafeTryFrontRemoveError: Debug + Display + Send + Sync;
    type SendAndSyncSafeTryFrontRemoveIter: Iterator<Item = u8> + Send + Sync;
}

impl<'a, T> SendAndSyncSafeBuffer<'a> for T
where
    T: 'static + Send + Sync + Buffer,
    <T as TryExtend<u8>>::Error: Send + Sync,
    <T as TryRemove<u8>>::Error: Send + Sync,
    <T as TryRemove<u8>>::RemoveIter<'a>: Send + Sync,
    <T as TryFrontExtend<u8>>::Error: Send + Sync,
    <T as TryFrontRemove<u8>>::Error: Send + Sync,
    <T as TryFrontRemove<u8>>::FrontRemoveIter<'a>: Send + Sync,
{
    type SendAndSyncSafeTryExtendError = <T as TryExtend<u8>>::Error;
    type SendAndSyncSafeTryRemoveError = <T as TryRemove<u8>>::Error;
    type SendAndSyncSafeTryRemoveIter = <T as TryRemove<u8>>::RemoveIter<'a>;
    type SendAndSyncSafeTryFrontExtendError = <T as TryFrontExtend<u8>>::Error;
    type SendAndSyncSafeTryFrontRemoveError = <T as TryFrontRemove<u8>>::Error;
    type SendAndSyncSafeTryFrontRemoveIter = <T as TryFrontRemove<u8>>::FrontRemoveIter<'a>;
}

/// Send safe equivalent of [`BufferReserve`]
///
/// [`BufferReserve`]: crate::BufferReserve
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

/// Send and Sync safe equivalent of [`BufferReserve`]
///
/// [`BufferReserve`]: crate::BufferReserve
pub trait SendAndSyncSafeBufferReserve:
    Send + Sync + BufferReserve<Buffer = Self::SendAndSyncSafeBuffer, TakeBuffer = Self::SendAndSyncSafeTakeBuffer>
{
    type SendAndSyncSafeBuffer: for<'a> SendAndSyncSafeBuffer<'a>;
    type SendAndSyncSafeTakeBuffer: Send + Sync + Future<Output = Self::SendAndSyncSafeBuffer>;
}

impl<T> SendAndSyncSafeBufferReserve for T
where
    T: Send + Sync + BufferReserve,
    T::Buffer: for<'a> SendAndSyncSafeBuffer<'a>,
    T::TakeBuffer: Send + Sync,
{
    type SendAndSyncSafeBuffer = T::Buffer;
    type SendAndSyncSafeTakeBuffer = T::TakeBuffer;
}

/// Send safe equivalent of [`Sender`]
///
/// [`Sender`]: crate::Sender
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

/// Send and Sync safe equivalent of [`Sender`]
///
/// [`Sender`]: crate::Sender
pub trait SendAndSyncSafeSender<'z>:
    'z
    + Send
    + Sync
    + Sender<
        Error = Self::SendAndSyncSafeError,
        Message = Self::SendAndSyncSafeMessage,
        SendFuture<'z> = Self::SendAndSyncSafeSendFuture,
    >
{
    type SendAndSyncSafeError: Send + Sync + Debug;
    type SendAndSyncSafeMessage: Send + Sync + Unpin;
    type SendAndSyncSafeSendFuture: Send + Sync + Future<Output = Result<(), Self::SendAndSyncSafeError>>;
}

impl<'z, T> SendAndSyncSafeSender<'z> for T
where
    T: 'z + Send + Sync + Sender,
    T::Error: Send + Sync,
    T::Message: Send + Sync,
    T::SendFuture<'z>: Send + Sync,
{
    type SendAndSyncSafeError = T::Error;
    type SendAndSyncSafeMessage = T::Message;
    type SendAndSyncSafeSendFuture = T::SendFuture<'z>;
}

/// Send safe equivalent of [`Receiver`]
///
/// [`Receiver`]: crate::Receiver
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

/// Send and Sync safe equivalent of [`Receiver`]
///
/// [`Receiver`]: crate::Receiver
pub trait SendAndSyncSafeReceiver<'z>:
    'z
    + Send
    + Sync
    + Receiver<Message = Self::SendAndSyncSafeMessage, ReceiveFuture<'z> = Self::SendAndSyncSafeReceiveFuture>
{
    type SendAndSyncSafeMessage: Send + Sync + Unpin;
    type SendAndSyncSafeReceiveFuture: Send + Sync + Future<Output = Option<Self::SendAndSyncSafeMessage>>;
}

impl<'z, T> SendAndSyncSafeReceiver<'z> for T
where
    T: 'z + Send + Sync + Receiver,
    T::Message: Send + Sync,
    T::ReceiveFuture<'z>: Send + Sync,
{
    type SendAndSyncSafeMessage = T::Message;
    type SendAndSyncSafeReceiveFuture = T::ReceiveFuture<'z>;
}

/// Send safe equivalent of [`Channel`]
///
/// [`Channel`]: crate::Channel
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

/// Send and Sync safe equivalent of [`Channel`]
///
/// [`Channel`]: crate::Channel
pub trait SendAndSyncSafeChannel:
    Send
    + Sync
    + Channel<
        SenderError = Self::SendAndSyncSafeSenderError,
        Message = Self::SendAndSyncSafeMessage,
        Sender = Self::SendAndSyncSafeSender,
        Receiver = Self::SendAndSyncSafeReceiver,
    >
{
    type SendAndSyncSafeSenderError: Send + Sync + Debug;
    type SendAndSyncSafeMessage: Send + Sync + Unpin;
    type SendAndSyncSafeSender: for<'z> SendAndSyncSafeSender<'z>;
    type SendAndSyncSafeReceiver: for<'z> SendAndSyncSafeReceiver<'z>;
}

impl<T> SendAndSyncSafeChannel for T
where
    T: Send + Sync + Channel,
    T::SenderError: Send + Sync,
    T::Message: Send + Sync,
    T::Sender: for<'z> SendAndSyncSafeSender<'z>,
    T::Receiver: for<'z> SendAndSyncSafeReceiver<'z>,
{
    type SendAndSyncSafeSenderError = T::SenderError;
    type SendAndSyncSafeMessage = T::Message;
    type SendAndSyncSafeSender = T::Sender;
    type SendAndSyncSafeReceiver = T::Receiver;
}

/// Send safe equivalent of [`ConnectionChannelEnds`]
///
/// [`ConnectionChannelEnds`]: crate::ConnectionChannelEnds
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

/// Send and Sync safe equivalent of [`ConnectionChannelEnds`]
///
/// [`ConnectionChannelEnds`]: crate::ConnectionChannelEnds
pub trait SendAndSyncSafeConnectionChannelEnds:
    Send
    + Sync
    + ConnectionChannelEnds<
        ToBuffer = Self::SendAndSyncSafeToBuffer,
        FromBuffer = Self::SendAndSyncSafeFromBuffer,
        TakeBuffer = Self::SendAndSyncSafeTakeBuffer,
        Sender = Self::SendAndSyncSafeSender,
        DataReceiver = Self::SendAndSyncSafeDataReceiver,
        EventReceiver = Self::SendAndSyncSafeEventReceiver,
    >
{
    type SendAndSyncSafeToBuffer: for<'a> SendAndSyncSafeBuffer<'a>;
    type SendAndSyncSafeFromBuffer: for<'a> SendAndSyncSafeBuffer<'a>;
    type SendAndSyncSafeTakeBuffer: Send + Sync + Future<Output = Self::SendAndSyncSafeToBuffer>;
    type SendAndSyncSafeSender: for<'z> SendAndSyncSafeSender<
        'z,
        SendAndSyncSafeMessage = FromConnectionIntraMessage<Self::SendAndSyncSafeToBuffer>,
    >;
    type SendAndSyncSafeDataReceiver: for<'z> SendAndSyncSafeReceiver<
        'z,
        SendAndSyncSafeMessage = ToConnectionDataIntraMessage<Self::SendAndSyncSafeFromBuffer>,
    >;
    type SendAndSyncSafeEventReceiver: for<'z> SendAndSyncSafeReceiver<
        'z,
        SendAndSyncSafeMessage = ToConnectionEventIntraMessage,
    >;
}

impl<T> SendAndSyncSafeConnectionChannelEnds for T
where
    T: Send + Sync + ConnectionChannelEnds,
    T::ToBuffer: for<'a> SendAndSyncSafeBuffer<'a>,
    T::FromBuffer: for<'a> SendAndSyncSafeBuffer<'a>,
    T::TakeBuffer: Send + Sync,
    T::Sender: for<'a> SendAndSyncSafeSender<'a, SendAndSyncSafeMessage = FromConnectionIntraMessage<T::ToBuffer>>,
    T::DataReceiver:
        for<'a> SendAndSyncSafeReceiver<'a, SendAndSyncSafeMessage = ToConnectionDataIntraMessage<T::FromBuffer>>,
    T::EventReceiver: for<'a> SendAndSyncSafeReceiver<'a, SendAndSyncSafeMessage = ToConnectionEventIntraMessage>,
{
    type SendAndSyncSafeToBuffer = T::ToBuffer;
    type SendAndSyncSafeFromBuffer = T::FromBuffer;
    type SendAndSyncSafeTakeBuffer = T::TakeBuffer;
    type SendAndSyncSafeSender = T::Sender;
    type SendAndSyncSafeDataReceiver = T::DataReceiver;
    type SendAndSyncSafeEventReceiver = T::EventReceiver;
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

/// The Send and Sync safe equivalent of [`ChannelReserve`]
///
/// The main usage of this is with methods and functions that would normally return
/// `impl ChannelReserve` instead return `impl SendAndSyncSafeChannelReserve`. The "need" to switch
/// arises from the associated types (and the associated types of the associated types (and the
/// associated types of those associated types (...ect))) of `ChannelReserve` not implementing
/// `Send`. This can be fixed by extrapolating the `impl ChannelReserve` to explicitly add the send
/// bound to every associated type, but that requires a massive and ugly `impl Trait` so
/// `SendSafeChannelReserve` was created to be used instead.
///
/// So long as all the associated types `Send` a type that implements `ChannelReserve` will also
/// implement `SendAndSyncSafeChannelReserve` with one exception. The associated type
/// `SendAndSyncSafeToConnectionChannel` needs to also implement `Sync`.
///
/// [`ChannelReserve`]: crate::ChannelReserve
pub trait SendAndSyncSafeChannelReserve:
    Send
    + Sync
    + ChannelReserve<
        Error = Self::SendAndSyncSafeError,
        SenderError = Self::SendAndSyncSafeSenderError,
        ToHostCmdChannel = Self::SendAndSyncSafeToHostCmdChannel,
        ToHostGenChannel = Self::SendAndSyncSafeToHostGenChannel,
        FromHostChannel = Self::SendAndSyncSafeFromHostChannel,
        ToConnectionDataChannel = Self::SendAndSyncSafeToConnectionDataChannel,
        ToConnectionEventChannel = Self::SendAndSyncSafeToConnectionEventChannel,
        FromConnectionChannel = Self::SendAndSyncSafeFromConnectionChannel,
        ConnectionChannelEnds = Self::SendAndSyncSafeConnectionChannelEnds,
    >
{
    type SendAndSyncSafeError: Debug + Send + Sync;
    type SendAndSyncSafeSenderError: Debug + Send + Sync;
    type SendAndSyncSafeToHostCmdChannel: SendAndSyncSafeChannel<
        SendAndSyncSafeSenderError = Self::SendAndSyncSafeSenderError,
        SendAndSyncSafeMessage = ToHostCommandIntraMessage,
    >;
    type SendAndSyncSafeToHostGenChannel: SendAndSyncSafeChannel<
        SendAndSyncSafeSenderError = Self::SendAndSyncSafeSenderError,
        SendAndSyncSafeMessage = ToHostGeneralIntraMessage<Self::SendAndSyncSafeConnectionChannelEnds>,
    >;
    type SendAndSyncSafeFromHostChannel: SendAndSyncSafeBufferReserve
        + SendAndSyncSafeChannel<
            SendAndSyncSafeSenderError = Self::SendAndSyncSafeSenderError,
            SendAndSyncSafeMessage = ToInterfaceIntraMessage<
                <Self::SendAndSyncSafeFromHostChannel as SendAndSyncSafeBufferReserve>::SendAndSyncSafeBuffer,
            >,
        >;
    type SendAndSyncSafeToConnectionDataChannel: SendAndSyncSafeBufferReserve
        + SendAndSyncSafeChannel<
            SendAndSyncSafeSenderError = Self::SendAndSyncSafeSenderError,
            SendAndSyncSafeMessage = ToConnectionDataIntraMessage<
                <Self::SendAndSyncSafeToConnectionDataChannel as SendAndSyncSafeBufferReserve>::SendAndSyncSafeBuffer,
            >,
        >;

    type SendAndSyncSafeToConnectionEventChannel: SendAndSyncSafeChannel<
        SendAndSyncSafeSenderError = Self::SendAndSyncSafeSenderError,
        SendAndSyncSafeMessage = ToConnectionEventIntraMessage,
    >;

    type SendAndSyncSafeFromConnectionChannel: SendAndSyncSafeBufferReserve
        + SendAndSyncSafeChannel<
            SendAndSyncSafeSenderError = Self::SendAndSyncSafeSenderError,
            SendAndSyncSafeMessage = FromConnectionIntraMessage<
                <Self::SendAndSyncSafeFromConnectionChannel as SendAndSyncSafeBufferReserve>::SendAndSyncSafeBuffer,
            >,
        >;
    type SendAndSyncSafeConnectionChannelEnds: SendAndSyncSafeConnectionChannelEnds;
}

impl<T> SendAndSyncSafeChannelReserve for T
where
    T: Send + Sync + ChannelReserve,
    T::Error: Send + Sync,
    T::SenderError: Send + Sync,
    T::ToHostCmdChannel: SendAndSyncSafeChannel<
        SendAndSyncSafeSenderError = T::SenderError,
        SendAndSyncSafeMessage = ToHostCommandIntraMessage,
    >,
    T::ToHostGenChannel: SendAndSyncSafeChannel<
        SendAndSyncSafeSenderError = T::SenderError,
        SendAndSyncSafeMessage = ToHostGeneralIntraMessage<T::ConnectionChannelEnds>,
    >,
    T::FromHostChannel: SendAndSyncSafeBufferReserve
        + SendAndSyncSafeChannel<
            SendAndSyncSafeSenderError = T::SenderError,
            SendAndSyncSafeMessage = ToInterfaceIntraMessage<
                <T::FromHostChannel as SendAndSyncSafeBufferReserve>::SendAndSyncSafeBuffer,
            >,
        >,
    T::ToConnectionDataChannel: SendAndSyncSafeBufferReserve
        + SendAndSyncSafeChannel<
            SendAndSyncSafeSenderError = T::SenderError,
            SendAndSyncSafeMessage = ToConnectionDataIntraMessage<
                <T::ToConnectionDataChannel as SendAndSyncSafeBufferReserve>::SendAndSyncSafeBuffer,
            >,
        >,
    T::ToConnectionEventChannel: SendAndSyncSafeChannel<
        SendAndSyncSafeSenderError = T::SenderError,
        SendAndSyncSafeMessage = ToConnectionEventIntraMessage,
    >,

    T::FromConnectionChannel: SendAndSyncSafeBufferReserve
        + SendAndSyncSafeChannel<
            SendAndSyncSafeSenderError = T::SenderError,
            SendAndSyncSafeMessage = FromConnectionIntraMessage<
                <T::FromConnectionChannel as SendAndSyncSafeBufferReserve>::SendAndSyncSafeBuffer,
            >,
        >,
    T::ConnectionChannelEnds: SendAndSyncSafeConnectionChannelEnds,
{
    type SendAndSyncSafeError = T::Error;
    type SendAndSyncSafeSenderError = T::SenderError;
    type SendAndSyncSafeToHostCmdChannel = T::ToHostCmdChannel;
    type SendAndSyncSafeToHostGenChannel = T::ToHostGenChannel;
    type SendAndSyncSafeFromHostChannel = T::FromHostChannel;
    type SendAndSyncSafeToConnectionDataChannel = T::ToConnectionDataChannel;
    type SendAndSyncSafeToConnectionEventChannel = T::ToConnectionEventChannel;
    type SendAndSyncSafeFromConnectionChannel = T::FromConnectionChannel;
    type SendAndSyncSafeConnectionChannelEnds = T::ConnectionChannelEnds;
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
    type SendSafeSender: for<'a> SendSafeSender<'a, SendSafeMessage = ToInterfaceIntraMessage<Self::SendSafeToBuffer>>;
    type SendSafeCmdReceiver: for<'a> SendSafeReceiver<'a, SendSafeMessage = ToHostCommandIntraMessage>;
    type SendSafeGenReceiver: for<'a> SendSafeReceiver<
        'a,
        SendSafeMessage = ToHostGeneralIntraMessage<Self::SendSafeConnectionChannelEnds>,
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

/// The Send and Sync safe equivalent of [`HostChannelEnds`]
///
/// The main usage of this is with methods and functions that would normally return
/// `impl HostChannelEnds` instead return `impl SendAndSyncSafeHostChannelEnds`. The "need" to
/// switch arises from the associated types (and the associated types of the associated types (and
/// the associated types of those associated types (...ect))) of `HostChannelEnds` not implementing
/// `Send`. This can be fixed by extrapolating the `impl HostChannelEnds` to explicitly add the send
/// bound to associated type, but that requires a massive and ugly `impl Trait` so
/// `SendAndSyncSafeHostChannelEnds` was created to be used instead.
///
/// So long as all the associated types `Send` a type that implements `HostChannelEnds` will also
/// implement `SendAndSyncSafeHostChannelEnds`.
///
/// [`HostChannelEnds`]: crate::HostChannelEnds
pub trait SendAndSyncSafeHostChannelEnds:
    Send
    + Sync
    + HostChannelEnds<
        ToBuffer = Self::SendAndSyncSafeToBuffer,
        FromBuffer = Self::SendAndSyncSafeFromBuffer,
        TakeBuffer = Self::SendAndSyncSafeTakeBuffer,
        Sender = Self::SendAndSyncSafeSender,
        CmdReceiver = Self::SendAndSyncSafeCmdReceiver,
        GenReceiver = Self::SendAndSyncSafeGenReceiver,
        ConnectionChannelEnds = Self::SendAndSyncSafeConnectionChannelEnds,
    >
{
    type SendAndSyncSafeToBuffer: for<'a> SendAndSyncSafeBuffer<'a>;
    type SendAndSyncSafeFromBuffer: for<'a> SendAndSyncSafeBuffer<'a>;
    type SendAndSyncSafeTakeBuffer: Send + Sync + Future<Output = Self::ToBuffer>;
    type SendAndSyncSafeSender: for<'a> SendAndSyncSafeSender<
        'a,
        SendAndSyncSafeMessage = ToInterfaceIntraMessage<Self::SendAndSyncSafeToBuffer>,
    >;
    type SendAndSyncSafeCmdReceiver: for<'a> SendAndSyncSafeReceiver<
        'a,
        SendAndSyncSafeMessage = ToHostCommandIntraMessage,
    >;
    type SendAndSyncSafeGenReceiver: for<'a> SendAndSyncSafeReceiver<
        'a,
        SendAndSyncSafeMessage = ToHostGeneralIntraMessage<Self::SendAndSyncSafeConnectionChannelEnds>,
    >;
    type SendAndSyncSafeConnectionChannelEnds: SendAndSyncSafeConnectionChannelEnds;
}

impl<T> SendAndSyncSafeHostChannelEnds for T
where
    T: Send + Sync + HostChannelEnds,
    T::ToBuffer: for<'a> SendAndSyncSafeBuffer<'a>,
    T::FromBuffer: for<'a> SendAndSyncSafeBuffer<'a>,
    T::TakeBuffer: Send + Sync,
    T::Sender: for<'a> SendAndSyncSafeSender<'a, SendAndSyncSafeMessage = ToInterfaceIntraMessage<T::ToBuffer>>,
    T::CmdReceiver: for<'a> SendAndSyncSafeReceiver<'a, SendAndSyncSafeMessage = ToHostCommandIntraMessage>,
    T::GenReceiver: for<'a> SendAndSyncSafeReceiver<
        'a,
        SendAndSyncSafeMessage = ToHostGeneralIntraMessage<T::ConnectionChannelEnds>,
    >,
    T::ConnectionChannelEnds: SendAndSyncSafeConnectionChannelEnds,
{
    type SendAndSyncSafeToBuffer = T::ToBuffer;
    type SendAndSyncSafeFromBuffer = T::FromBuffer;
    type SendAndSyncSafeTakeBuffer = T::TakeBuffer;
    type SendAndSyncSafeSender = T::Sender;
    type SendAndSyncSafeCmdReceiver = T::CmdReceiver;
    type SendAndSyncSafeGenReceiver = T::GenReceiver;
    type SendAndSyncSafeConnectionChannelEnds = T::ConnectionChannelEnds;
}
