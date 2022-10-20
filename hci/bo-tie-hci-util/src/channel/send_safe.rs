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

/// A wrapper for `impl SendSafeChannelReserve` or `impl SendSafeHostChannelEnds`
///
/// This wrapper is used to add the `Send` bound to the associated types of the traits
/// [`ChannelReserve`] and [`HostChannelEnds`] without
pub struct SendSafe<T: Send>(T);

impl<T: Send> SendSafe<T> {
    pub fn new(t: T) -> Self {
        SendSafe(t)
    }
}

impl<T> Future for SendSafe<T>
where
    T: Future + Send,
{
    type Output = T::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|this| &mut this.0).poll(cx) }
    }
}

impl<T> Iterator for SendSafe<T>
where
    T: Iterator<Item = u8> + Send,
{
    type Item = T::Item;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next()
    }
}

impl<T: Send + Debug> Debug for SendSafe<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        T::fmt(&self.0, f)
    }
}

impl<T: Send + Display> Display for SendSafe<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        T::fmt(&self.0, f)
    }
}

impl<T: Send + DerefMut<Target = [u8]>> DerefMut for SendSafe<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}

impl<T: Send + Deref<Target = [u8]>> Deref for SendSafe<T> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl<T> TryExtend<u8> for SendSafe<T>
where
    T: Send + TryExtend<u8>,
    T::Error: Send,
{
    type Error = SendSafe<T::Error>;

    fn try_extend<E>(&mut self, iter: E) -> Result<(), Self::Error>
    where
        E: IntoIterator<Item = u8>,
    {
        self.0.try_extend(iter).map_err(|e| SendSafe::new(e))
    }
}

impl<T, I> TryRemove<u8> for SendSafe<T>
where
    for<'a> T: 'a + Send + TryRemove<u8, RemoveIter<'a> = I>,
    T::Error: Send,
    I: Iterator<Item = u8> + Send,
{
    type Error = SendSafe<T::Error>;
    type RemoveIter<'a> = SendSafe<T::RemoveIter<'a>> where Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.0
            .try_remove(how_many)
            .map(|iter| SendSafe::new(iter))
            .map_err(|e| SendSafe::new(e))
    }
}

impl<T> TryFrontExtend<u8> for SendSafe<T>
where
    T: Send + TryFrontExtend<u8>,
    T::Error: Send,
{
    type Error = SendSafe<T::Error>;

    fn try_front_extend<E>(&mut self, iter: E) -> Result<(), Self::Error>
    where
        E: IntoIterator<Item = u8>,
    {
        self.0.try_front_extend(iter).map_err(|e| SendSafe::new(e))
    }
}

impl<T, I> TryFrontRemove<u8> for SendSafe<T>
where
    for<'a> T: 'a + Send + TryFrontRemove<u8, FrontRemoveIter<'a> = I>,
    T::Error: Send,
    I: Iterator<Item = u8> + Send,
{
    type Error = SendSafe<T::Error>;
    type FrontRemoveIter<'a> = SendSafe<T::FrontRemoveIter<'a>> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.0
            .try_front_remove(how_many)
            .map(|iter| SendSafe::new(iter))
            .map_err(|e| SendSafe::new(e))
    }
}

impl<T, I1, I2> Buffer for SendSafe<T>
where
    for<'a, 'b> T: 'a + 'b + Send + Buffer<RemoveIter<'a> = I1, FrontRemoveIter<'b> = I2>,
    <T as TryExtend<u8>>::Error: Send,
    <T as TryRemove<u8>>::Error: Send,
    <T as TryFrontExtend<u8>>::Error: Send,
    <T as TryFrontRemove<u8>>::Error: Send,
    I1: Iterator<Item = u8> + Send,
    I2: Iterator<Item = u8> + Send,
{
    fn with_capacity(front: usize, back: usize) -> Self
    where
        Self: Sized,
    {
        Self(T::with_capacity(front, back))
    }

    fn clear_with_capacity(&mut self, front: usize, back: usize) {
        self.0.clear_with_capacity(front, back)
    }
}

impl<T> BufferReserve for SendSafe<T>
where
    T: SendSafeBufferReserve,
{
    type Buffer = T::SendSafeBuffer;
    type TakeBuffer = SendSafe<T::SendSafeTakeBuffer>;

    fn take<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        SendSafe::new(self.0.take(front_capacity, back_capacity))
    }

    fn reclaim(&mut self, buffer: Self::Buffer) {
        self.0.reclaim(buffer)
    }
}

impl<T, E, M, F> Sender for SendSafe<T>
where
    for<'z> T: 'z + Send + Sync + Sender<Error = E, Message = M, SendFuture<'z> = F>,
    E: Send + Debug,
    M: Send + Unpin,
    F: Send + Future<Output = Result<(), E>>,
{
    type Error = E;
    type Message = M;
    type SendFuture<'a> = SendSafe<F> where Self: 'a;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        SendSafe(self.0.send(t))
    }
}

impl<T, M, F> Receiver for SendSafe<T>
where
    for<'z> T: 'z + Send + Sync + Receiver<Message = M, ReceiveFuture<'z> = F>,
    M: Send + Unpin,
    F: Send + Future<Output = Option<M>>,
{
    type Message = M;
    type ReceiveFuture<'a> = SendSafe<F> where Self: 'a;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        self.0.poll_recv(cx)
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        SendSafe(self.0.recv())
    }
}

impl<T, S, R> Channel for SendSafe<T>
where
    T: Send + Channel<Sender = S, Receiver = R>,
    T::SenderError: Send,
    T::Message: Send,
    S: Send + Sender<Error = T::SenderError, Message = T::Message>,
    R: Send + Receiver<Message = T::Message>,
    SendSafe<S>: Sender<Error = T::SenderError, Message = T::Message>,
    SendSafe<R>: Receiver<Message = T::Message>,
{
    type SenderError = T::SenderError;
    type Message = T::Message;
    type Sender = SendSafe<S>;
    type Receiver = SendSafe<R>;

    fn get_sender(&self) -> Self::Sender {
        SendSafe(self.0.get_sender())
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        self.0.take_receiver().map(|rx| SendSafe(rx))
    }
}

impl<T, ToB, FrB, TakeB, S, R> ConnectionChannelEnds for SendSafe<T>
where
    T: Send
        + Sync
        + ConnectionChannelEnds<ToBuffer = ToB, FromBuffer = FrB, TakeBuffer = TakeB, Sender = S, Receiver = R>,
    ToB: Send,
    FrB: Send,
    TakeB: Send,
    S: Send,
    R: Send + Sync + Receiver<Message = ToConnectionIntraMessage<SendSafe<FrB>>>,
    for<'a> R::ReceiveFuture<'a>: Send,
    SendSafe<ToB>: Buffer,
    SendSafe<FrB>: Buffer,
    SendSafe<TakeB>: Future<Output = SendSafe<ToB>>,
    SendSafe<S>: Sender<Message = FromConnectionIntraMessage<SendSafe<ToB>>>,
{
    type ToBuffer = SendSafe<ToB>;
    type FromBuffer = SendSafe<FrB>;
    type TakeBuffer = SendSafe<TakeB>;
    type Sender = SendSafe<S>;
    type Receiver = R;

    fn get_sender(&self) -> Self::Sender {
        SendSafe::new(self.0.get_sender())
    }

    fn take_buffer<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        SendSafe::new(self.0.take_buffer(front_capacity, back_capacity))
    }

    fn get_receiver(&self) -> &Self::Receiver {
        self.0.get_receiver()
    }

    fn get_mut_receiver(&mut self) -> &mut Self::Receiver {
        self.0.get_mut_receiver()
    }
}

impl<T, ToHC, ToHG, FrH, ToC, FrC, CE, B1, B2, B3> ChannelReserve for SendSafe<T>
where
    T: Send
        + ChannelReserve<
            ToHostCmdChannel = ToHC,
            ToHostGenChannel = ToHG,
            FromHostChannel = FrH,
            ToConnectionChannel = ToC,
            FromConnectionChannel = FrC,
            ConnectionChannelEnds = CE,
        >,
    T::Error: Send,
    T::SenderError: Send,
    ToHC: Send,
    ToHG: Send,
    FrH: Send,
    ToC: Send,
    FrC: Send,
    CE: Send,
    B1: Send,
    B2: Send,
    B3: Send,
    SendSafe<ToHC>: Channel<SenderError = T::SenderError, Message = ToHostCommandIntraMessage>,
    SendSafe<ToHG>: Channel<SenderError = T::SenderError, Message = ToHostGeneralIntraMessage<SendSafe<CE>>>,
    SendSafe<FrH>: BufferReserve<Buffer = SendSafe<B1>>
        + Channel<SenderError = T::SenderError, Message = FromHostIntraMessage<SendSafe<B1>>>,
    SendSafe<ToC>: BufferReserve<Buffer = SendSafe<B2>>
        + Channel<SenderError = T::SenderError, Message = ToConnectionIntraMessage<SendSafe<B2>>>,
    SendSafe<FrC>: BufferReserve<Buffer = SendSafe<B3>>
        + Channel<SenderError = T::SenderError, Message = FromConnectionIntraMessage<SendSafe<B3>>>,
    SendSafe<CE>: ConnectionChannelEnds,
{
    type Error = T::Error;
    type SenderError = T::SenderError;
    type ToHostCmdChannel = SendSafe<ToHC>;
    type ToHostGenChannel = SendSafe<ToHG>;
    type FromHostChannel = SendSafe<FrH>;
    type ToConnectionChannel = SendSafe<ToC>;
    type FromConnectionChannel = SendSafe<FrC>;
    type ConnectionChannelEnds = SendSafe<CE>;

    fn try_remove(&mut self, handle: ConnectionHandle) -> Result<(), Self::Error> {
        self.0.try_remove(handle)
    }

    fn add_new_connection(
        &mut self,
        handle: ConnectionHandle,
        flow_control_id: FlowControlId,
    ) -> Result<Self::ConnectionChannelEnds, Self::Error> {
        self.0
            .add_new_connection(handle, flow_control_id)
            .map(|ce| SendSafe::new(ce))
    }

    fn get_channel(
        &self,
        id: TaskId,
    ) -> Option<FromInterface<Self::ToHostCmdChannel, Self::ToHostGenChannel, Self::ToConnectionChannel>> {
        self.0.get_channel(id).map(|fi| match fi {
            FromInterface::HostCommand(hc) => FromInterface::HostCommand(SendSafe::new(hc)),
            FromInterface::HostGeneral(hg) => FromInterface::HostGeneral(SendSafe::new(hg)),
            FromInterface::Connection(c) => FromInterface::Connection(SendSafe::new(c)),
        })
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
