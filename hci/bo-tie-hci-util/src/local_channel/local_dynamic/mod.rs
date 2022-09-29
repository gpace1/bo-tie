//! A local channel with dynamically allocated buffers
//!
//! This is a local channel where the buffer is allocated dynamically upon creation. However, the
//! channel will not reallocate its buffer if it fills up. Both the send and receive are
//! asynchronous so if the channel cannot accept any more messages the sender will await until a
//! message is removed by the receiver.
//!
//! This is a local channel so it can only be used between async tasks running on the same thread.

use super::{
    LocalQueueBuffer, LocalQueueBufferReceive, LocalQueueBufferSend, LocalReceiverFuture, LocalSendFuture,
    LocalSendFutureError,
};
use crate::{
    BufferReserve, Channel, ChannelReserve, ConnectionChannelEnds, ConnectionHandle, FlowControlId, FlowCtrlReceiver,
    FromConnectionIntraMessage, FromHostIntraMessage, FromInterface, HostChannel, HostChannelEnds, InterfaceReceivers,
    Receiver, Sender, TaskId, ToConnectionIntraMessage, ToHostCommandIntraMessage, ToHostGeneralIntraMessage,
};
use alloc::collections::VecDeque;
use alloc::rc::Rc;
use bo_tie_util::buffer::de_vec::{DeVec, DynBufferReserve, TakeDynReserveFuture};
use core::cell::RefCell;
use core::fmt::{Display, Formatter};
use core::task::{Context, Poll, Waker};

/// The sender for a local channel
pub struct LocalChannelSender<T, M>(T)
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>;

impl<T, M> Clone for LocalChannelSender<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>> + Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T, M> LocalChannelSender<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    fn new(t: T) -> Self {
        t.borrow_mut().sender_count += 1;

        Self(t)
    }
}

impl<T, M> LocalQueueBuffer for LocalChannelSender<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    type Payload = M;

    fn call_waker(&self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<T, M> LocalQueueBufferSend for LocalChannelSender<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    fn is_full(&self) -> bool {
        let local_channel = self.0.borrow();

        local_channel.channel_buffer.len() == local_channel.channel_buffer.capacity()
    }

    fn receiver_exists(&self) -> bool {
        self.0.borrow().receiver_exists
    }

    fn push(&self, packet: Self::Payload) {
        self.0.borrow_mut().channel_buffer.push_back(packet)
    }
}

impl<T, M: Unpin> Sender for LocalChannelSender<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    type Error = LocalSendFutureError;
    type Message = M;
    type SendFuture<'a> = LocalSendFuture<'a, Self, M> where Self: 'a;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
        LocalSendFuture::new(self, t)
    }
}

impl<T, M> Drop for LocalChannelSender<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    fn drop(&mut self) {
        let mut sender = self.0.borrow_mut();

        sender.sender_count -= 1;

        if sender.sender_count == 0 {
            sender.waker.take().map(|waker| waker.wake());
        }
    }
}

/// The receiver for a local channel
pub struct LocalChannelReceiver<T, M>(T)
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>;

impl<T, M> LocalChannelReceiver<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    fn new(inner: T) -> Self {
        inner.borrow_mut().receiver_exists = true;

        LocalChannelReceiver(inner)
    }
}
impl<T, M> LocalQueueBuffer for LocalChannelReceiver<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    type Payload = M;

    fn call_waker(&self) {
        self.0.borrow_mut().waker.take().map(|w| w.wake());
    }

    fn set_waker(&self, waker: Waker) {
        self.0.borrow_mut().waker = Some(waker)
    }
}

impl<T, M> LocalQueueBufferReceive for LocalChannelReceiver<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    fn has_senders(&self) -> bool {
        self.0.borrow().sender_count != 0
    }

    fn is_empty(&self) -> bool {
        self.0.borrow().channel_buffer.is_empty()
    }

    fn pop_next(&self) -> Self::Payload {
        self.0.borrow_mut().channel_buffer.pop_front().unwrap()
    }
}

impl<T, M: Unpin> Receiver for LocalChannelReceiver<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    type Message = M;
    type ReceiveFuture<'a> = LocalReceiverFuture<'a, Self> where Self: 'a,;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        if self.has_senders() {
            if self.is_empty() {
                self.0.borrow_mut().waker = Some(cx.waker().clone());

                Poll::Pending
            } else {
                Poll::Ready(Some(self.pop_next()))
            }
        } else {
            Poll::Ready(None)
        }
    }

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        LocalReceiverFuture(self)
    }
}

impl<T, M> Drop for LocalChannelReceiver<T, M>
where
    T: core::ops::Deref<Target = RefCell<LocalChannelInner<M>>>,
{
    fn drop(&mut self) {
        self.0.borrow_mut().receiver_exists = false;
    }
}

/// A local channel for sending a message type
///
/// ## Local Type
/// This is a channel for sending messages between async tasks running on the same thread. A local
/// channel is not `Send` safe so it cannot pass messages outside of the same thread. However it
/// can be put within green threads that run on the same task, so long as the scheduler is not
/// pre-emptive.
pub struct LocalChannel<T>(Rc<RefCell<LocalChannelInner<T>>>);

impl<T> Clone for LocalChannel<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> core::ops::Deref for LocalChannel<T> {
    type Target = RefCell<LocalChannelInner<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> LocalChannel<T> {
    fn new(capacity: usize) -> Self {
        let inner = Rc::new(RefCell::new(LocalChannelInner::new(capacity)));

        LocalChannel(inner)
    }
}

impl<T: Unpin> Channel for LocalChannel<T> {
    type SenderError = LocalSendFutureError;
    type Message = T;
    type Sender = LocalChannelSender<Self, T>;
    type Receiver = LocalChannelReceiver<Self, T>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(self.clone())
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        if self.borrow().receiver_exists {
            None
        } else {
            Some(LocalChannelReceiver::new(self.clone()))
        }
    }
}

/// The inner part of a local channel
///
/// This is not really used outside of the library, so it hidden from the doc.
#[doc(hidden)]
pub struct LocalChannelInner<T> {
    sender_count: usize,
    receiver_exists: bool,
    channel_buffer: VecDeque<T>,
    waker: Option<Waker>,
}

impl<T> LocalChannelInner<T> {
    fn new(capacity: usize) -> Self {
        let senders_count = 0;
        let receiver_exists = false;
        let buffer = VecDeque::with_capacity(capacity);
        let waker = None;

        LocalChannelInner {
            sender_count: senders_count,
            receiver_exists,
            channel_buffer: buffer,
            waker,
        }
    }
}

/// A local channel with buffering support
///
/// This channel acts as both a message channel and a buffer reserve. The reserve of buffers is
/// associated with this channel but are not bound to it (they can be used by something else).
///
/// ## Local Type
/// This is a channel for sending messages between async tasks running on the same thread. A local
/// channel is not `Send` safe so it cannot pass messages outside of the same thread. However it
/// can be put within green threads that run on the same task, so long as the scheduler is not
/// pre-emptive.
pub struct LocalBufferedChannel<B, T>(Rc<LocalBufferedChannelInner<B, T>>);

impl<B, T> Clone for LocalBufferedChannel<B, T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<B, T> core::ops::Deref for LocalBufferedChannel<B, T> {
    type Target = RefCell<LocalChannelInner<T>>;

    fn deref(&self) -> &Self::Target {
        &self.0.channel
    }
}

impl<B, T> LocalBufferedChannel<B, T> {
    fn new(capacity: usize) -> Self {
        Self(Rc::new(LocalBufferedChannelInner::new(capacity)))
    }
}

impl<B: Unpin, T: Unpin> Channel for LocalBufferedChannel<B, T> {
    type SenderError = LocalSendFutureError;
    type Message = T;
    type Sender = LocalChannelSender<Self, T>;
    type Receiver = LocalChannelReceiver<Self, T>;

    fn get_sender(&self) -> Self::Sender {
        LocalChannelSender::new(self.clone())
    }

    fn take_receiver(&self) -> Option<Self::Receiver> {
        Some(LocalChannelReceiver(self.clone()))
    }
}

impl<B, T> BufferReserve for LocalBufferedChannel<B, T>
where
    B: bo_tie_util::buffer::Buffer,
{
    type Buffer = B;
    type TakeBuffer = TakeDynReserveFuture<B>;

    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>,
    {
        self.0
            .reserve
            .borrow_mut()
            .take(front_capacity.into().unwrap_or_default())
    }

    fn reclaim(&mut self, buffer: Self::Buffer) {
        self.0.reserve.borrow_mut().reclaim(buffer)
    }
}

/// The inner part of a local buffered channel
///
/// This is not really used outside of the library, so it hidden from the doc.
#[doc(hidden)]
pub struct LocalBufferedChannelInner<B, T> {
    reserve: RefCell<DynBufferReserve<B>>,
    channel: RefCell<LocalChannelInner<T>>,
}

impl<B, T> LocalBufferedChannelInner<B, T> {
    fn new(capacity: usize) -> Self {
        let reserve = RefCell::new(DynBufferReserve::new(capacity));
        let channel = RefCell::new(LocalChannelInner::new(capacity));

        LocalBufferedChannelInner { reserve, channel }
    }
}

/// Channel ends for a connection
pub struct ConnectionDynChannelEnds {
    send_channel: LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
    receiver: LocalChannelReceiver<
        LocalBufferedChannel<DeVec<u8>, ToConnectionIntraMessage<DeVec<u8>>>,
        ToConnectionIntraMessage<DeVec<u8>>,
    >,
}

impl ConnectionChannelEnds for ConnectionDynChannelEnds {
    type ToBuffer = DeVec<u8>;

    type FromBuffer = DeVec<u8>;

    type TakeBuffer =
        <LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>> as BufferReserve>::TakeBuffer;

    type Sender = LocalChannelSender<
        LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
        FromConnectionIntraMessage<DeVec<u8>>,
    >;

    type Receiver = LocalChannelReceiver<
        LocalBufferedChannel<DeVec<u8>, ToConnectionIntraMessage<DeVec<u8>>>,
        ToConnectionIntraMessage<DeVec<u8>>,
    >;

    fn get_sender(&self) -> Self::Sender {
        self.send_channel.get_sender()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.send_channel.take(front_capacity)
    }

    fn get_receiver(&self) -> &Self::Receiver {
        &self.receiver
    }

    fn get_mut_receiver(&mut self) -> &mut Self::Receiver {
        &mut self.receiver
    }
}

/// Connection async task information
///
/// This is the information required for communicating to a connection async task.
struct ConnectionData {
    sender_channel: LocalBufferedChannel<DeVec<u8>, ToConnectionIntraMessage<DeVec<u8>>>,
    handle: ConnectionHandle,
    flow_control_id: FlowControlId,
}

struct OutgoingChannels {
    host_command_response: LocalChannel<ToHostCommandIntraMessage>,
    host_general: LocalChannel<ToHostGeneralIntraMessage<ConnectionDynChannelEnds>>,
}

struct IncomingChannels {
    acl: LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
    sco: LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
    le_acl: LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
    le_iso: LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
}

/// Dedicated Task Channels
///
/// These channels are dedicated to exist so lang as the interface and host async tasks exist. All
/// Channels except for the `event_channel` are directed from another task to the interface async
/// task. The `event_channel` is a channel from the interface async task to the host async task.
struct DedicatedChannels {
    incoming: IncomingChannels,
    outgoing: OutgoingChannels,
}

/// A Channel Manager for local channels
///
/// This is a manager of local channels that are dynamically allocated at runtime. These channels
/// are not `Send` safe as the internal buffers are borrowed by both users of the channel.
///
/// The channels of a `LocalChannelManager` are allocated when they are needed. A channel consists
/// of a [`VecDeque`](std::collections::VecDeque) for the message buffer which is shared by the
/// sender and receiver. These channel buffers are allocated with an initial capacity that is also
/// the maximum capacity of the channel. If a channel's buffer reaches maximum capacity, then any
/// further sends will pend.
pub struct LocalChannelReserve {
    new_channels_size: usize,
    connections: RefCell<alloc::vec::Vec<ConnectionData>>,
    dedicated: DedicatedChannels,
    flow_control_receiver: FlowCtrlReceiver<
        LocalChannelReceiver<
            LocalBufferedChannel<DeVec<u8>, FromHostIntraMessage<DeVec<u8>>>,
            FromHostIntraMessage<DeVec<u8>>,
        >,
        LocalChannelReceiver<
            LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>,
            FromConnectionIntraMessage<DeVec<u8>>,
        >,
    >,
}

impl LocalChannelReserve {
    fn new(builder: LocalChannelReserveBuilder) -> (Self, impl HostChannelEnds) {
        let connections = RefCell::new(alloc::vec::Vec::new());

        let host_command_response = LocalChannel::new(builder.get_command_return_channel_size());
        let host_general = LocalChannel::new(builder.get_general_events_channel_size());
        let commands = LocalBufferedChannel::new(builder.get_command_channel_size());
        let acl = LocalBufferedChannel::new(builder.get_acl_data_channel_size());
        let sco = LocalBufferedChannel::new(builder.get_sco_data_channel_size());
        let le_acl = LocalBufferedChannel::new(builder.get_le_acl_data_channel_size());
        let le_iso = LocalBufferedChannel::new(builder.get_le_iso_data_channel_size());
        let new_channels_size = builder.get_connection_receive_channel_size();

        let interface_receivers = InterfaceReceivers {
            cmd_receiver: commands.take_receiver().unwrap(),
            acl_receiver: acl.take_receiver().unwrap(),
            sco_receiver: sco.take_receiver().unwrap(),
            le_acl_receiver: le_acl.take_receiver().unwrap(),
            le_iso_receiver: le_iso.take_receiver().unwrap(),
        };

        let flow_control_receiver = FlowCtrlReceiver::new(interface_receivers);

        let host_ends = HostDynChannelEnds {
            command_channel: commands.clone(),
            command_response: host_command_response.take_receiver().unwrap(),
            general: host_general.take_receiver().unwrap(),
        };

        let incoming = IncomingChannels {
            acl,
            sco,
            le_acl,
            le_iso,
        };

        let outgoing = OutgoingChannels {
            host_command_response,
            host_general,
        };

        let dedicated = DedicatedChannels { incoming, outgoing };

        let manager = Self {
            new_channels_size,
            connections,
            dedicated,
            flow_control_receiver,
        };
        let this = manager;

        (this, host_ends)
    }
}

impl ChannelReserve for LocalChannelReserve {
    type Error = LocalChannelManagerError;

    type SenderError = LocalSendFutureError;

    type ToHostCmdChannel = LocalChannel<ToHostCommandIntraMessage>;

    type ToHostGenChannel = LocalChannel<ToHostGeneralIntraMessage<Self::ConnectionChannelEnds>>;

    type FromHostChannel = LocalBufferedChannel<DeVec<u8>, FromHostIntraMessage<DeVec<u8>>>;

    type ToConnectionChannel = LocalBufferedChannel<DeVec<u8>, ToConnectionIntraMessage<DeVec<u8>>>;

    type FromConnectionChannel = LocalBufferedChannel<DeVec<u8>, FromConnectionIntraMessage<DeVec<u8>>>;

    type ConnectionChannelEnds = ConnectionDynChannelEnds;

    fn try_remove(&mut self, to_remove: ConnectionHandle) -> Result<(), Self::Error> {
        if let Ok(index) = self
            .connections
            .get_mut()
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&to_remove))
        {
            self.connections.get_mut().remove(index);

            Ok(())
        } else {
            Err(LocalChannelManagerError::ChannelIdDoesNotExist)
        }
    }

    fn add_new_connection(
        &self,
        connection_handle: ConnectionHandle,
        flow_control_id: FlowControlId,
    ) -> Result<Self::ConnectionChannelEnds, Self::Error> {
        let from_new_task_channel = match flow_control_id {
            FlowControlId::Cmd => unreachable!(),
            FlowControlId::Acl => self.dedicated.incoming.acl.clone(),
            FlowControlId::Sco => self.dedicated.incoming.sco.clone(),
            FlowControlId::LeAcl => self.dedicated.incoming.le_acl.clone(),
            FlowControlId::LeIso => self.dedicated.incoming.le_iso.clone(),
        };

        let to_new_task_channel = LocalBufferedChannel::new(self.new_channels_size);

        let new_task_ends = ConnectionDynChannelEnds {
            send_channel: from_new_task_channel,
            receiver: to_new_task_channel.take_receiver().unwrap(),
        };

        let index = if let Err(index) = self
            .connections
            .borrow()
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
        {
            index
        } else {
            return Err(LocalChannelManagerError::ChannelIdAlreadyUsed);
        };

        let channel_data = ConnectionData {
            sender_channel: to_new_task_channel,
            handle: connection_handle,
            flow_control_id,
        };

        self.connections.borrow_mut().insert(index, channel_data);

        Ok(new_task_ends)
    }

    fn get_channel(
        &self,
        id: TaskId,
    ) -> Option<FromInterface<Self::ToHostCmdChannel, Self::ToHostGenChannel, Self::ToConnectionChannel>> {
        match id {
            TaskId::Host(HostChannel::Command) => Some(FromInterface::HostCommand(
                self.dedicated.outgoing.host_command_response.clone(),
            )),
            TaskId::Host(HostChannel::General) => {
                Some(FromInterface::HostGeneral(self.dedicated.outgoing.host_general.clone()))
            }
            TaskId::Connection(connection_handle) => {
                let ref_connections = self.connections.borrow();

                ref_connections
                    .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
                    .ok()
                    .and_then(|index| ref_connections.get(index))
                    .map(|ConnectionData { sender_channel, .. }| FromInterface::Connection(sender_channel.clone()))
            }
        }
    }

    fn get_flow_control_id(&self, connection_handle: ConnectionHandle) -> Option<FlowControlId> {
        let ref_other_task_data = self.connections.borrow();

        ref_other_task_data
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
            .ok()
            .and_then(|index| ref_other_task_data.get(index))
            .map(|ConnectionData { flow_control_id, .. }| *flow_control_id)
    }

    fn get_flow_ctrl_receiver(
        &mut self,
    ) -> &mut FlowCtrlReceiver<
        <Self::FromHostChannel as Channel>::Receiver,
        <Self::FromConnectionChannel as Channel>::Receiver,
    > {
        &mut self.flow_control_receiver
    }
}

#[derive(Debug)]
pub enum LocalChannelManagerError {
    ChannelIdAlreadyUsed,
    ChannelIdDoesNotExist,
}

impl Display for LocalChannelManagerError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalChannelManagerError::ChannelIdAlreadyUsed => f.write_str("channel id already used"),
            LocalChannelManagerError::ChannelIdDoesNotExist => f.write_str("channel for id does not exist"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LocalChannelManagerError {}

struct HostDynChannelEnds {
    command_channel: LocalBufferedChannel<DeVec<u8>, FromHostIntraMessage<DeVec<u8>>>,
    command_response: LocalChannelReceiver<LocalChannel<ToHostCommandIntraMessage>, ToHostCommandIntraMessage>,
    general: LocalChannelReceiver<
        LocalChannel<ToHostGeneralIntraMessage<ConnectionDynChannelEnds>>,
        ToHostGeneralIntraMessage<ConnectionDynChannelEnds>,
    >,
}

impl HostChannelEnds for HostDynChannelEnds {
    type ToBuffer = DeVec<u8>;

    type FromBuffer = DeVec<u8>;

    type TakeBuffer = <LocalBufferedChannel<DeVec<u8>, FromHostIntraMessage<DeVec<u8>>> as BufferReserve>::TakeBuffer;

    type Sender = LocalChannelSender<
        LocalBufferedChannel<DeVec<u8>, FromHostIntraMessage<DeVec<u8>>>,
        FromHostIntraMessage<DeVec<u8>>,
    >;

    type CmdReceiver = LocalChannelReceiver<LocalChannel<ToHostCommandIntraMessage>, ToHostCommandIntraMessage>;

    type GenReceiver = LocalChannelReceiver<
        LocalChannel<ToHostGeneralIntraMessage<ConnectionDynChannelEnds>>,
        ToHostGeneralIntraMessage<ConnectionDynChannelEnds>,
    >;

    type ConnectionChannelEnds = ConnectionDynChannelEnds;

    fn get_sender(&self) -> Self::Sender {
        self.command_channel.get_sender()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.command_channel.take(front_capacity)
    }

    fn get_cmd_recv(&self) -> &Self::CmdReceiver {
        &self.command_response
    }

    fn get_mut_cmd_recv(&mut self) -> &mut Self::CmdReceiver {
        &mut self.command_response
    }

    fn get_gen_recv(&self) -> &Self::GenReceiver {
        &self.general
    }

    fn get_mut_gen_recv(&mut self) -> &mut Self::GenReceiver {
        &mut self.general
    }
}

/// A builder for a local channel
///
/// This is used to configure the build of the local channels before creating the interface using
/// a [`LocalChannelReserve`].
///
/// ## Data Channels
/// All connection async tasks use the same channel to the interface for sending the same type of
/// data to the Controller. The main reason for this is flow control. The interface async task will
/// only receive from the data channel when it knows that there is room on the Controller to store
/// the data packet.
///
/// There are four kinds of data channels, two for BR/EDR packets and two or three for LE
/// data packets. While the requirements for usage are listed below, in reality the requirements are
/// met internally and do not need to be worried about. The requirements are listed to better help
/// in determining custom sizes for these channels.
///
/// ### ACL Data Channel
/// BR/EDR ACL data packets must be sent to the Controller through the ACL data channel. If the
/// Controller does not support a separate LE ACl buffer (it uses the same buffer for both BR/EDR
/// and LE ACL Data) this channel must also be used LE ACL Data.
///
/// ### SCO Data Channel
/// BR/EDR SCO data packets must be sent to the Controller through the SCO data channel.
///
/// ### LE ACL Data Channel
/// If the controller supports a separate buffer for LE ACL Data, then this data must be sent to the
/// Controller through the LE ACL data channel.
///
/// ### LE ISO Data Channel
/// LE ISO data must be sent to the Controller through the LE ISO data channel.
pub struct LocalChannelReserveBuilder {
    command_channel_size: Option<usize>,
    command_return_channel_size: Option<usize>,
    general_events_channel_size: Option<usize>,
    acl_data_channel_size: Option<usize>,
    sco_data_channel_size: Option<usize>,
    le_acl_data_channel_size: Option<usize>,
    le_iso_data_channel_size: Option<usize>,
    connection_receive_channel_size: Option<usize>,
}

impl LocalChannelReserveBuilder {
    const DEFAULT_CHANNEL_SIZE: usize = 32; // arbitrary default

    /// Create a new `LocalChannelBuilder`
    pub fn new() -> Self {
        Self {
            command_channel_size: None,
            command_return_channel_size: None,
            general_events_channel_size: None,
            acl_data_channel_size: None,
            sco_data_channel_size: None,
            le_acl_data_channel_size: None,
            le_iso_data_channel_size: None,
            connection_receive_channel_size: None,
        }
    }

    /// Set the maximum size of the command channels
    ///
    /// This sets the size of the command channels used for communicating with the host async task.
    /// The channel used by the host to send commands to the controller and the channel used for
    /// sending the events containing the events Command Complete and Command Status are sized to
    /// this.
    pub fn set_command_channel_sizes(&mut self, channel_size: usize) -> &mut Self {
        self.command_channel_size = channel_size.into();
        self.command_return_channel_size = channel_size.into();
        self
    }

    /// Set the size of the channel for sending ACL data to the interface async task
    ///
    /// This will generally only be used by BR/EDR operation, but it is also used by LE operation
    /// whenever the Controller shares the same flow control buffers for both BR/EDR and LE ACL
    /// data.
    pub fn set_acl_data_channel_size(&mut self, channel_size: usize) -> &mut Self {
        self.acl_data_channel_size = channel_size.into();
        self
    }

    /// Set the size of the channel for sending SCO data to the interface async task
    pub fn set_sco_data_channel_size(&mut self, channel_size: usize) -> &mut Self {
        self.sco_data_channel_size = channel_size.into();
        self
    }

    /// Set the size of the channel for sending LE ACL data to the interface async task
    ///
    /// This will be the
    pub fn set_le_acl_data_channel_size(&mut self, channel_size: usize) -> &mut Self {
        self.le_acl_data_channel_size = channel_size.into();
        self
    }

    pub fn set_le_iso_data_channel_size(&mut self, channel_size: usize) -> &mut Self {
        self.le_iso_data_channel_size = channel_size.into();
        self
    }

    /// Get the command_channel_size
    fn get_command_channel_size(&self) -> usize {
        self.command_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the command return channel size
    fn get_command_return_channel_size(&self) -> usize {
        self.command_return_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the general events channel size
    fn get_general_events_channel_size(&self) -> usize {
        self.general_events_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the ACL data channel size
    fn get_acl_data_channel_size(&self) -> usize {
        self.acl_data_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the SCO data channel size
    fn get_sco_data_channel_size(&self) -> usize {
        self.sco_data_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the LE ACL data channel size
    fn get_le_acl_data_channel_size(&self) -> usize {
        self.le_acl_data_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the LE ISO data channel size
    fn get_le_iso_data_channel_size(&self) -> usize {
        self.le_iso_data_channel_size.unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Get the LE connection receive channel size
    fn get_connection_receive_channel_size(&self) -> usize {
        self.connection_receive_channel_size
            .unwrap_or(Self::DEFAULT_CHANNEL_SIZE)
    }

    /// Build the `LocalChannelManager`
    ///
    /// The return is the local channel manager along with the host channel ends for it.
    pub fn build(self) -> (LocalChannelReserve, impl HostChannelEnds) {
        LocalChannelReserve::new(self)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::test::*;

    #[test]
    fn local_init_usize() {
        let _: LocalChannel<usize> = LocalChannel::new(20);
    }

    #[test]
    fn local_init_ref_mut_usize() {
        let _: LocalChannel<&mut usize> = LocalChannel::new(20);
    }

    #[tokio::test]
    async fn local_add_remove_usize() {
        let l: LocalChannel<usize> = LocalChannel::new(5);

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        channel_send_and_receive(l, test_vals, test_vals, PartialEq::eq).await
    }

    #[tokio::test]
    async fn local_add_remove_usize_single_capacity() {
        let l: LocalChannel<usize> = LocalChannel::new(1);

        let test_vals = [21, 32, 44, 26, 84, 321, 123, 4321, 24, 2142, 485961, 1, 55];

        channel_send_and_receive(l, test_vals, test_vals, PartialEq::eq).await
    }

    #[tokio::test]
    async fn local_add_remove_byte_slice() {
        let l: LocalChannel<&[u8]> = LocalChannel::new(4);

        let test_vals: [&[u8]; 8] = [
            "Hello world".as_bytes(),
            "Where were we last night".as_bytes(),
            "3y2j`kl4hjlhbavucoxy78gy3u2k14hg5 431".as_bytes(),
            "4hbn2341bjkl4j".as_bytes(),
            "more spam".as_bytes(),
            "even more spam".as_bytes(),
            "this is a test of the boring alert system".as_bytes(),
            "who asked for your opinion on my test data?".as_bytes(),
        ];

        channel_send_and_receive(l, test_vals, test_vals, PartialEq::eq).await
    }

    #[tokio::test]
    async fn local_add_remove_array() {
        const SIZE: usize = 20;

        let l: LocalChannel<[usize; SIZE]> = LocalChannel::new(4);

        let test_vals: [[usize; SIZE]; 10] = [
            [0; SIZE], [1; SIZE], [2; SIZE], [3; SIZE], [4; SIZE], [5; SIZE], [6; SIZE], [7; SIZE], [8; SIZE],
            [9; SIZE],
        ];

        channel_send_and_receive(l, test_vals, test_vals, PartialEq::eq).await
    }
}
