//! Implementation for the interface between the host and controller
//!
//! The host is split up between a host functional component and an interface component. The host
//! functional part contains the controller commanding and data processing portions which are
//! referred to the host-controller async task and connection async task respectively. The interface
//! portion of the host is referred to as the interface async task. Its job is to constantly service
//! the driver and controller for messages to and from it.
//!
//! An interface async task is platform specific. It is needs to include the driver to the interface
//! as well as an `Interface`. It needs to be implemented to constantly listen to both data coming
//! from the other async tasks and data coming from the interface.
//!
//! ## Messaging
//! The interface async task is the gateway to the interface. HCI packets to and from the controller
//! must go through the interface async task and consequently HCI packets from other async tasks
//! must also go through the interface. The interface async task's job is to constantly await the
//! physical interface, so its the only safe way to handle messaging to the controller. The main
//! reason is so that it can quickly serve the interface driver (usually to flush peripheral
//! buffers), but also to capture HCI events not awaited upon by another async task.
//!
//! Messaging between the interface async task and the other async tasks is done through
//! asynchronous multiple producer single consumer (mpsc) channels. There is always two of these
//! channels for the host async task and every connection async task. This is what allows for the
//! async tasks to be separated from monitoring the controller. This library classifies channels
//! into two kinds, 'send safe' and 'local'. If the channels are send safe, then all async tasks
//! will be send safe (assuming the user doesn't have `!Send` implementation), because channels
//! happen to be the defining component for the HCI async tasks to implement `Send`. A Local channel
//! does not `Send` (which means the async tasks are also !Send) but they're designed to run
//! efficiently within the same thread. They also do not require allocation when using a local
//! static channel.
//!
//! ## Specification Defined Interfaces
//! There are four types of interfaces mentioned within the Bluetooth Specification (v5.2) but
//! interfacing between the host and controller can be done via any interface so long as the host
//! to controller functional specification can be applied to it. As a general rule any interface
//! can work so long as there is a way to send and receive data between the host and controller
//! asynchronously in respect to either side's CPU.
//!
//! UART, USB, Secure Digital (SD), and Three-Wire UART interfaces have defined specification for
//! how to use them with the functional specification. Everything that is defined within the
//! specification is implemented within this library, but this only covers the data encapsulation
//! and some of configuration details.

use crate::hci::common::ConnectionHandle;
use crate::hci::events::Events;
use crate::hci::interface::flow_control::FlowControlQueues;
use crate::hci::{BufferReserve, CommandEventMatcher};
use core::fmt::{Debug, Display, Formatter};
use core::future::Future;
use core::ops::Deref;

mod flow_control;
mod local_channel;
pub mod uart;

/// Identifiers of channels
///
/// The interface has a collection of channels for sending data to either the host or connection.
/// A `ChannelId` is used for identifying the channels in this collection.
#[derive(Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum TaskId {
    Host,
    Connection(ConnectionHandle),
}

/// Flow control information
#[derive(Default, Debug, Copy, Clone)]
pub struct FlowControl {
    packet_count: usize,
    data_blocks: usize,
}

/// A message channel
///
/// This is a trait for a flow-controlled multiple sender single receiver data channel. This is a
/// channel for sending data between the host async task or connection async task and the interface
/// async task.
///
/// ## Flow Control
/// Flow control is implemented via the interface async task, but information for the flow control
/// is stored within a `Channel`. What information is stored is dependent on the type of channel,
/// but the interface async task will determine what information is needed to be stored.
///
/// Flow control is only for the controller. There is no flow control upwards to the host and
/// connection async tasks as a channel to those tasks naturally implements it.
///
/// The flow control information should be initialized with [`Default`](std::default::Default) by
/// the channel. It then will be initialized to the current controller later by the interface async
/// task.
pub trait Channel {
    type SenderError: Debug;

    type Message: Unpin;

    type Sender: Sender<Error = Self::SenderError, Message = Self::Message>;

    type Receiver: Receiver<Message = Self::Message>;

    /// Get the sender *to* the async task
    ///
    /// This gets the sender for sending messages to the associated async task. Messages received
    /// from the controller are sent to the corresponding async task through this sender.
    fn get_sender(&self) -> Self::Sender;

    /// Take the receiver *to* the async task
    ///
    /// This is intended to be called once to take the receiver associated with the sender to the
    /// async task. It is taken as part of the construction of the asynchronous task. This method
    /// can be assumed to only be called once.
    fn take_receiver(&self) -> Option<Self::Receiver>;

    /// Do something on the flow control information
    fn on_flow_control<F>(&self, f: F)
    where
        F: FnOnce(&mut FlowControl);
}

trait ChannelExt: Channel {
    /// Increment the number of data packets that can be sent
    fn inc_flow_control_packets<N>(&mut self, number: N)
    where
        N: Into<usize>,
    {
        self.on_flow_control(|fc| fc.packet_count += number.into());
    }

    /// Decrement the number of packets that can be sent
    ///
    /// The result of calling this method will reduce the number of packets that the controller can
    /// currently receive by one but not less than zero. The return is true as long as the flow
    /// control tracker believes that the controller can currently receive another packet.
    fn dec_flow_control_packets(&mut self) -> bool {
        let mut can_receive = false;

        self.on_flow_control(|fc| {
            can_receive = 0
                != fc
                    .packet_count
                    .checked_sub(1)
                    .map(|result| {
                        fc.packet_count = result;
                        result
                    })
                    .unwrap_or_default()
        });

        can_receive
    }

    /// Set the data blocks and number of data packets
    fn inc_flow_control_packets_and_data<N, D>(&mut self, number_of_packets: N, number_of_data_blocks: D)
    where
        N: Into<usize>,
        D: Into<usize>,
    {
        self.on_flow_control(|fc| {
            fc.packet_count += number_of_packets.into();
            fc.data_blocks += number_of_data_blocks.into();
        })
    }

    /// Set the flow control information
    fn set_flow_control(&mut self, flow_control: FlowControl) {
        self.on_flow_control(|fc| *fc = flow_control)
    }

    /// Get the flow control information
    fn get_flow_control(&mut self) -> FlowControl {
        let mut flow_control = FlowControl::default();

        self.on_flow_control(|fc| flow_control = *fc);

        flow_control
    }
}

impl<T: Channel> ChannelExt for T {}

/// A channel reserve
///
/// The point of a channel reserve is to minimize the amount of message movement between the sender
/// and receiver. This includes the initial writing of data into the message.
pub trait ChannelReserve {
    /// The error type associated with the `try_*` method within `ChannelReserve`
    type Error;

    /// The error returned by the implementation of Sender
    ///
    /// This is the same type as `Error` of [`Sender`]
    type SenderError: Debug;

    /// The error that occurs when trying to extend a buffer fails
    type TryExtendError: Debug;

    /// Error returned by [`for_new_task`]
    type ForNewTaskError: Debug;

    /// The type for the sender between async tasks
    type Sender: Sender<Error = Self::SenderError, Message = IntraMessage<Self::Buffer>>;

    /// The type for the receiver between async tasks
    type Receiver: Receiver<Message = IntraMessage<Self::Buffer>>;

    /// The type for buffering messages between the host and controller
    type Buffer: Unpin + crate::TryExtend<u8, Error = Self::TryExtendError> + Deref<Target = [u8]>;

    /// The mpsc channel
    type Channel: BufferReserve<Buffer = Self::Buffer>
        + Channel<
            SenderError = Self::SenderError,
            Message = IntraMessage<Self::Buffer>,
            Sender = Self::Sender,
            Receiver = Self::Receiver,
        >;

    /// Try to remove a channel
    fn try_remove(&mut self, id: TaskId) -> Result<(), Self::Error>;

    /// Create new channels for an async task
    ///
    /// This creates two new channels for communication with a new async task. The ends of these new
    /// channels are split up between the interface async task and the async task identified by
    /// input `task_id`. The ends used by the interface async task are saved within `self`. The ends
    /// used by the async task identified by `task_id` are returned by this method.  
    ///
    /// # Panic
    /// This method may panic if `for_id` is already used
    fn add_new_task(&mut self, task_id: TaskId) -> Result<ChannelEnds<Self::Channel>, Self::ForNewTaskError>
    where
        Self::Channel: Sized;

    /// Get the channel ends associated by the specified ID
    ///
    /// `None` is returned if no channel exists for the provided identifier.
    fn get(&self, id: TaskId) -> Option<&ChannelEnds<Self::Channel>>;
}

trait ChannelReserveExt: ChannelReserve {
    /// Prepare for sending a message
    ///
    /// If there is a channel with provided `ChannelId` in this `ChannelReserve`, then a
    /// `GetPrepareSend` is returned. The return is a future that outputs a `PrepareSend` when it
    /// can acquire a message from this buffer reserve. The output `PrepareSend` can then be used
    /// to modify the message before it can be used as a future to send the message.
    fn prepare_send(
        &self,
        id: TaskId,
    ) -> Option<GetPrepareSend<Self::Channel, <Self::Channel as BufferReserve>::TakeBuffer>> {
        self.get(id).map(|channel| GetPrepareSend::new(channel))
    }
}

impl<T: ChannelReserve> ChannelReserveExt for T {}

/// Ends of the channels to another async task
///
/// This contains the two channel ends held by the interface for the channels connecting the two
/// async task.
struct ChannelEnds<C: Channel> {
    sender: C::Sender,
    receiver: C::Receiver,
}

impl<C: Channel> ChannelEnds<C> {
    /// Create a new `ChannelEnds`
    pub fn new(sender: C::Sender, receiver: C::Receiver) -> Self {
        Self { sender, receiver }
    }

    /// Get the sender of messages to the async task
    fn get_sender(&self) -> &C::Sender {
        &self.sender
    }

    /// Get the receiver of messages from the async task
    fn get_receiver(&self) -> &C::Receiver {
        &self.receiver
    }
}

/// A future for acquiring a `PrepareSend`
///
/// This future awaits until it can acquire a buffer for use as a channel message. Usually this
/// future returns right away, but it is needed in the case where the reserve is waiting to free up
/// a buffer for this send process. When the future does poll to completion it returns a
/// `PrepareSend`.
struct GetPrepareSend<'a, C, T> {
    channel_ends: Option<&'a ChannelEnds<C>>,
    take_buffer: T,
}

impl<'a, C> GetPrepareSend<'a, C, C::TakeBuffer>
where
    C: BufferReserve,
{
    pub fn new(channel_ends: &'a ChannelEnds<C>) -> Self {
        let take_buffer = channel_ends.sender.take(None);
        let channel_ends = Some(channel_ends);

        GetPrepareSend {
            channel_ends,
            take_buffer,
        }
    }
}

impl<C> Future for GetPrepareSend<C, C::TakeBuffer>
where
    C: Channel + BufferReserve,
{
    type Output = PrepareSend<C, C::Buffer>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        unsafe { core::pin::Pin::new_unchecked(&mut this.take_buffer) }
            .poll(cx)
            .map(|buffer| {
                let channel_ends = this
                    .channel_ends
                    .take()
                    .expect("GetPrepareSend already polled to completion");

                PrepareSend::new(channel_ends, buffer)
            })
    }
}

/// A Preparer for sending a message
///
/// The point of a `PrepareSend` is to write the message before sending the message. The main point
/// of this is for optimizing where buffers reserves benefit being written in-place, such as static
/// allocated memory.
///
/// A `PrepareSend` contains the message to be sent. It can be modified through `AsRef`/`AsMut` as
/// well as the crate traits `TryExtend`/`TryRemove`/`TryFrontExtend`/`TryFrontRemove`. Once
/// modification of the message is done, a `PrepareSend` can be converted into a future with the
/// function [`and_send`](PrepareSend::and_send) to send the message.
struct PrepareSend<'a, C, B> {
    channel_ends: &'a ChannelEnds<C>,
    buffer: B,
}

impl<'a, C, B> PrepareSend<'a, C, B>
where
    C: Channel,
{
    fn new(channel_ends: &'a ChannelEnds<C>, buffer: B) -> Self {
        Self { channel_ends, buffer }
    }

    /// Take a `PrepareSend` and return a future to send a message
    ///
    /// This take a `PrepareSend` and a closure `f` to convert the buffered data into a message (of
    /// type M) and return a future for sending the message.
    async fn and_send<F>(ps: Self, f: F) -> Result<(), C::SenderError>
    where
        F: FnOnce(B) -> C::Message,
    {
        let message = f(ps.buffer);

        ps.channel_ends.get_sender().send(message).await
    }
}

impl<C, M> AsRef<M> for PrepareSend<C, M> {
    fn as_ref(&self) -> &M {
        &self.buffer
    }
}

impl<C, M> AsMut<M> for PrepareSend<C, M> {
    fn as_mut(&mut self) -> &mut M {
        &mut self.buffer
    }
}

impl<C, M> Deref for PrepareSend<C, M>
where
    M: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl<C, M> crate::TryExtend<u8> for PrepareSend<C, M>
where
    M: crate::TryExtend<u8>,
{
    type Error = M::Error;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        self.buffer.try_extend(iter)
    }
}

impl<C, M> crate::TryRemove<u8> for PrepareSend<C, M>
where
    M: crate::TryRemove<u8>,
{
    type Error = M::Error;
    type RemoveIter<'a> = M::RemoveIter<'a> where M: 'a, Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.buffer.try_remove(how_many)
    }
}

impl<C, M> crate::TryFrontExtend<u8> for PrepareSend<C, M>
where
    M: crate::TryFrontExtend<u8>,
{
    type Error = M::Error;

    fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        self.buffer.try_front_extend(iter)
    }
}

impl<C, M> crate::TryFrontRemove<u8> for PrepareSend<C, M>
where
    M: crate::TryFrontRemove<u8>,
{
    type Error = M::Error;
    type FrontRemoveIter<'a> = M::FrontRemoveIter<'a> where M: 'a, Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.buffer.try_front_remove(how_many)
    }
}

/// The interface
///
/// An `Interface` is the component of the host that must run with the interface driver. Its the
/// part of the host that must perpetually await upon the
pub struct Interface<R, F> {
    channel_reserve: R,
    flow_ctrl_queues: F,
    initial_connection_flow_control: FlowControl,
}

impl<R, F> Interface<R, F>
where
    R: ChannelReserve,
    F: FlowControlQueues,
{
    /// Create channels for a new connection
    pub fn new_connection(&mut self, handle: ConnectionHandle) -> Result<(R::Sender, R::Receiver), R::Error> {
        let mut channel = self.channel_reserve.try_add(TaskId::Connection(handle))?;

        let sender = self.channel_reserve.get_self_sender();

        channel.set_flow_control(self.initial_connection_flow_control);

        let receiver = channel.get_to_receiver().unwrap();

        Ok((sender, receiver))
    }

    /// Buffer received HCI packet from the interface until it can be sent upwards
    ///
    /// An interface may be unable to receive complete HCI packets from the interface. Instead of
    /// having the driver process the fragmented HCI packet into complete fragment, a buffered send
    /// can be used to do this. This buffers interface data until a complete packet is held within
    /// the buffer. The buffered send is consumed and then the HCI packet is sent upward (either to
    /// the host or connection async task).
    ///
    /// ```
    /// # #![feature(generic_associated_types)]
    /// # use std::future::Future;
    /// # use std::pin::Pin;
    /// # use std::task::{Context, Poll};
    /// # use std::fmt::Debug;
    /// # use crate::bo_tie::hci::interface::{BufferSend, Channel, TaskId, ChannelReserve, HciPacket, HciPacketType, Interface, Receiver, Sender};
    /// #
    /// # struct Sf;
    /// # impl Future for Sf {
    /// #     type Output = Result<(), ()>;
    /// #
    /// #     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct Rf;
    /// # impl Future for Rf {
    /// #     type Output = Option<HciPacket<()>>;
    /// #
    /// #     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct S;
    /// # impl Sender for S {
    /// #     type Error = ();
    /// #     type Payload = ();
    /// #     type SendFuture<'a> = Sf;
    /// #
    /// #     fn send<'a>(&'a mut self, t: HciPacket<Self::Message>) -> Self::SendFuture<'a> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct R;
    /// # impl Receiver for R {
    /// # type Message = ();
    /// # type ReceiveFuture<'a> = Rf;
    /// #
    /// #     fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct C;
    /// # impl Channel for C {
    /// #    type Sender<'a> = S;
    /// #    type Receiver<'a> = R;
    /// #    
    /// #    fn get_to_sender<'a>(&'a self) -> Self::Sender<'a> {
    /// #        unimplemented!()
    /// #    }
    /// #    
    /// #    fn get_to_receiver<'a>(&'a self) -> Self::Receiver<'a> {
    /// #        unimplemented!()
    /// #    }
    /// # }
    /// #
    /// # struct CM;
    /// # impl ChannelReserve for CM {
    /// #    type Error = usize;
    /// #    type Channel = C;
    /// #
    /// #    fn get_self_receiver(&self) -> &Self::Channel {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn try_add(&mut self, id: TaskId) -> Result<usize, Self::Error> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn try_remove(&mut self, id: TaskId) -> Result<Self::Channel, Self::Error> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn get(&self, id: TaskId) -> Option<&Self::Channel> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn get_by_index(&self, index: usize) -> Option<&Self::Channel> {
    /// #        unimplemented!()
    /// #    }
    /// # }
    /// #
    /// # struct Driver;
    /// # impl Driver {
    /// #    fn read_packet_type(&self) -> HciPacketType { unimplemented!() }
    /// #
    /// #    async fn read_byte(&self) -> u8 { unimplemented!() }
    /// # }
    /// #
    /// # async {
    /// # let mut interface = Interface::<Vec<u8>>::new_local(0);
    /// # let driver = Driver;
    /// # let packet_type = HciPacketType::Command;
    /// # let _ = {
    /// // The Bluetooth Specification leaves how to determine the type
    /// // of a HCI packet to the interface implementation. Here this
    /// // is magically done in the dummy method `read_packet_type`. How
    /// // it is done for a driver is a bit more complicated.
    /// let packet_type: HciPacketType = driver.read_packet_type();
    ///
    /// let mut buffer_send = interface.buffer_send(packet_type);
    ///
    /// // Bytes are
    /// while !buffer_send.add(driver.read_byte().await) {}
    ///
    /// buffer_send.send().await
    /// # }.ok();
    /// # };
    /// ```
    pub fn buffered_send(&mut self, packet_type: HciPacketType) -> BufferedSend<'_, R, F> {
        BufferedSend::new(self, packet_type)
    }

    /// Send a complete HCI packet
    ///
    /// This sends a complete `HciPacket` to the correct destination (either the host or a
    /// connection async task). It is up to the implementation to guarantee that the data within
    /// the packet is complete.
    pub async fn send(&mut self, packet_type: HciPacketType, packet: &[u8]) -> Result<(), SendError<R>> {
        match packet_type {
            HciPacketType::Command => Err(SendError::<R>::Command),
            HciPacketType::Acl => self.send_acl(packet).await.map_err(|e| e.into()),
            HciPacketType::Sco => Err(SendError::<R>::Unimplemented(HciPacketType::Sco)),
            HciPacketType::Event => self.maybe_send_event(packet).await.map_err(|e| e.into()),
            HciPacketType::Iso => Err(SendError::<R>::Unimplemented(HciPacketType::Iso)),
        }
    }

    /// Receive a HCI packet
    ///
    /// Await for the next `HciPacket` to be sent to the interface.
    ///
    /// This method returns `None` when there are no more Senders associated with the underlying
    /// receiver. The interface async task should exit after `None` is received.
    pub fn recv(&mut self) -> Recv<'_, R, F> {
        Recv { interface: self }
    }

    /// Parse an event for information that is relevant to this interface
    ///
    /// The interface needs to know of a few things from certain events.
    ///
    /// `true` is returned if the event is to be returned to the host.
    ///
    /// # Processed Events
    /// * *Command Complete* and *Command Status* events contain the information on how many HCI
    ///   commands can be sent to the controller.
    /// * *Number of Completed Packets* event contains information on the number of packets sent for
    ///   a specific connection.
    /// * *Number of Completed Data Blocks* event contains information on the number of packets sent
    ///   and
    fn parse_event<E>(&mut self, event_data: &[u8]) -> Result<bool, SendMessageError<E>> {
        let first_byte = *event_data
            .get(0)
            .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Event))?;

        let len = 2usize
            + *event_data
                .get(1)
                .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Event))? as usize;

        let event_parameter = event_data
            .get(2..len)
            .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Event))?;

        match Events::try_from_event_codes(first_byte, 0 /* does not matter */) {
            Ok(Events::CommandComplete) => self.parse_command_complete_event(event_parameter),
            Ok(Events::CommandStatus) => self.parse_command_status_event(event_parameter),
            Ok(Events::NumberOfCompletedPackets) => self.parse_number_of_completed_packets_event(event_parameter),
            Ok(Events::NumberOfCompletedDataBlocks) => {
                self.parse_number_of_completed_data_blocks_event(event_parameter)
            }
            _ => Ok(true),
        }
    }

    /// Parse a command complete event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_command_complete_event<E>(&mut self, event_parameter: &[u8]) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::CommandCompleteData;
        use core::convert::TryFrom;

        let cc_data = CommandCompleteData::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::CommandComplete))?;

        if 0 != cc_data.number_of_hci_command_packets {
            self.channel_reserve
                .get(TaskId::Host)
                .ok_or(SendMessageError::HostClosed)?
                .inc_flow_control_packets(cc_data.number_of_hci_command_packets);

            self.flow_ctrl_queues.set_ready(TaskId::Host);
        }

        Ok(cc_data.command_opcode.is_some())
    }

    /// Parse a command status event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_command_status_event<E>(&mut self, event_parameter: &[u8]) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::CommandStatusData;
        use core::convert::TryFrom;

        let cs_data = CommandStatusData::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::CommandStatus))?;

        if 0 != cs_data.number_of_hci_command_packets {
            self.channel_reserve
                .get(TaskId::Host)
                .ok_or(SendMessageError::HostClosed)?
                .inc_flow_control_packets(cs_data.number_of_hci_command_packets);

            self.flow_ctrl_queues.set_ready(TaskId::Host);
        }

        Ok(cs_data.command_opcode.is_some())
    }

    /// Parse a Number of Completed Packets event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_number_of_completed_packets_event<E>(
        &mut self,
        event_parameter: &[u8],
    ) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::{Multiple, NumberOfCompletedPacketsData};
        use core::convert::TryFrom;

        let ncp_data = Multiple::<NumberOfCompletedPacketsData>::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::NumberOfCompletedPackets))?;

        for ncp in ncp_data {
            if 0 != ncp.completed_packets {
                let channel_id = TaskId::Connection(ncp.connection_handle);

                self.channel_reserve
                    .get(channel_id)
                    .ok_or(SendMessageError::UnknownConnectionHandle(ncp.connection_handle))?
                    .inc_flow_control_packets(ncp.completed_packets);

                self.flow_ctrl_queues.set_ready(channel_id);
            }
        }

        Ok(false)
    }

    /// Parse a Number of Completed Data Blocks event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    ///
    /// If the return is `Ok` then it always contains `false`.
    fn parse_number_of_completed_data_blocks_event<E>(
        &mut self,
        event_parameter: &[u8],
    ) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::NumberOfCompletedDataBlocksData;
        use core::convert::TryFrom;

        let ncdb_data = NumberOfCompletedDataBlocksData::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::NumberOfCompletedDataBlocks))?;

        for ncdb in ncdb_data.completed_packets_and_blocks {
            if 0 != ncdb.completed_packets {
                let channel_id = TaskId::Connection(ncdb.connection_handle);

                self.channel_reserve
                    .get(channel_id)
                    .ok_or(SendMessageError::UnknownConnectionHandle(ncdb.connection_handle))?
                    .inc_flow_control_packets_and_data(ncdb.completed_packets, ncdb.completed_blocks);

                self.flow_ctrl_queues.set_ready(channel_id);
            }
        }

        Ok(false)
    }

    /// Send an event to the host
    ///
    /// This will send the prepared event to the host so long it is not one of the events purely
    /// about the buffers on the controller.
    ///
    /// ## Informational Events
    /// The events *Number of Completed Packets*, *Number of Completed Data Blocks*, and when either
    /// *Command Complete* and *Command Status* does not contain a command code are not sent to the
    /// host. All the information within those events is only relevant to the interface async task.
    async fn maybe_send_event(&mut self, packet: &[u8]) -> Result<(), SendError<R>> {
        use crate::TryExtend;

        if self.parse_event(&packet)? {
            let mut prepare_send = self
                .channel_reserve
                .prepare_send(TaskId::Host)
                .ok_or(SendError::<R>::HostClosed)?
                .await;

            prepare_send
                .try_extend(packet.iter().cloned())
                .map_err(|e| SendError::<R>::BufferExtend(e))?;

            PrepareSend::and_send(prepare_send, |buffer| IntraMessageType::Event(buffer).into())
                .await
                .map_err(|e| SendMessageError::ChannelError(e))?
        }

        Ok(())
    }

    async fn send_acl(&mut self, packet: &[u8]) -> Result<(), SendError<R>> {
        use crate::TryExtend;
        use core::convert::TryFrom;

        let raw_handle = <u16>::from_le_bytes([
            *packet
                .get(0)
                .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Acl))?,
            *packet
                .get(1)
                .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Acl))?,
        ]);

        let connection_handle =
            ConnectionHandle::try_from(raw_handle).map_err(|_| SendMessageError::InvalidConnectionHandle)?;

        let mut prepare_send = self
            .channel_reserve
            .prepare_send(TaskId::Connection(connection_handle))
            .ok_or(SendError::<R>::HostClosed)?
            .await;

        prepare_send
            .try_extend(packet.iter().cloned())
            .map_err(|e| SendError::<R>::BufferExtend(e))?;

        PrepareSend::and_send(prepare_send, |buffer| IntraMessageType::Acl(buffer).into())
            .await
            .map_err(|e| SendMessageError::ChannelError(e).into())
    }
}

impl Interface<local_channel::LocalChannelManager, ()> {
    /// Create a new local `Interface`
    ///
    /// This host controller interface is local to a single thread. The interface, host, and
    /// connections async tasks must run on an local executor or other type of executor that does
    /// not require async tasks to be thread safe.
    ///
    /// # Note
    /// A local interface uses dynamic memory allocation for buffering and messages between async
    /// tasks. A pure `no_std` implementation can be created with
    /// [`new_local_static`](Interface::new_local_static).
    pub fn new_local(channel_size: usize) -> Self {
        let mut channel_reserve = local_channel::LocalChannelManager::new(channel_size);

        // This should always work, hence the usage of unwrap
        channel_reserve.try_add(TaskId::Host).ok().unwrap();

        Interface {
            channel_reserve,
            initial_connection_flow_control: FlowControl::default(),
            flow_ctrl_queues: todo!(),
        }
    }
}

impl Interface<(), ()> {
    /// Create a statically sized local interface
    ///
    /// This host controller interface is local to a single thread. The interface, host, and
    /// connections async tasks must run on an local executor or other type of executor that does
    /// not require async tasks to be thread safe.
    ///
    /// The number of channels is defined by the constant `CHANNEL_COUNT`. The interface task has
    /// two channels to ever other task, this constant must be equal to two times the number of
    /// connection async tasks plus two for the channels to the host async task.
    ///
    /// # Using
    /// A trick is done for this syntax of using method.
    /// ```
    /// use bo_tie::hci::interface::{TaskId, Interface, ChannelReserve};
    /// use bo_tie::l2cap::{ACLU, MinimumMtu};
    ///
    /// let mut channel_reserve = local_channel::LocalStaticChannelManager::new();
    ///
    /// // This should always work, hence the usage of unwrap
    /// channel_reserve.try_add(TaskId::Host).ok().unwrap();
    ///
    /// let interface = Interface::new_stack_local::<5, 5, ACLU::MIN_MTU>(channel_reserve);
    /// ```
    #[cfg(feature = "unstable")]
    pub fn new_stack_local<'a, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>(
        channel_reserve: &'a local_channel::LocalStackChannelReserve<'static, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    ) -> Interface<&'a local_channel::LocalStackChannelReserve<'static, CHANNEL_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, ()>
    {
        Interface {
            channel_reserve,
            initial_connection_flow_control: FlowControl::default(),
            flow_ctrl_queues: todo!(),
        }
    }
}

/// Future returned by the method [`recv`](Interface::recv)
pub struct Recv<'a, R, F> {
    interface: &'a Interface<R, F>,
}

impl<'a, R, F> Future for Recv<'a, R, F>
where
    R: ChannelReserve,
    F: FlowControlQueues,
{
    type Output = Option<IntraMessage<R::Buffer>>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context<'_>) -> core::task::Poll<Self::Output> {
        use core::task::Poll;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.interface.flow_ctrl_queues.next_ready() {
                Some(id) => {
                    // this loops to the next ready id if a channel
                    // doesn't exist for the associated channel id.
                    if let Some(channel) = this.interface.channel_reserve.get(id) {
                        // continue if there is not another message
                        if let ready @ Poll::Ready(_) = channel.get_from_receiver().poll_recv(cx) {
                            // decrement the number of packets that can be sent and
                            // put the channel in the pending queue if the controller
                            // cannot accept any more packets.
                            if !channel.dec_flow_control_packets() {
                                this.interface.flow_ctrl_queues.set_pending(id)
                            }

                            break ready;
                        }
                    }
                }
                None => {
                    this.interface.flow_ctrl_queues.set_ready_waker(cx.waker());

                    break Poll::Pending;
                }
            }
        }
    }
}

#[derive(Debug)]
pub enum SendErrorReason<C, B> {
    ChannelError(C),
    BufferExtend(B),
    Command,
    InvalidHciPacket(HciPacketType),
    InvalidHciEvent(Events),
    InvalidConnectionHandle,
    UnknownConnectionHandle(ConnectionHandle),
    HostClosed,
    Unimplemented(HciPacketType),
}

impl<C, B> Display for SendErrorReason<C, B>
where
    C: Display,
    B: Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            SendErrorReason::ChannelError(c) => Display::fmt(c, f),
            SendErrorReason::BufferExtend(b) => Display::fmt(b, f),
            SendErrorReason::Command => f.write_str("cannot send command to host"),
            SendErrorReason::InvalidHciEvent(event) => write!(f, "received invalid HCI event for '{}'", event),
            SendErrorReason::InvalidHciPacket(ty) => write!(f, "invalid HCI packet for '{}'", ty),
            SendErrorReason::InvalidConnectionHandle => f.write_str("invalid connection handle"),
            SendErrorReason::UnknownConnectionHandle(h) => write!(f, "no connection for handle: {}", h),
            SendErrorReason::HostClosed => f.write_str("Host task is closed"),
            SendErrorReason::Unimplemented(p_type) => write!(f, "HCI message type {} is unimplemented", p_type),
        }
    }
}

impl<C, B> From<SendMessageError<C>> for SendErrorReason<C, B> {
    fn from(sme: SendMessageError<C>) -> Self {
        match sme {
            SendMessageError::ChannelError(c) => SendErrorReason::ChannelError(c),
            SendMessageError::InvalidHciEvent(event) => SendErrorReason::InvalidHciEvent(event),
            SendMessageError::InvalidHciPacket(ty) => SendErrorReason::InvalidHciPacket(ty),
            SendMessageError::HostClosed => SendErrorReason::HostClosed,
            SendMessageError::InvalidConnectionHandle => SendErrorReason::InvalidConnectionHandle,
            SendMessageError::UnknownConnectionHandle(h) => SendErrorReason::UnknownConnectionHandle(h),
        }
    }
}

impl<C, B> From<MessageError<B>> for SendErrorReason<C, B> {
    fn from(me: MessageError<B>) -> Self {
        match me {
            MessageError::BufferExtend(e) => SendErrorReason::BufferExtend(e),
            MessageError::HostClosed => SendErrorReason::HostClosed,
            MessageError::InvalidConnectionHandle => SendErrorReason::InvalidConnectionHandle,
            MessageError::UnknownConnectionHandle(handle) => SendErrorReason::UnknownConnectionHandle(handle),
        }
    }
}

/// Error returned by operations of [`Interface`] or [`BufferedSend`]
pub type SendError<R> =
    SendErrorReason<<R as ChannelReserveTypes>::SenderError, <R as ChannelReserveTypes>::TryExtendError>;

enum SendMessageError<T> {
    ChannelError(T),
    InvalidHciEvent(Events),
    InvalidHciPacket(HciPacketType),
    HostClosed,
    InvalidConnectionHandle,
    UnknownConnectionHandle(ConnectionHandle),
}

enum MessageError<B> {
    BufferExtend(B),
    HostClosed,
    InvalidConnectionHandle,
    UnknownConnectionHandle(ConnectionHandle),
}

impl<B> From<TaskId> for MessageError<B> {
    fn from(channel_id: TaskId) -> Self {
        match channel_id {
            TaskId::Host => MessageError::HostClosed,
            TaskId::Connection(handle) => MessageError::UnknownConnectionHandle(handle),
        }
    }
}

/// Type for method `maybe_send`
///
/// A `BufferedSend` is used whenever the interface cannot send complete HCI packets. Either the
/// buffers for the interface is too small or data is sent indiscriminately. The only requirement
/// is that bytes are fed to a `BufferedSend` in correct order. Trying to "overfeed" with more bytes
/// than necessary will result in the `BufferedSend` ignoring them.
///
/// For information on how to use this see the method [`buffer_send`](Interface::buffered_send)
pub struct BufferedSend<'a, R: ChannelReserve, F> {
    interface: &'a mut Interface<R, F>,
    packet_type: HciPacketType,
    packet_len: core::cell::Cell<Option<usize>>,
    channel_id_state: core::cell::RefCell<BufferedChannelId>,
    buffer: core::cell::RefCell<Option<R::Buffer>>,
}

impl<'a, R, F> BufferedSend<'a, R, F>
where
    R: ChannelReserve,
    F: FlowControlQueues,
{
    /// Create a new `BufferSend`
    fn new(interface: &'a mut Interface<R, F>, packet_type: HciPacketType) -> Self {
        BufferedSend {
            interface,
            packet_type,
            packet_len: core::cell::Cell::new(None),
            channel_id_state: core::cell::RefCell::new(BufferedChannelId::None),
            buffer: core::cell::RefCell::new(None),
        }
    }

    /// Get the channel
    ///
    /// # Error
    /// An error is returned if the channel no longer exists
    ///
    /// # Panic
    /// This will panic if self.channel_id_state cannot be converted into a channel if.
    fn get_channel(&self) -> Result<R::Channel, MessageError<R::TryExtendError>> {
        let channel_id = self.channel_id_state.borrow().try_into_channel_id().unwrap();

        self.interface.channel_reserve.get(channel_id).ok_or(channel_id.into())
    }

    /// Add bytes before the *parameter length* in the Command packet or Event packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once three bytes of the Command packet are processed.
    #[inline]
    async fn add_initial_command_or_event_byte(&self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        use crate::TryExtend;

        let packet_type = self.packet_type;

        let mut buffer_borrow = Some(self.buffer.borrow_mut());

        let prepare_send;

        if let Some(ref mut ps) = **buffer_borrow.as_mut().unwrap() {
            prepare_send = ps;
        } else {
            buffer_borrow.take();

            self.channel_id_state.replace(BufferedChannelId::Host);

            self.buffer.replace(Some(self.get_channel()?.take(None).await));

            buffer_borrow = Some(self.buffer.borrow_mut());

            prepare_send = buffer_borrow.as_mut().unwrap().as_mut().unwrap();
        }

        prepare_send
            .try_extend_one(byte)
            .map_err(|e| MessageError::BufferExtend(e))?;

        match packet_type {
            HciPacketType::Command => {
                if 3 == prepare_send.len() {
                    self.packet_len.set(Some(3usize + prepare_send[2] as usize));
                }
            }
            HciPacketType::Event => {
                if 2 == prepare_send.len() {
                    self.packet_len.set(Some(2usize + prepare_send[2] as usize));
                }
            }
            HciPacketType::Acl | HciPacketType::Sco | HciPacketType::Iso => unreachable!(),
        }

        Ok(())
    }

    /// A generic function over adding the initial bytes for (ACL, SCO, and ISO) HCI packets.
    ///
    /// All HCI data packets happen to start with the connection handle with a data length field
    /// starting at the byte after. This is for adding bytes to the intra message buffer until the
    /// length bytes are added to the buffer. Once the length is known the member field `packet_len`
    /// will be set and this method cannot be called again.
    async fn add_initial_data_byte(&self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        use crate::TryExtend;

        let mut buffer_borrow = self.buffer.borrow_mut();

        match *buffer_borrow {
            None => {
                if let Some(handle) = self
                    .channel_id_state
                    .borrow_mut()
                    .add_byte(byte)
                    .map_err(|_| MessageError::InvalidConnectionHandle)?
                {
                    drop(buffer_borrow);

                    self.buffer.replace(self.get_channel()?.take(None).await.into());

                    self.buffer
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .try_extend(handle.get_raw_handle().to_le_bytes())
                        .map_err(|e| MessageError::BufferExtend(e))?;
                }
            }
            Some(ref mut prepare_send) => {
                prepare_send
                    .try_extend_one(byte)
                    .map_err(|e| MessageError::BufferExtend(e))?;

                match self.packet_type {
                    HciPacketType::Acl => {
                        if 4 == prepare_send.len() {
                            let len = <u16>::from_le_bytes([prepare_send[2], prepare_send[3]]);

                            self.packet_len.set(Some(4usize + len as usize));
                        }
                    }
                    HciPacketType::Iso => {
                        if 4 == prepare_send.len() {
                            let len_bytes = <u16>::from_le_bytes([prepare_send[2], prepare_send[3]]);

                            let len = len_bytes & 0x3FFF;

                            self.packet_len.set(Some(4usize + len as usize));
                        }
                    }
                    HciPacketType::Sco => {
                        // There is no len check because checking
                        // if the len is 3 is trivial

                        let len = prepare_send[2];

                        self.packet_len.set(Some(3usize + len as usize));
                    }
                    HciPacketType::Command | HciPacketType::Event => unimplemented!(),
                };
            }
        }

        Ok(())
    }

    /// Add initial bytes to the buffer
    ///
    /// These are bytes that are added before the length field has been buffered. Essentially this
    /// is called when `packet_len` is `None`.
    #[inline]
    async fn add_initial_byte(&self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        match self.packet_type {
            HciPacketType::Command => self.add_initial_command_or_event_byte(byte).await,
            HciPacketType::Acl => self.add_initial_data_byte(byte).await,
            HciPacketType::Sco => self.add_initial_data_byte(byte).await,
            HciPacketType::Event => self.add_initial_command_or_event_byte(byte).await,
            HciPacketType::Iso => self.add_initial_data_byte(byte).await,
        }
    }

    /// Add a byte to the buffer
    ///
    /// This adds a single byte to the buffer. If the added byte is determined to be the last byte
    /// of the HCI packet, `true` is returned to indicate that this `BufferedSend` is ready to send.
    ///
    /// ```
    /// use bo_tie::hci::interface::{HciPacketType, Interface};
    ///
    /// # let mut interface = Interface::new_local(1);
    /// # async fn example() {
    /// let mut buffered_send = interface.buffered_send(HciPacketType::Event);
    ///
    /// for byte in driver_bytes {
    ///     if buffered_send.add(*byte).await {
    ///         break
    ///     }
    /// }
    ///
    /// buffered_send.send().await
    /// # }
    /// ```
    ///
    /// # Error
    /// An error is returned if this `BufferedSend` already has a complete HCI Packet.
    pub async fn add(&self, byte: u8) -> Result<bool, SendError<R>> {
        use crate::TryExtend;

        match self.packet_len.get() {
            None => {
                self.add_initial_byte(byte).await?;

                Ok(false)
            }
            // prepared_send should be Some(_) when packet_len is Some(_)
            Some(len) if len != self.buffer.borrow().as_ref().unwrap().len() => {
                self.buffer
                    .borrow_mut()
                    .as_mut()
                    .unwrap()
                    .try_extend_one(byte)
                    .map_err(|e| SendError::<R>::BufferExtend(e))?;

                Ok(len == self.buffer.borrow().as_ref().unwrap().len())
            }
            _ => Err(SendError::<R>::InvalidHciPacket(self.packet_type)),
        }
    }

    /// Add bytes to the buffer
    ///
    /// This add multiple bytes to the buffer, stopping iteration of `iter` early when a complete
    /// HCI Packet is formed.
    ///
    /// # Return
    /// `true` is returned if the this `BufferSend` contains a complete HCI Packet.
    pub async fn add_bytes<I: IntoIterator<Item = u8>>(&mut self, iter: I) -> Result<bool, SendError<R>> {
        for i in iter {
            if self.add(i).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a complete HCI packet is stored and ready to be sent
    pub fn is_ready(&self) -> bool {
        self.packet_len
            .get()
            .as_ref()
            .and_then(|len| Some(*len == self.buffer.borrow().as_ref()?.len()))
            .unwrap_or_default()
    }

    /// Send the HCI Packet to its destination
    ///
    /// When a complete packet is sored within this `BufferSend`, this method is called to transfer
    /// the packet to its destination. An error is returned if this method is called before a
    /// complete HCI packet is stored within this `BufferedSend`.
    pub async fn send(self) -> Result<(), SendError<R>> {
        BufferedSendSetup::new(self).into_future().await
    }
}

/// The state of a connection handle within a buffered
#[derive(Copy, Clone)]
enum BufferedChannelId {
    /// Connection handle has not been set or acquired yet
    None,
    /// First byte of a connection handle
    ConnectionHandleFirstByte(u8),
    /// Host
    Host,
    /// Complete connection handle
    ConnectionHandle(ConnectionHandle),
}

impl BufferedChannelId {
    /// Add a byte to the connection handle
    ///
    /// Add a byte to the buffered connection handle. When a
    /// # Error
    /// An error is returned when the connection handle is invalid
    ///
    /// # Panics
    /// * This method will panic if self is enum `Unused` or `ConnectionHandle`
    fn add_byte(
        &mut self,
        byte: u8,
    ) -> Result<Option<ConnectionHandle>, <ConnectionHandle as core::convert::TryFrom<[u8; 2]>>::Error> {
        use core::convert::TryFrom;

        match core::mem::replace(self, BufferedChannelId::None) {
            BufferedChannelId::None => {
                *self = BufferedChannelId::ConnectionHandleFirstByte(byte);

                Ok(None)
            }
            BufferedChannelId::ConnectionHandleFirstByte(first) => {
                let connection_handle = ConnectionHandle::try_from([first, byte])?;

                *self = BufferedChannelId::ConnectionHandle(connection_handle);

                Ok(Some(connection_handle))
            }
            BufferedChannelId::ConnectionHandle(_) | BufferedChannelId::Host => unreachable!(),
        }
    }

    fn try_into_channel_id(&self) -> Option<TaskId> {
        match self {
            BufferedChannelId::None | BufferedChannelId::ConnectionHandleFirstByte(_) => None,
            BufferedChannelId::Host => Some(TaskId::Host),
            BufferedChannelId::ConnectionHandle(handle) => Some(TaskId::Connection(*handle)),
        }
    }
}

/// Setup for sending a buffered HCI message
///
/// This is necessary as the compiler cannot determine an appropriate lifetime for the returned
/// future in method [`send`](BufferedSend::send) of `BufferedSend`.
///
/// # Why
/// `BufferedSend` cannot be the one to send the message as it self assigns a reference to another
/// reference within in itself where by the compiler cannot determine the lifetime of the future
/// returned by `send` (confused yet? lol).
///
/// To specifically explain what is going on, the issue occurs as a reference to a sender of a
/// channel is acquired from the field in `interface`. If `send` was to be an async method the
/// returned future would need to keep this sender until the future is dropped. The
/// problem occurs because `send` moves `self`. In fact if `send` took `self` by reference and used
/// the implementation scoped lifetime `'a` there would no issue. The compiler will assign the
/// lifetime `'a` to the returned future and successfully compile. The problem with moving `self` is
/// that moving actually creates a new lifetime (different to `'a`) so the compiler assigns that to
/// the future instead causing a compiler error stating that the future could outlive the captured
/// reference to the sender. Using a `BufferedSendSetup` stops the lifetime created from the move of
/// `self` being applied to the returned future and instead applies the impl scoped lifetime `'a` to
/// it.
///
/// ```
/// # use core::future::Future;
///
/// # // stubs
/// # struct BufferedSend<'a, R>(&'a R);
/// # trait ChannelReserve {}
/// # struct SendError<R>(R);
/// # struct BufferedSendSetup<'a, R>(&'a R);
/// # impl<'a, R> BufferedSendSetup<'a, R> {
/// #     fn new(bs: BufferedSend<'a, R>) -> Self { Self(bs.0) }
/// #     async fn into_future(self) -> Result<(), SendError<R>> { unimplemented!() }    
/// # }
///
/// // This is a shadow of what goes on in the method `send` for `BufferedSend`
/// impl<'a, R> BufferedSend<'a, R>
/// where
///     R: ChannelReserve,
/// {
///     /* ... other methods ... */
///
///               // ⬐ The compiler gives `self` some lifetime like '1
///     pub fn send(self) -> impl Future<Output = Result<(), SendError<R>>> + 'a {
///
///         // ┌ BufferedSendSetup captures the lifetime associated with the send future.
///         // |
///         // ↓                         ⬐ `new` moves `self` so lifetime '1 ends here
///         BufferedSendSetup::<'a, R>::new(self).into_future()
///     }
/// }
/// ```
enum BufferedSendSetup<R: ChannelReserve> {
    NoOp,
    Send(R::Sender, IntraMessage<R::Buffer>),
    Err(SendError<R>),
}

impl<R> BufferedSendSetup<R>
where
    R: ChannelReserve,
{
    fn new<F>(bs: BufferedSend<R, F>) -> Self {
        if bs.is_ready() {
            match bs.packet_type {
                HciPacketType::Acl => Self::from_acl(bs),
                HciPacketType::Sco => unimplemented!("SCO not implemented yet"),
                HciPacketType::Event => Self::from_event(bs),
                HciPacketType::Iso => unimplemented!("ISO not implemented yet"),
                HciPacketType::Command => unreachable!(),
            }
        } else {
            BufferedSendSetup::Err(SendError::<R>::InvalidHciPacket(bs.packet_type))
        }
    }

    fn from_event<F>(bs: BufferedSend<R, F>) -> Self {
        let buffer = match bs.buffer.take() {
            Some(buffer) => buffer,
            None => return BufferedSendSetup::Err(SendError::<R>::InvalidHciPacket(bs.packet_type)),
        };

        match bs.interface.parse_event(&buffer) {
            Err(e) => BufferedSendSetup::Err(e.into()),
            Ok(true) => {
                let channel = match bs.get_channel() {
                    Ok(channel) => channel,
                    Err(e) => return BufferedSendSetup::Err(e.into()),
                };

                let message = IntraMessageType::Event(buffer).into();

                let sender = channel.get_to_sender();

                BufferedSendSetup::Send(sender, message)
            }
            Ok(false) => BufferedSendSetup::NoOp,
        }
    }

    fn from_acl<F>(bs: BufferedSend<R, F>) -> Self {
        let buffer = match bs.buffer.take() {
            Some(buffer) => buffer,
            None => return BufferedSendSetup::Err(SendError::<R>::InvalidHciPacket(bs.packet_type)),
        };

        let channel = match bs.get_channel() {
            Ok(channel) => channel,
            Err(e) => return BufferedSendSetup::Err(e.into()),
        };

        let message = IntraMessageType::Acl(buffer).into();

        let sender = channel.get_to_sender();

        BufferedSendSetup::Send(sender, message)
    }

    async fn into_future(self) -> Result<(), SendError<R>> {
        match self {
            BufferedSendSetup::NoOp => Ok(()),
            BufferedSendSetup::Send(sender, message) => {
                sender.send(message).await.map_err(|e| SendError::<R>::ChannelError(e))
            }
            BufferedSendSetup::Err(e) => Err(e),
        }
    }
}

/// The Sender trait
///
/// This trait is used for the sender side of a asynchronous mpsc channel. Its used for sending
/// messages both to and from the interface task and either the host task or a connection task.
/// Messages are sent via the method `send` which returns the type `SendFuture`. The channel
/// associated with the implementation of `Sender` should contain a message queue so that
/// `SendFuture` will only pend when the message queue is full.
///
/// This trait is a gatekeeper on whether the host, interface, and connection tasks are `Send` safe.
/// Since every task has channels to another task, the implementor of this trait is guaranteed to be
/// part of every task. Thus if the `Sender` is `!Send` then the async tasks will also be `!Send`.
/// This prevents the usage of most async executors with the exception of local ones (executors that
/// run on the same thread the tasks were spawned from).
///
/// If the interface task cannot be made `Send` safe for other reasons it is recommended to use
/// either a [`LocalChannel`](local_channel::LocalChannel) or a
/// [`LocalStaticChannel`](local_channel::LocalChannel) instead of directly implementing this trait.
/// Both of these types already implement the trait [`Channel`](Channel).
///
/// Implementing `Sender` is fairly easy if type for the `SendFuture` is known.
/// ```
/// #![feature(generic_associated_types)]
/// # use std::cell::RefCell;
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// use futures::channel::mpsc;
/// use bo_tie::hci::interface::Sender;
///
/// /// The mpsc `Sender` is wrapped in a `RefCell` as it requires
/// /// mutable access to itself in order to send a message. The
/// /// value is only mutably borrowed when the future is polled in
/// /// attempting to send a message.
/// struct FuturesSender<T>(RefCell<mpsc::Sender<T>>);
///
/// struct RefSend<'a, T>(&'a RefCell<mpsc::Sender<T>>, Option<T>);
///
/// impl<T: Unpin> Future for RefSend<'_, T> {
///     type Output = Result<(), mpsc::SendError>;
///
///     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
///         let this = self.get_mut();
///
///         let mut sender = this.0.borrow_mut();
///
///         sender.poll_ready(cx)?;
///
///         let val = this.1.take().unwrap();
///
///         Poll::Ready(sender.start_send(val))
///     }
/// }
/// impl<T> Sender for FuturesSender<T>
/// where
///     T: Unpin
/// {
///     type Error = mpsc::SendError;
///     type Message = T;
///     type SendFuture<'a> = RefSend<'a, T> where T: 'a;
///
///     fn send<'a>(&'a self, t: Self::Message) -> Self::SendFuture<'a> {
///         RefSend(self, Some(t))
///     }
/// }
/// ```
///
/// If the type is unknown then the feature `type_alias_impl_trait` can be enabled for ease of
/// implementation.
/// ```
/// #![feature(generic_associated_types)]
/// #![feature(type_alias_impl_trait)]
/// # use std::future::Future;
/// use tokio::sync::mpsc;
/// use bo_tie::hci::interface::{Sender, HciPacket};
///
/// struct TokioSender<T>(mpsc::Sender<HciPacket<T>>);
///
/// impl<T> Sender for TokioSender<T> {
///     type Error = mpsc::error::SendError<HciPacket<T>>;
///     type Message = T;
///     type SendFuture<'a> = impl Future<Output = Result<(), Self::Error>> + 'a where T: 'a;
///
///     fn send<'a>(&'a self, t: Self::Message) -> Self::SendFuture<'a> {
///         // Since `send` is an async method, its return type is hidden.
///         self.0.send(t)
///    }
/// }
/// ```
pub trait Sender {
    type Error: Debug;
    type Message: Unpin;
    type SendFuture<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    fn send(&self, t: Self::Message) -> Self::SendFuture<'_>;
}

/// The Receiver trait
///
/// This trait is used for the receiver side of a asynchronous mpsc channel. Its used for receiving
/// messages both to and from the interface task and either the host task or a connection task.
/// Messages are sent via the method `recv` which returns the type `ReceiveFuture`. The channel
/// associated with the implementation of `Receiver` should contain a message queue so that
/// `ReceiveFuture` will only pend when the message queue is empty.
///
/// This trait is a gatekeeper on whether the host, interface, and connection tasks are `Send` safe.
/// Since every task has channels to another task, the implementor of this trait is guaranteed to be
/// part of every task. Thus if the `Receiver` is `!Send` then the async tasks will also be `!Send`.
/// This prevents the usage of most async executors with the exception of local ones (executors that
/// run on the same thread the tasks were spawned from).
///
/// If the interface task cannot be made `Send` safe for other reasons it is recommended to use
/// either a [`LocalChannel`](local_channel::LocalChannel) or a
/// [`LocalStaticChannel`](local_channel::LocalChannel) instead of directly implementing this trait.
/// Both of these types already implement the trait [`Channel`](Channel.
///
/// Implementing `Receiver` is fairly easy if type for the `ReceiveFuture` is known. Here is an
/// example where `Receiver` is implemented for a mpsc `Receiver` of the
/// [futures](https://github.com/rust-lang/futures-rs) crate.
/// ```
/// #![feature(generic_associated_types)]
/// # use std::cell::RefCell;
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// use futures::channel::mpsc;
/// use futures::stream::Stream;
/// use bo_tie::hci::interface::Receiver;
///
/// struct FuturesReceiver<T>(RefCell<mpsc::Receiver<T>>);
///
/// struct RefReceiver<'a, T>(&'a RefCell<mpsc::Receiver<T>>);
///
/// impl<T> Future for RefReceiver<'_, T> {
///     type Output = Option<T>;
///
///     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
///         let mut receiver = self.get_mut().0.borrow_mut();
///
///         Stream::poll_next(Pin::new(&mut *receiver), cx)
///     }
/// }
///
/// impl<T> Receiver for FuturesReceiver<T>
/// where
///     T: Unpin
/// {
///     type Message = T;
///     type ReceiveFuture<'a> = RefReceiver<'a, T> where T: 'a;
///
///     fn recv<'a>(&'a self) -> Self::ReceiveFuture<'a> {
///         RefReceiver(& self.0)
///     }
/// }
/// ```
///
/// If the type is unknown then the feature `type_alias_impl_trait` can be enabled for ease of
/// implementation.
/// ```
/// #![feature(generic_associated_types)]
/// #![feature(type_alias_impl_trait)]
/// # use std::future::Future;
/// use tokio::sync::mpsc;
/// use bo_tie::hci::interface::Receiver;
///
/// struct TokioSender<T>(mpsc::Receiver<T>);
///
/// impl<T> Receiver for TokioSender<T> {
///     type Message = T;
///     type ReceiveFuture<'a> = impl Future<Output = Option<T>> + 'a where T: 'a;
///
///     fn recv<'a>(&'a self) -> Self::ReceiveFuture<'a> {
///         // Since `send` is an async method, its return type is hidden.
///         self.0.recv()
///    }
/// }
/// ```
pub trait Receiver {
    type Message: Unpin;
    type ReceiveFuture<'a>: Future<Output = Option<Self::Message>>
    where
        Self: 'a;

    fn poll_recv(&mut self, cx: &mut core::task::Context<'_>) -> core::task::Poll<Option<Self::Message>>;

    fn recv(&self) -> Self::ReceiveFuture<'_>;
}

/// The types of HCI packets
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum HciPacketType {
    /// Command packet
    Command,
    /// Asynchronous Connection-Oriented Data Packet
    Acl,
    /// Synchronous Connection-Oriented Data Packet
    Sco,
    /// Event Packet
    Event,
    /// Isochronous Data Packet
    Iso,
}

impl Display for HciPacketType {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            HciPacketType::Command => f.write_str("Command"),
            HciPacketType::Acl => f.write_str("ACL"),
            HciPacketType::Sco => f.write_str("SCO"),
            HciPacketType::Event => f.write_str("Event"),
            HciPacketType::Iso => f.write_str("ISO"),
        }
    }
}
/// Inner interface messaging
///
/// This is the type for messages sent between the interface async task and either the host or a
/// connection async tasks. HCI packets are the most common message, but there is also other types
/// of messages sent for task related things.
#[repr(transparent)]
pub struct IntraMessage<T> {
    pub(crate) ty: IntraMessageType<T>,
}

impl<T> IntraMessage<T> {
    /// Get a mutable reference to the buffer
    ///
    /// This will return a mutable reference the buffer if the `IntraMessageType` contains a buffer.
    pub(crate) fn get_mut_buffer(&mut self) -> Option<&mut T> {
        match &mut self.ty {
            IntraMessageType::Command(_, t) => Some(t),
            IntraMessageType::Acl(t) => Some(t),
            IntraMessageType::Sco(t) => Some(t),
            IntraMessageType::Event(t) => Some(t),
            IntraMessageType::Iso(t) => Some(t),
        }
    }

    /// Print the kind of message
    ///
    /// This is used for debugging purposes
    pub(crate) fn kind(&self) -> &'static str {
        match self.ty {
            IntraMessageType::Command(_, _) => "Command",
            IntraMessageType::Acl(_) => "Acl",
            IntraMessageType::Sco(_) => "Sco",
            IntraMessageType::Event(_) => "Event",
            IntraMessageType::Iso(_) => "Iso",
        }
    }
}

impl<T> From<IntraMessageType<T>> for IntraMessage<T> {
    fn from(ty: IntraMessageType<T>) -> Self {
        Self { ty }
    }
}

/// An enum of the type of message sent between two async tasks
pub(crate) enum IntraMessageType<T> {
    /*----------------------------
     HCI Packet messages
    ----------------------------*/
    /// HCI Command Packet
    Command(CommandEventMatcher, T),
    /// HCI asynchronous Connection-Oriented Data Packet
    Acl(T),
    /// HCI synchronous Connection-Oriented Data Packet
    Sco(T),
    /// HCI Event Packet
    Event(T),
    /// HCI isochronous Data Packet
    Iso(T),
    /*----------------------------
     Meta information messages
    ----------------------------*/
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    /// Creates a HciPacket where the packet_type is always `Command`
    ///
    /// This is used wherever the packet_type has no purpose in the test.
    pub fn quick_packet<T>(data: T) -> HciPacket<T> {
        HciPacket {
            packet_type: HciPacketType::Command,
            data,
        }
    }

    /// Test sending and receiving a set of values for a specific channel
    ///
    /// This test that
    /// * for the given set test values, the channel can send each value and receive the values in
    ///   order.
    /// * When all instances of the sender are dropped, the receiver will return `None` upon
    ///   awaiting to receive a value.
    ///
    /// # Note
    /// If the internal channel buffer is limited in size, `test_vals` should be larger than that
    /// size.
    pub async fn generic_send_and_receive<'a, P, C, S, R>(channel: &'a C, test_vals: &[P])
    where
        C: Channel<Sender<'a> = S, Receiver<'a> = R> + 'a,
        S: Sender<Payload = P> + 'a,
        R: Receiver<Payload = P> + 'a,
        <<C as Channel>::Sender<'a> as Sender>::Error: Debug,
        P: PartialEq + Debug + Clone,
    {
        use futures::FutureExt;

        let mut sender = channel.get_to_sender();
        let mut receiver = channel.get_to_receiver();

        let mut send_task = Box::pin(
            async {
                for val in test_vals.iter() {
                    let to_send = quick_packet(val.clone());

                    sender.send(to_send).await.unwrap();
                }
            }
            .fuse(),
        );

        let mut recv_task = Box::pin(
            async {
                for val in test_vals.iter() {
                    let rx = receiver.recv().await.map(|packet| packet.data);

                    assert_eq!(Some(val), rx.as_ref());
                }
            }
            .fuse(),
        );

        let mut send_done = false;
        let mut recv_done = false;

        while !send_done || !recv_done {
            tokio::select! {
            _ = &mut send_task => send_done = true,
            _ = &mut recv_task => recv_done = true,
            }
        }

        drop(send_task);
        drop(recv_task);
        drop(sender);

        // Check that the receiver returns none when the sender is dropped
        assert!(receiver.recv().await.is_none())
    }
}
