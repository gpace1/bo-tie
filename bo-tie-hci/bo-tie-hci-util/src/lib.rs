//! Common items for the host controller interface
//!
//! This crate carries the parts of the HCI that are used by multiple HCI crates.

#![feature(generic_associated_types)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod events;
pub mod le;
pub mod local_channel;
pub mod opcodes;

use bo_tie_util::buffer::{Buffer, BufferReserve, TryExtend};
use core::fmt;
use core::fmt::{Debug, Display, Formatter};
use core::future::Future;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll};

/// The connection handle
///
/// This is used as an identifier of a connection by both the host and interface. Its created by the
/// controller when a connection is established between this device and another device.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct ConnectionHandle {
    handle: u16,
}

impl fmt::Display for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.handle)
    }
}

impl fmt::Binary for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:b}", self.handle)
    }
}

impl fmt::LowerHex for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.handle)
    }
}

impl fmt::Octal for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:o}", self.handle)
    }
}

impl fmt::UpperHex for ConnectionHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:X}", self.handle)
    }
}

impl AsRef<u16> for ConnectionHandle {
    fn as_ref(&self) -> &u16 {
        &self.handle
    }
}

impl ConnectionHandle {
    pub const MAX: u16 = 0x0EFF;

    const ERROR: &'static str = "Raw connection handle value larger then the maximum (0x0EFF)";

    pub fn get_raw_handle(&self) -> u16 {
        self.handle
    }
}

impl TryFrom<u16> for ConnectionHandle {
    type Error = &'static str;

    fn try_from(raw: u16) -> Result<Self, Self::Error> {
        if raw <= ConnectionHandle::MAX {
            Ok(ConnectionHandle { handle: raw })
        } else {
            Err(Self::ERROR)
        }
    }
}

impl TryFrom<[u8; 2]> for ConnectionHandle {
    type Error = &'static str;

    fn try_from(raw: [u8; 2]) -> Result<Self, Self::Error> {
        let raw_val = <u16>::from_le_bytes(raw);

        core::convert::TryFrom::<u16>::try_from(raw_val)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum EncryptionLevel {
    Off,
    E0,
    AesCcm,
}

/// A matcher of events in response to a command
///
/// This is used for matching a HCI packet from the controller to the events [Command Complete] or
/// [Command Status]. Either one will match so long as the opcode within the event matches the
/// opcode within the `CommandEventMatcher`.
///
/// [Command Complete]: events::parameters::CommandCompleteData
/// [Command Status]: events::parameters::CommandStatusData
#[derive(Clone, Copy)]
pub struct CommandEventMatcher {
    op_code: opcodes::HciCommand,
    event: events::Events,
    matcher: for<'a> fn(&'a [u8]) -> Option<u16>,
}

impl CommandEventMatcher {
    /// Create a new `CommandEventMatcher` for the event `CommandComplete`
    ///
    /// A event matcher will be made for the event 'Command Complete' for the chosen `source`.
    pub fn new_command_complete(op_code: opcodes::HciCommand) -> Self {
        fn get_op_code(raw: &[u8]) -> Option<u16> {
            // bytes 3 and 4 are the opcode within an HCI event
            // packet containing a Command Complete event.

            let b1 = raw.get(3)?;
            let b2 = raw.get(4)?;

            Some(<u16>::from_le_bytes([*b1, *b2]))
        }

        Self {
            op_code,
            event: events::Events::CommandComplete,
            matcher: get_op_code,
        }
    }

    /// Create a new `CommandEventMatcher` for the event `CommandStatus`
    pub fn new_command_status(op_code: opcodes::HciCommand) -> Self {
        fn get_op_code(raw: &[u8]) -> Option<u16> {
            // bytes 4 and 5 are the opcode within an HCI event
            // packet containing a Command Status event.

            let b1 = raw.get(4)?;
            let b2 = raw.get(5)?;

            Some(<u16>::from_le_bytes([*b1, *b2]))
        }

        Self {
            op_code,
            event: events::Events::CommandStatus,
            matcher: get_op_code,
        }
    }

    pub fn get_op_code(&self) -> opcodes::HciCommand {
        self.op_code
    }

    pub fn get_event(&self) -> events::Events {
        self.event
    }
}

/// Identifiers of channels
///
/// The interface has a collection of channels for sending data to either the host or connection.
/// A `ChannelId` is used for identifying the channels in this collection.
#[derive(Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum TaskId {
    Host,
    Connection(ConnectionHandle),
}

/// Identification for a flow controller
///
/// An [`Interface`] has a different flow controller for each of the possible data buffers in a
/// controller.
///
/// ### Legend
/// `Cmd` -> Commands buffer
/// `Acl` -> ACL data buffer
/// `Sco` -> SCO data buffer
/// `LeAcl` -> LE ACL data buffer
/// `LeIso` -> LE ISO data buffer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowControlId {
    Cmd,
    Acl,
    Sco,
    LeAcl,
    LeIso,
}

impl FlowControlId {
    /// Create an iterator to cycles through the enumerations starting at the enumeration after
    ///
    /// This creates an iterator that is used iterate through the enumerations within
    /// `FlowControlId`. The iterator starts at the enumeration listed after the enumeration that
    /// method `cycle_after` was called on. The last item output by the iterator is always the
    /// enumeration that called `cycle_after`.
    fn cycle_after(self) -> impl Iterator<Item = Self> {
        struct Cycle {
            current: FlowControlId,
            cnt: usize,
        }

        impl Cycle {
            const ENUM_COUNT: usize = 5;

            fn new(id: FlowControlId) -> Self {
                let current = id;
                let cnt = 0;

                Self { current, cnt }
            }

            fn next_id(&self) -> FlowControlId {
                match self.current {
                    FlowControlId::Cmd => FlowControlId::Acl,
                    FlowControlId::Acl => FlowControlId::Sco,
                    FlowControlId::Sco => FlowControlId::LeAcl,
                    FlowControlId::LeAcl => FlowControlId::LeIso,
                    FlowControlId::LeIso => FlowControlId::Cmd,
                }
            }
        }

        impl Iterator for Cycle {
            type Item = FlowControlId;

            fn next(&mut self) -> Option<Self::Item> {
                if self.cnt < Self::ENUM_COUNT {
                    self.current = self.next_id();

                    self.cnt += 1;

                    Some(self.current)
                } else {
                    None
                }
            }
        }

        Cycle::new(self)
    }
}

/// A trait for getting the size of the payload
///
/// This trait is required to extract the size of the payload of an HCI data message (ACL, SCO, or
/// ISO). Its used for block-based flow control to determine if the controller can accept
trait GetDataPayloadSize {
    /// Get the size of the payload of an HCI packet
    ///
    /// # Note
    /// This method will return `None` if the intra message is a meta type message.
    fn get_payload_size(&self) -> Option<usize>;
}

/// Flow control information
///
/// This is flow control information about a specific buffer within the controller. It's used to
/// monitor the buffer space within the controller by keeping a count of the space available within
/// it.
///
/// `FlowControl` is used for both command and data HCI packets. For commands it contains the
/// number of commands that can be currently sent to the controller. For data packets it either
/// contains the number of packets that can be sent to the controller or the number of data blocks
/// that is free within the controller.
///
/// ## Kinds
/// As specified in the Bluetooth Specification, *packet-based* and *data-block-based* are the two
/// kinds of buffering done for HCI within a Controller. In `FlowControl` the enumeration `Packets`
/// corresponds to *packet-based* flow control, and `DataBlocks` corresponds to *data-block-based*
/// flow control. Users of this library can specify at runtime what kind of flow control to use for
/// data packets, but command flow control always uses `Packets`.
///
/// ### `Packets`
/// `Packets` is a flow control mechanism of counting the number of packets that can be sent to the
/// controller. The enumeration consist of `how_many` packets can currently be sent to the
/// controller and the boolean `awaiting` to indicate if interface has messages awaiting for
/// `how_many` to be greater than 0. When `how_many` is increased to be greater than zero an
/// `awating` is true, the interface async task send the awaiting message to the interface driver.
///
/// ### `DataBlocks`
/// `DataBlocks` is a flow control mechanism of counting the number of bytes the controller can
/// currently accept from a HCI data packet. Here, `how_many` represents the maximum number of bytes
/// in a payload of a HCI data packet that can be currently accepted by the controller. The field
/// `awaiting` is the size of the payload of the next HCI data packet to be sent to the controller.
/// When `how_many` is greater than `awaiting` the interface async task will send the awaiting
/// message to the interface driver. When `awaiting` is none, then there is no awaiting message.
///
/// The `halted` field is a flag to halt the sending of messages to the controller, regardless of
/// the value of `how_many`. `halted` is only true when the controller wants to resize the number of
/// empty data blocks to a value less than what the host *may* think there is. It used during the
/// process of re-acquiring the buffer information after the `NumberOfCompletedDataBlocks` event
/// contains `None` (or zero in the event parameters) for the total number of data blocks.
///
/// Currently *data-block-based* flow control is only supports ACL data.
///
/// ### Default
/// The default flow control type is *packet-based*.
#[derive(Debug, Copy, Clone)]
pub enum FlowControl {
    Packets {
        how_many: usize,
        awaiting: bool,
    },
    DataBlocks {
        how_many: usize,
        halted: bool,
        awaiting: Option<usize>,
    },
}

impl Default for FlowControl {
    fn default() -> Self {
        FlowControl::Packets {
            how_many: 0,
            awaiting: false,
        }
    }
}

impl FlowControl {
    /// Check if it is possible to send another HCI data message
    fn is_capped(&self) -> bool {
        0 == match self {
            FlowControl::Packets { how_many, .. } => *how_many,
            FlowControl::DataBlocks { how_many, .. } => *how_many,
        }
    }

    /// Reduce the flow control by tye provided message
    ///
    /// This reduces the flow control information. For `Packets` the 'how_many' count is reduced by
    /// one (unless it is already zero). For `DataBlocks` the `how_many` is reduced by the input
    /// `by` (floored to zero). Both the `awaiting` fields of `Packets` and `DataBlocks` are set to
    /// their default values after this method is called.
    ///
    /// # Note
    /// Input `by` is ignored if this is `Packets`.
    ///
    /// # Panic
    /// Input `payload_info` must not return `None` from method
    /// [`get_payload_size`](GetPayloadSize::get_payload_size)
    fn reduce<T: GetDataPayloadSize>(&mut self, payload_info: &T) {
        match self {
            FlowControl::Packets { how_many, awaiting } => {
                how_many.checked_sub(1).map(|new| *how_many = new);

                *awaiting = Default::default();
            }
            FlowControl::DataBlocks { how_many, awaiting, .. } => {
                match how_many.checked_sub(payload_info.get_payload_size().unwrap()) {
                    Some(new) => *how_many = new,
                    None => *how_many = 0,
                };

                *awaiting = Default::default();
            }
        }
    }

    /// Set the awaiting message flag
    ///
    /// # Panic
    /// Input `payload_info` must not return `None` from method
    /// [`get_payload_size`](GetPayloadSize::get_payload_size)
    fn set_awaiting<T: GetDataPayloadSize>(&mut self, payload_info: &T) {
        match self {
            FlowControl::Packets { awaiting, .. } => *awaiting = true,
            FlowControl::DataBlocks { awaiting, .. } => *awaiting = Some(payload_info.get_payload_size().unwrap()),
        }
    }

    /// Halt the sending of messages to the controller
    ///
    /// This halts the sending of messages to the controller regardless of the value of `how_many`
    ///
    /// # Note
    /// This does nothing if `self` is `Packets`
    pub fn halt(&mut self) {
        if let FlowControl::DataBlocks { halted, .. } = self {
            *halted = true
        }
    }
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
    type SenderError: fmt::Debug;

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
}

/// Ends of the channels for an async task
///
/// Communication between the interface async task and any other task is done through two channels
/// for bi-directional data transmission. The `ChannelEnds` are the parts of the channels used by
/// one of the async tasks.
pub trait ChannelEnds: Sized {
    /// The buffer type of messages *to* the interface async task
    type ToBuffer: Buffer;

    /// The buffer type of messages *from* the interface async task
    type FromBuffer: Buffer;

    /// The future for acquiring a buffer from the channel to send
    type TakeBuffer: Future<Output = Self::ToBuffer>;

    /// The type used to send messages to the interface async task
    type Sender: Sender<Message = ToIntraMessage<Self::ToBuffer>>;

    /// The type used for receiving messages from the interface async task
    type Receiver: Receiver<Message = FromIntraMessage<Self::FromBuffer, Self>>;

    /// Get the sender of messages to the other async task
    fn get_sender(&self) -> Self::Sender;

    /// Take a buffer
    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>;

    /// Get the receiver of messages from the async task
    fn get_receiver(&self) -> &Self::Receiver;

    /// Get a mutable reference to the receiver of messages from the async task
    fn get_mut_receiver(&mut self) -> &mut Self::Receiver;
}

/// A channel reserve
///
/// The point of a channel reserve is to minimize the amount of message movement between the sender
/// and receiver. This includes the initial writing of data into the message.
pub trait ChannelReserve {
    /// The error type associated with the `try_*` method within `ChannelReserve`
    type Error: Debug;

    /// The error returned by the implementation of Sender
    ///
    /// This is the same type as `Error` of [`Sender`]
    type SenderError: Debug;

    /// The error that occurs when trying to extend a buffer fails
    type TryExtendError: Debug;

    /// The buffer for creating a message sent from the interface async task *to* another
    /// async task
    type ToBuffer: Unpin + TryExtend<u8, Error = Self::TryExtendError> + Deref<Target = [u8]>;

    /// The mpsc channel type for sending messages from the interface async task *to* another async
    /// task
    type ToChannel: BufferReserve<Buffer = Self::ToBuffer>
        + Channel<SenderError = Self::SenderError, Message = FromIntraMessage<Self::ToBuffer, Self::TaskChannelEnds>>;

    /// The buffer for creating a message sent *from* another async task to the interface async
    /// task
    type FromBuffer: Unpin + TryExtend<u8, Error = Self::TryExtendError> + Deref<Target = [u8]>;

    /// The mpsc channel type for the interface async task to receiving messages *from* another
    /// async task
    type FromChannel: BufferReserve<Buffer = Self::FromBuffer>
        + Channel<SenderError = Self::SenderError, Message = ToIntraMessage<Self::FromBuffer>>;

    /// The ends of the channels used by another async task to communicate with the channel ends
    /// stored by this `ChannelReserve`.
    type TaskChannelEnds: ChannelEnds<ToBuffer = Self::FromBuffer>;

    /// Try to remove a channel
    fn try_remove(&mut self, id: TaskId) -> Result<(), Self::Error>;

    /// Add a new async task
    ///
    /// This creates a new channel for the task identified by `task_id`. The return is the channel
    /// ends used by the async task to communicate with the interface async task.
    ///
    /// # Panic
    /// This method may panic if `task_id` is already used.
    fn add_new_task(
        &self,
        task_id: TaskId,
        flow_control_id: FlowControlId,
    ) -> Result<Self::TaskChannelEnds, Self::Error>;

    /// Get the channel for sending messages *to* the async task associated by the specified task ID
    ///
    /// `None` is returned if no channel is associated with the input identifier.
    fn get(&self, id: TaskId) -> Option<Self::ToChannel>;

    /// Get the controller flow control identification
    ///
    /// This gets the flow control identifier that is associated to the task ID.
    ///
    /// `None` is returned if no data flow control id is associated with the input identifier.
    fn get_flow_control_id(&self, id: TaskId) -> Option<FlowControlId>;

    /// Get the [`FlowCtrlReceiver`]
    ///
    /// This returns the `FlowCtrlReceiver` used by this `ChannelReserve`.
    fn get_flow_ctrl_receiver(&mut self) -> &mut FlowCtrlReceiver<<Self::FromChannel as Channel>::Receiver>;
}

macro_rules! inc_flow_ctrl {
    ($fc:expr, $ty:ident, $how_many:expr $(,)?) => {{
        match &mut $fc.$ty {
            FlowControl::Packets { how_many, .. } => *how_many += $how_many,
            FlowControl::DataBlocks { how_many, .. } => *how_many += $how_many,
        }

        $fc.call_waker()
    }};
}

pub trait ChannelReserveExt: ChannelReserve {
    /// Prepare for sending a message
    ///
    /// If there is a channel with provided `ChannelId` in this `ChannelReserve`, then a
    /// [`PrepareBufferMsg`] is returned. A `PrepareBufferMsg` is a future for acquiring the buffer
    /// from the channel used by the interface to send messages to the task associated by `id`. Upon
    /// polling to completion a pair containing the buffer to use and the channels sender are output
    /// by the `PrepareBufferMsg`.
    ///
    /// `prepare_buffer_msg` should not be used if no buffer is required in the `IntraMessage` to
    /// send to the async task. Instead use method
    /// [`get_sender`](ChannelReserveExt::get_sender) to skip trying to acquire a buffer.
    fn prepare_buffer_msg(
        &self,
        id: TaskId,
        front_capacity: usize,
    ) -> Option<PrepareBufferMsg<<Self::ToChannel as Channel>::Sender, <Self::ToChannel as BufferReserve>::TakeBuffer>>
    {
        self.get(id)
            .map(|channel| PrepareBufferMsg::from_channel(&channel, front_capacity))
    }

    /// Get a sender to another async task
    ///
    /// The return is the sender used for sending messages to the async task associated by `id`.
    /// None is returned if no channel information exists for the provided `id` this method.
    fn get_sender(&self, id: TaskId) -> Option<<Self::ToChannel as Channel>::Sender> {
        self.get(id).map(|channel| channel.get_sender())
    }

    /// Receive the next message
    fn receive_next(&mut self) -> ReceiveNext<'_, <Self::FromChannel as Channel>::Receiver> {
        ReceiveNext(self.get_flow_ctrl_receiver())
    }

    /// Increment the flow control for commands
    ///
    /// This increments the number of commands that can be sent to the controller by the number
    /// provided by input `how_many`.
    fn inc_cmd_flow_ctrl(&mut self, how_many: usize) {
        inc_flow_ctrl!(self.get_flow_ctrl_receiver(), cmd_flow_control, how_many);
    }

    /// Increment the flow control for ACL data
    ///
    /// This increments the amount of ACL data that can be sent to the controller by the number
    /// provided by input `how_many`. The value of `how_many` depends on the type of flow control
    /// currently implemented.
    ///
    /// ## Packet-Based
    /// In packet based flow control, input `how_many` is the number of ACL data packets completed
    /// by the controller from the last time this method was called. `how_many` directly corresponds
    /// to the number of completed packets within the event
    /// [`NumberOfCompletedPackets`](crate::hci::events::EventsData::NumberOfCompletedPackets)
    ///
    /// ## Data-Block-Based
    /// In data block based flow control, input `how_many` is the number of bytes that the
    /// controller can currently accept since the last time this method was called. This value must
    /// be calculated from the number of data blocks that were completed as stated in the event
    /// [`NumberOfCompletedDataBlocks`](crate::hci::events::EventsData::NumberOfCompletedDataBlocks).
    ///
    /// This method shall not be called if the event `NumberOfCompletedDataBlocks` contained `None`
    /// for the `total_data_blocks` field. This indicates that the host needs to update its buffer
    /// information through the
    /// [`read_data_block_size`](crate::hci::info_params::read_data_block_size) command.
    fn inc_acl_flow_ctrl(&mut self, how_many: usize) {
        inc_flow_ctrl!(self.get_flow_ctrl_receiver(), acl_flow_control, how_many);
    }

    /// Increment the flow control for SCO data
    ///
    /// This increments the amount of SCO data that can be sent to the controller by the number
    /// provided by input `how_many`. The value of `how_many` depends on the type of flow control
    /// currently implemented.
    ///
    /// ## Packet-Based
    /// In packet based flow control, input `how_many` is the number of SCO data packets completed
    /// by the controller from the last time this method was called. `how_many` directly corresponds
    /// to the number of completed packets within the event
    /// [`NumberOfCompletedPackets`](crate::hci::events::EventsData::NumberOfCompletedPackets)
    fn inc_sco_flow_control(&mut self, how_many: usize) {
        inc_flow_ctrl!(self.get_flow_ctrl_receiver(), sco_flow_control, how_many);
    }

    /// Increment the flow control for LE ACL data
    ///
    /// This increments the amount of ACL data that can be sent to the controller by the number
    /// provided by input `how_many`. The value of `how_many` depends on the type of flow control
    /// currently implemented.
    ///
    /// ## Packet-Based
    /// In packet based flow control, input `how_many` is the number of ACL data packets completed
    /// by the controller from the last time this method was called. `how_many` directly corresponds
    /// to the number of completed packets within the event
    /// [`NumberOfCompletedPackets`](crate::hci::events::EventsData::NumberOfCompletedPackets)
    ///
    /// ## Data-Block-Based
    /// In data block based flow control, input `how_many` is the number of bytes that the
    /// controller can currently accept since the last time this method was called. This value must
    /// be calculated from the number of data blocks that were completed as stated in the event
    /// [`NumberOfCompletedDataBlocks`](crate::hci::events::EventsData::NumberOfCompletedDataBlocks).
    ///
    /// This method shall not be called if the event `NumberOfCompletedDataBlocks` contained `None`
    /// for the `total_data_blocks` field. This indicates that the host needs to update its buffer
    /// information through the
    /// [`read_data_block_size`](crate::hci::info_params::read_data_block_size) command.
    fn inc_le_acl_flow_control(&mut self, how_many: usize) {
        inc_flow_ctrl!(self.get_flow_ctrl_receiver(), le_acl_flow_control, how_many);
    }

    /// Increment the flow control for ISO data
    ///
    /// This increments the amount of ISO data that can be sent to the controller by the number
    /// provided by input `how_many`. The value of `how_many` depends on the type of flow control
    /// currently implemented.
    ///
    /// ## Packet-Based
    /// In packet based flow control, input `how_many` is the number of ISO data packets completed
    /// by the controller from the last time this method was called. `how_many` directly corresponds
    /// to the number of completed packets within the event
    /// [`NumberOfCompletedPackets`](crate::hci::events::EventsData::NumberOfCompletedPackets)
    fn inc_le_iso_flow_control(&mut self, how_many: usize) {
        inc_flow_ctrl!(self.get_flow_ctrl_receiver(), le_iso_flow_control, how_many);
    }
}

impl<T: ChannelReserve> ChannelReserveExt for T {}

/// A future for acquiring a `PrepareSend`
///
/// This future awaits until it can acquire a buffer for use as a channel message. Usually this
/// future returns right away, but it is needed in the case where the reserve is waiting to free up
/// a buffer for this send process. When the future does poll to completion it returns a
/// `PrepareSend`.
pub struct PrepareBufferMsg<S, T> {
    sender: Option<S>,
    take_buffer: T,
}

impl<S, T> PrepareBufferMsg<S, T> {
    fn from_channel<'a, C>(channel: &'a C, front_capacity: usize) -> Self
    where
        C: Channel<Sender = S> + BufferReserve<TakeBuffer = T>,
        T: 'a,
    {
        let take_buffer = channel.take(front_capacity);
        let sender = Some(channel.get_sender());

        PrepareBufferMsg { sender, take_buffer }
    }
}

impl<S, T> Future for PrepareBufferMsg<S, T>
where
    T: Future,
{
    type Output = (T::Output, S);

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        unsafe { Pin::new_unchecked(&mut this.take_buffer) }
            .poll(cx)
            .map(|buffer| {
                let sender = this.sender.take().expect("GetPrepareSend already polled to completion");

                (buffer, sender)
            })
    }
}

/// Receivers used by an interface async task
pub struct InterfaceReceivers<R> {
    pub cmd_receiver: R,
    pub acl_receiver: R,
    pub sco_receiver: R,
    pub le_acl_receiver: R,
    pub le_iso_receiver: R,
}

/// A flow controlled receiver
///
/// This is used to manage the flow control from the interface async task to the interface driver.
/// The interface async task monitors the buffers of the controller to ensure that data is not sent
/// to it when the controller cannot accept it.
///
/// This works by only releasing messages from a channel when the controller can accept it. There is
/// possibly five different kinds of buffers in a controller. A
pub struct FlowCtrlReceiver<R: Receiver> {
    cmd_receiver: PeekableReceiver<R>,
    acl_receiver: PeekableReceiver<R>,
    sco_receiver: PeekableReceiver<R>,
    le_acl_receiver: PeekableReceiver<R>,
    le_iso_receiver: PeekableReceiver<R>,
    last_received: FlowControlId,
    cmd_flow_control: FlowControl,
    acl_flow_control: FlowControl,
    sco_flow_control: FlowControl,
    le_acl_flow_control: FlowControl,
    le_iso_flow_control: FlowControl,
    block_size: usize,
    waker: Option<core::task::Waker>,
}

impl<R: Receiver> FlowCtrlReceiver<R> {
    /// Create a new `FlowCtrlReceiver`
    pub fn new(receivers: InterfaceReceivers<R>) -> Self {
        let cmd_receiver = receivers.cmd_receiver.peekable();
        let acl_receiver = receivers.acl_receiver.peekable();
        let sco_receiver = receivers.sco_receiver.peekable();
        let le_acl_receiver = receivers.le_acl_receiver.peekable();
        let le_iso_receiver = receivers.le_iso_receiver.peekable();
        let last_received = FlowControlId::Cmd;
        let cmd_flow_control = FlowControl::default();
        let acl_flow_control = FlowControl::default();
        let sco_flow_control = FlowControl::default();
        let le_acl_flow_control = FlowControl::default();
        let le_iso_flow_control = FlowControl::default();
        let block_size = 0;
        let waker = None;

        Self {
            cmd_receiver,
            acl_receiver,
            sco_receiver,
            le_acl_receiver,
            le_iso_receiver,
            last_received,
            cmd_flow_control,
            acl_flow_control,
            sco_flow_control,
            le_acl_flow_control,
            le_iso_flow_control,
            block_size,
            waker,
        }
    }

    fn set_waker(&mut self, waker: &core::task::Waker) {
        self.waker = Some(waker.clone())
    }

    fn call_waker(&mut self) {
        self.waker.take().map(|waker| waker.wake());
    }
}

/// A future for receiving from a async task
///
/// This is the receiver for receiving messages from any other async task.
///
/// # Note
/// When all async tasks are closed, when polled `RecvNext` will return `None`.
pub struct ReceiveNext<'a, R: Receiver>(&'a mut FlowCtrlReceiver<R>);

impl<R> Future for ReceiveNext<'_, R>
where
    R: Receiver,
    R::Message: GetDataPayloadSize,
{
    type Output = Option<R::Message>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        macro_rules! fc_rx {
            ($fcr:expr, $receiver:ident, $fc:ident, $cx:expr, $fc_id:expr, $dead_cnt:expr) => {
                match $fcr.$receiver.poll_peek($cx) {
                    core::task::Poll::Pending => {}
                    core::task::Poll::Ready(None) => $dead_cnt += 1,
                    core::task::Poll::Ready(Some(message)) => {
                        if $fcr.$fc.is_capped() {
                            $fcr.$fc.set_awaiting(message);

                            // set the waker to awake this when the
                            // flow control information is updated.
                            $fcr.set_waker($cx.waker())
                        } else {
                            $fcr.$fc.reduce(message);

                            $fcr.last_received = $fc_id;

                            let msg = $fcr.$receiver.poll_recv($cx);

                            debug_assert!(msg.is_ready());

                            return msg;
                        }
                    }
                }
            };
        }

        let fcr = unsafe { &mut self.get_unchecked_mut().0 };

        let mut dead_cnt = 0;

        for fc_id in fcr.last_received.cycle_after() {
            match fc_id {
                FlowControlId::Cmd => fc_rx!(fcr, cmd_receiver, cmd_flow_control, cx, fc_id, dead_cnt),
                FlowControlId::Acl => fc_rx!(fcr, acl_receiver, acl_flow_control, cx, fc_id, dead_cnt),
                FlowControlId::Sco => fc_rx!(fcr, sco_receiver, sco_flow_control, cx, fc_id, dead_cnt),
                FlowControlId::LeAcl => fc_rx!(fcr, le_acl_receiver, le_acl_flow_control, cx, fc_id, dead_cnt),
                FlowControlId::LeIso => fc_rx!(fcr, le_iso_receiver, le_iso_flow_control, cx, fc_id, dead_cnt),
            }
        }

        if dead_cnt == 5 {
            Poll::Ready(None)
        } else {
            Poll::Pending
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
/// use bo_tie_hci_util::Sender;
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
/// use bo_tie_hci_util::{Sender, HciPacket};
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

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>>;

    fn recv(&self) -> Self::ReceiveFuture<'_>;
}

/// Extension method to trait [`Receiver`]
trait ReceiverExt: Receiver {
    /// Make a receiver peekable
    ///
    /// This converts a `Receiver` into a peekable receiver. This effectively adds the method
    /// [`peek`] to a receiver which will await for and then return a reference to the next message.
    /// Further calls to `peek` will return a future that immediately output a reference to the same
    /// message. Once [`recv`](Receiver::recv) is called the future returned by it will immediately
    /// output the message previously referenced by `peek`.
    ///
    /// # Note
    /// The issue with a peekable receiver is that
    fn peekable(self) -> PeekableReceiver<Self>
    where
        Self: Sized,
    {
        PeekableReceiver {
            receiver: self,
            peeked: core::cell::Cell::new(None),
        }
    }
}

impl<R: Receiver> ReceiverExt for R {}

/// A peekable receiver
///
/// This struct is created by the [`peekable`](ReceiverExt::peekable) method on `ReceiverExt`.
struct PeekableReceiver<R: Receiver> {
    receiver: R,
    peeked: core::cell::Cell<Option<R::Message>>,
}

impl<R: Receiver> PeekableReceiver<R> {
    fn poll_peek(&mut self, cx: &mut Context<'_>) -> Poll<Option<&R::Message>> {
        if self.peeked.get_mut().is_some() {
            Poll::Ready(self.peeked.get_mut().as_ref())
        } else {
            match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(message)) => {
                    self.peeked = Some(message).into();

                    Poll::Ready(self.peeked.get_mut().as_ref())
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }
}

impl<R: Receiver> Receiver for PeekableReceiver<R> {
    type Message = R::Message;
    type ReceiveFuture<'a> = PeekableReceiveFuture<'a, R> where Self: 'a,;

    fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
        match self.peeked.take() {
            Some(message) => Poll::Ready(Some(message)),
            None => self.receiver.poll_recv(cx),
        }
    }

    fn recv(&self) -> Self::ReceiveFuture<'_> {
        PeekableReceiveFuture(self, None)
    }
}

struct PeekableReceiveFuture<'a, R: Receiver>(&'a PeekableReceiver<R>, Option<R::ReceiveFuture<'a>>);

impl<R: Receiver> Future for PeekableReceiveFuture<'_, R> {
    type Output = Option<R::Message>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match (this.0.peeked.take(), &mut this.1) {
                (None, None) => this.1 = Some(this.0.receiver.recv()),
                (Some(message), _) => return Poll::Ready(Some(message)),
                (None, Some(rx)) => return unsafe { Pin::new_unchecked(rx).poll(cx) },
            }
        }
    }
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
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        match self {
            HciPacketType::Command => f.write_str("Command"),
            HciPacketType::Acl => f.write_str("ACL"),
            HciPacketType::Sco => f.write_str("SCO"),
            HciPacketType::Event => f.write_str("Event"),
            HciPacketType::Iso => f.write_str("ISO"),
        }
    }
}

/// HCI packet kind
///
/// This is an enu
pub enum HciPacket<T: Deref<Target = [u8]>> {
    Command(T),
    Acl(T),
    Sco(T),
    Event(T),
    Iso(T),
}

/// Intra messages sent to the interface async task
///
/// This is the type for messages sent to the interface async task from another async task. All
/// message except for [`IntraMessageType::Event`] are received by the interface async task.
///
/// ## Generics
/// * Generic `T` is the type used as the buffer for HCI data and command messages.
pub struct ToIntraMessage<T> {
    // The enum of `IntraMessageType` that uses
    // its second generic not sent by another
    // async task to the interface async task.
    pub(crate) ty: IntraMessageType<T, ()>,
}

impl<T> ToIntraMessage<T> {
    /// Convert a ToIntraMessage into a HciPacket
    ///
    /// This method may only be called when field `ty` is a `Command`, `Acl`, `Sco` or `Iso`
    /// `IntraMessageType`.
    ///
    /// # Panic
    /// This method panics if field `ty` is not one of the valid enums.
    pub fn into_hci_packet(self) -> HciPacket<T>
    where
        T: Deref<Target = [u8]>,
    {
        match self.ty {
            IntraMessageType::Command(_, t) => HciPacket::Command(t),
            IntraMessageType::Acl(t) => HciPacket::Acl(t),
            IntraMessageType::Sco(t) => HciPacket::Sco(t),
            IntraMessageType::Iso(t) => HciPacket::Iso(t),
            _ => panic!("invalid intra message {}", self.ty.kind()),
        }
    }
}

impl<T> From<IntraMessageType<T, ()>> for ToIntraMessage<T> {
    fn from(ty: IntraMessageType<T, ()>) -> Self {
        Self { ty }
    }
}

impl<T: Deref<Target = [u8]>> GetDataPayloadSize for ToIntraMessage<T> {
    /// A payload size is only returned for the data type (ACL, SCO, ISO) HCI messages.
    fn get_payload_size(&self) -> Option<usize> {
        match &self.ty {
            IntraMessageType::Acl(t) => Some(<u16>::from_le_bytes([t[2], t[3]]).into()),
            IntraMessageType::Sco(t) => Some(t[2].into()),
            IntraMessageType::Iso(t) => Some(<u16>::from_le_bytes([t[2], t[3] & 0x3F]).into()),
            _ => None,
        }
    }
}

/// Intra messages sent from the interface async task
///
/// This is the type for messages sent from the interface async task to another async task. All
/// message except for [`IntraMessageType::Command`] are sent from the interface async task.
///
/// ## Generics
/// * Generic `T` is the type used as the buffer for HCI data and command messages.
/// * Generic `C` implements [`ChannelEnds`]
#[repr(transparent)]
pub struct FromIntraMessage<T, C> {
    pub ty: IntraMessageType<T, C>,
}

impl<T, C> From<IntraMessageType<T, C>> for FromIntraMessage<T, C> {
    fn from(ty: IntraMessageType<T, C>) -> Self {
        Self { ty }
    }
}

/// An enum for the kinds of message sent between two async tasks
///
/// This is the message sent between the interface, host, and connection async tasks.
pub enum IntraMessageType<T, C> {
    /*----------------------------
     HCI Packet messages
    ----------------------------*/
    /// HCI Command Packet
    Command(CommandEventMatcher, T),
    /// HCI asynchronous Connection-Oriented Data Packet
    Acl(T),
    /// HCI synchronous Connection-Oriented Data Packet
    Sco(T),
    /// HCI Event Packet.
    Event(events::EventsData),
    /// HCI isochronous Data Packet
    Iso(T),
    /*----------------------------
     Inner host specific messages

     These messages do not translate to HCI Packet messages
    ----------------------------*/
    /// Connection information
    ///
    /// When the interface async task receives an event that indicates that a connection was made,
    /// it will send this intra message to the host async task. `Connection` contains the channel
    /// ends for that can be used to create a new connection async task. This intra message is sent
    /// before the event that indicated the connection.
    ///
    /// The events connection complete, synchronous connection complete, LE connection complete, and
    /// LE enhanced connection complete all trigger the sending of this intra message.
    Connection(C),
    /// This is sent by a connection async task or the interface async task to indicate that a
    /// connection is disconnected.
    ///
    /// When sent by a connection async task it means that the connection is to be disconnected on
    /// the host end and the disconnection should be made by the Controller. The task must provide
    /// a reason for the disconnection.
    ///
    /// When send by the interface async task to a connection async task then it means that the
    /// Controller has been disconnected from the peer device. The disconnect reason is the same
    /// as reason as provided by the Controller in the disconnection event.
    Disconnect(bo_tie_util::errors::Error),
}

impl<T, C> IntraMessageType<T, C> {
    /// Print the kind of message
    ///
    /// This is used for debugging purposes
    #[doc(hidden)]
    pub const fn kind(&self) -> &'static str {
        match self {
            IntraMessageType::Command(_, _) => "Command",
            IntraMessageType::Acl(_) => "Acl",
            IntraMessageType::Sco(_) => "Sco",
            IntraMessageType::Event(_) => "Event",
            IntraMessageType::Iso(_) => "Iso",
            IntraMessageType::Disconnect(_) => "Disconnect",
            IntraMessageType::Connection(_) => "(BR/EDR) Connection",
        }
    }
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
