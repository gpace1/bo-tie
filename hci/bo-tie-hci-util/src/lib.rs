//! Common items for the host controller interface
//!
//! This crate carries the parts of the HCI that are used by multiple HCI crates.
//!
//! # Async Tasks
//! The Host Controller Interface is broken up into three kinds of async tasks.
//!
//! ### Interface Async Task
//! The interface async task is used for direct interaction between the interface and the host. Its
//! job is to perform flow control to the Controller and distribute messages from the controller to
//! the other async tasks. All messages to and from the Controller must go through the interface
//! task. Whenever another task is said to 'send/receive data from the Controller' in reality it is
//! sending or receiving data from the interface async task.
//!
//! ### Host Async Task
//! This task is used for sending HCI commands and processing events from the Controller. There
//! always must be a host async task "alive" for the HCI to continue running. If the host is dropped
//! then the interface async task will also exit.
//!
//! ### Connection Async Task
//! Unlike the interface and host async tasks, there can be any number of connection async tasks,
//! limited to the number of connections the Controller can support. Connection tasks are created
//! from the host async task after the reception of one of the connection complete events.
//!
//! # Channels
//! Channels are used for communication between the async tasks that make up the HCI. When creating
//! the HCI the user of the library will either use their another library's channels or create a
//! local HCI that uses local channels.
//!
//! ## Implemented Channels
//! Channels from another library can be used with the implementation of the HCI. If an async
//! executor is used that requires send safety for async tasks, then custom implemented channels
//! must be used.
//!
//! ## Local Channels
//! "local" is used to mean that the channels are are not `Send` safe. In fact, when a "local" HCI
//! is created, (one of) the reason's why it is not `Send` safe is because the channels. "local"
//! channels are quite lightweight and have no direct interaction with the operating system. They
//! are implemented by `bo-tie` and so no external channel implementation is required for them to be
//! used.
//!
//! ### Stack Allocated
//! Note: currently unstable
//!
//! In environments where dynamically allocated memory cannot be done, [local stack channels] can
//! be used.
//!
//! # Buffering
//! Double ended vectors are used for buffering bytes transferred over the HCI. If user selected
//! channel or a local dynamic channel is used then [`DeVec`] is used as the buffering type. When a
//! stack local channel is chosen then the buffering type is [`DeLinearBuffer`] (but stack local
//! channels are still experimental).
//!
//! The need for a double ended vector comes from the architecture of having protocol layers in a
//! stack arrangement. Since the protocols of Bluetooth use packets that contain a header followed
//! by a payload, the final packet that is sent ends up being a nesting doll of different protocols.
//! Luckily for Bluetooth, the size of all the header can be known from at the top layer protocol.
//!
//! When a `DeVec` is used as a buffer at the top layer, it is created with a capacity equal to the
//! sum of the header sizes of all layers. Headers are then extended to the *front* of the buffer as
//! it is passed down the protocol layers. When a packet is received from another device it is put
//! within it's entirety into a `DeVec`. As it is passed up the protocol layers the headers are
//! popped off the front.
//!
//! [local stack channels]: local_channel::local_stack
//! [`DeVec`]: bo_tie_util::buffer::de_vec::DeVec
//! [`DeLinearBuffer`]: bo_tie_util::buffer::stack::DeLinearBuffer

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(all(not(feature = "std"), not(test)), no_std)]

extern crate alloc;
extern crate core;

pub mod channel;
pub mod events;
pub mod le;
pub mod local_channel;
pub mod opcodes;

use bo_tie_util::buffer::Buffer;
use core::fmt;
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
}

impl CommandEventMatcher {
    /// Create a new `CommandEventMatcher` for the event `CommandComplete`
    ///
    /// A event matcher will be made for the event 'Command Complete' for the chosen `source`.
    pub fn new_command_complete(op_code: opcodes::HciCommand) -> Self {
        Self {
            op_code,
            event: events::Events::CommandComplete,
        }
    }

    /// Create a new `CommandEventMatcher` for the event `CommandStatus`
    pub fn new_command_status(op_code: opcodes::HciCommand) -> Self {
        Self {
            op_code,
            event: events::Events::CommandStatus,
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
    Host(HostChannel),
    Connection(ConnectionHandle),
}

/// The interface async task has two channels for sending to the Host async task, whereas the Host
/// only has one channel for sending commands to the interface async task. The `CommandEvent`
/// channel is for sending the `CommandComplete` and `CommandStatus` events to the host. The
/// `GeneralEvent` channel is for sending all other events except for those that pertain to flow
/// control to the Controller.
#[derive(Eq, PartialEq, PartialOrd, Ord, Copy, Clone)]
pub enum HostChannel {
    Command,
    General,
}

/// The "kind" of connection
///

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
///
/// [`Interface`]: (../bo_tie_hci_interface/Interface/index.html)
#[derive(Debug, Clone, Copy, PartialEq, Eq, bo_tie_macros::DepthCount)]
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
/// ISO). Its used for block-based flow control to determine if the controller can accept the data
/// within its buffers.
trait GetDataPayloadSize {
    /// Get the size of the payload of an HCI packet
    ///
    /// # Note
    /// This method will return `None` if the intra message is a meta type message.
    fn get_payload_size(&self) -> Option<usize>;
}

/// Command flow control information
///
/// This is the information required for flow control of commands to the Controller. `send_count` is
/// the number of commands that can be sent to the controller, and `awaiting` is used whenever
/// `send_count` is zero and there is a HCI command packet awaiting to be sent to the Controller.
///
/// # Note
/// The default `CommandFlowControl` is created with a `send_count` of one instead of zero.
/// Otherwise, no commands would be able to be sent to the controller.
#[derive(Debug, Copy, Clone)]
struct CommandFlowControl {
    send_count: usize,
}

impl Default for CommandFlowControl {
    fn default() -> Self {
        CommandFlowControl { send_count: 1 }
    }
}

/// Packet based flow control information
///
/// All Controller buffers except for the the ACL buffer (not the LE ACl buffer) utilize packet
/// based flow control. This is a flow control mechanism of counting the number of packets that can
/// be sent to the controller. It consist of `how_many` packets can currently be sent to the
/// controller and the boolean `awaiting` to indicate if interface has messages awaiting for
/// `how_many` to be greater than 0. When `how_many` is increased to be greater than zero an
/// `awating` is true, the interface async task send the awaiting message to the interface driver.
#[derive(Default, Debug, Copy, Clone)]
struct PacketBasedFlowControl {
    how_many: usize,
}

/// Block based flow control information
///
/// Block based flow control is a method of using blocks of buffers to stage packet data. When a
/// data packet is received, the data portion of the packet will occupy one or more buffer 'blocks'
/// within the Controller. The number of data blocks is tracked and a packet will only be sent to
/// the host when there is enough data blocks to contain it.
///
/// Packets are only sent when there is enough *empty* blocks to contain the data. Any extra space
/// not used within the last block occupied by a packet is disregarded by this flow control
/// mechanism for purposes of flow control.
///
/// Field `how_many` is the number of known empty blocks within the Controller. `block_size` is the
/// number of bytes within each block buffer. `awaiting` is a boolean to indicate that there is
/// currently HCI packet(s) awaiting to be sent to the Controller.  
#[derive(Debug, Copy, Clone)]
struct BlockBasedFlowControl {
    total: usize,
    how_many: usize,
    block_size: usize,
    halt: bool,
}

/// ACL buffer flow control information
///
/// Flow control for the ACL data buffer can either be packet based or data block based. The default
/// flow control type is *packet-based* as that is the kind of flow control used by the ACL data
/// buffer upon reset of the Controller.
#[derive(Debug, Copy, Clone)]
enum AclFlowControl {
    Packets(PacketBasedFlowControl),
    DataBlocks(BlockBasedFlowControl),
}

impl AclFlowControl {
    /// Set the total number of Data Blocks
    ///
    /// # Note
    /// This method does nothing if this is not the enum `DataBlocks`
    ///
    /// # Panic
    /// A panic occurs when the difference between the previous total number of data blocks and the
    /// new total number of data blocks is greater than the current value of field `how_many`.
    fn set_total_block_count(&mut self, total: usize) {
        if let AclFlowControl::DataBlocks(block) = self {
            if let Some(reduction) = block.total.checked_sub(total) {
                block.how_many -= reduction;
            }

            block.total = total;
        }
    }

    /// Halt block based flow control
    ///
    /// # Note
    /// This method does nothing if this is not the enum `DataBlocks`
    fn halt_block_based(&mut self) {
        if let AclFlowControl::DataBlocks(block) = self {
            block.halt = true
        }
    }

    /// Resume block based flow control
    ///
    /// If block based flow control is resumed, then true is returned.
    fn resume_block_based(&mut self) -> bool {
        match self {
            AclFlowControl::DataBlocks(block) => {
                let ret = !block.halt;

                block.halt = true;

                ret
            }
            _ => false,
        }
    }
}
impl Default for AclFlowControl {
    fn default() -> Self {
        AclFlowControl::Packets(PacketBasedFlowControl::default())
    }
}

trait FlowControl {
    /// Increase the flow control
    fn increase(&mut self, by: usize);

    /// Reduce the flow control by the provided message
    ///
    /// This reduces the flow control information. For commands or packet based flow control this
    /// just reduces the number that can be sent by one. For data block the reduction is based on
    /// the size of the payload divided by the block size rounded up to the nearest whole number.
    ///
    /// An error is returned if the flow control information cannot be reduced.
    fn try_reduce<T: GetDataPayloadSize>(&mut self, payload_info: &T) -> Result<(), ()>;

    /// Check if flow control is halted
    ///
    /// When flow control is halted, the flow controller will never clear HCI packets to be sent to
    /// the Controller.
    fn is_halted(&self) -> bool;
}

impl FlowControl for CommandFlowControl {
    fn increase(&mut self, by: usize) {
        self.send_count += by;
    }

    fn try_reduce<T: GetDataPayloadSize>(&mut self, data: &T) -> Result<(), ()> {
        if let Some(_) = data.get_payload_size() {
            self.send_count = self.send_count.checked_sub(1).ok_or(())?;
        }

        Ok(())
    }

    fn is_halted(&self) -> bool {
        false
    }
}

impl FlowControl for PacketBasedFlowControl {
    fn increase(&mut self, by: usize) {
        self.how_many += by;
    }

    fn try_reduce<T: GetDataPayloadSize>(&mut self, data: &T) -> Result<(), ()> {
        if let Some(_) = data.get_payload_size() {
            self.how_many = self.how_many.checked_sub(1).ok_or(())?;
        }

        Ok(())
    }

    fn is_halted(&self) -> bool {
        false
    }
}

impl FlowControl for BlockBasedFlowControl {
    fn increase(&mut self, by: usize) {
        self.how_many += by;
    }

    fn try_reduce<T: GetDataPayloadSize>(&mut self, payload_info: &T) -> Result<(), ()> {
        if let Some(payload_size) = payload_info.get_payload_size() {
            // For simplicity one is always added instead of performing
            // a remainder check. Only when `payload_size` is a multiple
            // of `self.block_size` that an extra block is not needed.
            let blocks_required = payload_size / self.block_size + 1;

            self.how_many = self.how_many.checked_sub(blocks_required).ok_or(())?;
        }

        Ok(())
    }

    fn is_halted(&self) -> bool {
        self.halt
    }
}

impl FlowControl for AclFlowControl {
    fn increase(&mut self, by: usize) {
        match self {
            Self::Packets(p) => p.increase(by),
            Self::DataBlocks(b) => b.increase(by),
        }
    }

    fn try_reduce<T: GetDataPayloadSize>(&mut self, payload_info: &T) -> Result<(), ()> {
        match self {
            Self::Packets(p) => p.try_reduce(payload_info),
            Self::DataBlocks(b) => b.try_reduce(payload_info),
        }
    }

    fn is_halted(&self) -> bool {
        match self {
            Self::Packets(_) => false,
            Self::DataBlocks(b) => b.is_halted(),
        }
    }
}

/// A reserve of buffers
///
/// A reserve is for storing previously used buffers for reuse later. The main purpose is to reduce
/// the number of dynamic allocations of buffers during the lifetime of a program using `bo-tie`.
///
/// Typically buffers in `bo-tie` end up having roughly the same capacity. The controller's data
/// transfer limit generally becomes the limiting factor for how large of an allocation a buffer
/// ends up being, so taking buffers from a reserve generally means the buffer can be reused
/// without having to re-allocate.
#[doc(hidden)]
pub trait BufferReserve {
    type Buffer: Buffer + Unpin;

    type TakeBuffer: Future<Output = Self::Buffer>;

    /// Take a buffer from the reserve
    ///
    /// If there is no more buffers within the reserve the returned future will await. However, it
    /// is intended that there be enough buffers in the reserve so that most of the time this does
    /// not await.
    fn take<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>;

    /// Reclaim an unused buffer
    ///
    /// Buffers can be reclaimed for reuse later. However, if the reserve is full then the buffer to
    /// be reclaimed is dropped.
    fn reclaim(&mut self, buffer: Self::Buffer);
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

/// Channel ends for a connection async task
///
/// A connection's channel ends are the parts of the channels used for communicating between it and
/// the interface async task.
///
/// ### The `TakeBuffer`
/// Before a connection can send a messages to the interface async task it must acquire a buffer and
/// fill it with the data of the HCI data packet. The point of the `TakeBuffer` type is to provide
/// a future for awaiting a 'pool' of buffers and acquire one from it.
pub trait ConnectionChannelEnds: Sized {
    /// The buffer type of messages *to* the interface async task
    type ToBuffer: Buffer;

    /// The buffer type of messages *from* the interface async task
    type FromBuffer: Buffer;

    /// The future for acquiring a buffer from the channel to send
    type TakeBuffer: Future<Output = Self::ToBuffer>;

    /// The type used to send messages to the interface async task
    type Sender: Sender<Message = FromConnectionIntraMessage<Self::ToBuffer>>;

    /// The type used for receiving messages from the interface async task
    type Receiver: Receiver<Message = ToConnectionIntraMessage<Self::FromBuffer>>;

    /// Get the sender of messages to the interface async task
    fn get_sender(&self) -> Self::Sender;

    /// Take a buffer
    fn take_buffer<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>;

    /// Get the receiver of messages from the interface async task
    fn get_receiver(&self) -> &Self::Receiver;

    /// Get a mutable reference to the receiver of messages from the interface async task
    fn get_mut_receiver(&mut self) -> &mut Self::Receiver;
}

/// Ends of the channels used by the Host
///
/// The host async task has one channel for sending to the interface async task, but two channels
/// for receiving from it. The interface task splits the events sent from the Controller into the
/// two channels going to the host async task. Command response events (Command Status/Complete)
/// are sent within the 'command' channel and all other events sent to the host (excluding those
/// never sent to the host task) are sent within the 'generic events' channel.
///
/// ### The `TakeBuffer`
/// Before a host can send a messages to the interface async task it must acquire a buffer and
/// fill it with the data of the HCI command packet. The point of the `TakeBuffer` type is to
/// provide a future for awaiting a 'pool' of buffers and acquire one from it.
pub trait HostChannelEnds {
    /// The buffer type of messages *to* the interface async task
    type ToBuffer: Buffer;

    /// The buffer type of messages *from* the interface async task
    type FromBuffer: Buffer;

    /// The future for acquiring a buffer from the channel to send
    type TakeBuffer: Future<Output = Self::ToBuffer>;

    /// The type used to send messages to the interface async task
    type Sender: Sender<Message = ToInterfaceIntraMessage<Self::ToBuffer>>;

    /// The type used for receiving command response messages from the interface async task
    type CmdReceiver: Receiver<Message = ToHostCommandIntraMessage>;

    /// The type used for receiving general messages from the interface async task
    type GenReceiver: Receiver<Message = ToHostGeneralIntraMessage<Self::ConnectionChannelEnds>>;

    /// The channel ends type for a connection
    type ConnectionChannelEnds: ConnectionChannelEnds;

    /// The front and back capacities (in that order) of a buffer as required by the driver
    ///
    /// Every buffer allocated by a connection must have these values added to the front and back
    /// capacities to a new or cleared buffer.
    fn driver_buffer_capacities(&self) -> (usize, usize);

    /// Get the sender of messages to the interface async task
    fn get_sender(&self) -> Self::Sender;

    /// Take a buffer
    fn take_buffer<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>;

    /// Get the receiver of command response messages from the interface async task
    fn get_cmd_recv(&self) -> &Self::CmdReceiver;

    /// Get a mutable reference to the receiver of command response messages from the interface async task
    fn get_mut_cmd_recv(&mut self) -> &mut Self::CmdReceiver;

    /// Get the receiver of general response messages from the interface async task
    fn get_gen_recv(&self) -> &Self::GenReceiver;

    /// Get a mutable reference to the receiver of general response messages from the interface async task
    fn get_mut_gen_recv(&mut self) -> &mut Self::GenReceiver;
}

/// A channel reserve
///
/// The point of a channel reserve is to minimize the amount of message movement between the sender
/// and receiver. This includes the initial writing of data into the message.
pub trait ChannelReserve {
    /// The error type associated with the `try_*` method within `ChannelReserve`
    type Error: fmt::Debug;

    /// The error returned by the implementation of Sender
    ///
    /// This is the same type as `Error` of [`Sender`]
    type SenderError: fmt::Debug;

    /// The channel type for sending command response messages to the host async task
    type ToHostCmdChannel: Channel<SenderError = Self::SenderError, Message = ToHostCommandIntraMessage>;

    /// The channel type for sending general messages to the host async task
    type ToHostGenChannel: Channel<
        SenderError = Self::SenderError,
        Message = ToHostGeneralIntraMessage<Self::ConnectionChannelEnds>,
    >;

    /// The channel type for messages sent from the host async task
    type FromHostChannel: BufferReserve
        + Channel<
            SenderError = Self::SenderError,
            Message = ToInterfaceIntraMessage<<Self::FromHostChannel as BufferReserve>::Buffer>,
        >;

    /// The channel type for sending messages to another connection async task
    type ToConnectionChannel: BufferReserve
        + Channel<
            SenderError = Self::SenderError,
            Message = ToConnectionIntraMessage<<Self::ToConnectionChannel as BufferReserve>::Buffer>,
        >;

    /// The channel type for messages sent from another connection async task
    type FromConnectionChannel: BufferReserve
        + Channel<
            SenderError = Self::SenderError,
            Message = FromConnectionIntraMessage<<Self::FromConnectionChannel as BufferReserve>::Buffer>,
        >;

    /// Channel ends for a connection async task
    type ConnectionChannelEnds: ConnectionChannelEnds;

    /// Try to remove a connection
    fn try_remove(&mut self, handle: ConnectionHandle) -> Result<(), Self::Error>;

    /// Add a new connection async task
    ///
    /// The interface async task begins the creation of a new connection async task by creating the
    /// channel used by it to send messages to the new connection async task. The return of this
    /// method is the connection ends for the new connection.
    fn add_new_connection(
        &mut self,
        handle: ConnectionHandle,
        flow_control_id: FlowControlId,
    ) -> Result<Self::ConnectionChannelEnds, Self::Error>;

    /// Get the channel for sending messages to `id`
    ///
    /// `None` is returned if no channel is associated with the task identifier.
    fn get_channel(
        &self,
        id: TaskId,
    ) -> Option<FromInterface<Self::ToHostCmdChannel, Self::ToHostGenChannel, Self::ToConnectionChannel>>;

    /// Get the controller flow control identification for a connection
    ///
    /// This gets the flow control identifier that is associated to the task ID.
    ///
    /// `None` is returned if no data flow control id is associated with the input identifier.
    fn get_flow_control_id(&self, handle: ConnectionHandle) -> Option<FlowControlId>;

    /// Get the [`FlowCtrlReceiver`]
    ///
    /// This returns the `FlowCtrlReceiver` used by this `ChannelReserve`.
    fn get_flow_ctrl_receiver(
        &mut self,
    ) -> &mut FlowCtrlReceiver<
        <Self::FromHostChannel as Channel>::Receiver,
        <Self::FromConnectionChannel as Channel>::Receiver,
    >;
}

pub trait ChannelReserveExt: ChannelReserve {
    /// Get a sender to another async task
    ///
    /// The return is the sender used for sending messages to the async task associated by `id`.
    /// None is returned if no channel information exists for the provided `id` this method.
    fn get_sender(
        &self,
        id: TaskId,
    ) -> Option<
        FromInterface<
            <Self::ToHostCmdChannel as Channel>::Sender,
            <Self::ToHostGenChannel as Channel>::Sender,
            <Self::ToConnectionChannel as Channel>::Sender,
        >,
    > {
        self.get_channel(id).map(|channel_type| match channel_type {
            FromInterface::HostCommand(hc) => FromInterface::HostCommand(hc.get_sender()),
            FromInterface::HostGeneral(hg) => FromInterface::HostGeneral(hg.get_sender()),
            FromInterface::Connection(c) => FromInterface::Connection(c.get_sender()),
        })
    }

    /// Receive the next message
    fn receive_next(
        &mut self,
    ) -> ReceiveNext<'_, <Self::FromHostChannel as Channel>::Receiver, <Self::FromConnectionChannel as Channel>::Receiver>
    {
        ReceiveNext(self.get_flow_ctrl_receiver())
    }

    /// Increment the flow control for commands
    ///
    /// This increments the number of commands that can be sent to the controller by the number
    /// provided by input `how_many`.
    fn inc_cmd_flow_ctrl(&mut self, how_many: usize) {
        // todo: allow for more than one command to be sent at a time
        let how_many = core::cmp::min(1, how_many);

        if how_many != 0 {
            self.get_flow_ctrl_receiver().cmd_flow_control.increase(how_many);

            self.get_flow_ctrl_receiver().call_waker();
        }
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
    /// [`NumberOfCompletedPackets`](crate::events::EventsData::NumberOfCompletedPackets)
    ///
    /// ## Data-Block-Based
    /// In data block based flow control, input `how_many` is the number of blocks the controller
    /// can currently accept data into since the last time this method was called. This value must
    /// be calculated from the number of data blocks that were completed as stated in the event
    /// [`NumberOfCompletedDataBlocks`](crate::events::EventsData::NumberOfCompletedDataBlocks).
    ///
    /// This method shall not be called if the event `NumberOfCompletedDataBlocks` contained `None`
    /// for the `total_data_blocks` field. This indicates that the host needs to update its buffer
    /// information through the
    /// [`read_data_block_size`](../bo_tie_hci_host/commands/info_params/read_data_block_size) command.
    fn inc_acl_flow_ctrl(&mut self, how_many: usize) {
        if how_many != 0 {
            self.get_flow_ctrl_receiver().acl_flow_control.increase(how_many);

            self.get_flow_ctrl_receiver().call_waker();
        }
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
    /// [`NumberOfCompletedPackets`](crate::events::EventsData::NumberOfCompletedPackets)
    fn inc_sco_flow_control(&mut self, how_many: usize) {
        if how_many != 0 {
            self.get_flow_ctrl_receiver().sco_flow_control.increase(how_many);

            self.get_flow_ctrl_receiver().call_waker();
        }
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
    /// [`NumberOfCompletedPackets`](crate::events::EventsData::NumberOfCompletedPackets)
    fn inc_le_acl_flow_control(&mut self, how_many: usize) {
        if how_many != 0 {
            self.get_flow_ctrl_receiver().le_acl_flow_control.increase(how_many);

            self.get_flow_ctrl_receiver().call_waker();
        }
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
    /// [`NumberOfCompletedPackets`](crate::events::EventsData::NumberOfCompletedPackets)
    fn inc_le_iso_flow_control(&mut self, how_many: usize) {
        if how_many != 0 {
            self.get_flow_ctrl_receiver().le_iso_flow_control.increase(how_many);

            self.get_flow_ctrl_receiver().call_waker();
        }
    }

    /// Set the total number of blocks for ACL flow control
    ///
    /// # Note
    /// This method does nothing if ACL is currently flow controlled by packets
    fn set_acl_flow_control_block_count(&mut self, count: usize) {
        self.get_flow_ctrl_receiver()
            .acl_flow_control
            .set_total_block_count(count)
    }

    /// Halt block based ACL flow control
    ///
    /// When flow control is halted, the flow controller will not send HCI ACL packets to the
    /// Bluetooth Controller until either method [`resume_acl_flow_control`] is called or flow
    /// control for ACL packets is switched to packed based flow control. Halting is necessary when
    /// the *Number of Completed Data Blocks* event instructs the host to send the *Read Data Block
    /// Size* command.
    ///
    /// [`resume_acl_flow_control`]: ChannelReserveExt::resume_acl_flow_control
    fn halt_acl_flow_control(&mut self) {
        self.get_flow_ctrl_receiver().acl_flow_control.halt_block_based()
    }

    /// Resume block based ACL flow control
    ///
    /// This will remove the halt from the ACL flow controller. This method does nothing if flow
    /// control is not halted or the ACL flow control is currently packet based.
    fn resume_acl_flow_control(&mut self) {
        if self.get_flow_ctrl_receiver().acl_flow_control.resume_block_based() {
            self.get_flow_ctrl_receiver().call_waker()
        }
    }
}

impl<T: ChannelReserve> ChannelReserveExt for T {}

/// Receivers used by an interface async task
pub struct InterfaceReceivers<H, R> {
    pub cmd_receiver: H,
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
pub struct FlowCtrlReceiver<H: Receiver, C: Receiver> {
    cmd_receiver: PeekableReceiver<H>,
    acl_receiver: PeekableReceiver<C>,
    sco_receiver: PeekableReceiver<C>,
    le_acl_receiver: PeekableReceiver<C>,
    le_iso_receiver: PeekableReceiver<C>,
    last_received: FlowControlId,
    cmd_flow_control: CommandFlowControl,
    acl_flow_control: AclFlowControl,
    sco_flow_control: PacketBasedFlowControl,
    le_acl_flow_control: PacketBasedFlowControl,
    le_iso_flow_control: PacketBasedFlowControl,
    waker: Option<core::task::Waker>,
}

impl<H: Receiver, C: Receiver> FlowCtrlReceiver<H, C> {
    /// Create a new `FlowCtrlReceiver`
    fn new(receivers: InterfaceReceivers<H, C>) -> Self {
        let cmd_receiver = receivers.cmd_receiver.peekable();
        let acl_receiver = receivers.acl_receiver.peekable();
        let sco_receiver = receivers.sco_receiver.peekable();
        let le_acl_receiver = receivers.le_acl_receiver.peekable();
        let le_iso_receiver = receivers.le_iso_receiver.peekable();
        let last_received = FlowControlId::Cmd;
        let cmd_flow_control = Default::default();
        let acl_flow_control = Default::default();
        let sco_flow_control = Default::default();
        let le_acl_flow_control = Default::default();
        let le_iso_flow_control = Default::default();
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
            waker,
        }
    }

    /// Set the flow control information based on the buffer information from the
    ///
    /// # Note
    /// All flow control will be packet based after this is called
    pub fn set_to_packet_buffer(&mut self, buffer_info: PacketBufferInformation) {
        self.acl_flow_control = AclFlowControl::Packets(PacketBasedFlowControl {
            how_many: buffer_info.acl.count,
        });

        self.sco_flow_control = PacketBasedFlowControl {
            how_many: buffer_info.sco.count,
        };

        self.le_acl_flow_control = PacketBasedFlowControl {
            how_many: buffer_info.le_acl.count,
        };

        self.le_iso_flow_control = PacketBasedFlowControl {
            how_many: buffer_info.le_iso.count,
        };
    }

    pub fn set_waker(&mut self, waker: &core::task::Waker) {
        self.waker = Some(waker.clone())
    }

    pub fn call_waker(&mut self) {
        self.waker.take().map(|waker| waker.wake());
    }
}

/// A future for receiving from a async task
///
/// This is the receiver for receiving messages from any other async task.
///
/// # Note
/// When all async tasks are closed, when polled `RecvNext` will return `None`.
pub struct ReceiveNext<'a, H: Receiver, R: Receiver>(&'a mut FlowCtrlReceiver<H, R>);

impl<H, R> Future for ReceiveNext<'_, H, R>
where
    H: Receiver,
    H::Message: GetDataPayloadSize,
    R: Receiver,
    R::Message: GetDataPayloadSize,
{
    type Output = Option<TaskSource<H::Message, R::Message>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let fcr = unsafe { &mut self.get_unchecked_mut().0 };

        let mut dead_cnt = 0;

        macro_rules! task_wrap {
            (Host, $msg:expr) => {
                $msg.map(|o_msg| o_msg.map(|msg| $crate::TaskSource::Host(msg)))
            };
            (Conn, $msg:expr) => {
                $msg.map(|o_msg| o_msg.map(|msg| $crate::TaskSource::Connection(msg)))
            };
        }

        macro_rules! fc_rx {
            ($source:tt, $receiver:ident, $fc:ident, $fc_id:expr) => {
                match fcr.$receiver.poll_peek(cx) {
                    core::task::Poll::Pending => {}
                    core::task::Poll::Ready(None) => dead_cnt += 1,
                    core::task::Poll::Ready(Some(message)) => {
                        if !fcr.$fc.is_halted() {
                            match fcr.$fc.try_reduce(message) {
                                Ok(_) => {
                                    fcr.last_received = $fc_id;

                                    let msg = fcr.$receiver.poll_recv(cx);

                                    debug_assert!(msg.is_ready());

                                    return task_wrap!($source, msg);
                                }
                                Err(_) => fcr.set_waker(cx.waker()),
                            }
                        }
                    }
                }
            };
        }

        for fc_id in fcr.last_received.cycle_after() {
            match fc_id {
                FlowControlId::Cmd => fc_rx!(Host, cmd_receiver, cmd_flow_control, fc_id),
                FlowControlId::Acl => fc_rx!(Conn, acl_receiver, acl_flow_control, fc_id),
                FlowControlId::Sco => fc_rx!(Conn, sco_receiver, sco_flow_control, fc_id),
                FlowControlId::LeAcl => fc_rx!(Conn, le_acl_receiver, le_acl_flow_control, fc_id),
                FlowControlId::LeIso => fc_rx!(Conn, le_iso_receiver, le_iso_flow_control, fc_id),
            }
        }

        if dead_cnt == FlowControlId::full_depth() {
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
/// Implementing `Sender` is fairly easy if type for the `SendFuture` is known.
/// ```
/// # use std::cell::RefCell;
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// # use bo_tie_hci_util::Sender;
/// use futures::channel::mpsc;
///
/// struct FuturesSender<T>(mpsc::Sender<T>);
///
/// impl<T> Sender for FuturesSender<T>
/// where
///     T: Unpin
/// {
///     type Error = mpsc::SendError;
///     type Message = T;
///     type SendFuture<'a> = futures::sink::Send<'a, mpsc::Sender<T>, T> where Self: 'a;
///
///     fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
///         use futures::SinkExt;
///
///         self.0.send(t)
///     }
/// }
/// ```
///
/// If the type is unknown then the nightly feature `type_alias_impl_trait` can be enabled for ease of
/// implementation.
/// ```
/// #![feature(type_alias_impl_trait)]
/// # use std::fmt::Debug;
/// # use std::future::Future;
/// # use bo_tie_hci_util::Sender;
/// use tokio::sync::mpsc;
///
/// struct TokioSender<T>(mpsc::Sender<T>);
///
/// impl<T> Sender for TokioSender<T>
/// where
///     T: Unpin + Debug
/// {
///     type Error = mpsc::error::SendError<T>;
///     type Message = T;
///     type SendFuture<'a> = impl Future<Output = Result<(), Self::Error>> + 'a where Self: 'a;
///
///     fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_> {
///         // Since `send` is an async method, its return type is hidden.
///         self.0.send(t)
///    }
/// }
/// ```
pub trait Sender {
    type Error: fmt::Debug + fmt::Display;
    type Message: Unpin;
    type SendFuture<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    fn send(&mut self, t: Self::Message) -> Self::SendFuture<'_>;
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
/// Implementing `Receiver` is fairly easy if type for the `ReceiveFuture` is known.
/// ```
/// # use std::cell::RefCell;
/// # use std::future::Future;
/// # use std::pin::Pin;
/// # use std::task::{Context, Poll};
/// # use bo_tie_hci_util::Receiver;
/// use futures::channel::mpsc;
///
/// struct FuturesReceiver<T>(mpsc::Receiver<T>);
///
/// impl<T> Receiver for FuturesReceiver<T>
/// where
///     T: Unpin
/// {
///     type Message = T;
///     type ReceiveFuture<'a> = futures::stream::Next<'a, mpsc::Receiver<T>> where Self: 'a;
///
///     fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
///         futures::Stream::poll_next(Pin::new(&mut self.0), cx)
///     }
///
///     fn recv(&mut self) -> Self::ReceiveFuture<'_> {
///         use futures::StreamExt;
///
///         self.0.next()
///     }
/// }
/// ```
///
/// If the type is unknown then the nightly feature `type_alias_impl_trait` can be enabled for ease
/// of implementation.
/// ```
/// #![feature(type_alias_impl_trait)]
/// # use std::fmt::Debug;
/// # use std::future::Future;
/// # use std::task::{Context, Poll};
/// # use bo_tie_hci_util::Receiver;
/// use tokio::sync::mpsc;
///
/// struct TokioReceiver<T>(mpsc::Receiver<T>);
///
/// impl<T> Receiver for TokioReceiver<T>
/// where
///     T: Unpin + Debug
/// {
///     type Message = T;
///     type ReceiveFuture<'a> = impl Future<Output = Option<Self::Message>> + 'a where Self: 'a;
///
///     fn poll_recv(&mut self, cx: &mut Context<'_>) -> Poll<Option<Self::Message>> {
///         self.0.poll_recv(cx)
///     }
///
///     fn recv(&mut self) -> Self::ReceiveFuture<'_> {
///         // Since `recv` is an async method, its return type is hidden.
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

    fn recv(&mut self) -> Self::ReceiveFuture<'_>;
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
            peeked: None,
        }
    }
}

impl<R: Receiver> ReceiverExt for R {}

/// A peekable receiver
///
/// This struct is created by the [`peekable`] method of `ReceiverExt`. The method [`poll_peek`] is
/// used to poll the receiver and return a reference to the message. The trait [`Receiver`] can then
/// be used to take the peeked message from the `PeekableReceiver`.
///
/// # Note
/// If `poll_peek` has already returned `Poll::Ready`, then the method will act like it is fused
/// and continue to return a reference to the same message. In order to peek the next message, the
/// current message must be taken via the methods of `Receiver`.
///
/// [`peekable`]: ReceiverExt::peekable
/// [`poll_peek`]: PeekableReceiver::poll_peek
struct PeekableReceiver<R: Receiver> {
    receiver: R,
    peeked: Option<R::Message>,
}

impl<R: Receiver> PeekableReceiver<R> {
    fn poll_peek(&mut self, cx: &mut Context<'_>) -> Poll<Option<&R::Message>> {
        if self.peeked.is_some() {
            Poll::Ready(self.peeked.as_ref())
        } else {
            match self.receiver.poll_recv(cx) {
                Poll::Ready(Some(message)) => {
                    self.peeked = Some(message);

                    Poll::Ready(self.peeked.as_ref())
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

    fn recv(&mut self) -> Self::ReceiveFuture<'_> {
        match self.peeked.take() {
            msg @ Some(_) => PeekableReceiveFuture::Peeked(msg),
            None => PeekableReceiveFuture::NextRecv(self.receiver.recv()),
        }
    }
}

/// The receive future for [`PeekableReceiver`]
///
/// A future for either returning the peeked value or awaiting the next value to be received.
enum PeekableReceiveFuture<'a, R: Receiver + 'a> {
    Peeked(Option<R::Message>),
    NextRecv(R::ReceiveFuture<'a>),
}

impl<R: Receiver> Future for PeekableReceiveFuture<'_, R> {
    type Output = Option<R::Message>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        match this {
            PeekableReceiveFuture::Peeked(msg) => Poll::Ready(msg.take()),
            PeekableReceiveFuture::NextRecv(rx) => unsafe { Pin::new_unchecked(rx).poll(cx) },
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

impl fmt::Display for HciPacketType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            HciPacketType::Command => f.write_str("Command"),
            HciPacketType::Acl => f.write_str("ACL"),
            HciPacketType::Sco => f.write_str("SCO"),
            HciPacketType::Event => f.write_str("Event"),
            HciPacketType::Iso => f.write_str("ISO"),
        }
    }
}

/// A HCI packet
///
/// This is a wrapper around a buffer containing a HCI packet. `HciPacket` is used to describe what
/// kind of HCI packet is contained within the buffer.
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
pub enum HciPacket<T> {
    Command(T),
    Acl(T),
    Sco(T),
    Event(T),
    Iso(T),
}

impl<T> HciPacket<T> {
    /// Map a `HciPacket`
    ///
    /// This is used to map a `HciPacket<T>` to a `HciPacket<V>`
    pub fn map<F, V>(self, f: F) -> HciPacket<V>
    where
        F: FnOnce(T) -> V,
    {
        match self {
            HciPacket::Command(t) => HciPacket::Command(f(t)),
            HciPacket::Acl(t) => HciPacket::Acl(f(t)),
            HciPacket::Sco(t) => HciPacket::Sco(f(t)),
            HciPacket::Event(t) => HciPacket::Event(f(t)),
            HciPacket::Iso(t) => HciPacket::Iso(f(t)),
        }
    }
}

impl<T: Deref<Target = [u8]>> TryFrom<ToInterfaceIntraMessage<T>> for HciPacket<T> {
    type Error = &'static str;

    fn try_from(i: ToInterfaceIntraMessage<T>) -> Result<Self, Self::Error> {
        match i {
            ToInterfaceIntraMessage::Command(c) => Ok(HciPacket::Command(c)),
            ToInterfaceIntraMessage::Disconnect(_, c) => Ok(HciPacket::Command(c)),
            ToInterfaceIntraMessage::PacketBufferInfo(_) => {
                Err("'FromHostIntraMessage::BufferInfo' cannot be converted to a HciPacket")
            }
        }
    }
}

impl<T: Deref<Target = [u8]>> TryFrom<FromConnectionIntraMessage<T>> for HciPacket<T> {
    type Error = &'static str;

    fn try_from(i: FromConnectionIntraMessage<T>) -> Result<Self, Self::Error> {
        match i {
            FromConnectionIntraMessage::Acl(t) => Ok(HciPacket::Acl(t)),
            FromConnectionIntraMessage::Sco(t) => Ok(HciPacket::Sco(t)),
            FromConnectionIntraMessage::Iso(t) => Ok(HciPacket::Iso(t)),
        }
    }
}

/// Packet based flow control buffer information
///
/// Packet based flow control is where the Controller will individually buffer packets. The number
/// of packets that can be buffered along with the maximum size of the payload (a.k.a. the data
/// portion) of each packet is manufacture specific.
#[derive(Debug, Default, Clone, Copy)]
pub struct PacketFlowCtrlInfo {
    count: usize,
    max_size: usize,
}

impl PacketFlowCtrlInfo {
    /// Get the number of data packets that can be stored by the Controller
    pub fn get_number_of_packets(&self) -> usize {
        self.count
    }

    /// Set the number of data packets that can be stored by the Controller
    pub fn set_number_of_packets(&mut self, count: usize) {
        self.count = count
    }

    /// Get the maximum size of the data portion of the packet
    pub fn get_max_data_size(&self) -> usize {
        self.max_size
    }

    /// Set the maximum size of the data portion of the packet
    pub fn set_max_data_size(&mut self, size: usize) {
        self.max_size = size
    }
}

/// Data block based flow control buffer information
///
/// Data block based flow control is where a pool of "data blocks" are used for buffering HCI data
/// packets. The Controller still has a maximum size of a data packet, but packets can occupy
/// multiple blocks within the Controller.
#[derive(Debug, Default, Clone, Copy)]
pub struct DataBlockFlowControl {
    blocks: usize,
    block_size: usize,
    data_size: usize,
}

impl DataBlockFlowControl {
    /// Get the number of blocks
    pub fn get_number_of_blocks(&self) -> usize {
        self.blocks
    }

    /// Set the number of blocks
    pub fn set_number_of_blocks(&mut self, number_of_blocks: usize) {
        self.blocks = number_of_blocks
    }

    /// Get the size of each block
    pub fn get_block_size(&self) -> usize {
        self.block_size
    }

    /// Set the block size
    pub fn set_block_size(&mut self, block_size: usize) {
        self.block_size = block_size
    }

    /// Get the maximum size of the data portion of the packet
    pub fn get_max_data_size(&self) -> usize {
        self.data_size
    }

    /// Set the maximum size of the data portion of the packet
    pub fn set_max_data_size(&mut self, max_data_size: usize) {
        self.data_size = max_data_size
    }
}

/// Flow Control information regarding the buffers of the Controller
///
/// This is sent from the host async task to the interface async task as part of the host's
/// initialization. It provides the interface task with the flow control information of the data
/// buffers to the interface async task. Without this information, the interface async task will
/// not know how many packets/data blocks the Controller can accept and will refuse to send any
/// data to the controller.
#[derive(Debug, Default)]
pub struct PacketBufferInformation {
    pub acl: PacketFlowCtrlInfo,
    pub sco: PacketFlowCtrlInfo,
    pub le_acl: PacketFlowCtrlInfo,
    pub le_iso: PacketFlowCtrlInfo,
}

/// A messages sent from all other async tasks to the interface async task
///
/// The host async task sends `Commands` and `BufferInfo` to the interface async task. Connections
/// async tasks sends `Disconnect` to the interface async task.
#[derive(Debug)]
pub enum ToInterfaceIntraMessage<T> {
    Command(T),
    PacketBufferInfo(PacketBufferInformation),
    Disconnect(ConnectionHandle, T),
}

impl<T: Deref<Target = [u8]>> GetDataPayloadSize for ToInterfaceIntraMessage<T> {
    // This method is never called as there is no block-like flow control for commands, but might as
    // well implement it in case that changes. If this ever does change then the cold attribute
    // needs to be removed.
    #[cold]
    fn get_payload_size(&self) -> Option<usize> {
        match self {
            ToInterfaceIntraMessage::Command(command) => Some(command[2] as usize),
            _ => None,
        }
    }
}

/// A command responses sent to the host async task
///
/// When the controller has finished processing a command it sends either the [`CommandComplete`] or
/// [`CommandStatus`] events to the Host. The interface async task will send these events within
/// the command response channel to the host async task.
///
/// [`CommandComplete`]: events::EventsData::CommandComplete
/// [`CommandStatus`]: events::EventsData::CommandStatus
#[derive(Debug)]
pub enum ToHostCommandIntraMessage {
    CommandComplete(events::parameters::CommandCompleteData),
    CommandStatus(events::parameters::CommandStatusData),
}

/// A general message sent to the host async task
///
/// Messages that are not in response to a command are sent within the general message channel.
///
/// ### Events
/// All events except for command response and the flow control events
/// [`NumberOfCompletedPackets`], and [`NumberOfCompletedDataBlocks`] are sent via the general
/// channel.
///
/// ### Connection Channel Ends
/// A new connection's channel ends used for communicating with the interface are sent to the host
/// through the general channel.
///
/// [`NumberOfCompletedPackets`]: crate::events::Events::NumberOfCompletedPackets
/// [`NumberOfCompletedDataBlocks`]: crate::events::Events::NumberOfCompletedDataBlocks
#[derive(Debug)]
pub enum ToHostGeneralIntraMessage<T> {
    Event(events::EventsData),
    NewConnection(T),
}

/// A messages from a connection async task
///
/// This is a message sent from a connection async task to the interface async task.
#[derive(Debug)]
pub enum FromConnectionIntraMessage<T> {
    /// HCI asynchronous Connection-Oriented Data Packet
    Acl(T),
    /// HCI synchronous Connection-Oriented Data Packet
    Sco(T),
    /// HCI isochronous Data Packet
    Iso(T),
}

impl<T: Deref<Target = [u8]>> GetDataPayloadSize for FromConnectionIntraMessage<T> {
    fn get_payload_size(&self) -> Option<usize> {
        match self {
            FromConnectionIntraMessage::Acl(t) => Some(<u16>::from_le_bytes([t[2], t[3]]).into()),
            FromConnectionIntraMessage::Sco(t) => Some(t[2].into()),
            FromConnectionIntraMessage::Iso(t) => Some(<u16>::from_le_bytes([t[2], t[3] & 0x3F]).into()),
        }
    }
}

/// A messages to a connection async task
///
/// This is a message sent to a connection async task from the interface async task.
#[derive(Debug)]
pub enum ToConnectionIntraMessage<T> {
    /// HCI asynchronous Connection-Oriented Data Packet
    Acl(T),
    /// HCI synchronous Connection-Oriented Data Packet
    Sco(T),
    /// HCI isochronous Data Packet
    Iso(T),
    /// A disconnection indication
    Disconnect(bo_tie_util::errors::Error),
}

/// An enumeration of different channels from the interface async task
///
/// This is used to differentiate the different channels that can be returned by the method
/// [`get_channel`] of `ChannelReserve` or [`get_sender`] of `ChannelReserveExt`.
///
/// [`get_channel`]: ChannelReserve::get_channel
/// [`get_sender`]: ChannelReserveExt::get_sender
pub enum FromInterface<Hc, Hg, C> {
    HostCommand(Hc),
    HostGeneral(Hg),
    Connection(C),
}

/// An enumeration of different channels to the interface async task
pub enum TaskSource<H, C> {
    Host(H),
    Connection(C),
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

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
    pub async fn channel_send_and_receive<P, C, I, S, R, F>(channel: C, tx_vals: I, expected_rx_vals: I, cmp: F)
    where
        C: Channel<Sender = S, Receiver = R>,
        I: IntoIterator<Item = P>,
        S: Sender<Message = P>,
        R: Receiver<Message = P>,
        <<C as Channel>::Sender as Sender>::Error: fmt::Debug,
        F: Fn(&P, &P) -> bool,
    {
        use futures::FutureExt;

        let mut sender = channel.get_sender();
        let mut receiver = channel.take_receiver().unwrap();

        let mut send_task = Box::pin(
            async {
                for val in tx_vals {
                    sender.send(val).await.unwrap();
                }
            }
            .fuse(),
        );

        let mut recv_task = Box::pin(
            async {
                for val in expected_rx_vals {
                    let rx = receiver.recv().await.map(|packet| packet).unwrap();

                    assert!(cmp(&val, &rx), "channel input did not match channel output");
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
