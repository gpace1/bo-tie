//! The Host Controller Interface (HCI)
//!
//! The HCI is the primary way of interacting with the controller for this library.

#[macro_use]
pub mod common;
pub mod error;
pub mod opcodes;
#[macro_use]
pub mod events;
// mod flow_ctrl;
pub mod interface;

use crate::hci::interface::{Channel, ChannelEnds, ChannelReserve};
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// Used to get the information required for sending a command from the host to the controller
///
/// The type Parameter should be a packed structure of the command's parameters
pub trait CommandParameter<const PARAMETER_SIZE: usize> {
    /// The command to send to the Bluetooth Controller.
    ///
    /// This is the OGF & OCF pair.
    const COMMAND: opcodes::HCICommand;

    /// Convert Self into the parameter form
    ///
    /// The returned parameter is the structure defined as the parameter part of the command packet
    /// for the specific HCI command.
    fn get_parameter(&self) -> [u8; PARAMETER_SIZE];

    /// Get the command packet to be sent to the controller
    ///
    /// The format of the command packet is to send the command opcode, followed by the length of
    /// the parameter, and then finally the parameter.
    ///
    /// # Note
    /// HCI packets do not contain information on the type of packet that they are. This command
    /// packet must be wrapped within a type to give the interface driver the knowledge
    fn as_command_packet<T>(&self, buffer: &mut T) -> Result<(), T::Error>
    where
        T: crate::TryExtend<u8>,
    {
        let parameter = self.get_parameter();

        // Add opcode to packet
        buffer.try_extend(Self::COMMAND.as_opcode_pair().as_opcode().to_le_bytes())?;

        // Add the length of the parameter
        buffer.try_extend(core::iter::once(parameter.len() as u8))?;

        // Add the parameter
        buffer.try_extend(parameter)
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ACLPacketBoundary {
    FirstNonFlushable,
    ContinuingFragment,
    FirstAutoFlushable,
    CompleteL2capPdu,
}

impl ACLPacketBoundary {
    /// Get the value shifted into the correct place of the Packet Boundary Flag in the HCI ACL
    /// data packet. The returned value is in host byte order.
    fn get_shifted_val(&self) -> u16 {
        (match self {
            ACLPacketBoundary::FirstNonFlushable => 0x0,
            ACLPacketBoundary::ContinuingFragment => 0x1,
            ACLPacketBoundary::FirstAutoFlushable => 0x2,
            ACLPacketBoundary::CompleteL2capPdu => 0x3,
        }) << 12
    }

    /// Get the `ACLPacketBoundary` from the first 16 bits of a HCI ACL data packet. The input
    /// `val` does not need to be masked to only include the Packet Boundary Flag, however it does
    /// need to be in host byte order.
    fn from_shifted_val(val: u16) -> Self {
        match (val >> 12) & 3 {
            0x0 => ACLPacketBoundary::FirstNonFlushable,
            0x1 => ACLPacketBoundary::ContinuingFragment,
            0x2 => ACLPacketBoundary::FirstAutoFlushable,
            0x3 => ACLPacketBoundary::CompleteL2capPdu,
            _ => panic!("This cannot happen"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ACLBroadcastFlag {
    // Point-to-point message
    NoBroadcast,
    // Broadcast to all active slaves
    ActiveSlaveBroadcast,
}

impl ACLBroadcastFlag {
    /// Get the value shifted into the correct place of the Packet Boundary Flag in the HCI ACL
    /// data packet. The returned value is in host byte order.
    fn get_shifted_val(&self) -> u16 {
        (match self {
            ACLBroadcastFlag::NoBroadcast => 0x0,
            ACLBroadcastFlag::ActiveSlaveBroadcast => 0x1,
        }) << 14
    }

    /// Get the `ACLBroadcastFlag` from the first 16 bits of a HCI ACL data packet. The input
    /// `val` does not need to be masked to only include the Packet Boundary Flag, however it does
    /// need to be in host byte order.
    fn try_from_shifted_val(val: u16) -> Result<Self, ()> {
        match (val >> 14) & 1 {
            0x0 => Ok(ACLBroadcastFlag::NoBroadcast),
            0x1 => Ok(ACLBroadcastFlag::ActiveSlaveBroadcast),
            0x2 | 0x3 => Err(()),
            _ => panic!("This cannot happen"),
        }
    }
}

#[derive(Debug)]
pub enum HciACLPacketError {
    PacketTooSmall,
    InvalidBroadcastFlag,
    InvalidConnectionHandle(&'static str),
}

impl core::fmt::Display for HciACLPacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HciACLPacketError::PacketTooSmall => write!(f, "Packet is too small to be a valid HCI ACL Data"),
            HciACLPacketError::InvalidBroadcastFlag => write!(f, "Packet has invalid broadcast Flag"),
            HciACLPacketError::InvalidConnectionHandle(reason) => {
                write!(f, "Invalid connection handle, {}", reason)
            }
        }
    }
}

/// A HCI ACL Data Packet
///
/// HCI ACL data packets are sent between the host and controller for a specified connection. They
/// consist of a header and payload. The header contains a connection handle, a packet boundary
/// flag, a broadcast flag, and the total length of the payload. The connection handle is used by
/// the receiver of this packet to determine what connection the payload is for. The packet boundary
/// is used to recombining fragmented fragmented and indicating whether the data automatically
/// flushable. The broadcast flag is used to indicate that the data is a broadcast flag.
///
/// # LE-U Logical Link
/// For a LE-U logical link, a HCI ACL Data Packet header is limited to a subset of the possible
/// header configuration flags. A LE-U Logical link does not support automatic flushing of packets
/// in a controller, nor does it support connectionless L2CAP channels. The packet boundary flag can
/// be either
/// ['FirstNonFlushable`](crate::hci::ACLPacketBoundary::FirstNonFlushable) or
/// [`ContinuingFragment`](crate::hci::ACLPacketBoundary::ContinuingFragment), but it cannot be
/// [`FirstAutoFlushable`](crate::hci::ACLPacketBoundary::FirstAutoFlushable) or
/// [`CompleteL2capPdu`](crate::hci::ACLPacketBoundary::CompleteL2capPdu). The broadcast flag must
/// always be
/// [`NoBroadcast`](crate::hci::ACLBroadcastFlag::NoBroadcast). Lastly the connection handle can
/// only be a primary controller handle (which is generated with a *LE Connection Complete* or
/// *LE Enhanced Connection Complete* event for LE-U).
#[derive(Debug)]
pub struct HciACLData<T> {
    connection_handle: common::ConnectionHandle,
    packet_boundary_flag: ACLPacketBoundary,
    broadcast_flag: ACLBroadcastFlag,
    payload: T,
}

impl<T> HciACLData<T> {
    /// The size of the header of a HCI ACL data packet
    pub const HEADER_SIZE: usize = 4;

    /// It is required that the minimum maximum payload size of a HCI ACL data packet be 27 bytes.
    /// Both the host and controller must be able to accept a HCI ACL data packet with 27 bytes.
    /// Larger maximum payload sizes may be defined by either the host or controller.
    pub const MIN_MAX_PAYLOAD_SIZE: usize = 27;

    /// Create a new HciACLData
    ///
    /// # Panic
    /// The payload length must not be larger than the maximum `u16` number
    pub fn new(
        connection_handle: common::ConnectionHandle,
        packet_boundary_flag: ACLPacketBoundary,
        broadcast_flag: ACLBroadcastFlag,
        payload: T,
    ) -> Self
    where
        T: core::ops::Deref<Target = [u8]>,
    {
        assert!(payload.len() <= <u16>::MAX.into());

        HciACLData {
            connection_handle,
            packet_boundary_flag,
            broadcast_flag,
            payload,
        }
    }

    pub fn get_handle(&self) -> &common::ConnectionHandle {
        &self.connection_handle
    }

    pub fn get_payload(&self) -> &T {
        &self.payload
    }

    pub fn get_packet_boundary_flag(&self) -> ACLPacketBoundary {
        self.packet_boundary_flag
    }

    pub fn get_broadcast_flag(&self) -> ACLBroadcastFlag {
        self.broadcast_flag
    }

    /// Convert the `HciACLData` into a iterator over bytes of a HCI packet
    ///
    /// # Note
    /// Collecting the returned iterator into a `Vec` produces the same result as the return of
    /// method [`to_packet`](HciACLData::to_packet)
    pub fn to_packet_iter(&self) -> impl Iterator<Item = u8> + ExactSizeIterator + '_
    where
        T: core::ops::Deref<Target = [u8]>,
    {
        struct HciAclPacketIter<'a, T> {
            state: Option<usize>,
            raw_handle_and_flags: u16,
            total_data_length: u16,
            payload: &'a T,
        }

        impl<'a, T> HciAclPacketIter<'a, T>
        where
            T: core::ops::Deref<Target = [u8]>,
        {
            fn new(data: &'a HciACLData<T>) -> Self {
                Self {
                    state: Some(0),
                    raw_handle_and_flags: data.connection_handle.get_raw_handle()
                        | data.packet_boundary_flag.get_shifted_val()
                        | data.broadcast_flag.get_shifted_val(),
                    total_data_length: data.get_payload().len() as u16,
                    payload: &data.payload,
                }
            }
        }

        impl<T> Iterator for HciAclPacketIter<'_, T>
        where
            T: core::ops::Deref<Target = [u8]>,
        {
            type Item = u8;

            fn next(&mut self) -> Option<Self::Item> {
                self.state.and_then(|state| match state {
                    0 | 1 => {
                        self.state = Some(state + 1);

                        Some(self.raw_handle_and_flags.to_le_bytes()[state])
                    }
                    2 | 3 => {
                        self.state = Some(2);

                        Some(self.total_data_length.to_le_bytes()[state])
                    }
                    _ => {
                        let index = state - 4;

                        if index < self.payload.len() {
                            self.state = Some(state + 1);

                            Some(self.payload[index])
                        } else {
                            self.state = None;
                            None
                        }
                    }
                })
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                let size = 4 + self.payload.len();

                (size, Some(size))
            }
        }

        impl<T> ExactSizeIterator for HciAclPacketIter<'_, T> where T: core::ops::Deref<Target = [u8]> {}

        HciAclPacketIter::new(self)
    }

    /// Attempt to create a `HciAclData` with the provided buffer
    ///
    /// The buffer must contain a complete HCI ACL packet within it.
    fn try_from_buffer(mut buffer: T) -> Result<Self, HciACLPacketError>
    where
        T: crate::TryFrontRemove<u8> + crate::TryRemove<u8> + core::ops::Deref<Target = [u8]>,
    {
        let first_2_bytes = <u16>::from_le_bytes([
            buffer.try_front_pop().ok_or(HciACLPacketError::PacketTooSmall)?,
            buffer.try_front_pop().ok_or(HciACLPacketError::PacketTooSmall)?,
        ]);

        let connection_handle = match common::ConnectionHandle::try_from(first_2_bytes & 0xFFF) {
            Ok(handle) => handle,
            Err(e) => return Err(HciACLPacketError::InvalidConnectionHandle(e)),
        };

        let packet_boundary_flag = ACLPacketBoundary::from_shifted_val(first_2_bytes);

        let broadcast_flag = match ACLBroadcastFlag::try_from_shifted_val(first_2_bytes) {
            Ok(flag) => flag,
            Err(_) => return Err(HciACLPacketError::InvalidBroadcastFlag),
        };

        let data_length = <u16>::from_le_bytes([
            buffer.try_front_pop().ok_or(HciACLPacketError::PacketTooSmall)?,
            buffer.try_front_pop().ok_or(HciACLPacketError::PacketTooSmall)?,
        ]) as usize;

        let remove_len = buffer
            .len()
            .checked_sub(data_length)
            .ok_or(HciACLPacketError::PacketTooSmall)?;

        // remove_len should have verified how many bytes are to be truncated from it
        buffer.try_remove(remove_len).ok().unwrap();

        Ok(HciACLData {
            connection_handle,
            packet_boundary_flag,
            broadcast_flag,
            payload: buffer,
        })
    }

    /// Convert into a
    /// [`ACLDataFragment`](crate::l2cap::ACLDataFragment)
    pub fn into_acl_fragment(self) -> crate::l2cap::L2capFragment<T>
    where
        T: core::ops::Deref<Target = [u8]>,
    {
        use crate::l2cap::L2capFragment;

        match self.packet_boundary_flag {
            ACLPacketBoundary::ContinuingFragment => L2capFragment::new(false, self.payload),
            _ => L2capFragment::new(true, self.payload),
        }
    }
}

impl<'a> HciACLData<&'a [u8]> {
    /// Attempt to create a `HciAclData`
    ///
    /// A `HciACLData` is created if the packet is in the correct HCI ACL data packet format. If
    /// not, then an error is returned.
    pub fn try_from_packet(packet: &'a [u8]) -> Result<Self, HciACLPacketError> {
        Self::try_from_buffer(packet)
    }

    /// Convert the `HciACLData` into a raw packet
    ///
    /// This will convert HciACLDataOwned into a HCI ACL packet that can be sent between the host
    /// and controller.
    pub fn to_packet(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.payload.len() + 4);

        let first_2_bytes = self.connection_handle.get_raw_handle()
            | self.packet_boundary_flag.get_shifted_val()
            | self.broadcast_flag.get_shifted_val();

        v.extend_from_slice(&first_2_bytes.to_le_bytes());

        v.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());

        v.extend_from_slice(&self.payload);

        v
    }
}

/// A buffer
///
/// Buffers within the HCI are used for passing HCI packets between the host, connection, and
/// interface async tasks. The only requirement is that a buffer act like a double ended vector. The
/// implementation needs to push and pop bytes to both the front and end of a buffer. This is
/// because a HCI packet ends up being a nesting of multiple different protocols. Bytes of protocol
/// header information are pushed to the front of a buffer while payload data is pushed to the end
/// of the buffer.
pub trait Buffer:
    core::ops::DerefMut<Target = [u8]> + crate::TryExtend<u8> + crate::TryRemove<u8> + crate::TryFrontRemove<u8> + Unpin
{
    /// Create a Buffer with the front and back capacities
    fn with_capacity(front: usize, back: usize) -> Self
    where
        Self: Sized;

    /// Clear the buffer and set new capacity thresholds
    fn clear_with_capacity(&mut self, front: usize, back: usize);
}

/// Extension methods for types that implement [`Buffer`]
trait BufferExt: Buffer {
    fn new() -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(0, 0)
    }

    fn with_front_capacity(front: usize) -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(front, 0)
    }

    fn with_back_capacity(back: usize) -> Self
    where
        Self: Sized,
    {
        Self::with_capacity(0, back)
    }

    fn clear_uncapped(&mut self) {
        self.clear_with_capacity(0, 0)
    }

    fn clear_with_front_capacity(&mut self, front: usize) {
        self.clear_with_capacity(front, 0)
    }

    fn clear_with_back_capacity(&mut self, back: usize) {
        self.clear_with_capacity(0, back)
    }
}

impl<T> BufferExt for T where T: Buffer {}

/// A reserve of buffers
///
/// A reserve is for storing previously used buffers for usage later. The main purpose is for both
/// reducing dynamic allocations of memory and the amount of times data is copied as its passed
/// between the interface async task and another HCI async task. Buffers are taken and reclaimed
/// by a reserve. Taking removes a buffer from the reserve and reclaiming adds a buffer to the
/// reserve.
#[doc(hidden)]
pub trait BufferReserve {
    type Buffer: Buffer + Unpin;

    type TakeBuffer: Future<Output = Self::Buffer>;

    /// Take a buffer from the reserve
    ///
    /// If there is no more buffers within the reserve the returned future will await. However, it
    /// is intended that there be enough buffers in the reserve so that most of the time this does
    /// not await.
    fn take<S>(&self, front_capacity: S) -> Self::TakeBuffer
    where
        S: Into<Option<usize>>;

    /// Reclaim an unused buffer
    ///
    /// Buffers can be reclaimed for reuse later. However, if the reserve is full then the buffer to
    /// be reclaimed is dropped.
    fn reclaim(&mut self, buffer: Self::Buffer);
}

/// A matcher of events in response to a command
///
/// This is used for matching a HCI packet from the controller to the events Command Complete and
/// Command Status. Either one will match so long as the opcode within the event matches the opcode
/// within the `CommandEventMatcher`.
#[derive(Clone, Copy)]
pub struct CommandEventMatcher {
    op_code: opcodes::HCICommand,
    event: events::Events,
    get_op_code: for<'a> fn(&'a [u8]) -> Option<u16>,
}

impl CommandEventMatcher {
    /// Create a new `CommandEventMatcher` for the event `CommandComplete`
    fn new_command_complete(op_code: opcodes::HCICommand) -> Self {
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
            get_op_code,
        }
    }

    /// Create a new `CommandEventMatcher` for the event `CommandStatus`
    fn new_command_status(op_code: opcodes::HCICommand) -> Self {
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
            get_op_code,
        }
    }
}

/// The trait for a [`Host`] to communicate with the interface
///
/// This trait is used for communication by a host async task with an interface async task. It
/// provides access to the sender and receiver used by a `Host` and the buffer reserve for creating
/// an [`IntraMessage`](interface::IntraMessage) to send to an interface.
///
/// There are three types `HostInterface`s. These types are modeled to be flexible for various
/// kinds of platforms that would use the `bo-tie`. The *preferred*  implementation.
pub trait HostInterface {
    /// Buffer type for messages to the interface async task
    type ToBuffer: Buffer;

    /// Buffer type for messages from the interface async task
    type FromBuffer: Buffer;

    /// The type containing the channels ends used for communicating with the interface async task
    type ChannelEnds: ChannelEnds;

    /// Sender for messages to the interface
    type Sender: interface::Sender<Message = interface::ToIntraMessage<Self::ToBuffer>>;

    /// The receiver of messages from the interface
    type Receiver: interface::Receiver<Message = interface::FromIntraMessage<Self::FromBuffer, Self::ChannelEnds>>;

    /// The future used for taking a buffer
    type TakeBuffer: Future<Output = Self::ToBuffer>;

    /// Get the sender of messages to the interface async task
    fn get_sender(&self) -> Self::Sender;

    /// Get the receiver for messages from the interface async task
    fn get_receiver(&self) -> &Self::Receiver;

    /// Take a buffer
    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>;
}

/// An interface for a singled threaded HCI
///
/// When an async task executor does not require the async tasks to be [`Send`] safe, a
/// `LocalHostInterface` can be used
struct DynLocalHostInterface {
    ends: interface::local_channel::local_dynamic_channel::DynChannelEnds,
}

impl HostInterface for DynLocalHostInterface {
    type ToBuffer = <interface::local_channel::local_dynamic_channel::DynChannelEnds as ChannelEnds>::ToBuffer;

    type FromBuffer = <interface::local_channel::local_dynamic_channel::DynChannelEnds as ChannelEnds>::FromBuffer;

    type ChannelEnds = interface::local_channel::local_dynamic_channel::DynChannelEnds;

    type Sender = <interface::local_channel::local_dynamic_channel::DynChannelEnds as ChannelEnds>::Sender;

    type Receiver = <interface::local_channel::local_dynamic_channel::DynChannelEnds as ChannelEnds>::Receiver;

    type TakeBuffer = <interface::local_channel::local_dynamic_channel::DynChannelEnds as ChannelEnds>::TakeBuffer;

    fn get_sender(&self) -> Self::Sender {
        self.ends.get_sender()
    }

    fn get_receiver(&self) -> &Self::Receiver {
        self.ends.get_receiver()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.ends.take_buffer(front_capacity)
    }
}

/// Create a locally used Host Controller Interface
pub async fn new_local_hci(
    max_connections: usize,
) -> Result<(Host<impl HostInterface>, interface::Interface<impl ChannelReserve>), CommandError<impl HostInterface>> {
    use interface::InitHostTaskEnds;

    let mut interface = interface::Interface::new_local(max_connections + 1);

    let ends = interface.init_host_task_ends().unwrap();

    let host_interface = DynLocalHostInterface { ends };

    let host = Host::init(host_interface).await?;

    Ok((host, interface))
}

#[cfg(feature = "unstable")]
struct StackLocalHostInterface<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    ends: interface::local_channel::local_stack_channel::ChannelEndsType<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
}

#[cfg(feature = "unstable")]
impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> HostInterface
    for StackLocalHostInterface<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type ToBuffer = <interface::local_channel::local_stack_channel::ChannelEndsType<
        'z,
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    > as ChannelEnds>::ToBuffer;

    type FromBuffer = <interface::local_channel::local_stack_channel::ChannelEndsType<
        'z,
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    > as ChannelEnds>::FromBuffer;

    type ChannelEnds =
        interface::local_channel::local_stack_channel::ChannelEndsType<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;

    type Sender = <interface::local_channel::local_stack_channel::ChannelEndsType<
        'z,
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    > as ChannelEnds>::Sender;

    type Receiver = <interface::local_channel::local_stack_channel::ChannelEndsType<
        'z,
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    > as ChannelEnds>::Receiver;

    type TakeBuffer = <interface::local_channel::local_stack_channel::ChannelEndsType<
        'z,
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    > as ChannelEnds>::TakeBuffer;

    fn get_sender(&self) -> Self::Sender {
        self.ends.get_sender()
    }

    fn get_receiver(&self) -> &Self::Receiver {
        self.ends.get_receiver()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.ends.take_buffer(front_capacity)
    }
}

/// The primer for a stack local HCI
///
/// This is the "allocation area" for the stack local HCI implementation. The stack local host,
/// connection, and interface async tasks utilize rust by borrowing from this primer to ensure that
/// they can safely allocate on the stack. For more information see the method
/// [`new_stack_local_hci`].
#[cfg(feature = "unstable")]
pub struct StackLocalHciPrimer<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    data: interface::local_channel::local_stack_channel::LocalStackChannelReserveData<
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    >,
}

#[cfg(feature = "unstable")]
impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    StackLocalHciPrimer<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new host and interface
    // There should not be multiple interfaces created at the same time per `StackLocalHciPrimer`.
    // Here we're abusing rust's borrow checker a bit as this returns an interface that depends on
    // the lifetime of a mutable reference to a `StackLocalHciPrimer`.
    pub async fn init<'a>(
        &'a self,
    ) -> Result<
        (
            Host<impl HostInterface + 'a>,
            interface::Interface<impl ChannelReserve + 'a>,
        ),
        CommandError<impl HostInterface + 'a>,
    > {
        use interface::InitHostTaskEnds;

        let mut interface = interface::Interface::new_stack_local(&self.data);

        let ends = interface.init_host_task_ends().unwrap();

        let host_interface = StackLocalHostInterface { ends };

        let host = Host::init(host_interface).await?;

        Ok((host, interface))
    }
}

/// Create a local, stack buffered HCI
///
/// This is used to create a host controller interface whereby async tasks must run on a local
/// executor. The host, connection, and interface async tasks are *not* [`Send`] safe and cannot be
/// run on an executor that requires send safe async tasks. Using a locally restricted HCI can be
/// advantageous where there is a light usage of Bluetooth by the application or where environments
/// cannot support
#[cfg(feature = "unstable")]
pub fn new_stack_local_hci<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>(
) -> StackLocalHciPrimer<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE> {
    let data = interface::local_channel::local_stack_channel::LocalStackChannelReserveData::<
        TASK_COUNT,
        CHANNEL_SIZE,
        BUFFER_SIZE,
    >::new();

    StackLocalHciPrimer { data }
}

/// The host interface
///
/// This is used by the host to interact with the Bluetooth Controller. It is the host side of the
/// host controller interface.
pub struct Host<H: HostInterface> {
    host_interface: H,
    next_connection: Option<H::ChannelEnds>,
    acl_max_mtu: usize,
    sco_max_mtu: usize,
    le_acl_max_mtu: usize,
    le_iso_max_mtu: usize,
}

impl<H> Host<H>
where
    H: HostInterface,
{
    /// Initialize the host
    async fn init(host_interface: H) -> Result<Self, CommandError<H>> {
        let mut host = Host {
            host_interface,
            next_connection: None,
            acl_max_mtu: 0,
            sco_max_mtu: 0,
            le_acl_max_mtu: 0,
            le_iso_max_mtu: 0,
        };

        let buffer_info = info_params::read_buffer_size::send(&mut host).await?;

        host.acl_max_mtu = buffer_info.hc_acl_data_packet_len;

        host.sco_max_mtu = buffer_info.hc_synchronous_data_packet_len;

        let buffer_info = le::mandatory::read_buffer_size::send_v2(&mut host).await?;

        host.le_acl_max_mtu = match buffer_info.acl {
            Some(bs) => bs.len.into(),
            None => host.acl_max_mtu,
        };

        host.le_iso_max_mtu = buffer_info.iso.map(|bs| bs.len.into()).unwrap_or_default();

        Ok(host)
    }

    /// Send a command with the provided matcher to the interface async task
    ///
    /// Returns the event received from the interface async task (hopefully) contains the event sent
    /// in response to the command.
    ///
    /// # Note
    /// This method is intended to only be used internally
    #[doc(hidden)]
    async fn send_command<CP, const CP_SIZE: usize>(
        &mut self,
        parameter: CP,
        event_matcher: CommandEventMatcher,
    ) -> Result<events::EventsData, CommandError<H>>
    where
        CP: CommandParameter<CP_SIZE>,
    {
        use interface::IntraMessageType;
        use interface::{Receiver, Sender};

        let mut buffer = self.host_interface.take_buffer(None).await;

        parameter
            .as_command_packet(&mut buffer)
            .map_err(|e| CommandError::TryExtendBufferError(e))?;

        self.host_interface
            .get_sender()
            .send(IntraMessageType::Command(event_matcher, buffer).into())
            .await
            .map_err(|e| CommandError::SendError(e))?;

        let received = self
            .host_interface
            .get_receiver()
            .recv()
            .await
            .map(|from_im| from_im.ty)
            .ok_or(CommandError::ReceiverClosed)?;

        match received {
            IntraMessageType::Event(e @ events::EventsData::CommandComplete(_))
            | IntraMessageType::Event(e @ events::EventsData::CommandStatus(_)) => Ok(e),
            _ => todo!("need to queue intra messages that are not the correct events"),
        }
    }

    /// Send a command to the controller expecting a returned parameter
    ///
    /// This sends the command within `cmd_data` to the controller and awaits for the Command
    /// Complete event. The return parameter within the Command Complete event is then returned by
    /// the controller.
    ///
    /// Input `cmd_data` is the type used as the command parameter sent to the controller.
    ///
    /// The returned type `T` must be able to be converted from the pair of raw parameter bytes
    /// accompanied with the number of commands that can be sent to the controller.
    ///
    /// # Controller Error
    /// If a status code is provided as part of the return parameter within the Command Complete
    /// event, this method will return an `Err` containing the status instead of returning possibly
    /// invalid data.
    async fn send_command_expect_complete<CP, T, const CP_SIZE: usize>(
        &mut self,
        parameter: CP,
    ) -> Result<T, CommandError<H>>
    where
        CP: CommandParameter<CP_SIZE>,
        T: TryFromCommandComplete,
    {
        use events::EventsData;

        let event_matcher = CommandEventMatcher::new_command_complete(CP::COMMAND);

        let command_return = self.send_command(parameter, event_matcher).await?;

        match command_return {
            EventsData::CommandComplete(data) => Ok(T::try_from(&data)?),
            e => unreachable!("invalid event matched for command: {:?}", e),
        }
    }

    /// Send a command to the controller expecting a status
    ///
    /// This sends the command within `cmd_data` to the controller and awaits for the Command
    /// Complete event. The return parameter within the Command Complete event is then returned by
    /// the controller.
    ///
    /// Input `cmd_data` is the type used as the command parameter sent to the controller. The
    /// return is the number of HCI commands that the controller can currently accept.
    ///
    /// # Note
    /// The returned number is invalidated when another Command Complete or Command Status event is
    /// sent from the controller.
    ///
    /// # Controller Error
    /// If there is a status code within the event returned from the controller, this method will
    /// return an `Err` containing the status.
    async fn send_command_expect_status<CP, const CP_SIZE: usize>(
        &mut self,
        parameter: CP,
    ) -> Result<usize, CommandError<H>>
    where
        CP: CommandParameter<CP_SIZE> + 'static,
    {
        use events::EventsData;

        let event_matcher = CommandEventMatcher::new_command_status(CP::COMMAND);

        let command_return = self.send_command(parameter, event_matcher).await?;

        match command_return {
            EventsData::CommandStatus(data) => {
                if error::Error::NoError == data.status {
                    Ok(data.number_of_hci_command_packets.into())
                } else {
                    Err(data.status.into())
                }
            }
            e => unreachable!("invalid event matched for command: {:?}", e),
        }
    }

    /// Get a future for a Bluetooth Event
    ///
    /// This will create a future for awaiting events from the controller. A specific event can
    /// be awaited for or `None` can be provided to match all *maskable* events.
    ///
    /// [`CommandComplete`](crate::hci::events::Events::CommandComplete),
    /// [`CommandStatus`](crate::hci::events::Events::CommandStatus), and
    /// [`NumberOfCompletedPackets`](crate::hci::events::Events::NumberOfCompletedPackets) are the
    /// non-maskable events and they will not be returned by the future when `None` is used for
    /// input `event`. This function will await on these events if `event` is specifically one of
    /// these events, but it is unlikely you will need to await these events yourself. This library
    /// incorporates the awaiting of either `CommandComplete` or `CommandStatus` events in its
    /// implemented HCI commands, and a flow controller will await the `NumberOfCompletedPackets`
    /// event for controlling the sending of data packets to the Bluetooth controller.
    ///
    /// # Limitations
    /// You cannot await this function concurrently (or polled in parallel) with the same value for
    /// input 'event'. It will produce undefined behavior (probably race condition) because input
    /// `event` cannot be differentiated to wake the correct context by the underlying Bluetooth
    /// controller driver. It is safe to use this concurrently if these conditions are not met.
    ///
    /// The function
    /// [`wait_for_event_with_matcher`](crate::hci::HostInterface::wait_for_event_with_matcher)
    /// can be used to further refine the matching event to get around the limitation of this
    /// function. However it can also run into the same problem if the matcher is not differential
    /// enough between two events.
    pub async fn wait_for_event<E>(&mut self, event: E) -> Result<events::EventsData, WaitForEventError>
    where
        E: Into<Option<events::Events>>,
    {
        use interface::{IntraMessageType, Receiver};

        let event_opt = event.into();

        loop {
            let intra_message = self
                .host_interface
                .get_receiver()
                .recv()
                .await
                .ok_or(WaitForEventError::ReceiverClosed)?;

            if let IntraMessageType::Event(event_data) = intra_message.ty {
                match event_opt {
                    Some(ref event) => {
                        if event_data.get_event_name() == *event {
                            break Ok(event_data);
                        }
                    }
                    None => break Ok(event_data),
                }
            } else {
                break Err(WaitForEventError::UnexpectedIntraMessage(intra_message.ty.kind()));
            }
        }
    }
}

/// An error when trying to send a command
pub enum CommandError<H>
where
    H: HostInterface,
{
    TryExtendBufferError(<H::ToBuffer as crate::TryExtend<u8>>::Error),
    CommandError(error::Error),
    SendError(<H::Sender as interface::Sender>::Error),
    EventError(events::EventError),
    InvalidEventParameter,
    ReceiverClosed,
}

impl<H> core::fmt::Debug for CommandError<H>
where
    H: HostInterface,
    <H::ToBuffer as crate::TryExtend<u8>>::Error: core::fmt::Debug,
    <H::Sender as interface::Sender>::Error: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CommandError::TryExtendBufferError(e) => f.debug_tuple("BufferError").field(e).finish(),
            CommandError::CommandError(e) => f.debug_tuple("CommandError").field(e).finish(),
            CommandError::SendError(e) => f.debug_tuple("SendError").field(e).finish(),
            CommandError::EventError(e) => f.debug_tuple("EventError").field(e).finish(),
            CommandError::InvalidEventParameter => f.debug_tuple("InvalidEventParameter").finish(),
            CommandError::ReceiverClosed => f.debug_tuple("ReceiverClosed").finish(),
        }
    }
}

impl<H> core::fmt::Display for CommandError<H>
where
    H: HostInterface,
    <H::ToBuffer as crate::TryExtend<u8>>::Error: core::fmt::Display,
    <H::Sender as interface::Sender>::Error: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CommandError::TryExtendBufferError(e) => core::fmt::Display::fmt(e, f),
            CommandError::CommandError(e) => core::fmt::Display::fmt(e, f),
            CommandError::SendError(e) => core::fmt::Display::fmt(e, f),
            CommandError::EventError(e) => core::fmt::Display::fmt(e, f),
            CommandError::InvalidEventParameter => f.write_str("command complete event contained an invalid parameter"),
            CommandError::ReceiverClosed => f.write_str("interface is not running"),
        }
    }
}

impl<H: HostInterface> From<events::EventError> for CommandError<H> {
    fn from(e: events::EventError) -> Self {
        CommandError::EventError(e)
    }
}

impl<H: HostInterface> From<error::Error> for CommandError<H> {
    fn from(e: error::Error) -> Self {
        CommandError::CommandError(e)
    }
}

impl<H: HostInterface> From<CCParameterError> for CommandError<H> {
    fn from(e: CCParameterError) -> Self {
        match e {
            CCParameterError::CommandError(e) => CommandError::CommandError(e),
            CCParameterError::InvalidEventParameter => CommandError::InvalidEventParameter,
        }
    }
}

/// A trait for converting from a Command Complete Event
trait TryFromCommandComplete {
    fn try_from(cc: &events::CommandCompleteData) -> Result<Self, CCParameterError>
    where
        Self: Sized;
}

/// An error when converting the parameter of a Command Complete to a concrete type fails.
enum CCParameterError {
    CommandError(error::Error),
    InvalidEventParameter,
}

macro_rules! check_status {
    ($raw_data:expr) => {
        error::Error::from(*$raw_data.get(0).ok_or(CCParameterError::InvalidEventParameter)?)
            .ok_or_else(|e| CCParameterError::CommandError(e))?;
    };
}

/// Error for method [`wait_for_event`](HostInterface::wait_for_event)
#[derive(Debug)]
pub enum WaitForEventError {
    ReceiverClosed,
    EventConversionError(events::EventError),
    UnexpectedIntraMessage(&'static str),
}

impl core::fmt::Display for WaitForEventError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            WaitForEventError::ReceiverClosed => f.write_str("interface task is dropped"),
            WaitForEventError::EventConversionError(e) => core::fmt::Display::fmt(e, f),
            WaitForEventError::UnexpectedIntraMessage(kind) => write!(
                f,
                "Unexpected intra \
                message '{}' (this is a library bug)",
                kind
            ),
        }
    }
}

impl From<events::EventError> for WaitForEventError {
    fn from(e: events::EventError) -> Self {
        WaitForEventError::EventConversionError(e)
    }
}

/// A type used when a Command Complete event return parameter is expected to only contains a status
///
/// This is used for commands where the controller returns a command complete event but the only
/// thing in the parameter is a status.
///
/// `OnlyStatus` just contains the number of commands the controller can currently accept.
struct OnlyStatus(usize);

impl TryFromCommandComplete for OnlyStatus {
    fn try_from(cc: &events::CommandCompleteData) -> Result<Self, CCParameterError> {
        check_status!(cc.raw_data);

        Ok(Self(cc.number_of_hci_command_packets.into()))
    }
}

impl FlowControlInfo for OnlyStatus {
    fn command_count(&self) -> usize {
        self.0
    }
}

struct AclConnection<C: ChannelEnds> {
    max_mtu: usize,
    min_mtu: usize,
    mtu: core::cell::Cell<usize>,
    channel_ends: C,
    sender: C::Sender,
}

impl<C> crate::l2cap::ConnectionChannel for AclConnection<C>
where
    C: ChannelEnds,
{
    type SendBuffer = C::ToBuffer;
    type SendFut<'a> = ConnectionChannelSender<'a, C> where Self: 'a;
    type SendFutErr = <C::Sender as interface::Sender>::Error;
    type RecvBuffer = C::FromBuffer;
    type RecvFut<'a> = AclReceiverMap<'a, C> where Self: 'a;

    fn send(&self, data: crate::l2cap::BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
        // todo: not sure if this will be necessary when the type of input data is `BasicInfoFrame<Self::Buffer<'_>>`
        let front_capacity = HciACLData::<()>::HEADER_SIZE;

        let channel_ends = &self.channel_ends;

        let sender = &self.sender;

        let iter = SelfSendBufferIter {
            front_capacity,
            channel_ends,
            sender,
        };

        ConnectionChannelSender {
            sliced_future: data.into_sliced_packet(self.get_mtu(), iter),
        }
    }

    fn set_mtu(&self, mtu: u16) {
        self.mtu.set(mtu.into())
    }

    fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    fn max_mtu(&self) -> usize {
        self.max_mtu
    }

    fn min_mtu(&self) -> usize {
        self.min_mtu
    }

    fn receive(&self) -> Self::RecvFut<'_> {
        AclReceiverMap {
            receiver: self.channel_ends.get_receiver(),
            receive_future: None,
        }
    }
}

/// A self sending buffer
///
/// This is a wrapper around a buffer and a sender. When it is created it is in buffer mode and can
/// be de-referenced as a slice or extended,
struct AclBufferBuilder<'a, C: ChannelEnds> {
    sender: &'a C::Sender,
    buffer: C::ToBuffer,
}

impl<'a, C> crate::TryExtend<u8> for AclBufferBuilder<'a, C>
where
    C: ChannelEnds,
{
    type Error = AclBufferError<C::ToBuffer>;

    fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = u8>,
    {
        self.buffer.try_extend(iter).map_err(|e| AclBufferError::Buffer(e))
    }
}

impl<'a, C> core::future::IntoFuture for AclBufferBuilder<'a, C>
where
    C: ChannelEnds,
{
    type Output = <<C::Sender as interface::Sender>::SendFuture<'a> as Future>::Output;
    type IntoFuture = <C::Sender as interface::Sender>::SendFuture<'a>;

    fn into_future(self) -> Self::IntoFuture {
        use interface::Sender;

        let message = interface::IntraMessageType::Acl(self.buffer).into();

        self.sender.send(message)
    }
}

/// Error for `TryExtend` implementation of `SelfSendBuffer`
enum AclBufferError<T: crate::TryExtend<u8>> {
    Buffer(T::Error),
    IncorrectIntraMessageType,
}

impl<T: crate::TryExtend<u8>> core::fmt::Debug for AclBufferError<T>
where
    T::Error: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AclBufferError::Buffer(e) => e.fmt(f),
            AclBufferError::IncorrectIntraMessageType => f.write_str("Incorrect message type for SelfSendBuffer"),
        }
    }
}

impl<T: crate::TryExtend<u8>> core::fmt::Display for AclBufferError<T>
where
    T::Error: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            AclBufferError::Buffer(e) => e.fmt(f),
            AclBufferError::IncorrectIntraMessageType => f.write_str("Incorrect message type for SelfSendBuffer"),
        }
    }
}

struct SelfSendBufferIter<'a, C: ChannelEnds> {
    front_capacity: usize,
    channel_ends: &'a C,
    sender: &'a C::Sender,
}

impl<'a, C> Iterator for SelfSendBufferIter<'a, C>
where
    C: ChannelEnds,
{
    type Item = SelfSendBufferFutureMap<'a, C>;

    fn next(&mut self) -> Option<Self::Item> {
        let take_buffer = self.channel_ends.take_buffer(self.front_capacity);

        let sender = self.sender;

        Some(SelfSendBufferFutureMap { sender, take_buffer })
    }
}

struct SelfSendBufferFutureMap<'a, C: ChannelEnds> {
    sender: &'a C::Sender,
    take_buffer: C::TakeBuffer,
}

impl<'a, C> Future for SelfSendBufferFutureMap<'a, C>
where
    C: ChannelEnds,
{
    type Output = AclBufferBuilder<'a, C>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        unsafe { Pin::new_unchecked(&mut this.take_buffer) }
            .poll(cx)
            .map(|buffer| {
                let ends = this.sender;

                AclBufferBuilder { sender: ends, buffer }
            })
    }
}

struct ConnectionChannelSender<'a, C: ChannelEnds> {
    sliced_future: crate::l2cap::send_future::AsSlicedPacketFuture<
        SelfSendBufferIter<'a, C>,
        Vec<u8>,
        SelfSendBufferFutureMap<'a, C>,
        AclBufferBuilder<'a, C>,
        <C::Sender as interface::Sender>::SendFuture<'a>,
    >,
}

impl<'a, C> Future for ConnectionChannelSender<'a, C>
where
    C: ChannelEnds,
{
    type Output = Result<(), <C::Sender as interface::Sender>::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|this| &mut this.sliced_future) }.poll(cx)
    }
}

pub struct AclReceiverMap<'a, C: ChannelEnds> {
    receiver: &'a C::Receiver,
    receive_future: Option<<C::Receiver as interface::Receiver>::ReceiveFuture<'a>>,
}

impl<'a, C> Future for AclReceiverMap<'a, C>
where
    C: ChannelEnds,
{
    type Output = Option<
        Result<
            crate::l2cap::L2capFragment<C::FromBuffer>,
            crate::l2cap::BasicFrameError<<C::FromBuffer as crate::TryExtend<u8>>::Error>,
        >,
    >;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use crate::l2cap::BasicFrameError;
        use interface::Receiver;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.receive_future {
                None => this.receive_future = Some(this.receiver.recv()),
                Some(ref mut receiver) => match unsafe { Pin::new_unchecked(receiver) }.poll(cx) {
                    Poll::Pending => break Poll::Pending,
                    Poll::Ready(None) => break Poll::Ready(None),
                    Poll::Ready(Some(intra_message)) => match intra_message.ty {
                        interface::IntraMessageType::Acl(data) => match HciACLData::try_from_buffer(data) {
                            Ok(data) => {
                                let fragment = data.into_acl_fragment();

                                break Poll::Ready(Some(Ok(fragment)));
                            }
                            Err(_) => {
                                break Poll::Ready(Some(Err(BasicFrameError::Other(
                                    "Received invalid HCI ACL Data packet",
                                ))))
                            }
                        },
                        interface::IntraMessageType::Sco(_) => {
                            break Poll::Ready(Some(Err(BasicFrameError::Other(
                                "synchronous connection data is not implemented",
                            ))))
                        }
                        interface::IntraMessageType::Iso(_) => {
                            break Poll::Ready(Some(Err(BasicFrameError::Other(
                                "isochronous connection data is not implemented",
                            ))))
                        }
                        _ => unreachable!(),
                    },
                },
            }
        }
    }
}

/// Controller *Command* flow-control information
///
/// Command flow control information is issued as part of the Command Complete and Command Status
/// events. A controller sends back the number of commands that can be currently sent to the
/// controller as part of the information in both events. This trait is implemented for every `send`
/// command method in this library.
///
/// This trait is not very useful
pub trait FlowControlInfo {
    /// Get the number of HCI command packets that can be set to the controller
    ///
    /// This function returns the Num_HCI_Command_Packets parameter of the Command Complete and
    /// Command Status Events.
    ///
    /// The return is the number of packets that the Controller can accept from the Host at the time
    /// of issuing either the Command Complete or Command Status event. If this number is zero, then
    /// the Host must wait until another Command Complete or Command Status event that does not
    /// have the number of HCI command packets parameter as zero. Be aware that the Controller can
    /// issue a Command Complete Event with no opcode to indicate that the host can send packets
    /// to the controller.
    fn command_count(&self) -> usize;
}

impl FlowControlInfo for usize {
    fn command_count(&self) -> usize {
        *self
    }
}

// All these were down here for the macros, planning to move them to a new module named `commands`
pub mod cb;
pub mod info_params;
pub mod le;
pub mod link_control;
pub mod link_policy;
pub mod status_prams;
pub mod testing;
