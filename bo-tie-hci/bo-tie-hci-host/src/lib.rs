//! The Host Interface to the Controller
//!
//! This is the implementation of the host of the Host Controller Interface. It's purpose is to
//! function and control the Bluetooth controller. The host is broken into to three parts  

#![feature(generic_associated_types)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

/// A helper macro for quickly checking the status return of a command
macro_rules! check_status {
    ($raw_data:expr) => {
        match crate::errors::Error::from(*$raw_data.get(0).ok_or(CCParameterError::InvalidEventParameter)?) {
            crate::errors::Error::NoError => (),
            e => return Err(CCParameterError::CommandError(e)),
        }
    };
}

pub mod commands;

use bo_tie_hci_util::events;
use bo_tie_hci_util::opcodes;
use bo_tie_util::errors;
use alloc::vec::Vec;
use bo_tie_hci_util::{Channel, ChannelEnds, ChannelReserve, FlowControlId};
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use std::ops::Deref;
use std::sync::mpsc::{Receiver, Sender};

/// Used to get the information required for sending a command from the host to the controller
///
/// The type Parameter should be a packed structure of the command's parameters
pub trait CommandParameter<const PARAMETER_SIZE: usize> {
    /// The command to send to the Bluetooth Controller.
    ///
    /// This is the OGF & OCF pair.
    const COMMAND: opcodes::HciCommand;

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
        T: bo_tie_util::buffer::TryExtend<u8>,
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

/// The packet boundary flag
///
/// The packet boundary flag is a two bit flag within the HCI ACL data packet. It's used to provide
/// flow control information to both the Host and Controller.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AclPacketBoundary {
    FirstNonFlushable,
    ContinuingFragment,
    FirstAutoFlushable,
    CompleteL2capPdu,
}

impl AclPacketBoundary {
    /// Get the value shifted into the correct place of the Packet Boundary Flag in the HCI ACL
    /// data packet. The returned value is in host byte order.
    fn get_shifted_val(&self) -> u16 {
        (match self {
            AclPacketBoundary::FirstNonFlushable => 0x0,
            AclPacketBoundary::ContinuingFragment => 0x1,
            AclPacketBoundary::FirstAutoFlushable => 0x2,
            AclPacketBoundary::CompleteL2capPdu => 0x3,
        }) << 12
    }

    /// Get the `AclPacketBoundary` from the first 16 bits of a HCI ACL data packet. The input
    /// `val` does not need to be masked to only include the Packet Boundary Flag, however it does
    /// need to be in host byte order.
    fn from_shifted_val(val: u16) -> Self {
        match (val >> 12) & 3 {
            0x0 => AclPacketBoundary::FirstNonFlushable,
            0x1 => AclPacketBoundary::ContinuingFragment,
            0x2 => AclPacketBoundary::FirstAutoFlushable,
            0x3 => AclPacketBoundary::CompleteL2capPdu,
            _ => panic!("This cannot happen"),
        }
    }
}

/// The broadcast flag
///
/// The broadcast flag is an indicator of who the message is for or from. The `BrEdrBroadcast` may
/// only be used for ACL data packets sent from the host interface task to the Controller of a
/// central device of a piconet or from the Controller to the host interface task of a peripheral
/// device of a piconet. All other ACL data packets will have `NoBroadcast` set as the flag.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum AclBroadcastFlag {
    /// Point-to-point message
    NoBroadcast,
    /// Broadcast to all active slaves
    BrEdrBroadcast,
}

impl AclBroadcastFlag {
    /// Get the value shifted into the correct place of the Packet Boundary Flag in the HCI ACL
    /// data packet. The returned value is in host byte order.
    fn get_shifted_val(&self) -> u16 {
        (match self {
            AclBroadcastFlag::NoBroadcast => 0x0,
            AclBroadcastFlag::BrEdrBroadcast => 0x1,
        }) << 14
    }

    /// Get the `AclBroadcastFlag` from the first 16 bits of a HCI ACL data packet. The input
    /// `val` does not need to be masked to only include the Packet Boundary Flag, however it does
    /// need to be in host byte order.
    fn try_from_shifted_val(val: u16) -> Result<Self, ()> {
        match (val >> 14) & 1 {
            0x0 => Ok(AclBroadcastFlag::NoBroadcast),
            0x1 => Ok(AclBroadcastFlag::BrEdrBroadcast),
            0x2 | 0x3 => Err(()),
            _ => panic!("This cannot happen"),
        }
    }
}

/// Error from a HCI ACL packet
///
/// Packets can become errors from either the host interface task or the Controller.
#[derive(Debug)]
pub enum HciAclPacketError {
    PacketTooSmall,
    InvalidBroadcastFlag,
    InvalidConnectionHandle(&'static str),
}

impl core::fmt::Display for HciAclPacketError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HciAclPacketError::PacketTooSmall => write!(f, "Packet is too small to be a valid HCI ACL Data"),
            HciAclPacketError::InvalidBroadcastFlag => write!(f, "Packet has invalid broadcast Flag"),
            HciAclPacketError::InvalidConnectionHandle(reason) => {
                write!(f, "Invalid connection handle, {}", reason)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for HciAclPacketError {}

/// The HCI ACL Data Packet
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
/// ['FirstNonFlushable`](crate::AclPacketBoundary::FirstNonFlushable) or
/// [`ContinuingFragment`](crate::AclPacketBoundary::ContinuingFragment), but it cannot be
/// [`FirstAutoFlushable`](crate::AclPacketBoundary::FirstAutoFlushable) or
/// [`CompleteL2capPdu`](crate::AclPacketBoundary::CompleteL2capPdu). The broadcast flag must
/// always be
/// [`NoBroadcast`](crate::hci::AclBroadcastFlag::NoBroadcast). Lastly the connection handle can
/// only be a primary controller handle (which is generated with a *LE Connection Complete* or
/// *LE Enhanced Connection Complete* event for LE-U).
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub struct HciAclData<T> {
    connection_handle: bo_tie_hci_util::ConnectionHandle,
    packet_boundary_flag: AclPacketBoundary,
    broadcast_flag: AclBroadcastFlag,
    payload: T,
}

impl<T> HciAclData<T> {
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
        connection_handle: bo_tie_hci_util::ConnectionHandle,
        packet_boundary_flag: AclPacketBoundary,
        broadcast_flag: AclBroadcastFlag,
        payload: T,
    ) -> Self
    where
        T: Deref<Target = [u8]>,
    {
        assert!(payload.len() <= <u16>::MAX.into());

        HciAclData {
            connection_handle,
            packet_boundary_flag,
            broadcast_flag,
            payload,
        }
    }

    pub fn get_handle(&self) -> &bo_tie_hci_util::ConnectionHandle {
        &self.connection_handle
    }

    pub fn get_payload(&self) -> &T {
        &self.payload
    }

    pub fn get_packet_boundary_flag(&self) -> AclPacketBoundary {
        self.packet_boundary_flag
    }

    pub fn get_broadcast_flag(&self) -> AclBroadcastFlag {
        self.broadcast_flag
    }

    /// Convert the `HciACLData` into a iterator over bytes of a HCI packet
    ///
    /// # Note
    /// Collecting the returned iterator into a `Vec` produces the same result as the return of
    /// method [`to_packet`](HciACLData::to_packet)
    pub fn to_packet_iter(&self) -> impl Iterator<Item = u8> + ExactSizeIterator + '_
    where
        T: Deref<Target = [u8]>,
    {
        struct HciAclPacketIter<'a, T> {
            state: Option<usize>,
            raw_handle_and_flags: u16,
            total_data_length: u16,
            payload: &'a T,
        }

        impl<'a, T> HciAclPacketIter<'a, T>
        where
            T: Deref<Target = [u8]>,
        {
            fn new(data: &'a HciAclData<T>) -> Self {
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
    fn try_from_buffer(mut buffer: T) -> Result<Self, HciAclPacketError>
    where
        T: bo_tie_util::buffer::TryFrontRemove<u8> + bo_tie_util::buffer::TryRemove<u8> + Deref<Target = [u8]>,
    {
        let first_2_bytes = <u16>::from_le_bytes([
            buffer.try_front_pop().ok_or(HciAclPacketError::PacketTooSmall)?,
            buffer.try_front_pop().ok_or(HciAclPacketError::PacketTooSmall)?,
        ]);

        let connection_handle = match bo_tie_hci_util::ConnectionHandle::try_from(first_2_bytes & 0xFFF) {
            Ok(handle) => handle,
            Err(e) => return Err(HciAclPacketError::InvalidConnectionHandle(e)),
        };

        let packet_boundary_flag = AclPacketBoundary::from_shifted_val(first_2_bytes);

        let broadcast_flag = match AclBroadcastFlag::try_from_shifted_val(first_2_bytes) {
            Ok(flag) => flag,
            Err(_) => return Err(HciAclPacketError::InvalidBroadcastFlag),
        };

        let data_length = <u16>::from_le_bytes([
            buffer.try_front_pop().ok_or(HciAclPacketError::PacketTooSmall)?,
            buffer.try_front_pop().ok_or(HciAclPacketError::PacketTooSmall)?,
        ]) as usize;

        let remove_len = buffer
            .len()
            .checked_sub(data_length)
            .ok_or(HciAclPacketError::PacketTooSmall)?;

        // remove_len should have verified how many bytes are to be truncated from it
        buffer.try_remove(remove_len).ok().unwrap();

        Ok(HciAclData {
            connection_handle,
            packet_boundary_flag,
            broadcast_flag,
            payload: buffer,
        })
    }

    /// Convert into a raw packet
    ///
    /// This will convert `HciAclData` into a HCI ACL packet that can be sent between the host
    /// and controller.
    pub fn to_packet(&self) -> Vec<u8>
    where
        T: Deref<Target = [u8]>,
    {
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

#[cfg(feature = "l2cap")]
impl<T> From<HciAclData<T>> for bo_tie_l2cap::L2capFragment<T>
where
    T: Deref<Target = [u8]>,
{
    fn from(hci_acl_data: HciAclData<T>) -> Self {
        use bo_tie_l2cap::L2capFragment;

        match hci_acl_data.packet_boundary_flag {
            AclPacketBoundary::ContinuingFragment => L2capFragment::new(false, hci_acl_data.payload),
            _ => L2capFragment::new(true, hci_acl_data.payload),
        }
    }
}

impl<'a> HciAclData<&'a [u8]> {
    /// Attempt to create a `HciAclData`
    ///
    /// A `HciACLData` is created if the packet is in the correct HCI ACL data packet format. If
    /// not, then an error is returned.
    pub fn try_from_packet(packet: &'a [u8]) -> Result<Self, HciAclPacketError> {
        Self::try_from_buffer(packet)
    }
}

// The trait for a [`Host`] to communicate with the interface
///
/// This trait is used for communication by a host async task with an interface async task. It
/// provides access to the sender and receiver used by a `Host` and the buffer reserve for creating
/// an [`IntraMessage`](interface::IntraMessage) to send to an interface.
///
/// There are three types `HostInterface`s. These types are modeled to be flexible for various
/// kinds of platforms that would use the `bo-tie`. The *preferred*  implementation.
pub trait HostInterface {
    /// Buffer type for messages to the interface async task
    type ToBuffer: bo_tie_util::buffer::Buffer;

    /// Buffer type for messages from the interface async task
    type FromBuffer: bo_tie_util::buffer::Buffer;

    /// The type containing the channels ends used for communicating with the interface async task
    type ChannelEnds: ChannelEnds;

    /// Sender for messages to the interface
    type Sender: bo_tie_hci_util::Sender<Message = bo_tie_hci_util::ToIntraMessage<Self::ToBuffer>>;

    /// The receiver of messages from the interface
    type Receiver: bo_tie_hci_util::Receiver<
        Message = bo_tie_hci_util::FromIntraMessage<Self::FromBuffer, Self::ChannelEnds>,
    >;

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
    next_connection: Option<NextConnection<H::ChannelEnds>>,
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
    ///
    /// The host needs to be aware of the flow control information for the Controller in order to
    /// properly function. This will query the Controller for information about its buffers before
    /// returning a `Host`.
    ///
    /// # Error
    /// If this returns an error then the information about the buffers cannot be acquired.
    async fn init(host_interface: H) -> Result<Self, CommandError<H>> {
        use errors::Error;

        let mut host = Host {
            host_interface,
            next_connection: Default::default(),
            acl_max_mtu: Default::default(),
            sco_max_mtu: Default::default(),
            le_acl_max_mtu: Default::default(),
            le_iso_max_mtu: Default::default(),
        };

        let buffer_info = commands::info_params::read_buffer_size::send(&mut host).await?;

        host.acl_max_mtu = buffer_info.hc_acl_data_packet_len;

        host.sco_max_mtu = buffer_info.hc_synchronous_data_packet_len;

        let (le_acl_max_mtu, le_iso_max_mtu) = if cfg!(feature = "le") {
            match commands::le::read_buffer_size::send_v2(&mut host).await {
                Err(CCParameterError::CommandError(Error::UnknownHciCommand)) => {
                    if let Some(buffer_size_info_v1) = commands::le::read_buffer_size::send_v1(&mut host).await? {
                        let le_acl_max_mtu = buffer_size_info_v1.acl.len.into();

                        (le_acl_max_mtu, 0)
                    }
                }
                e @ Err(_) => e?,
                Ok(buffer_size_info_v2) => {
                    let le_acl_max_mtu = match buffer_size_info_v2.acl {
                        Some(bs) => bs.len.into(),
                        None => host.acl_max_mtu,
                    };

                    let le_iso_max_mtu = buffer_size_info_v2.iso.map(|bs| bs.len.into()).unwrap_or_default();

                    (le_acl_max_mtu, le_iso_max_mtu)
                }
            }
        } else {
            (0, 0)
        };

        host.le_acl_max_mtu = le_acl_max_mtu;

        host.le_iso_max_mtu = le_iso_max_mtu;

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
    async fn send_command<P, const CP_SIZE: usize>(
        &self,
        parameter: P,
        event_matcher: bo_tie_hci_util::CommandEventMatcher,
    ) -> Result<events::EventsData, CommandError<H>>
    where
        P: CommandParameter<CP_SIZE>,
    {
        use bo_tie_hci_util::{IntraMessageType, Receiver, Sender};

        let mut buffer = self.host_interface.take_buffer(None).await;

        parameter
            .as_command_packet(&mut buffer)
            .map_err(|e| CommandError::TryExtendBufferError(e))?;

        self.host_interface
            .get_sender()
            .send(IntraMessageType::Command(event_matcher, buffer).into())
            .await
            .map_err(|e| CommandError::SendError(e))?;

        self.get_next_event([events::Events::CommandComplete, events::Events::CommandStatus])

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

        let event_matcher = bo_tie_hci_util::CommandEventMatcher::new_command_complete(CP::COMMAND);

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

        let event_matcher = bo_tie_hci_util::CommandEventMatcher::new_command_status(CP::COMMAND);

        let command_return = self.send_command(parameter, event_matcher).await?;

        match command_return {
            EventsData::CommandStatus(data) => {
                if errors::Error::NoError == data.status {
                    Ok(data.number_of_hci_command_packets.into())
                } else {
                    Err(data.status.into())
                }
            }
            e => unreachable!("invalid event matched for command: {:?}", e),
        }
    }

    /// Get the next event from the Controller
    ///
    /// This awaits for the next event to be sent from the Controller
    ///
    /// # Event Lists
    ///
    /// ## `None`
    ///
    ///
    /// [`CommandComplete`]: bo_tie_hci_util::events::Events::CommandComplete
    /// [`CommandStatus`]: bo_tie_hci_util::events::Events::CommandStatus
    /// [`NumberOfCompletedPackets`]: bo_tie_hci_util::events::Events::NumberOfCompletedPackets
    pub async fn get_next_event(&mut self) -> Result<events::EventsData, NextEventError>
    {
        use bo_tie_hci_util::{IntraMessageType, Receiver};
        use bo_tie_hci_util::events::{EventsData, LeMetaData};
        use bo_tie_hci_util::events::parameters::LinkType;

        let mut connection_ends: Option<H::ChannelEnds> = None;

        loop {
            let intra_message = self
                .host_interface
                .get_receiver()
                .recv()
                .await
                .ok_or(NextEventError::ReceiverClosed)?;

            match intra_message {
                IntraMessageType::Event(EventsData::ConnectionComplete(cc)) => {
                    let connection_kind = match cc.link_type {
                        LinkType::AclConnection => ConnectionKind::BrEdrAcl,
                        _ => ConnectionKind::BrEdrSco,
                    };

                    self.set_next_connection(connection_ends.take().unwrap(), connection_kind, cc.connection_handle)
                }
                IntraMessageType::Event(EventsData::SynchronousConnectionComplete(scc)) => {
                    self.set_next_connection(connection_ends.take().unwrap(), ConnectionKind::BrEdrSco, scc.connection_handle)
                }
                IntraMessageType::Event(EventsData::LeMeta(LeMetaData::ConnectionComplete(lcc))) => {
                    self.set_next_connection(connection_ends.take().unwrap(), ConnectionKind::LeAcl, lcc.connection_handle)
                }
                IntraMessageType::Event(EventsData::LeMeta(LeMetaData::EnhancedConnectionComplete(lecc))) => {
                    self.set_next_connection(connection_ends.take().unwrap(), ConnectionKind::LeAcl, lecc.connection_handle)
                }
                IntraMessageType::Event(event_data) => {
                    if list.iter().find(|event_name| event_name == event_data.get_event_name()) {
                        break Ok(event_data)
                    }
                    // otherwise continue looping
                },
                IntraMessageType::Connection(connection) => connection_ends.replace(connection),
                _ => break Err(NextEventError::UnexpectedIntraMessage(intra_message.ty.kind()))
            }
        }
    }

    /// Filter the events sent from the controller
    ///
    /// This is a shortcut for filtering the events sent from the controller to just the events
    /// within `list`. The Controller will subsequently only send these events to the Host which can
    /// then be caught by method [`get_next_event`](Host::get_next_event).
    ///
    /// # Note
    /// This cannot filter out events that are [not maskable], but they are handled internally by
    /// `bo-tie`'s implementation of the HCI.
    ///
    /// [not maskable]: (crate::commands::cb::set_event_mask).
    pub async fn filter_events<L>(&mut self, list: L) -> Result<(), CommandError<H>>
    where
        L: EventsList,
    {
        use commands::cb::{set_event_mask, set_event_mask_page_2};
        use commands::le::set_event_mask as le_set_event_mask;

        // Set the masks
        //
        // note:
        // these mask functions short-circuit when the `list`
        // contain none of the events they mask.

        set_event_mask::send(self, list.iter()).await?;

        set_event_mask_page_2::send(self, list.iter()).await?;

        le_set_event_mask::send(self, list.iter()).await
    }

    /// Set the field `next_connection`
    fn set_next_connection(&mut self, ends: H::ChannelEnds, kind: ConnectionKind, handle: bo_tie_hci_util::ConnectionHandle) {
        self.next_connection = NextConnection {
            ends,
            kind,
            handle,
        }.into();
    }
}

/// Enum for kind of connection
enum ConnectionKind {
    BrEdrAcl,
    BrEdrSco,
    LeAcl,
}

/// Next Connection Information
struct NextConnection<T> {
    ends: T,
    kind: ConnectionKind,
    handle: bo_tie_hci_util::ConnectionHandle
}

/// An error when trying to send a command
pub enum CommandError<H>
where
    H: HostInterface,
{
    TryExtendBufferError(<H::ToBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error),
    CommandError(errors::Error),
    SendError(<H::Sender as bo_tie_hci_util::Sender>::Error),
    EventError(events::EventError),
    InvalidEventParameter,
    ReceiverClosed,
}

impl<H> core::fmt::Debug for CommandError<H>
where
    H: HostInterface,
    <H::ToBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error: core::fmt::Debug,
    <H::Sender as bo_tie_hci_util::Sender>::Error: core::fmt::Debug,
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
    <H::ToBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error: core::fmt::Display,
    <H::Sender as bo_tie_hci_util::Sender>::Error: core::fmt::Display,
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

impl<H: HostInterface> From<errors::Error> for CommandError<H> {
    fn from(e: errors::Error) -> Self {
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
    fn try_from(cc: &events::parameters::CommandCompleteData) -> Result<Self, CCParameterError>
    where
        Self: Sized;
}

impl TryFromCommandComplete for () {
    fn try_from(cc: &events::parameters::CommandCompleteData) -> Result<Self, CCParameterError> {
        check_status!(cc.return_parameter);

        Ok(Self)
    }
}

/// An error when converting the parameter of a Command Complete to a concrete type fails.
enum CCParameterError {
    CommandError(errors::Error),
    InvalidEventParameter,
}

/// Error for method [`get_next_event`](Host::get_next_event)
#[derive(Debug)]
pub enum NextEventError {
    ReceiverClosed,
    EventConversionError(events::EventError),
    UnexpectedIntraMessage(&'static str),
}

impl core::fmt::Display for NextEventError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NextEventError::ReceiverClosed => f.write_str("interface task is dropped"),
            NextEventError::EventConversionError(e) => core::fmt::Display::fmt(e, f),
            NextEventError::UnexpectedIntraMessage(kind) => write!(
                f,
                "Unexpected intra \
                message '{}' (this is a library bug)",
                kind
            ),
        }
    }
}

impl From<events::EventError> for NextEventError {
    fn from(e: events::EventError) -> Self {
        NextEventError::EventConversionError(e)
    }
}

/// A list of events
///
/// This is used by the method [`get_next_event_in`] for matching against a list of events.
pub trait EventsList {
    fn iter(&self) -> EventsIterator<'_, Self>
    where
        EventsIterator<'_, Self>: Iterator<Item = events::Events>;
}

struct EventsIterator<'a, E> {
    cnt: usize,
    events_list: &'a E,
}

macro_rules! impl_events_iterator_for_list {
    () => {
        type Item = events::Events;

        fn next(&mut self) -> Option<Self::Item> {
            let ret = self.events_list.get(self.cnt);

            self.cnt += 1;

            ret.copied()
        }
    };
}

macro_rules! impl_events_iterator_for_non_generic_ty {
    ($ty:ty) => {
        impl Iterator for EventsIterator<'_, $ty> {
            impl_events_iterator_for_list!()
        }
    }
}

macro_rules! impl_event_list_for_non_generic_type {
    ($ty:ty) => {
        impl EventsList for $ty {
            fn iter(&self) -> EventsIterator<'_, Self> {
                EventsIterator {
                    cnt: 0,
                    events_list: self,
                }
            }
        }

        impl_events_iterator_for_non_generic_ty!()
    };
}

impl_event_list_for_non_generic_type!(&[events::Events]);
impl_event_list_for_non_generic_type!(alloc::vec::Vec<events::Events>);
impl_event_list_for_non_generic_type!(alloc::boxed::Box<events::Events>);
impl_event_list_for_non_generic_type!(alloc::rc::Rc<events::Events>);
impl_event_list_for_non_generic_type!(alloc::collections::VecDeque);
impl_event_list_for_non_generic_type!(alloc::collections::BTreeSet);

impl Iterator for EventsIterator<'_, events::Events> {
    type Item = events::Events;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cnt == 0 {
            self.cnt += 1;
            Some(*self.events_list)
        } else {
            None
        }
    }
}

impl EventsList for events::Events {
    fn iter(&self) -> EventsIterator<'_, Self> where EventsIterator<'_, Self>: Iterator<Item=events::Events> {
        EventsIterator {
            cnt: 0,
            events_list: self,
        }
    }
}

impl<const SIZE: usize> Iterator for EventsIterator<'_, [events::Events; SIZE]> {
    impl_events_iterator_for_list!();
}

impl<const SIZE: usize> EventsList for [events::Events; SIZE] {
    fn iter(&self) -> EventsIterator<'_, Self>
    where
        EventsIterator<'_, Self>: Iterator<Item = events::Events>,
    {
        EventsIterator {
            cnt: 0,
            events_list: self,
        }
    }
}

impl<const SIZE: usize> Iterator for EventsIterator<'_, &[events::Events; SIZE]> {
    impl_events_iterator_for_list!();
}

impl<const SIZE: usize> EventsList for &[events::Events; SIZE] {
    fn iter(&self) -> EventsIterator<'_, Self>
        where
            EventsIterator<'_, Self>: Iterator<Item = events::Events>,
    {
        EventsIterator {
            cnt: 0,
            events_list: self,
        }
    }
}

/// An connection with ACL data
struct LeConnection<C: ChannelEnds> {
    max_mtu: usize,
    mtu: core::cell::Cell<usize>,
    channel_ends: C,
    sender: C::Sender,
}

impl<C: ChannelEnds> LeConnection<C> {
    /// Get the receiver
    pub fn get_receiver(&self) -> &C::Receiver {
        self.channel_ends.get_receiver()
    }

    /// Get the sender
    pub fn get_sender(&self) -> &C::Sender {
        &self.sender
    }

    /// Get the maximum size of an ACl payload
    ///
    /// This returns the maximum size the payload of a HCI ACL data packet can be. Higher layer
    /// protocols must fragment messages to this size.
    ///
    /// # Note
    /// This is the same as the maximum size for a payload of a HCI ACl data packet.
    pub fn get_max_mtu(&self) -> usize {
        self.max_mtu
    }

    /// Get the current maximum transmission size
    ///
    /// Get the currently set maximum transmission unit.
    pub fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    /// Set the current maximum transmission size
    ///
    /// Set the current maximum transmission unit.
    pub fn set_mtu(&mut self, to: usize) {
        self.mtu.set(to)
    }
}

#[cfg(feature = "l2cap")]
impl<C> bo_tie_l2cap::ConnectionChannel for LeConnection<C>
where
    C: ChannelEnds,
{
    type SendBuffer = C::ToBuffer;
    type SendFut<'a> = ConnectionChannelSender<'a, C> where Self: 'a;
    type SendFutErr = <C::Sender as bo_tie_hci_util::Sender>::Error;
    type RecvBuffer = C::FromBuffer;
    type RecvFut<'a> = AclReceiverMap<'a, C> where Self: 'a;

    fn send(&self, data: bo_tie_l2cap::BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
        // todo: not sure if this will be necessary when the type of input data is `BasicInfoFrame<Self::Buffer<'_>>`
        let front_capacity = HciAclData::<()>::HEADER_SIZE;

        let channel_ends = &self.channel_ends;

        let sender = &self.sender;

        let iter = SelfSendBufferIter {
            front_capacity,
            channel_ends,
            sender,
        };

        ConnectionChannelSender {
            sliced_future: data.into_fragments(self.get_mtu(), iter),
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
        use bo_tie_l2cap::MinimumMtu;

        bo_tie_l2cap::LeU::MIN_MTU
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
/// be de-referenced as a slice or extended to fill the buffer. It then can be converted into a
/// future to send the message to the interface async task.
#[cfg(feature = "l2cap")]
struct AclBufferBuilder<'a, C: ChannelEnds> {
    sender: &'a C::Sender,
    buffer: C::ToBuffer,
}

#[cfg(feature = "l2cap")]
impl<'a, C> bo_tie_util::buffer::TryExtend<u8> for AclBufferBuilder<'a, C>
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

#[cfg(feature = "l2cap")]
impl<'a, C> core::future::IntoFuture for AclBufferBuilder<'a, C>
where
    C: ChannelEnds,
{
    type Output = <<C::Sender as bo_tie_hci_util::Sender>::SendFuture<'a> as Future>::Output;
    type IntoFuture = <C::Sender as bo_tie_hci_util::Sender>::SendFuture<'a>;

    fn into_future(self) -> Self::IntoFuture {
        use bo_tie_hci_util::Sender;

        let message = bo_tie_hci_util::IntraMessageType::Acl(self.buffer).into();

        self.sender.send(message)
    }
}

/// Error for `TryExtend` implementation of `SelfSendBuffer`
#[cfg(feature = "l2cap")]
enum AclBufferError<T: bo_tie_util::buffer::TryExtend<u8>> {
    Buffer(T::Error),
    IncorrectIntraMessageType,
}

#[cfg(feature = "l2cap")]
impl<T: bo_tie_util::buffer::TryExtend<u8>> core::fmt::Debug for AclBufferError<T>
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

#[cfg(feature = "l2cap")]
impl<T: bo_tie_util::buffer::TryExtend<u8>> core::fmt::Display for AclBufferError<T>
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

#[cfg(feature = "l2cap")]
struct SelfSendBufferIter<'a, C: ChannelEnds> {
    front_capacity: usize,
    channel_ends: &'a C,
    sender: &'a C::Sender,
}

#[cfg(feature = "l2cap")]
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

#[cfg(feature = "l2cap")]
struct SelfSendBufferFutureMap<'a, C: ChannelEnds> {
    sender: &'a C::Sender,
    take_buffer: C::TakeBuffer,
}

#[cfg(feature = "l2cap")]
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

#[cfg(feature = "l2cap")]
struct ConnectionChannelSender<'a, C: ChannelEnds> {
    sliced_future: bo_tie_l2cap::send_future::AsSlicedPacketFuture<
        SelfSendBufferIter<'a, C>,
        Vec<u8>,
        SelfSendBufferFutureMap<'a, C>,
        AclBufferBuilder<'a, C>,
        <C::Sender as bo_tie_hci_util::Sender>::SendFuture<'a>,
    >,
}

#[cfg(feature = "l2cap")]
impl<'a, C> Future for ConnectionChannelSender<'a, C>
where
    C: ChannelEnds,
{
    type Output = Result<(), <C::Sender as bo_tie_hci_util::Sender>::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.map_unchecked_mut(|this| &mut this.sliced_future) }.poll(cx)
    }
}

#[cfg(feature = "l2cap")]
pub struct AclReceiverMap<'a, C: ChannelEnds> {
    receiver: &'a C::Receiver,
    receive_future: Option<<C::Receiver as bo_tie_hci_util::Receiver>::ReceiveFuture<'a>>,
}

#[cfg(feature = "l2cap")]
impl<'a, C> Future for AclReceiverMap<'a, C>
where
    C: ChannelEnds,
{
    type Output = Option<
        Result<
            bo_tie_l2cap::L2capFragment<C::FromBuffer>,
            bo_tie_l2cap::BasicFrameError<<C::FromBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>,
        >,
    >;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        use bo_tie_hci_util::Receiver;
        use bo_tie_l2cap::BasicFrameError;

        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.receive_future {
                None => this.receive_future = Some(this.receiver.recv()),
                Some(ref mut receiver) => match unsafe { Pin::new_unchecked(receiver) }.poll(cx) {
                    Poll::Pending => break Poll::Pending,
                    Poll::Ready(None) => break Poll::Ready(None),
                    Poll::Ready(Some(intra_message)) => match intra_message.ty {
                        bo_tie_hci_util::IntraMessageType::Acl(data) => match HciAclData::try_from_buffer(data) {
                            Ok(data) => {
                                let fragment = bo_tie_l2cap::L2capFragment::from(data);

                                break Poll::Ready(Some(Ok(fragment)));
                            }
                            Err(_) => {
                                break Poll::Ready(Some(Err(BasicFrameError::Other(
                                    "Received invalid HCI ACL Data packet",
                                ))))
                            }
                        },
                        bo_tie_hci_util::IntraMessageType::Sco(_) => {
                            break Poll::Ready(Some(Err(BasicFrameError::Other(
                                "synchronous connection data is not implemented",
                            ))))
                        }
                        bo_tie_hci_util::IntraMessageType::Iso(_) => {
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

/// The size of the array within [`EnabledEvents`]
const ENABLED_EVENT_BIT_MASK_SIZE: usize = (events::Events::full_depth() / <usize>::BITS as usize) + 1;

/// A list of enabled events
///
/// This contains a *record* of the events enabled to be sent from the Controller to the Host. An
/// `EnabledEvents` does not have the functionality to dynamically update itself whenever an event
/// is masked on the Controller. It can be converted into an iterator to retrieve the events that
/// were marked as enabled within this.
pub struct EnabledEvents([usize; ENABLED_EVENT_BIT_MASK_SIZE]);

impl EnabledEvents {
    fn new() -> Self {
        EnabledEvents(Default::default())
    }

    fn from_iter<I>(i: I) -> Self where I: IntoIterator<Item = events::Events> {
        let mut this = Self::new();

        i.into_iter().for_each(|e| this.set_mask(e));

        this
    }

    fn set_mask(&mut self, e: events::Events) {
        let depth = e.get_depth();

        let index = depth / <usize>::BITS as usize;

        let shr = depth % <usize>::BITS as usize;

        self.0[index] |= 1 << shr;
    }
}

impl IntoIterator for EnabledEvents {
    type Item = events::Events;
    type IntoIter = EnabledEventsIter;

    fn into_iter(self) -> Self::IntoIter {
        let position = 0;

        let mut array_iter = self.0.into_iter();

        let last = array_iter.next();

        EnabledEventsIter { position, last, array_iter }
    }
}

/// Iterator for [`EnabledEvents`]
pub struct EnabledEventsIter {
    position: usize,
    last: Option<usize>,
    array_iter: core::array::IntoIter<Self::Item, ENABLED_EVENT_BIT_MASK_SIZE>,
}

impl Iterator for EnabledEventsIter {
    type Item = events::Events;

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(val) = self.last {
            if self.position < <usize>::BITS as usize {
                let shr = self.position % <usize>::BITS as usize;

                let opt_event = (val & (1 << shr) != 0).then(|| events::Events::from_depth(self.position));

                self.position += 1;

                if let event @ Some(_) = opt_event {
                    return event
                }

            } else {
                self.last = self.array_iter.next();
                self.position - <usize>::BITS as usize;
            }
        }

        None
    }
}