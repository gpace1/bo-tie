//! The Host Interface to the Controller
//!
//! This is the implementation of the host of the Host Controller Interface. It's purpose is to
//! function and control the Bluetooth controller. The host is broken into to three parts
//!
//! ## Commands
//! Commands are located within the module [`commands`]. Commands are organized by modules in the
//! form of "bo_tie_hci_host::commands::*command_group*::*command*".
//!
//! [`commands`]: crate::commands

#![cfg_attr(feature = "unstable-type-alias-impl-trait", feature(type_alias_impl_trait))]
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
#[cfg(feature = "l2cap")]
pub mod l2cap;

use alloc::vec::Vec;
use bo_tie_hci_util::{events, ToHostCommandIntraMessage};
use bo_tie_hci_util::{opcodes, ToHostGeneralIntraMessage};
use bo_tie_hci_util::{HostChannelEnds, PacketBufferInformation};
use bo_tie_util::errors;
use core::ops::Deref;

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
        buffer.try_extend(Self::COMMAND.into_opcode().to_le_bytes())?;

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
/// be either ['FirstNonFlushable`] or [`ContinuingFragment`], but it cannot be
/// [`FirstAutoFlushable`] or [`CompleteL2capPdu`]. The broadcast flag must always be
/// [`NoBroadcast`]. Lastly the connection handle can only be a primary controller handle (which is
/// generated with a *LE Connection Complete* or *LE Enhanced Connection Complete* event for LE-U).
///
/// ['FirstNonFlushable`]: crate::AclPacketBoundary::FirstNonFlushable
/// [`ContinuingFragment`]: crate::AclPacketBoundary::ContinuingFragment
/// [`FirstAutoFlushable`]: crate::AclPacketBoundary::FirstAutoFlushable
/// [`CompleteL2capPdu`]: crate::AclPacketBoundary::CompleteL2capPdu
/// [`NoBroadcast`]: crate::AclBroadcastFlag::NoBroadcast
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

    pub fn get_mut_payload(&mut self) -> &mut T {
        &mut self.payload
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
    /// method [`to_packet`](HciAclData::to_packet).
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
            T: Deref<Target = [u8]>,
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

        impl<T> ExactSizeIterator for HciAclPacketIter<'_, T> where T: Deref<Target = [u8]> {}

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

    /// Create an HCI ACL data packet using the inner buffer
    ///
    /// This will convert this `HciAclData` type into the inner buffer. The buffer must have enough
    /// front capacity to contain the header information (four bytes) of a HCI ACL data packet.
    ///
    /// # Error
    /// The header for the HCI ACL packet could not be pushed to the front of the buffer
    pub fn into_inner_packet(mut self) -> Result<T, <T as bo_tie_util::buffer::TryFrontExtend<u8>>::Error>
    where
        T: bo_tie_util::buffer::Buffer,
    {
        let first_2_bytes = self.connection_handle.get_raw_handle()
            | self.packet_boundary_flag.get_shifted_val()
            | self.broadcast_flag.get_shifted_val();

        let length = self.payload.len() as u16;

        // front extensions must be done in reverse order by item

        self.payload.try_front_extend(length.to_le_bytes())?;

        self.payload.try_front_extend(first_2_bytes.to_le_bytes())?;

        Ok(self.payload)
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

/// The host interface
///
/// This is used by the host to interact with the Bluetooth Controller. Its purpose is to send
/// commands, receive events, and initialize connections between itself and the interface async
/// task.
pub struct Host<H: HostChannelEnds> {
    host_interface: H,
    acl_max_payload: usize,
    sco_max_payload: usize,
    le_acl_max_payload: usize,
    _le_iso_max_payload: usize,
    masked_events: MaskedEvents,
}

impl<H> Host<H>
where
    H: HostChannelEnds,
{
    /// Initialize the host
    ///
    /// This is generally called as part of the driver implementation.
    ///
    /// # Inputs
    /// `init` takes the channel ends used by the host and the `buffer_front_capacity` required by
    /// the driver. The channel ends are created from one of the channel implementations within the
    /// crate [`bo_tie_hci_util`]. The `buffer_front_capacity` is the front capacity of a buffer
    /// required for prepending driver and/or interface specific header information to a HCI packet
    /// (for example, UART would use a `buffer_front_capacity` equal to one as the packet indicator
    /// only requires one byte)
    ///
    /// # Operation
    /// The host needs to be aware of the flow control information for the Controller in order to
    /// properly function. This will query the Controller for information about its buffers before
    /// returning a `Host`.
    ///
    /// # Error
    /// An error is returned if the channel ends that were created with input host `ends` were
    /// dropped.
    pub async fn init(ends: H) -> Result<Self, CommandError<H>> {
        use bo_tie_hci_util::{Sender, ToInterfaceIntraMessage};

        let mut host = Host {
            host_interface: ends,
            acl_max_payload: Default::default(),
            sco_max_payload: Default::default(),
            le_acl_max_payload: Default::default(),
            _le_iso_max_payload: Default::default(),
            masked_events: Default::default(),
        };

        // reset the controller
        commands::cb::reset::send(&mut host).await?;

        let buffer_info = host.read_buffers().await?;

        let message = ToInterfaceIntraMessage::PacketBufferInfo(buffer_info);

        host.host_interface
            .get_sender()
            .send(message)
            .await
            .map_err(|e| CommandError::SendError(e))?;

        Ok(host)
    }

    /// Read the buffers of the Controller
    ///
    /// This is an exhaustive approach to reading all the different possible buffers that can be on
    /// the controller.
    async fn read_buffers(&mut self) -> Result<PacketBufferInformation, CommandError<H>> {
        use errors::Error;

        let mut packet_buffer_info = PacketBufferInformation::default();

        // get the main buffer info
        let buffer_info = commands::info_params::read_buffer_size::send(self).await?;

        self.acl_max_payload = buffer_info.acl_data_packet_len;

        self.sco_max_payload = buffer_info.synchronous_data_packet_len;

        packet_buffer_info
            .acl
            .set_max_data_size(buffer_info.acl_data_packet_len);
        packet_buffer_info
            .acl
            .set_number_of_packets(buffer_info.total_num_acl_data_packets);
        packet_buffer_info
            .sco
            .set_max_data_size(buffer_info.synchronous_data_packet_len);
        packet_buffer_info
            .sco
            .set_number_of_packets(buffer_info.total_num_acl_data_packets);

        // if LE is supported, get the LE info from the controller
        let (le_acl_max_mtu, le_iso_max_mtu) = match commands::le::read_buffer_size::send_v2(self).await {
            Err(CommandError::CommandError(Error::UnknownHciCommand)) => {
                if let Some(buffer_size_info_v1) = commands::le::read_buffer_size::send_v1(self).await? {
                    let le_acl_max_mtu = buffer_size_info_v1.acl.len.into();

                    packet_buffer_info
                        .le_acl
                        .set_max_data_size(buffer_size_info_v1.acl.len.into());

                    packet_buffer_info
                        .le_acl
                        .set_number_of_packets(buffer_size_info_v1.acl.cnt.into());

                    packet_buffer_info.le_iso.set_max_data_size(0);

                    packet_buffer_info.le_iso.set_number_of_packets(0);

                    (le_acl_max_mtu, 0)
                } else {
                    packet_buffer_info.le_acl.set_max_data_size(0);

                    packet_buffer_info.le_acl.set_number_of_packets(0);

                    packet_buffer_info.le_iso.set_max_data_size(0);

                    packet_buffer_info.le_iso.set_number_of_packets(0);

                    (0, 0)
                }
            }
            Ok(buffer_size_info_v2) => {
                let le_acl_max_mtu = match buffer_size_info_v2.acl {
                    Some(bs) => {
                        packet_buffer_info.le_acl.set_max_data_size(bs.len.into());

                        packet_buffer_info.le_acl.set_number_of_packets(bs.cnt.into());

                        bs.len.into()
                    }
                    None => {
                        packet_buffer_info.le_acl.set_max_data_size(0);

                        packet_buffer_info.le_acl.set_number_of_packets(0);

                        0
                    }
                };

                let le_iso_max_mtu = match buffer_size_info_v2.iso {
                    Some(bs) => {
                        packet_buffer_info.le_iso.set_max_data_size(bs.len.into());

                        packet_buffer_info.le_iso.set_number_of_packets(bs.cnt.into());

                        bs.len.into()
                    }
                    None => {
                        packet_buffer_info.le_iso.set_max_data_size(0);

                        packet_buffer_info.le_iso.set_number_of_packets(0);

                        0
                    }
                };

                (le_acl_max_mtu, le_iso_max_mtu)
            }
            Err(e) => return Err(e),
        };

        self.le_acl_max_payload = le_acl_max_mtu;

        self._le_iso_max_payload = le_iso_max_mtu;

        Ok(packet_buffer_info)
    }

    /// Send a command with the provided matcher to the interface async task
    ///
    /// Returns the event received from the interface async task containing the event sent in
    /// response to the command.
    async fn send_command<P, const CP_SIZE: usize>(
        &mut self,
        parameter: P,
    ) -> Result<ToHostCommandIntraMessage, CommandError<H>>
    where
        P: CommandParameter<CP_SIZE>,
    {
        use bo_tie_hci_util::{Receiver, Sender, ToInterfaceIntraMessage};

        let (front_capacity, back_capacity) = self.host_interface.driver_buffer_capacities();

        let mut buffer = self.host_interface.take_buffer(front_capacity, back_capacity).await;

        parameter
            .as_command_packet(&mut buffer)
            .map_err(|e| CommandError::TryExtendBufferError(e))?;

        self.host_interface
            .get_sender()
            .send(ToInterfaceIntraMessage::Command(buffer).into())
            .await
            .map_err(|e| CommandError::SendError(e))?;

        self.host_interface
            .get_mut_cmd_recv()
            .recv()
            .await
            .ok_or(CommandError::ReceiverClosed)
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
        match self.send_command(parameter).await? {
            ToHostCommandIntraMessage::CommandComplete(data) => Ok(T::try_from(&data)?),
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
    ) -> Result<(), CommandError<H>>
    where
        CP: CommandParameter<CP_SIZE> + 'static,
    {
        match self.send_command(parameter).await? {
            ToHostCommandIntraMessage::CommandStatus(data) => {
                if errors::Error::NoError == data.status {
                    Ok(())
                } else {
                    Err(data.status.into())
                }
            }
            e => unreachable!("invalid event matched for command: {:?}", e),
        }
    }

    /// Process the next general intra message
    ///
    /// Process the next thing sent from the interface async task over
    fn process_next(
        &mut self,
        message: <H::GenReceiver as bo_tie_hci_util::Receiver>::Message,
        ce: &mut Option<H::ConnectionChannelEnds>,
    ) -> Result<Option<Next<H::ConnectionChannelEnds>>, NextError> {
        use bo_tie_hci_util::events::{EventsData, LeMetaData};

        match message {
            ToHostGeneralIntraMessage::Event(EventsData::ConnectionComplete(cc)) => {
                let (head_cap, tail_cap) = self.host_interface.driver_buffer_capacities();

                let connection = Connection::new(
                    head_cap,
                    tail_cap,
                    self.acl_max_payload,
                    ConnectionKind::BrEdr(cc),
                    ce.take().ok_or(NextError::MissingConnectionEnds)?,
                );

                Ok(Some(Next::NewConnection(connection)))
            }
            ToHostGeneralIntraMessage::Event(EventsData::SynchronousConnectionComplete(scc)) => {
                let (head_cap, tail_cap) = self.host_interface.driver_buffer_capacities();

                let connection = Connection::new(
                    head_cap,
                    tail_cap,
                    self.sco_max_payload,
                    ConnectionKind::BrEdrSco(scc),
                    ce.take().ok_or(NextError::MissingConnectionEnds)?,
                );

                Ok(Some(Next::NewConnection(connection)))
            }
            ToHostGeneralIntraMessage::Event(EventsData::LeMeta(LeMetaData::ConnectionComplete(lcc))) => {
                let (head_cap, tail_cap) = self.host_interface.driver_buffer_capacities();

                let connection = Connection::new(
                    head_cap,
                    tail_cap,
                    self.le_acl_max_payload,
                    ConnectionKind::Le(lcc),
                    ce.take().ok_or(NextError::MissingConnectionEnds)?,
                );

                Ok(Some(Next::NewConnection(connection)))
            }
            ToHostGeneralIntraMessage::Event(EventsData::LeMeta(LeMetaData::EnhancedConnectionComplete(lecc))) => {
                let (head_cap, tail_cap) = self.host_interface.driver_buffer_capacities();

                let connection = Connection::new(
                    head_cap,
                    tail_cap,
                    self.le_acl_max_payload,
                    ConnectionKind::LeEnh(lecc),
                    ce.take().ok_or(NextError::MissingConnectionEnds)?,
                );

                Ok(Some(Next::NewConnection(connection)))
            }
            ToHostGeneralIntraMessage::Event(event_data) => Ok(Some(Next::Event(event_data))),
            ToHostGeneralIntraMessage::NewConnection(ends) => {
                ce.replace(ends);
                Ok(None)
            }
        }
    }

    /// Get the next thing from the interface async task
    ///
    /// Events and channel ends for a new connection async task are "received" from the controller
    /// through the `next` method.
    ///
    /// # Excluded Events
    /// The events [`CommandComplete`], [`CommandStatus`], [`NumberOfCompletedPackets`], and
    /// [`NumberOfCompletedDataBlocks`] are not be returned as they are handled internally
    /// by the host and interface async tasks.   
    ///
    /// [`CommandComplete`]: bo_tie_hci_util::events::Events::CommandComplete
    /// [`CommandStatus`]: bo_tie_hci_util::events::Events::CommandStatus
    /// [`NumberOfCompletedPackets`]: bo_tie_hci_util::events::Events::NumberOfCompletedPackets
    /// [`NumberOfCompletedDataBlocks`]: bo_tie_hci_util::events::Events::NumberOfCompletedDataBlocks
    pub async fn next(&mut self) -> Result<Next<H::ConnectionChannelEnds>, NextError> {
        use bo_tie_hci_util::Receiver;

        let mut connection_ends: Option<H::ConnectionChannelEnds> = None;

        loop {
            let intra_message = self
                .host_interface
                .get_mut_gen_recv()
                .recv()
                .await
                .ok_or(NextError::ReceiverClosed)?;

            if let Some(next) = self.process_next(intra_message, &mut connection_ends)? {
                break Ok(next);
            }
        }
    }

    /// Try to get the next thing from the interface async task
    ///
    /// This is `try` version of method [`next`]. If the interface async task has sent something to
    /// the host async task it will be returned, but if there is nothing within the channel then
    /// this method will return `None`. This method is still async as it will await for a second
    /// message if the first message in the channel is a connection ends message.
    ///
    /// [`next`]: Host::next
    pub async fn try_next(&mut self) -> Result<Option<Next<H::ConnectionChannelEnds>>, NextError> {
        use bo_tie_hci_util::Receiver;
        use core::future::Future;
        use core::pin::Pin;
        use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_stub, stub, stub, stub);

        fn clone_stub(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &VTABLE)
        }

        fn stub(_: *const ()) {}

        struct PollOnce<'a, R>(&'a mut R);

        impl<R> Future for PollOnce<'_, R>
        where
            R: Receiver,
        {
            type Output = Poll<Option<R::Message>>;

            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
                unsafe {
                    let rx = &mut self.get_unchecked_mut().0;

                    let waker = Waker::from_raw(clone_stub(core::ptr::null()));

                    Poll::Ready(rx.poll_recv(&mut Context::from_waker(&waker)))
                }
            }
        }

        let mut connection_ends: Option<H::ConnectionChannelEnds> = None;

        match PollOnce(self.host_interface.get_mut_gen_recv()).await {
            Poll::Ready(Some(message)) => match self.process_next(message, &mut connection_ends)? {
                Some(next) => Ok(Some(next)),
                None => {
                    // need to await the connection event information
                    self.next().await.map(|next| Some(next))
                }
            },
            Poll::Ready(None) => Err(NextError::ReceiverClosed),
            Poll::Pending => Ok(None),
        }
    }

    /// Mask the events sent from the Controller
    ///
    /// Events masked on the Controller are sent from the Controller to the Host. When this method
    /// is called it sets the masks for the events within `list`.
    ///
    /// This method is a shortcut for calling the `send` functions within [`set_event_mask`],
    /// [`set_event_mask_page_2`], and [`le::set_event_mask`].
    ///
    /// # Note
    /// This cannot filter out events that are [not maskable]. However they are handled internally
    /// by `bo-tie`'s implementation of the HCI, so they should never be seen when awaiting with
    /// awaiting with [`next_event`].
    ///
    /// [`set_event_mask`]: crate::commands::cb::set_event_mask
    /// [`set_event_mask_page_2`]: crate::commands::cb::set_event_mask_page_2
    /// [`le::set_event_mask`]: crate::commands::le::set_event_mask
    /// [not maskable]: crate::commands::cb::set_event_mask
    /// [`next_event`]: Host::next
    pub async fn mask_events<I, T>(&mut self, list: I) -> Result<(), CommandError<H>>
    where
        I: IntoIterator<Item = T> + Clone,
        T: core::borrow::Borrow<events::Events>,
    {
        use commands::cb::{set_event_mask, set_event_mask_page_2};
        use commands::le::set_event_mask as le_set_event_mask;

        let (send_page_1, send_page_2, send_le) = self.masked_events.set_events(list.clone());

        if send_page_1 {
            set_event_mask::send_command(self, list.clone()).await?;
        }

        if send_page_2 {
            set_event_mask_page_2::send_command(self, list.clone()).await?;
        }

        if send_le {
            le_set_event_mask::send_command(
                self,
                list.into_iter().filter_map(|e| match e.borrow() {
                    events::Events::LeMeta(meta) => Some(*meta),
                    _ => None,
                }),
            )
            .await?;
        }

        Ok(())
    }
}

/// The type returned by method [`next`] of `Host`
///
/// The next item from the interface async task is either an event or a new connection.
///
/// [`next`]: Host::next
#[derive(Debug)]
pub enum Next<C: bo_tie_hci_util::ConnectionChannelEnds> {
    Event(events::EventsData),
    NewConnection(Connection<C>),
}

/// A representation of a connection
///
/// On the HCI level, a `Connection` is nothing more than a container of the channel ends for the
/// connection async task along with some identifying information on what *kind* of connection was
/// made. To be useful to the higher layers of Bluetooth implemented by `bo-tie`, a `Connection`
/// needs to be converted into a structure that supports L2CAP.
///
/// # L2CAP Interface
/// A `Connection` is the bridge between the HCI and the upper protocol layers of Bluetooth. If this
/// library is compiled with the feature `l2cap` (which is part of the *default-features*) this type
/// can be converted into a type that implements [`ConnectionChannel`] of bo-tie-l2cap.
///
/// ### Flow Control
/// This provides the bridge between the HCI layer and the L2CAP layer. Data sent to the HCI
/// from the higher layers is flow controlled to fit the maximum HCI packet size supported by
/// the controller. This size depends on the data type used (ACL, SCO, or ISO), the connection
/// type (BR/EDR or LE), and the capabilities of the controller, but this information is already
/// discovered and implemented by the flow control.
///
/// ### Maximum Transmission Unit
/// The default maximum transmission unit is always initialized to the smallest it can be for the
/// given connection type (BR/EDR or LE). The MTU can then be adjusted by the higher layers to be
/// within the maximum and minimum bounds set by the implementation. The minimum bound is always
/// specification defined minimum value for the data/connection type. By default the maximum value
/// is set to `<u16>::MAX` as flow control is already implemented for data sent to the Controller.
/// However the method [`set_mtu_max_to_hci`] can be called before creating an `L2CAP` connection to
/// set the maximum MTU value to the maximum size of the HCI data packet.
///
/// [`ConnectionChannel`]: bo_tie_l2cap::ConnectionChannel
/// [`set_mtu_max_to_hci`]: Connection::set_mtu_max_to_hci
#[derive(Debug)]
pub struct Connection<C> {
    buffer_header_size: usize,
    buffer_tail_size: usize,
    hci_max: usize,
    bounded: bool,
    kind: ConnectionKind,
    ends: C,
}

impl<C: bo_tie_hci_util::ConnectionChannelEnds> Connection<C> {
    fn new(buffer_header_size: usize, buffer_tail_size: usize, hci_mtu: usize, kind: ConnectionKind, ends: C) -> Self {
        let bounded = false;

        Self {
            buffer_header_size,
            buffer_tail_size,
            hci_max: hci_mtu,
            bounded,
            kind,
            ends,
        }
    }

    /// Get the connection handle
    pub fn get_handle(&self) -> bo_tie_hci_util::ConnectionHandle {
        match &self.kind {
            ConnectionKind::BrEdr(c) => c.connection_handle,
            ConnectionKind::BrEdrSco(c) => c.connection_handle,
            ConnectionKind::Le(c) => c.connection_handle,
            ConnectionKind::LeEnh(c) => c.connection_handle,
        }
    }

    /// Get the kind of connection that was made
    ///
    /// A `ConnectionKind` contains the connection information sent by the controller.
    ///
    /// ### LE vs BR/EDR
    /// A `LeL2cap` can be constructed from a `Connection` by the method [`try_into_le`] when
    /// `ConnectionKind` is either [`Le`] or [`LeEnh`].
    ///
    /// [`Le`]: ConnectionKind::Le
    /// [`LeEnh`]: ConnectionKind::LeEnh
    pub fn get_kind(&self) -> ConnectionKind {
        self.kind.clone()
    }

    /// Bound the maximum MTU to the maximum size of the HCI data packet
    ///
    /// See [**Maximum Transmission Unit**].
    ///
    /// [**Maximum Transmission Unit**]: struct.Connections.html#Maximum-Transmission-Unit
    #[cfg(feature = "l2cap")]
    pub fn set_mtu_max_to_hci(&mut self) {
        self.bounded = true
    }

    /// Bound the maximum MTU to the maximum size of an L2CAP data packet
    ///
    /// See [**Maximum Transmission Unit**].
    ///
    /// # Note
    /// This is the default maximum MTU.
    ///
    /// [**Maximum Transmission Unit**]: struct.Connections.html#Maximum-Transmission-Unit
    #[cfg(feature = "l2cap")]
    pub fn set_mtu_max_to_l2cap(&mut self) {
        self.bounded = false
    }

    /// Try to create an `LeConnection`
    ///
    /// An `LeConnection` implements [`ConnectionChannel`] for a Bluetooth LE connection.
    ///
    /// [`ConnectionChannel`]: bo_tie_l2cap::ConnectionChannel
    #[cfg(feature = "l2cap")]
    pub fn try_into_le(self) -> Result<l2cap::LeL2cap<C>, Self> {
        match self.get_kind() {
            ConnectionKind::Le(_) | ConnectionKind::LeEnh(_) => {
                let max_mtu = if self.bounded { self.hci_max } else { <u16>::MAX.into() };
                let initial_mtu = <bo_tie_l2cap::LeU as bo_tie_l2cap::MinimumMtu>::MIN_MTU;

                let le = l2cap::LeL2cap::new(
                    self.get_handle(),
                    self.buffer_header_size,
                    self.buffer_tail_size,
                    max_mtu,
                    self.hci_max,
                    initial_mtu,
                    self.ends,
                );

                Ok(le)
            }
            _ => Err(self),
        }
    }

    /// Convert this into its inner channel ends
    ///
    /// This should be used whenever the upper Bluetooth protocols layers are implemented by another
    /// library. The method [`get_kind`] must still be used to get the 'kind' of connection that was
    /// created.
    ///
    /// [`get_kind`]: Connection::get_kind
    pub fn into_inner(self) -> C {
        self.ends
    }
}

/// Enum for kind of connection
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum ConnectionKind {
    BrEdr(events::parameters::ConnectionCompleteData),
    BrEdrSco(events::parameters::SynchronousConnectionCompleteData),
    Le(events::parameters::LeConnectionCompleteData),
    LeEnh(events::parameters::LeEnhancedConnectionCompleteData),
}

/// An error when trying to send a command
pub enum CommandError<H>
where
    H: HostChannelEnds,
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
    H: HostChannelEnds,
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
    H: HostChannelEnds,
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

impl<H: HostChannelEnds> From<events::EventError> for CommandError<H> {
    fn from(e: events::EventError) -> Self {
        CommandError::EventError(e)
    }
}

impl<H: HostChannelEnds> From<errors::Error> for CommandError<H> {
    fn from(e: errors::Error) -> Self {
        CommandError::CommandError(e)
    }
}

impl<H: HostChannelEnds> From<CCParameterError> for CommandError<H> {
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

        Ok(())
    }
}

/// An error when converting the parameter of a Command Complete to a concrete type fails.
enum CCParameterError {
    CommandError(errors::Error),
    InvalidEventParameter,
}

/// Error for method [`get_next_event`](Host::next)
#[derive(Debug)]
pub enum NextError {
    ReceiverClosed,
    EventConversionError(events::EventError),
    UnexpectedIntraMessage(&'static str),
    MissingConnectionEnds,
}

impl core::fmt::Display for NextError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            NextError::ReceiverClosed => f.write_str("interface task is dropped"),
            NextError::EventConversionError(e) => core::fmt::Display::fmt(e, f),
            NextError::UnexpectedIntraMessage(kind) => write!(
                f,
                "Unexpected intra \
                message '{}' (this is a library bug)",
                kind
            ),
            NextError::MissingConnectionEnds => f.write_str("interface did not send connection ends"),
        }
    }
}

impl From<events::EventError> for NextError {
    fn from(e: events::EventError) -> Self {
        NextError::EventConversionError(e)
    }
}

/// List of events masked by the user
///
/// A `Host` uses this to mirror the events that are masked on Controller. This contains the mask
/// of all events and a boolean for the LE Meta event.
///
/// # LE Meta
/// Because this library treats the LE events masks as part of the `Events` list, there needs to be
/// a separate flag for the mask to enable and disable all LE events.
#[derive(Default, Copy, Clone)]
struct MaskedEvents {
    mask: [u8; events::Events::full_depth() / 8 + 1],
    le_is_masked: bool,
}

impl MaskedEvents {
    /// Set the global mask for LE events
    fn set_le_mask(&mut self, to: bool) {
        self.le_is_masked = to;
    }

    fn set_event(&mut self, event: events::Events) {
        if let events::Events::LeMeta(_) = event {
            self.le_is_masked = true;
        }

        self.set(event.get_depth())
    }

    fn set(&mut self, pos: usize) {
        let index = pos / 8;
        let bit = pos % 8;

        self.mask[index] |= 1 << bit;
    }

    /// Update check
    ///
    /// This updates the list with input iterator of events and returns three booleans to indicate
    /// if page 1 of the event mask, page 2 of the event mask, and the LE event mask need to be
    /// updated on the controller.
    fn update_check(&mut self, old_mask: Self) -> (bool, bool, bool) {
        use commands::cb::{set_event_mask, set_event_mask_page_2};
        use commands::le::set_event_mask as le_set_event_mask;

        let mut page_1 = false;
        let mut page_2 = false;
        let mut le_page = false;
        let mut cnt = 0;

        while events::Events::full_depth() > cnt {
            let index = cnt / 8;
            let bit = cnt % 8;

            if self.mask[index] == old_mask.mask[index] {
                // skip bytes that are the same
                cnt += 8;
            } else if self.mask[index] & (1 << bit) == old_mask.mask[index] & (1 << bit) {
                // skip when the bits are the same
                cnt += 1;
            } else {
                // bits are different so check what is changed
                cnt += 1;

                let event = events::Events::from_depth(cnt);

                page_1 |= 0 != set_event_mask::event_to_mask_bit(&event);

                page_2 |= 0 != set_event_mask_page_2::event_to_mask_bit(&event);

                if let events::Events::LeMeta(le_meta) = event {
                    le_page |= 0 != le_set_event_mask::event_to_mask_bit(&le_meta);
                }
            }
        }

        (page_1, page_2, le_page)
    }

    /// Set all events
    ///
    /// This sets the events to the events within the input. The return is the output of
    /// `update_check`.
    fn set_events<I, E>(&mut self, iter: I) -> (bool, bool, bool)
    where
        I: IntoIterator<Item = E>,
        E: core::borrow::Borrow<events::Events>,
    {
        let old_mask = *self;

        *self = Default::default();

        iter.into_iter().for_each(|item| self.set_event(*item.borrow()));

        self.update_check(old_mask)
    }

    /// Clear the events
    ///
    /// This will clear the masks for the events in `clear_events` and set the internal `le_enabled`
    /// field to false if `le_meta` is true.
    #[inline]
    fn clear_events(&mut self, clear_events: &[events::Events], le_meta: bool) {
        let mut clear_mask = [0xFFu8; events::Events::full_depth() / 8 + 1];

        let mut cnt = 0;
        let len = clear_events.len();

        while len > cnt {
            let pos = clear_events[cnt].get_depth();
            let index = pos / 8;
            let bit = pos % 8;

            clear_mask[index] &= !(1 << bit);

            cnt += 1;
        }

        self.mask
            .iter_mut()
            .zip(clear_mask.iter())
            .for_each(|(mask_byte, clear_byte)| *mask_byte &= *clear_byte);

        if le_meta {
            self.le_is_masked = false;
        }
    }
}
