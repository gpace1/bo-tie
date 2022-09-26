//! The Host Interface to the Controller
//!
//! This is the implementation of the host of the Host Controller Interface. It's purpose is to
//! function and control the Bluetooth controller. The host is broken into to three parts  

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
use bo_tie_hci_util::ConnectionChannelEnds;
use bo_tie_hci_util::HostChannelEnds as HostInterface;
use bo_tie_hci_util::{events, ToHostCommandIntraMessage};
use bo_tie_hci_util::{opcodes, ToHostGeneralIntraMessage};
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

/// The host interface
///
/// This is used by the host to interact with the Bluetooth Controller. It is the host side of the
/// host controller interface.
pub struct Host<H: HostInterface> {
    host_interface: H,
    acl_max_mtu: usize,
    sco_max_mtu: usize,
    le_acl_max_mtu: usize,
    _le_iso_max_mtu: usize,
}

impl<H> Host<H>
where
    H: HostInterface,
{
    /// Initialize the host
    ///
    /// This resets the controller and then
    /// The host needs to be aware of the flow control information for the Controller in order to
    /// properly function. This will query the Controller for information about its buffers before
    /// returning a `Host`.
    ///
    /// # Error
    /// If this returns an error then the information about the buffers cannot be acquired.
    pub async fn init(ends: H) -> Result<Self, CommandError<H>> {
        let mut host = Host {
            host_interface: ends,
            acl_max_mtu: Default::default(),
            sco_max_mtu: Default::default(),
            le_acl_max_mtu: Default::default(),
            _le_iso_max_mtu: Default::default(),
        };

        // reset the controller
        commands::cb::reset::send(&mut host).await?;

        host.read_buffers().await?;

        Ok(host)
    }

    /// Read the buffers of the Controller
    ///
    /// This is an exhaustive approach to reading all the different possible buffers that can be on
    /// the controller.
    async fn read_buffers(&mut self) -> Result<(), CommandError<H>> {
        use errors::Error;

        // get the main buffer info
        let buffer_info = commands::info_params::read_buffer_size::send(self).await?;

        self.acl_max_mtu = buffer_info.hc_acl_data_packet_len;

        self.sco_max_mtu = buffer_info.hc_synchronous_data_packet_len;

        // if LE is supported, get the LE info from the controller
        let (le_acl_max_mtu, le_iso_max_mtu) = if cfg!(feature = "le") {
            match commands::le::read_buffer_size::send_v2(self).await {
                Err(CommandError::CommandError(Error::UnknownHciCommand)) => {
                    if let Some(buffer_size_info_v1) = commands::le::read_buffer_size::send_v1(self).await? {
                        let le_acl_max_mtu = buffer_size_info_v1.acl.len.into();

                        (le_acl_max_mtu, 0)
                    } else {
                        (0, 0)
                    }
                }
                Ok(buffer_size_info_v2) => {
                    let le_acl_max_mtu = match buffer_size_info_v2.acl {
                        Some(bs) => bs.len.into(),
                        None => self.acl_max_mtu,
                    };

                    let le_iso_max_mtu = buffer_size_info_v2.iso.map(|bs| bs.len.into()).unwrap_or_default();

                    (le_acl_max_mtu, le_iso_max_mtu)
                }
                e => return e.map(|_| ()),
            }
        } else {
            (0, 0)
        };

        self.le_acl_max_mtu = le_acl_max_mtu;

        self._le_iso_max_mtu = le_iso_max_mtu;

        Ok(())
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
        use bo_tie_hci_util::{FromHostIntraMessage, Receiver, Sender};

        let mut buffer = self.host_interface.take_buffer(None).await;

        parameter
            .as_command_packet(&mut buffer)
            .map_err(|e| CommandError::TryExtendBufferError(e))?;

        self.host_interface
            .get_sender()
            .send(FromHostIntraMessage::Command(buffer).into())
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
        use bo_tie_hci_util::events::{EventsData, LeMetaData};
        use bo_tie_hci_util::Receiver;

        let mut connection_ends: Option<H::ConnectionChannelEnds> = None;

        loop {
            let intra_message = self
                .host_interface
                .get_mut_gen_recv()
                .recv()
                .await
                .ok_or(NextError::ReceiverClosed)?;

            match intra_message {
                ToHostGeneralIntraMessage::Event(EventsData::ConnectionComplete(cc)) => {
                    let connection = Connection::new(
                        self.acl_max_mtu,
                        ConnectionKind::BrEdr(cc),
                        connection_ends.ok_or(NextError::MissingConnectionEnds)?,
                    );

                    break Ok(Next::NewConnection(connection));
                }
                ToHostGeneralIntraMessage::Event(EventsData::SynchronousConnectionComplete(scc)) => {
                    let connection = Connection::new(
                        self.sco_max_mtu,
                        ConnectionKind::BrEdrSco(scc),
                        connection_ends.ok_or(NextError::MissingConnectionEnds)?,
                    );

                    break Ok(Next::NewConnection(connection));
                }
                ToHostGeneralIntraMessage::Event(EventsData::LeMeta(LeMetaData::ConnectionComplete(lcc))) => {
                    let connection = Connection::new(
                        self.le_acl_max_mtu,
                        ConnectionKind::Le(lcc),
                        connection_ends.ok_or(NextError::MissingConnectionEnds)?,
                    );

                    break Ok(Next::NewConnection(connection));
                }
                ToHostGeneralIntraMessage::Event(EventsData::LeMeta(LeMetaData::EnhancedConnectionComplete(lecc))) => {
                    let connection = Connection::new(
                        self.le_acl_max_mtu,
                        ConnectionKind::LeEnh(lecc),
                        connection_ends.ok_or(NextError::MissingConnectionEnds)?,
                    );

                    break Ok(Next::NewConnection(connection));
                }
                ToHostGeneralIntraMessage::Event(event_data) => break Ok(Next::Event(event_data)),
                ToHostGeneralIntraMessage::NewConnection(ends) => {
                    connection_ends.replace(ends);
                }
            }
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

        // Set the masks
        //
        // note:
        // these mask functions will not send the any commands if none of the events within `list`
        // are masked by the command.

        set_event_mask::send(self, list.clone()).await?;

        set_event_mask_page_2::send(self, list.clone()).await?;

        le_set_event_mask::send(
            self,
            list.into_iter().filter_map(|e| match e.borrow() {
                events::Events::LeMeta(meta) => Some(*meta),
                _ => None,
            }),
        )
        .await
    }
}

/// The next item
///
/// The next item from the interface async task is either an event or a new connection.
#[derive(Debug)]
pub enum Next<C: ConnectionChannelEnds> {
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
    hci_mtu: usize,
    bounded: bool,
    kind: ConnectionKind,
    ends: C,
}

impl<C: ConnectionChannelEnds> Connection<C> {
    fn new(hci_mtu: usize, kind: ConnectionKind, ends: C) -> Self {
        let bounded = false;

        Self {
            hci_mtu,
            bounded,
            kind,
            ends,
        }
    }

    /// Get the kind of connection that was made
    ///
    /// There are multiple kinds of connections that can be made between two different controllers,
    /// but there are less types of connections then within `ConnectionKind`. ConnectionKind`
    /// contains the returned the event parameters that accompanied the connection event from the
    /// Controller.
    ///
    /// A `LeL2cap` can be constructed from a `Connection` when `ConnectionKind` is either [`Le`] or
    /// [`LeEnh`].
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
                let max_mtu = if self.bounded { self.hci_mtu } else { <u16>::MAX.into() };
                let initial_mtu = <bo_tie_l2cap::LeU as bo_tie_l2cap::MinimumMtu>::MIN_MTU;

                let le = l2cap::LeL2cap::new(max_mtu, initial_mtu, self.ends);

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
