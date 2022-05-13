//! The Host Controller Interface (HCI)
//!
//! The HCI is the primary way of interacting with the controller for this library.

#[macro_use]
pub mod common;
pub mod error;
pub mod opcodes;
#[macro_use]
pub mod events;
mod flow_ctrl;
pub mod interface;

use crate::l2cap::BasicInfoFrame;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

/// Try to rejuvenate a buffer
///
/// This is a trait for emptying a buffer and gives the buffer a capacity. This capacity could
/// be the same capacity as before, but it could also be a new capacity. However, the capacity of
/// the buffer does not change if the new capacity is less than the prior one.
///
/// # Note
/// All data previously in the buffer is dropped
#[doc(hidden)]
pub trait TryToRejuvenate {
    type Error;

    fn try_to_rejuvenate(&mut self, capacity: usize) -> Result<(), Self::Error>;
}

impl<T> TryToRejuvenate for Vec<T> {
    type Error = core::convert::Infallible;

    fn try_to_rejuvenate(&mut self, to: usize) -> Result<(), Self::Error> {
        self.clear();

        (self.capacity() < to)
            .then(self.reserve(to - self.capacity()))
            .ok_or(core::convert::Infallible)
    }
}

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
    fn as_command_packet<T>(&self, buffer: &mut T)
    where
        T: TryReserveTo + Extend<u8>,
    {
        use core::mem::size_of;

        let parameter_size = size_of::<Self::Parameter>();

        // Allocating a vector to the exact size of the packet. The 3 bytes come from the opcode
        // field (2 bytes) and the length field (1 byte)
        buffer.try_reserve_to(parameter_size + 3);

        let parameter = self.get_parameter();

        let p_bytes_p = &parameter as *const Self::Parameter as *const u8;

        let parm_bytes = unsafe { core::slice::from_raw_parts(p_bytes_p, parameter_size) };

        // Add opcode to packet
        buffer.extend(&Self::COMMAND.as_opcode_pair().as_opcode().to_le_bytes());

        // Add the length of the parameter
        buffer.extend(core::iter::once(parm_bytes.len() as u8));

        // Add the parameter
        buffer.extend(parm_bytes);
    }
}

/// A trait for matching received events
///
/// When receiving an event in a concurrent system, it can be unknown which context a received
/// event should be propagated to. The event must be matched to determine this.
pub trait EventMatcher: Sync + Send {
    /// Match the event data
    fn match_event(&self, event_data: &events::EventsData) -> bool;
}

impl<F> EventMatcher for F
where
    F: Fn(&events::EventsData) -> bool + Sized + Sync + Send,
{
    fn match_event(&self, event_data: &events::EventsData) -> bool {
        self(event_data)
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
pub struct HciACLData<'a> {
    connection_handle: common::ConnectionHandle,
    packet_boundary_flag: ACLPacketBoundary,
    broadcast_flag: ACLBroadcastFlag,
    /// This is always a L2CAP ACL packet
    payload: &'a [u8],
}

impl<'a> HciACLData<'a> {
    /// The size of the header of a HCI ACL data packet
    pub const HEADER_SIZE: usize = 4;

    /// It is required that the minimum maximum payload size of a HCI ACL data packet be 27 bytes.
    /// Both the host and controller must be able to accept a HCI ACL data packet with 27 bytes.
    /// Larger maximum payload sizes may be defined by either the host or controller.
    pub const MIN_MAX_PAYLOAD_SIZE: usize = 27;

    /// Create a new HciACLData
    ///
    /// # Panic
    /// The payload length must not be larger than the maximum u16 number
    pub fn new(
        connection_handle: common::ConnectionHandle,
        packet_boundary_flag: ACLPacketBoundary,
        broadcast_flag: ACLBroadcastFlag,
        payload: &'a [u8],
    ) -> Self {
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

    pub fn get_payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn get_packet_boundary_flag(&self) -> ACLPacketBoundary {
        self.packet_boundary_flag
    }

    pub fn get_broadcast_flag(&self) -> ACLBroadcastFlag {
        self.broadcast_flag
    }

    /// Convert the `HciACLData` into a raw packet
    ///
    /// This will convert HciACLDataOwned into a packet of bytes that can be sent between the host
    /// and controller.
    pub fn get_packet(&self) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::with_capacity(self.payload.len() + 4);

        let first_2_bytes = self.connection_handle.get_raw_handle()
            | self.packet_boundary_flag.get_shifted_val()
            | self.broadcast_flag.get_shifted_val();

        v.extend_from_slice(&first_2_bytes.to_le_bytes());

        v.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());

        v.extend_from_slice(&self.payload);

        v
    }

    /// Convert the `HciACLData` into a packet iterator
    ///
    /// The return is an iterator over the bytes send over the interface between the host and
    /// controller.
    ///
    /// # Note
    /// Collecting the returned iterator into a `Vec` produces the same thing as the return of
    /// [`get_packet`](HciAclData)
    pub fn get_packet_iter(&self) -> impl Iterator<Item = u8> + ExactSizeIterator {
        struct HciAclPacketIter<'a> {
            state: Option<usize>,
            raw_handle_and_flags: u16,
            total_data_length: u16,
            payload: &'a [u8],
        }

        impl<'a> HciAclPacketIter<'a> {
            fn new(data: &'a HciAclData) -> Self {
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

        impl Iterator for HciAclPacketIter<'_> {
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

        impl ExactSizeIterator for HciAclPacketIter<'_> {}
    }

    /// Attempt to create a `HciAclData`
    ///
    /// A `HciACLData` is created if the packet is in the correct HCI ACL data packet format. If
    /// not, then an error is returned.
    pub fn try_from_packet(packet: &[u8]) -> Result<Self, HciACLPacketError> {
        const HEADER_SIZE: usize = 4;

        if packet.len() >= HEADER_SIZE {
            let first_2_bytes = <u16>::from_le_bytes([packet[0], packet[1]]);

            let connection_handle = match common::ConnectionHandle::try_from(first_2_bytes & 0xFFF) {
                Ok(handle) => handle,
                Err(e) => return Err(HciACLPacketError::InvalidConnectionHandle(e)),
            };

            let packet_boundary_flag = ACLPacketBoundary::from_shifted_val(first_2_bytes);

            let broadcast_flag = match ACLBroadcastFlag::try_from_shifted_val(first_2_bytes) {
                Ok(flag) => flag,
                Err(_) => return Err(HciACLPacketError::InvalidBroadcastFlag),
            };

            let data_length = <u16>::from_le_bytes([packet[2], packet[3]]) as usize;

            Ok(HciACLData {
                connection_handle,
                packet_boundary_flag,
                broadcast_flag,
                payload: &packet[HEADER_SIZE..(HEADER_SIZE + data_length)],
            })
        } else {
            Err(HciACLPacketError::PacketTooSmall)
        }
    }

    /// Convert into a
    /// [`ACLDataFragment`](crate::l2cap::ACLDataFragment)
    pub fn into_acl_fragment(self) -> crate::l2cap::BasicFrameFragment<'a> {
        use crate::l2cap::BasicFrameFragment;

        match self.packet_boundary_flag {
            ACLPacketBoundary::ContinuingFragment => BasicFrameFragment::new(false, self.payload),
            _ => BasicFrameFragment::new(true, self.payload),
        }
    }
}

impl bo_tie_serde::HintedSerialize for HciACLData<'_> {
    fn hinted_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: bo_tie_serde::HintedSerializer,
        S::SerializeSeq: bo_tie_serde::SerializerHint,
        S::SerializeTuple: bo_tie_serde::SerializerHint,
        S::SerializeTupleStruct: bo_tie_serde::SerializerHint,
        S::SerializeTupleVariant: bo_tie_serde::SerializerHint,
        S::SerializeMap: bo_tie_serde::SerializerHint,
        S::SerializeStruct: bo_tie_serde::SerializerHint,
        S::SerializeStructVariant: bo_tie_serde::SerializerHint,
    {
        use core::convert::TryFrom;
        use serde::ser::{Error, SerializeStruct};

        let mut ser_struct = serializer.hinted_serialize_struct("HCI ACL Data Packet", 3)?;

        let first_2_bytes = self.connection_handle.get_raw_handle()
            | self.packet_boundary_flag.get_shifted_val()
            | self.broadcast_flag.get_shifted_val();

        ser_struct.serialize_field("handle and flags", &first_2_bytes)?;

        let len: u16 = TryFrom::try_from(self.payload.len()).or(Err(S::Error::custom(format_args!(
            "Length of HCI ACL data packet payload is larger than {}",
            u16::MAX
        ))))?;

        ser_struct.serialize_field("data length", &len)?;

        ser_struct.set_skip_len_hint();

        ser_struct.serialize_field("data", &self.payload)?;

        ser_struct.end()
    }
}

impl<'de> bo_tie_serde::HintedDeserialize<'de> for HciACLData<'de> {
    fn hinted_deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: bo_tie_serde::HintedDeserializer<'de> + bo_tie_serde::DeserializerHint,
    {
        enum Field {
            HandleAndFlags,
            DataLength,
            Data,
        }

        impl<'de> serde::de::Deserialize<'de> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct FieldVisitor;

                impl<'de> serde::de::Visitor<'de> for FieldVisitor {
                    type Value = Field;

                    fn expecting(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                        write!(formatter, "A string identifier")
                    }

                    fn visit_str<E>(self, value: &str) -> Result<Field, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            "handle and flags" => Ok(Field::HandleAndFlags),
                            "data length" => Ok(Field::DataLength),
                            "data" => Ok(Field::Data),
                            _ => Err(E::unknown_field(value, &["handle and flags", "data length", "data"])),
                        }
                    }
                }

                deserializer.deserialize_identifier(FieldVisitor)
            }
        }

        struct Visitor;

        impl Visitor {
            fn try_split_handle_and_flags<E>(
                &self,
                handle_and_flags: u16,
            ) -> Result<(common::ConnectionHandle, ACLPacketBoundary, ACLBroadcastFlag), E>
            where
                E: serde::de::Error,
            {
                let connection_handle = common::ConnectionHandle::try_from(handle_and_flags & 0xFFF)
                    .map_err(|e| serde::de::Error::custom(format_args!("invalid connection handle {}", e)))?;

                let packet_boundary_flag = ACLPacketBoundary::from_shifted_val(handle_and_flags);

                let broadcast_flag = ACLBroadcastFlag::try_from_shifted_val(handle_and_flags)
                    .map_err(|_| serde::de::Error::custom("invalid broadcast flag"))?;

                Ok((connection_handle, packet_boundary_flag, broadcast_flag))
            }
        }

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = HciACLData<'de>;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("struct HciACLData")
            }
        }

        impl<'de> bo_tie_serde::HintedVisitor<'de> for Visitor {
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: bo_tie_serde::DeserializerHint + serde::de::SeqAccess<'de>,
            {
                let handle_and_flags: u16 = seq.next_element()?.ok_or(serde::de::Error::invalid_length(0, &self))?;

                let data_len: u16 = seq.next_element()?.ok_or(serde::de::Error::invalid_length(1, &self))?;

                seq.hint_next_len(data_len.into());

                let payload: &[u8] = seq.next_element()?.ok_or(serde::de::Error::invalid_length(2, &self))?;

                let (connection_handle, packet_boundary_flag, broadcast_flag) =
                    self.try_split_handle_and_flags(handle_and_flags)?;

                Ok(HciACLData {
                    connection_handle,
                    packet_boundary_flag,
                    broadcast_flag,
                    payload,
                })
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: bo_tie_serde::DeserializerHint + serde::de::MapAccess<'de>,
            {
                let mut handle_and_flags: Option<u16> = None;
                let mut data_len: Option<u16> = None;
                let mut data: Option<&[u8]> = None;

                while let Some(field) = map.next_key()? {
                    match field {
                        Field::HandleAndFlags => handle_and_flags = Some(map.next_value()?),
                        Field::DataLength => data_len = Some(map.next_value()?),
                        Field::Data => {
                            let len = data_len.ok_or(serde::de::Error::missing_field("data length"))?;

                            map.hint_next_len(len.into());

                            data = Some(map.next_value()?);
                        }
                    }
                }

                let (connection_handle, packet_boundary_flag, broadcast_flag) = self.try_split_handle_and_flags(
                    handle_and_flags.ok_or(serde::de::Error::missing_field("handle and flags"))?,
                )?;

                let payload = data.ok_or(serde::de::Error::missing_field("data"))?;

                Ok(HciACLData {
                    connection_handle,
                    packet_boundary_flag,
                    broadcast_flag,
                    payload,
                })
            }
        }

        deserializer.deserialize_struct("HciACLData", &["handle and flags", "data length", "data"], Visitor)
    }
}

struct EventReturnFuture<'a, I, P>
where
    I: PlatformInterface,
    P: EventMatcher + Sync + Send + 'static,
{
    interface: &'a I,
    event: Option<events::Events>,
    matcher: Pin<Arc<P>>,
}

impl<'a, I, P> Future for EventReturnFuture<'a, I, P>
where
    I: PlatformInterface,
    P: EventMatcher + Send + Sync + 'static,
{
    type Output = Result<events::EventsData, I::ReceiveEventError>;

    fn poll(self: Pin<&mut Self>, cx: &mut core::task::Context) -> Poll<Self::Output> {
        match self
            .interface
            .receive_event(self.event, cx.waker(), self.matcher.clone())
        {
            Some(event_response) => Poll::Ready(event_response),
            None => Poll::Pending,
        }
    }
}

/// A reserve of buffers
///
/// A reserve is for storing previously used buffers for usage later. The main purpose is for both
/// reducing dynamic allocations of memory and the amount of times data is copied as its passed
/// between the interface async task and another HCI async task. Buffers are taken and reclaimed
/// by a reserve. Taking removes a buffer from the reserve and reclaiming adds a buffer to the
/// reserve.
#[doc(hidden)]
pub trait BufferReserve {
    type Buffer: core::ops::DerefMut<Target = [u8]>;
    type TakeBuffer: Future<Output = Self::Buffer>;

    /// Take a buffer from the reserve
    ///
    /// If there is no more buffers within the reserve the returned future will await. However, it
    /// is intended that there be enough buffers in the reserve so that most of the time this does
    /// not await.
    fn take(&mut self) -> Self::TakeBuffer;

    /// Reclaim an unused buffer
    ///
    /// Buffers can be reclaimed for reuse later. However, if the reserve is full then the buffer to
    /// be reclaimed is dropped.
    fn reclaim(&mut self, buffer: Self::Buffer);
}

/// A reserve of `Vec` buffers
///
/// ## Reclaiming Buffers
/// Buffers are reclaimed up to the capacity limit of the reserve. After that buffers are dropped
/// instead of reused.
struct VecBufferReserve(Vec<Vec<u8>>);

impl VecBufferReserve {
    fn new(capacity: usize) -> Self {
        Self(Vec::with_capacity(capacity))
    }
}

impl BufferReserve for VecBufferReserve {
    type Buffer = Vec<u8>;
    type TakeBuffer = TakeVecReserveFuture;

    fn take(&mut self) -> Self::TakeBuffer {
        if let Some(buffer) = self.pop() {
            TakeVecReserveFuture(buffer)
        } else {
            TakeVecReserveFuture(Vec::new())
        }
    }

    fn reclaim(&mut self, buffer: Self::Buffer) {
        if self.0.capacity() != self.0.len() {
            self.buffers.push(buffer);
        }
    }
}

/// A future for taking buffers from a `VecBufferReserve`
struct TakeVecReserveFuture(Vec<u8>);

impl Future for TakeVecReserveFuture {
    type Output = Vec<u8>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(core::mem::replace(&mut self.get_mut().0, Vec::new()))
    }
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

    /// Match an event packet
    ///
    /// This is used to match event packets received from the controller to the event expected in
    /// response to a previously sent command.
    fn match_packet(&self, event_packet: &[u8]) -> bool {
        use core::convert::TryFrom;
        use events::{Events, EventsData};

        let raw_opcode = match event_packet
            .get(0)
            .and_then(|event_code| Events::try_from_event_codes(*event_code, 0 /* irrelevant */).ok())
            .and_then(|event| (self.event == event).then(|| ()))
            .and_then(|_| (self.get_op_code)(event_packet))
        {
            Some(raw_opcode) => raw_opcode,
            None => return false,
        };

        let opc_pair = opcodes::OpCodePair::from_opcode(raw_opcode);

        match opcodes::HCICommand::try_from(opc_pair) {
            Ok(code) => self.expected_opcode == code,
            Err(reason) => {
                log::error!("{}", reason);
                false
            }
        }
    }
}

/// Generics used as part of a `HostInterface`
///
/// The generics within a `HostInterface` are not implementable by the user, so to simplify usage of
/// the `HostInterface`, the generics are wrapped up within this trait.
pub trait HostGenerics {
    type Buffer: core::ops::DerefMut<Target = [u8]>;
    type Sender: interface::Sender<Message = interface::IntraMessage<Self::Buffer>>;
    type Receiver: interface::Receiver<Message = interface::IntraMessage<Self::Buffer>>;
    type Reserve: BufferReserve<Buffer = Self::Buffer>;
}

/// The host interface
///
/// This is used by the host to interact with the Bluetooth Controller. It is the host side of the
/// host controller interface.
///
/// # Feature *flow-ctrl*
/// The default implementation of `HostInterface` provides no flow control for HCI data sent from
/// the host to the controller. HCI data packets that are too large or too many packets within too
/// short of time frame can be sent. It is up to the user of a HostInterface to be sure that the
/// HCI data packets sent to the controller are not too big or overflow the buffers.
///
/// Building this library with the "flow-ctrl" feature adds a flow controller to a `HostInterface`.
/// This flow controller monitors the *Number of Completed Packets Event* sent from the controller
/// and allows packets to be sent to the controller so long as there is space in the controllers
/// buffers. Every [`ConnectionChannel`](crate::l2cap::ConnectionChannel) made from a
/// `HostInterface` will be regulated by the flow controller when sending data to the controller.
///
/// A flow controller is not built with a HostInterface by default since there are a few issues with
/// having it. First is that a flow controller must be initialized. Without a flow controller a
/// `HostInterface` can be created with either `default()` or `from(your_interface)`, but with it
/// the only way to create a `HostInterface` is with the `initialize()` async method. The flow
/// controller's initialization process is to query the controller for the HCI send buffer
/// information, to get both the maximum HCI data packet size and number of HCI data packets the
/// size of the buffer. The next issue is that the *Number of Completed Packets Event* cannot be
/// awaited upon. The flow-controller must be the only user of this event. Lastly the 'raw'
/// `ConnectionChannel` implementations are not available, you are forced to use the flow
/// controller when creating a `ConnectionChannel`.
///
/// The main reason why feature *flow-ctrl* is not a part of the default features list is that for
/// most use cases a flow controller is unnecessary. It should really only be needed for when
/// numerous connections are made or for some reason the buffer information is unknown. Most of the
/// time the raw connections will suffice with the MTU value set to the maximum packet size of the
/// HCI receive data buffer on the controller.
pub struct HostInterface<H: HostGenerics> {
    interface_sender: H::Sender,
    interface_receiver: H::Receiver,
    buffer_reserve: H::Reserve,
}

impl<H> HostInterface<H>
where
    H: HostGenerics,
{
    /// Send a command with the provided matcher to the interface async task
    ///
    /// Returns the intra message received from the interface async task (hopefully) containing the
    /// expected controller response to the sent command.
    ///
    /// # Note
    /// This method is intended to only be used internally
    #[doc(hidden)]
    async fn send_command<CP, const CP_SIZE: usize>(
        &mut self,
        parameter: CP,
        event_matcher: CommandEventMatcher,
    ) -> Result<interface::IntraMessage<T>, CommandError<H>>
    where
        CP: CommandParameter<CP_SIZE> + 'static,
    {
        use interface::IntraMessageType;

        let mut packet = self.buffer_reserve.take().await;

        parameter.as_command_packet(self.buffer_reserve.take().await, &mut packet);

        self.interface_sender
            .send(IntraMessageType::Command(event_matcher, packet).into())
            .await?;

        self.interface_receiver.recv().await.ok_or(CommandError::ReceiverClosed)
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
        CP: CommandParameter<CP_SIZE> + 'static,
        T: TryFromCommandComplete,
    {
        use core::convert::TryFrom;
        use events::EventsData;
        use interface::IntraMessageType;

        let event_matcher = CommandEventMatcher::new_command_complete(CP::COMMAND);

        let intra_message = self.send_command(parameter, event_matcher)?;

        match intra_message.ty {
            IntraMessageType::Event(data) => match EventsData::try_from_packet(&data)? {
                EventsData::CommandComplete(data) => Ok(T::try_from(&data)),
                e => unreachable!("invalid event matched for command: {:?}", e),
            },
            _ => unreachable!("host task expected event intra message"),
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
        use core::convert::TryFrom;
        use events::EventsData;
        use interface::IntraMessageType;

        let event_matcher = CommandEventMatcher::new_command_status(CP::COMMAND);

        let intra_message = self.send_command(parameter, event_matcher)?;

        match intra_message.ty {
            IntraMessageType::Event(data) => match EventsData::try_from_packet(&data)? {
                EventsData::CommandStatus(data) => {
                    if error::Error::NoError == data.status {
                        Ok(data.number_of_hci_command_packets.into())
                    } else {
                        Err(data.status.into())
                    }
                }
                e => unreachable!("invalid event matched for command: {:?}", e),
            },
            _ => unreachable!("host task expected event intra message"),
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
    pub async fn wait_for_event<E>(&self, event: E) -> Result<(), R::Error>
    where
        E: Into<Option<events::Events>>,
    {
        fn default_matcher(_: &events::EventsData) -> bool {
            true
        }

        fn most_matcher(e: &events::EventsData) -> bool {
            e.get_event_name().is_maskable()
        }

        let opt_event: Option<events::Events> = event.into();

        let matcher = if opt_event.is_none() {
            most_matcher
        } else {
            default_matcher
        };

        EventReturnFuture {
            interface: &self.interface,
            event: opt_event,
            matcher: Arc::pin(matcher),
        }
    }

    /// Get a future for a *more* specific Bluetooth Event
    ///
    /// This is the same as the function
    /// [`wait_for_event`](crate::hci::HostInterface::wait_for_event)
    /// except an additional matcher is used to filter same events based on the data sent with the
    /// event. See
    /// [`EventMatcher`](crate::hci::EventMatcher)
    /// for information on implementing a matcher, but you can use a closure that borrows
    /// [`EventsData`](crate::hci::events::EventsData)
    /// as an input and returns a `bool` as a matcher.
    ///
    /// # Limitations
    /// While this can be used to further specify what event data gets returned by a future, its
    /// really just further filters the event data. The same exact undefined behaviour mentioned in
    /// the `Limitations` section of
    /// [`wait_for_event`](crate::hci::HostInterface::wait_for_event)
    /// will occur when the return of `wait_for_event_with_matcher` is awaited concurrently
    /// with matchers that return `true` given the same
    /// [`EventData`](crate::hci::events::EventsData) (the conditions for undefined behaviour
    /// for `wait_for_event` still apply).
    pub fn wait_for_event_with_matcher<'a, P>(
        &'a self,
        event: events::Events,
        matcher: P,
    ) -> impl Future<Output = Result<events::EventsData, <I as PlatformInterface>::ReceiveEventError>> + 'a
    where
        P: EventMatcher + Send + Sync + 'static,
    {
        EventReturnFuture {
            interface: &self.interface,
            event: event.into(),
            matcher: Arc::pin(matcher),
        }
    }
}

/// An error when trying to send a command
pub enum CommandError<H>
where
    H: HostGenerics,
{
    CommandError(error::Error),
    SendError(<H::Sender as interface::Sender>::Error),
    EventError(events::EventError),
    InvalidEventParameter,
    ReceiverClosed,
}

impl<H> core::fmt::Debug for CommandError<H>
where
    H: HostGenerics,
    <H::Sender as interface::Sender>::Error: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
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
    H: HostGenerics,
    <H::Sender as interface::Sender>::Error: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CommandError::CommandError(e) => core::fmt::Display::fmt(e, f),
            CommandError::SendError(e) => core::fmt::Display::fmt(e, f),
            CommandError::EventError(e) => core::fmt::Display::fmt(e, f),
            CommandError::InvalidEventParameter => f.write_str("command complete event contained an invalid parameter"),
            CommandError::ReceiverClosed => f.write_str("interface is not running"),
        }
    }
}

impl<S> From<events::EventError> for CommandError<S> {
    fn from(e: events::EventError) -> Self {
        CommandError::EventError(e)
    }
}

impl<S> From<error::Error> for CommandError<S> {
    fn from(e: error::Error) -> Self {
        CommandError::CommandError(e)
    }
}

impl<S> From<CCParameterError> for CommandError<S> {
    fn from(e: CCParameterError) -> Self {
        match e {
            CCParameterError::CommandError(e) => CommandError::CommandError(e),
            CCParameterError::InvalidEventParameter => CommandError::InvalidEventParameter,
        }
    }
}

/// A trait for converting from a Command Complete Event
trait TryFromCommandComplete {
    fn try_from(cc: &events::CommandCompleteData) -> Result<Self, CCParameterError>;
}

/// An error when converting the parameter of a Command Complete to a concrete type fails.
enum CCParameterError {
    CommandError(error::Error),
    InvalidEventParameter,
}

macro_rules! check_status {
    ($raw_data:expr) => {
        error::Error::from(*cc.raw_data.get(0).ok_or(CCParameterError::InvalidEventParameter)?)
            .ok_or_else(CCParameterError::InvalidEventParameter)?;
    };
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

#[cfg(feature = "flow-ctrl")]
#[cfg_attr(docsrs, doc(cfg(feature = "flow-ctrl")))]
impl<I, M> HostInterface<I, M>
where
    I: HciACLDataInterface + PlatformInterface + Send + Sync + Unpin + 'static,
    M: for<'a> AsyncLock<'a> + 'static,
{
    /// Create a new HostInterface
    pub async fn new() -> Arc<Self>
    where
        I: Default,
        M: Default,
    {
        let mut hci = HostInterface {
            interface: Default::default(),
            flow_controller: Default::default(),
        };

        flow_ctrl::flow_manager::HciDataPacketFlowManager::initialize(&mut hci).await;

        Arc::new(hci)
    }

    /// Create a connection channel with a flow controller
    ///
    /// This connection channel is flow controlled when sending HCI data to the controller. Unlike a
    /// raw channel this will make sure that the controller cannot be sent HCI ACL data that is
    /// either too large or too many within a time frame for the controller. Data that is larger
    /// than the maximum packet size will be fragmented into multiple packets and when there is no
    /// room in the controller's buffer the sending future will pend.
    ///
    /// # MTU
    /// The `max_mtu` input is the maximum value the logical link's MTU can be changed to over the
    /// lifetime of the connection channel. When this is initialized, the used MTU value is
    /// defaulted to the minimum possible MTU for LE-U, but if it changed it can only be changed to
    /// a value no greater than `max_mtu`. If `max_mtu` is `None` it defaults to the minimum MTU.
    ///
    /// The `max_mtu` will not be the initial value for the MTU of the connection. It is the maximum
    /// value that the MTU can be changed to. The default MTU is the minimum MTU a HCI ACL data
    /// payload can have, which translates to a 23 byte MTU for a L2CAP logical link. This is not
    /// necessarily the same as the minimum MTU for the L2CAP layer type, although it happens to be
    /// the same as the minimum MTU of a LE-U logical link packet. The `mtu` can be changed directly
    /// or through a higher layer protocol using the `set_mtu` method of a `ConnectionChannel`.
    ///
    /// # Fragmentation
    /// Data is fragmented to either the MTU or the maximum HCI data payload size minus the L2CAP
    /// data header size. If the MTU is changed to be larger than the maximum size supported by the
    /// Bluetooth Controller's buffer, it will be fragmented to the buffer's maximum instead of the
    /// set MTU.
    ///
    /// # Panic
    /// The minimum number of bytes in the payload of a HCI ACL data packet is
    /// [`MIN_MAX_PAYLOAD_SIZE`](crate::hci::HciACLData::MIN_MAX_PAYLOAD_SIZE) (27 bytes). A panic
    /// occurs if `max_mtu` plus the header size of a L2CAP data packet (4 bytes) is not greater
    /// than or equal to `MIN_MAX_PAYLOAD_SIZE`. Thus the minimum `max_mtu` is defined as the
    /// minimum mtu for LE-U since they are the same number of bytes.
    ///
    /// # Warning
    /// Supplying a handle that does not represent a connection with the controller will result in
    /// undefined behaviour.
    pub fn flow_ctrl_channel<Mtu>(
        self: Arc<Self>,
        handle: common::ConnectionHandle,
        max_mtu: Mtu,
    ) -> impl crate::l2cap::ConnectionChannel
    where
        Mtu: Into<Option<u16>>,
    {
        let max = match max_mtu.into() {
            None => self.flow_controller.get_max_payload_size(),
            Some(v) => {
                let val = <usize>::from(v);

                val
            }
        };

        flow_ctrl::HciLeUChannel::<I, Arc<Self>, M>::new_le_flow_controller(self, handle, max)
    }
}

#[derive(Debug)]
enum OutputErr<TargetErr, CmdErr>
where
    TargetErr: core::fmt::Display + core::fmt::Debug,
    CmdErr: core::fmt::Display + core::fmt::Debug,
{
    /// An error occurred at the target specific HCI implementation
    TargetSpecificErr(TargetErr),
    /// Cannot convert the data from the HCI packed form into its usable form.
    CommandDataConversionError(CmdErr),
    /// The first item is the received event and the second item is the event expected
    ReceivedIncorrectEvent(crate::hci::events::Events),
    /// This is used when either the 'command complete' or 'command status' events contain no data
    /// and are used to indicate the maximum number of HCI command packets that can be queued by
    /// the controller.
    ResponseHasNoAssociatedCommand,
    /// The command status event returned with this error
    CommandStatusErr(error::Error),
}

impl<TargetErr, CmdErr> core::fmt::Display for OutputErr<TargetErr, CmdErr>
where
    TargetErr: core::fmt::Display + core::fmt::Debug,
    CmdErr: core::fmt::Display + core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OutputErr::TargetSpecificErr(reason) => {
                core::write!(f, "{}", reason)
            }
            OutputErr::CommandDataConversionError(reason) => {
                core::write!(f, "{}", reason)
            }
            OutputErr::ReceivedIncorrectEvent(expected_event) => {
                core::write!(f, "Received unexpected event '{:?}'", expected_event)
            }
            OutputErr::ResponseHasNoAssociatedCommand => {
                core::write!(
                    f,
                    "Event Response contains no data and is not associated with \
                    a HCI command. This should have been handled by the driver and not received \
                    here"
                )
            }
            OutputErr::CommandStatusErr(reason) => {
                core::write!(f, "{}", reason)
            }
        }
    }
}

/// Controller flow-control information
///
/// Flow control information is issued as part of the Command Complete and Command Status events,
/// however the HCI commands of this library catch and do not return this information. This trait
/// is instead implemented on the return of those methods for the user to get the flow control
/// information.
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

macro_rules! event_pattern_creator {
    ( $event_path:path, $( $data:pat ),+ ) => { $event_path ( $($data),+ ) };
    ( $event_path:path ) => { $event_path };
}

macro_rules! impl_returned_future {
    // these inputs match the inputs from crate::hci::events::impl_get_data_for_command
    ($return_type: ty, $event:path, $data:pat, $error:ty, $to_do: block) => {
        struct ReturnedFuture<'a, I, CD, P>(CommandFutureReturn<'a, I, CD, P>)
        where
            I: PlatformInterface,
            CD: CommandParameter + Unpin,
            P: EventMatcher + Send + Sync + 'static;

        impl<'a, I, CD, P> core::future::Future for ReturnedFuture<'a, I, CD, P>
        where
            I: PlatformInterface,
            CD: CommandParameter + Unpin,
            P: EventMatcher + Send + Sync + 'static,
        {
            type Output = core::result::Result<$return_type, crate::hci::OutputErr<SendCommandError<I>, $error>>;

            fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {
                if let core::task::Poll::Ready(result) = self.get_mut().0.fut_poll(cx) {
                    match result {
                        Ok(event_pattern_creator!($event, $data)) => $to_do,
                        Ok(event @ _) => {
                            let ret = Err(crate::hci::OutputErr::ReceivedIncorrectEvent(
                                event.get_event_name(),
                            ));

                            core::task::Poll::Ready(ret)
                        }
                        Err(reason) => core::task::Poll::Ready(Err(crate::hci::OutputErr::TargetSpecificErr(reason))),
                    }
                } else {
                    core::task::Poll::Pending
                }
            }
        }
    };
}

/// A Future for the command complete event.
///
/// This future is used for awaiting the command complete event in response to a command sent. If
/// the Command Complete event is received and it's the one that doesn't contain an op code, this
/// future will return an error.
macro_rules! impl_command_complete_future {
    ($data_type: ty, $return_type: ty, $try_from_err_ty:ty) => {
        impl_returned_future!(
            $return_type,
            crate::hci::events::EventsData::CommandComplete,
            data,
            crate::hci::events::CommandDataErr<$try_from_err_ty>,
            {
                use crate::hci::OutputErr::{CommandDataConversionError, ResponseHasNoAssociatedCommand};

                match unsafe { crate::hci::events::GetDataForCommand::<$data_type>::get_return(&data) } {
                    Ok(Some(ret_val)) => core::task::Poll::Ready(Ok(ret_val)),
                    Ok(None) => core::task::Poll::Ready(Err(ResponseHasNoAssociatedCommand)),
                    Err(reason) => core::task::Poll::Ready(Err(CommandDataConversionError(reason))),
                }
            }
        );
    };
    ($data: ty, $try_from_err_ty:ty) => {
        impl_command_complete_future!($data, $data, $try_from_err_ty);
    };
}

macro_rules! impl_command_status_future {
    () => {
        impl_returned_future! {
            StatusFlowControlInfo,
            crate::hci::events::EventsData::CommandStatus,
            data,
            &'static str,
            {
                use crate::hci::OutputErr::CommandStatusErr;

                if let crate::hci::error::Error::NoError = data.status {

                    let ret = StatusFlowControlInfo(data.number_of_hci_command_packets as usize);

                    core::task::Poll::Ready(Ok(ret))
                } else {
                    core::task::Poll::Ready(Err(CommandStatusErr(data.status)))
                }
            }
        }
    };
}

/// For commands that receive a command complete with just a status
macro_rules! impl_status_return {
    ($command:expr) => {
        struct ReturnData;

        struct ReturnType(usize);

        impl crate::hci::FlowControlInfo for ReturnType {
            fn packet_space(&self) -> usize {
                self.0
            }
        }

        impl ReturnData {
            fn try_from((raw, packet_cnt): (u8, u8)) -> Result<ReturnType, error::Error> {
                let status = error::Error::from(raw);

                if let error::Error::NoError = status {
                    Ok(ReturnType(packet_cnt.into()))
                } else {
                    Err(status)
                }
            }
        }

        impl_get_data_for_command!($command, u8, ReturnData, ReturnType, error::Error);

        impl_command_complete_future!(ReturnData, ReturnType, error::Error);
    };
}

// All these are down here for the macros
pub mod cb;
pub mod info_params;
pub mod le;
pub mod link_control;
pub mod link_policy;
pub mod status_prams;
pub mod testing;
