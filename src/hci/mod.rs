//! The Host Controller Interface (HCI)
//!
//! The HCI is the primary way of interacting with the controller for this library.

pub mod opcodes;
pub mod common;
pub mod error;
#[macro_use] pub mod events;
mod flow_ctrl;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::fmt::Display;
use core::future::Future;
use core::pin::Pin;
use core::task::{ Poll, Waker };

/// Used to get the information required for sending a command from the host to the controller
///
/// The type Parameter should be a packed structure of the command's parameters
pub trait CommandParameter {
    /// Data for the parameter as specified by the Bluetooth Specification.
    type Parameter;

    /// The command to send to the Bluetooth Controller.
    ///
    /// This is the OGF & OCF pair.
    const COMMAND: opcodes::HCICommand;

    /// Convert Self into the parameter form
    ///
    /// The returned parameter is the structure defined as the parameter part of the command packet
    /// for the specific HCI command.
    fn get_parameter(&self) -> Self::Parameter;

    /// Get the command packet to be sent to the controller
    ///
    /// The format of the command packet is to send the command opcode, followed by the length of
    /// the parameter, and then finally the parameter. The packet is a fully packed structure tyus
    /// the parameter is of the type `Self::Parameter`.
    ///
    /// # Note
    /// This is not the entire packet sent to the interface as there may be additional information
    /// that needs to be sent for the HCI transport layer (such as the
    /// [HciPacketIndicator](crate::hci_transport::uart::HciPacketIndicator) used for UART).
    fn as_command_packet<'a>(&self) -> Vec<u8> {
        use core::mem::size_of;

        let parameter_size = size_of::<Self::Parameter>();

        // Allocating a vector to the exact size of the packet. The 3 bytes come from the opcode
        // field (2 bytes) and the length field (1 byte)
        let mut buffer: Vec<u8> =  Vec::with_capacity( parameter_size + 3);

        let parameter = self.get_parameter();

        let p_bytes_p = &parameter as *const Self::Parameter as *const u8;

        let parm_bytes = unsafe { core::slice::from_raw_parts( p_bytes_p, parameter_size ) };

        // Add opcode to packet
        buffer.extend_from_slice( &Self::COMMAND.as_opcode_pair().as_opcode().to_le_bytes() );

        // Add the length of the parameter
        buffer.push(parm_bytes.len() as u8);

        // Add the parameter
        buffer.extend_from_slice(parm_bytes);

        buffer
    }
}

/// A trait for matching received events
///
/// When receiving an event in a concurrent system, it can be unknown which context a received
/// event should be propigated to. The event must be matched to determine this.
pub trait EventMatcher: Sync + Send {
    /// Match the event data
    fn match_event(&self, event_data: &events::EventsData ) -> bool;
}

impl<F> EventMatcher for F where F: Fn( &events::EventsData ) -> bool + Sized + Sync + Send {
    fn match_event(&self, event_data: &events::EventsData) -> bool {
        self(event_data)
    }
}

#[derive(Debug, Clone, Copy)]
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
        ( match self {
            AclPacketBoundary::FirstNonFlushable => 0x0,
            AclPacketBoundary::ContinuingFragment => 0x1,
            AclPacketBoundary::FirstAutoFlushable => 0x2,
            AclPacketBoundary::CompleteL2capPdu => 0x3,
        } ) << 12
    }

    /// Get the `AclPacketBoundry` from the first 16 bits of a HCI ACL data packet. The input
    /// `val` does not need to be masked to only include the Packet Boundary Flag, however it does
    /// need to be in host byte order.
    fn from_shifted_val(val: u16) -> Self {
        match (val >> 12) & 3  {
            0x0 => AclPacketBoundary::FirstNonFlushable,
            0x1 => AclPacketBoundary::ContinuingFragment,
            0x2 => AclPacketBoundary::FirstAutoFlushable,
            0x3 => AclPacketBoundary::CompleteL2capPdu,
            _ => panic!("This cannot happen"),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum AclBroadcastFlag {
    // Point-to-point message
    NoBroadcast,
    // Broadcast to all active slaves
    ActiveSlaveBroadcast,
}

impl AclBroadcastFlag {

    /// Get the value shifted into the correct place of the Packet Boundary Flag in the HCI ACL
    /// data packet. The returned value is in host byte order.
    fn get_shifted_val(&self) -> u16 {
        ( match self {
            AclBroadcastFlag::NoBroadcast => 0x0,
            AclBroadcastFlag::ActiveSlaveBroadcast => 0x1,
        } ) << 14
    }

    /// Get the `AclPacketBoundry` from the first 16 bits of a HCI ACL data packet. The input
    /// `val` does not need to be masked to only include the Packet Boundary Flag, however it does
    /// need to be in host byte order.
    fn try_from_shifted_val(val: u16) -> Result<Self, ()> {
        match (val >> 14) & 1  {
            0x0 => Ok(AclBroadcastFlag::NoBroadcast),
            0x1 => Ok(AclBroadcastFlag::ActiveSlaveBroadcast),
            0x2 | 0x3 => Err( () ),
            _ => panic!("This cannot happen"),
        }
    }
}

#[derive(Debug)]
pub enum HciAclPacketConvertError {
    PacketTooSmall,
    InvalidBroadcastFlag,
    InvalidConnectionHandle( &'static str ),
}

impl Display for HciAclPacketConvertError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            HciAclPacketConvertError::PacketTooSmall =>
                write!(f, "Packet is too small to be a valid HCI ACL Data"),
            HciAclPacketConvertError::InvalidBroadcastFlag =>
                write!(f, "Packet has invalid broadcast Flag"),
            HciAclPacketConvertError::InvalidConnectionHandle(reason) =>
                write!(f, "Invalid connection handle, {}", reason),
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
/// ['FirstNonFlushable`](bo_tie::hci::AclPacketBoundary::FirstNonFlushable) or
/// [`ContinuingFragment`](bo_tie::hci::AclPacketBoundary::ContinuingFragment), but it cannot be
/// [`FirstAutoFlushable`](bo_tie::hci::AclPacketBoundary::FirstAutoFlushable) or
/// [`CompleteL2capPdu`](bo_tie::hci::AclPacketBoundary::CompleteL2capPdu). The broadcast flag must
/// always be
/// [`NoBroadcast`](bo_tie::hci::AclBroadcastFlag::NoBroadcast). Lastly the connection handle can
/// only be a primary controller handle (which is generated with a *LE Connection Complete* or
/// *LE Enhanced Connection Complete* event for LE-U).
#[derive(Debug)]
pub struct HciAclData {
    connection_handle: common::ConnectionHandle,
    packet_boundary_flag: AclPacketBoundary,
    broadcast_flag: AclBroadcastFlag,
    /// This is always a L2CAP ACL packet
    payload: Vec<u8>,
}

impl HciAclData {

    /// The size of the header of a HCI ACL data packet
    pub const HEADER_SIZE: usize = 4;

    /// Create a new HciAclData
    ///
    /// # Panic
    /// The payload length must not be larger than the maximum u16 number
    pub fn new(
        connection_handle: common::ConnectionHandle,
        packet_boundary_flag: AclPacketBoundary,
        broadcast_flag: AclBroadcastFlag,
        payload: Vec<u8>
    ) -> Self
    {
        assert!( payload.len() <= <u16>::MAX.into() );

        HciAclData { connection_handle, packet_boundary_flag, broadcast_flag, payload }
    }

    pub fn get_handle(&self) -> &common::ConnectionHandle {
        &self.connection_handle
    }

    pub fn get_payload(&self) -> &[u8] { &self.payload }

    pub fn get_packet_boundary_flag(&self) -> AclPacketBoundary { self.packet_boundary_flag }

    pub fn get_broadcast_flag(&self) -> AclBroadcastFlag { self.broadcast_flag }

    /// Convert the HciAclData into a raw packet
    ///
    /// This will convert HciAclData into a packet that can be sent between the host and controller.
    pub fn get_packet(&self) -> alloc::vec::Vec<u8> {

        let mut v = alloc::vec::Vec::with_capacity( self.payload.len() + 4 );

        let first_2_bytes = self.connection_handle.get_raw_handle()
            | self.packet_boundary_flag.get_shifted_val()
            | self.broadcast_flag.get_shifted_val();

        v.extend_from_slice( &first_2_bytes.to_le_bytes() );

        v.extend_from_slice( &(self.payload.len() as u16).to_le_bytes() );

        v.extend_from_slice( &self.payload );

        v
    }

    /// Attempt to create a `HciAclData`
    ///
    /// A `HciAclData` is created if the packet is in the correct HCI ACL data packet format. If
    /// not, then an error is returned.
    pub fn from_packet(packet: &[u8]) -> Result<Self, HciAclPacketConvertError> {
        const HEADER_SIZE: usize = 4;

        if packet.len() >= HEADER_SIZE {
            let first_2_bytes = <u16>::from_le_bytes( [ packet[0], packet[1] ] );

            let connection_handle = match common::ConnectionHandle::try_from( first_2_bytes & 0xFFF) {
                Ok(handle) => handle,
                Err(e) => return Err( HciAclPacketConvertError::InvalidConnectionHandle(e) ),
            };

            let packet_boundary_flag = AclPacketBoundary::from_shifted_val( first_2_bytes );

            let broadcast_flag = match AclBroadcastFlag::try_from_shifted_val( first_2_bytes ) {
                Ok(flag) => flag,
                Err(_) => return Err( HciAclPacketConvertError::InvalidBroadcastFlag ),
            };

            let data_length = <u16>::from_le_bytes( [ packet[2], packet[3] ] ) as usize;

            Ok(
                HciAclData {
                    connection_handle,
                    packet_boundary_flag,
                    broadcast_flag,
                    payload: packet[HEADER_SIZE..(HEADER_SIZE + data_length)].to_vec(),
                }
            )

        } else {
            Err( HciAclPacketConvertError::PacketTooSmall )
        }
    }

    /// Convert into a
    /// [`AclDataFragment`](crate::l2cap::AclDataFragment)
    pub fn into_acl_fragment(self) -> crate::l2cap::AclDataFragment {
        use crate::l2cap::AclDataFragment;

        match self.packet_boundary_flag {
            AclPacketBoundary::ContinuingFragment => AclDataFragment::new(false, self.payload),
            _                                     => AclDataFragment::new(true, self.payload),
        }
    }
}


/// Trait for interfacing with the controller
///
///
/// # Implementation
///
/// ## `send_command`
/// This is used for sending the command to the Bluetooth controller by the HostInterface object.
/// It is provided with a input that implements the
/// [`CommandParameter`](bo_tie::hci::CommandParameter) which contains all the information required
/// for sending the command packet to the Bluetooth controller.
///
/// ## `receive_event`
/// `receive_event` is used for implementing a future around the controller's event process. When
/// called it needs to check if the event is available to the Host or not. If the event is not not
/// immediately available, the implementation of `receive_event` needs to call wake on the provided
/// `waker` input when the event is accepted by the Host.
///
/// Events need to be correctly propagated to the right context that is currently waiting for the
/// requested event. Some events can be differentiated from themselves through the data passed with
/// the event, but most do not have any discernible way to tell which context should receive which
/// event. Its the responsibility of the implementor of `HostControllerInterface` to determine
/// what event goes with what `waker`, along with matching events to a `waker` based on the provided
/// matcher.
pub trait HostControllerInterface
{
    type SendCommandError: Debug + Display;
    type ReceiveEventError: Debug + Display;

    /// Send a command from the Host to the Bluetooth Controller
    ///
    /// This will return true if the command was sent to the bluetooth controller, and false if
    /// the command couldn't be transferred to the controller yet. This doesn't mean that an error
    /// occurred (it generally means that the bluetooth controller buffer is full), but it does mean
    /// that the command must be resent. If an error does occur then an Error will be returned.
    ///
    /// The `cmd_data` input contains all the HCI command information, where as the `waker` input
    /// is used to wake the context for the command to be resent.
    fn send_command<D,W>(&self, cmd_data: &D, waker: W) -> Result<bool, Self::SendCommandError>
    where D: CommandParameter,
          W: Into<Option<Waker>>;

    /// Receive an event from the Bluetooth controller
    ///
    /// This is implemented as a non-blocking operation, the host has either received the event or
    /// the event hasn't been send sent (or will never be sent) to the host. The function will
    /// return the data associated with the event (or an error if it occurs) if the event has been
    /// received or it will return None.
    ///
    /// If event is 'None' then the next event received by the host should be returned.
    ///
    /// If None is returned, the waker will be used to indicate that the event was received. But to
    /// get the events data, the exact same event and matcher reference (the matcher may be cloned)
    /// must be used to guarantee that the event data is returned.
    ///
    /// The function requires a
    /// [`Waker`](https://doc.rust-lang.org/core/task/struct.Waker.html) object because
    /// it will call wake when the event has been received after the event is received. At which
    /// point the function must be called again to receive the EventData.
    fn receive_event<P>(
        &self,
        event: Option<events::Events>,
        waker: &Waker,
        matcher: Pin<Arc<P>>,
    ) -> Option<Result<events::EventsData, Self::ReceiveEventError>>
    where P: EventMatcher + Send + Sync + 'static;
}

/// HCI ACL Data interface
///
/// This is the trait that must be implemented by the platform specific HCI structure.
pub trait HciAclDataInterface {
    type SendAclDataError: Debug + Display;
    type ReceiveAclDataError: Debug + Display;

    /// Send ACL data
    ///
    /// This will send ACL data to the controller for sending to the connected bluetooth device
    ///
    /// The return value is the number of bytes of acl data payload + 1 ( due to added packet
    /// indicator ) sent.
    fn send(
        &self,
        data: HciAclData,
    ) -> Result<usize, Self::SendAclDataError>;

    /// Register a handle for receiving ACL packets
    ///
    /// Unlike events, it can be unpredictable if data will be received by the controller while
    /// this API is waiting for it. There may be times where data sent from the controller
    /// to the host and there is nothing to receive it. Lower level implementations should utilize
    /// this function to enable buffers for each connection handle.
    ///
    /// The `receive_acl_data` function will be called afterwards to acquire the buffered data,
    /// however the buffer needs to still exist
    fn start_receiver(&self, handle: common::ConnectionHandle);

    /// Unregister a handle for receiving ACL packets
    ///
    /// This will be called once there will be no more ACL packets to be received or the user no
    /// longer cares about receiving ACL packets. Once this is called any buffers can be dropped
    /// that are associated with the given handle.
    fn stop_receiver(&self, handle: &common::ConnectionHandle);

    /// Receive ACL data
    ///
    /// Receive data from the controller for the given connection handle. If no data is available
    /// to be received then None will be returned and the provided waker will be used when the next
    /// ACL data is received.
    fn receive(
        &self,
        handle: &common::ConnectionHandle,
        waker: &Waker,
    ) -> Option<Result<alloc::vec::Vec<HciAclData>, Self::ReceiveAclDataError>>;
}

enum SendCommandError<I> where I: HostControllerInterface {
    Send(<I as HostControllerInterface>::SendCommandError),
    Recv(<I as HostControllerInterface>::ReceiveEventError),
}

impl<I> Debug for SendCommandError<I> where I: HostControllerInterface {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendCommandError::Send(err) => Debug::fmt(err, f),
            SendCommandError::Recv(err) => Debug::fmt(err, f),
        }
    }
}

impl<I> Display for SendCommandError<I> where I: HostControllerInterface {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendCommandError::Send(err) => Display::fmt(err, f),
            SendCommandError::Recv(err) => Display::fmt(err, f),
        }
    }
}

struct CommandFutureReturn<'a, I, CD, P>
where I: HostControllerInterface,
      CD: CommandParameter,
      P: EventMatcher + Send + Sync + 'static,
{
    interface: &'a I,
    /// Parameter data sent with the command packet
    ///
    /// This must be set to Some(*data*) for a command to be sent to the controller. No command
    /// will be sent to the controller if the `command_data` isn't set to Some.
    command_data: Option<CD>,
    event: events::Events,
    matcher: Pin<Arc<P>>,
}

impl<'a, I, CD, P> CommandFutureReturn<'a, I, CD, P>
where I: HostControllerInterface,
      CD: CommandParameter + Unpin,
      P: EventMatcher + Send + Sync + 'static,
{

    /// This is just called within an implemenation of future created by the macro
    /// `[impl_returned_future]`(../index.html#impl_returned_future)
    fn fut_poll(&mut self, cx: &mut core::task::Context) -> Poll<Result<events::EventsData, SendCommandError<I>>> {

        if let Some(ref data) = self.command_data {
            match self.interface.send_command(data, cx.waker().clone() ) {
                Err(e) => return Poll::Ready(Err(SendCommandError::Send(e))),
                // False means the command wasn't sent
                Ok(false) => return Poll::Pending,
                Ok(true) => { self.command_data.take(); },
            }
        }

        match self.interface.receive_event(self.event.into(), cx.waker(), self.matcher.clone()) {
            None => Poll::Pending,
            Some(result) => Poll::Ready(result.map_err(|e| SendCommandError::Recv(e)))
        }
    }
}

struct EventReturnFuture<'a, I, P>
where I: HostControllerInterface,
      P: EventMatcher + Sync + Send + 'static
{
    interface: &'a I,
    event: Option<events::Events>,
    matcher: Pin<Arc<P>>,
}

impl<'a, I, P> Future for EventReturnFuture<'a, I, P>
where I: HostControllerInterface,
P: EventMatcher + Send + Sync + 'static
{
    type Output = Result<events::EventsData, I::ReceiveEventError>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> Poll<Self::Output> {
        match self.interface.receive_event(self.event, cx.waker(), self.matcher.clone()) {
            Some(evnt_rspn) => Poll::Ready(evnt_rspn),
            None => Poll::Pending,
        }
    }
}

/// The host interface
///
/// This is used by the host to interact with the interface between itself and the Bluetooth
/// Controller.
#[derive(Clone, Default)]
#[cfg(not(feature = "flow-ctrl"))]
pub struct HostInterface<I> {
    interface: I,
}

#[cfg(feature = "flow-ctrl")]
pub struct HostInterface<I,F> {
    interface: I,
    flow_controller: F,
}

#[bo_tie_macros::host_interface]
impl<I> HostInterface<I> {
    pub fn into_inner(self) -> I { self.interface }
}

#[bo_tie_macros::host_interface]
impl<I> AsRef<I> for HostInterface<I> {
    fn as_ref(&self) -> &I {
        &self.interface
    }
}

#[bo_tie_macros::host_interface]
impl<I> AsMut<I> for HostInterface<I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.interface
    }
}

#[cfg(not(feature = "flow-ctrl"))]
impl<I> From<I> for HostInterface<I>
{
    fn from(interface: I) -> Self {
        HostInterface { interface }
    }
}

#[bo_tie_macros::host_interface]
impl<I> HostInterface<I>
where I: HostControllerInterface
{
    /// Send a command to the controller
    ///
    /// The command data will be used in the command packet to determine what HCI command is sent
    /// to the controller. The events specified must be the events directly returned by the
    /// controller in response to the command.
    ///
    /// A future is returned for waiting on the event generated from the controller in response to
    /// the sent command.
    fn send_command<'a, CD>( &'a self, cmd_data: CD, event: events::Events )
    -> CommandFutureReturn<'a, I, CD, impl EventMatcher + Send + Sync + 'static>
    where CD: CommandParameter + Unpin + 'static,
    {
        let cmd_matcher = | ed: &events::EventsData | {

            fn match_opcode<CD: CommandParameter>(opcode: Option<u16>) -> bool {
                match opcode {
                    Some(opcode) => {
                        use core::convert::TryFrom;

                        let expected_op_code =
                            opcodes::HCICommand::try_from(<CD as CommandParameter>::COMMAND)
                            .unwrap();

                        let recv_oc_code = opcodes::HCICommand::try_from(
                            opcodes::OpCodePair::from_opcode(opcode)
                        );

                        match recv_oc_code {
                            Ok(code) => {
                                expected_op_code == code
                            },
                            Err(reason) => {
                                log::error!("{}", reason);
                                false
                            }
                        }
                    }
                    None => false,
                }
            }

            match ed {
                events::EventsData::CommandComplete(data) => match_opcode::<CD>(data.command_opcode),
                events::EventsData::CommandStatus(data)   => match_opcode::<CD>(data.command_opcode),
                _ => false
            }
        };

        CommandFutureReturn {
            interface: &self.interface,
            command_data: Some(cmd_data),
            event,
            matcher: Arc::pin(cmd_matcher),
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
    pub fn wait_for_event<'a,E>(&'a self, event: E)
    -> impl Future<Output=Result<events::EventsData, <I as HostControllerInterface>::ReceiveEventError >> + 'a
    where E: Into<Option<events::Events>>,
    {
        fn default_matcher(_: &events::EventsData) -> bool { true }

        fn most_matcher(e: &events::EventsData) -> bool {
            e.get_event_name().is_maskable()
        }

        let opt_event: Option<events::Events> = event.into();

        let matcher = if opt_event.is_none() { most_matcher } else { default_matcher };

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
    pub fn wait_for_event_with_matcher<'a,P>(&'a self, event: events::Events, matcher: P)
    -> impl Future<Output=Result<events::EventsData, <I as HostControllerInterface>::ReceiveEventError >> + 'a
    where P: EventMatcher + Send + Sync + 'static,
    {
        EventReturnFuture {
            interface: &self.interface,
            event: event.into(),
            matcher: Arc::pin(matcher),
        }
    }
}

#[bo_tie_macros::host_interface(flow_ctrl_concrete = "flow_ctrl::NoFlowControl")]
impl<I> HostInterface<I> where I: HciAclDataInterface {

    /// Create a new raw LE-U logical link connection channel
    ///
    /// Make a raw HCI connection channel with the provided connection handle for a LE-U logical
    /// link. This connection channel provides no protection for the controller. There is no flow
    /// control in this connection channel for data sent to the controller. It is up to the user to
    /// make sure that the controllers data buffers do not overflow.
    ///
    /// The `max_mtu` input is the maximum value the logical link's MTU can be changed to over the
    /// lifetime of the connection channel. When this is initialized, the used MTU value is
    /// defaulted to the minimum possible MTU for LE-U, but if it changed it can only be changed to
    /// a value no greater than `max_mtu`. If `max_mtu` is `None` or smaller than the minimum MTU
    /// for LE-U, it defaults to the minimum MTU.
    pub fn le_raw_channel<'a,M>(&'a self, handle: common::ConnectionHandle, max_mtu: M)
    -> impl crate::l2cap::ConnectionChannel + 'a
    where M: Into<Option<u16>>
    {
        flow_ctrl::HciLeUChannel::new_raw(self, handle, max_mtu)
    }

    /// Create a new connection-oriented data channel with a `HostInterface` wrapped within an `Arc`
    ///
    /// This is an alternative to `new_le_raw_channel` for situations where the lifetime of
    /// `self` may not outlive the generated `ConnectionChannel`. This can be useful for thread
    /// pools or other synchronization related executors where it may be required to have a
    /// atomically reference counted `HostInterface`.
    pub fn sync_le_raw_channel<M>(self: Arc<Self>, handle: common::ConnectionHandle, max_mtu: M)
    -> impl crate::l2cap::ConnectionChannel
    where M: Into<Option<u16>>
    {
        flow_ctrl::HciLeUChannel::new_raw(self, handle, max_mtu)
    }
}

#[cfg(feature = "flow-ctrl")]
impl<I,M,L,G> HostInterface<I,flow_ctrl::flow_manager::HciDataPacketFlowManager<M>>
where I: HciAclDataInterface + HostControllerInterface + Send + Sync + Unpin + 'static,
      M: flow_ctrl::flow_manager::AsyncLock<Guard=G,Locker=L> + 'static,
      L: Future<Output=G> + 'static,
      G: 'static,
{
    /// Create a channel that uses a flow controller
    ///
    /// This connection channel will query the controller *once* to get the maximum HCI packet size
    /// and the number of HCI packets it can accept. This flow controller will then fragment data
    /// to the maximum size (if needed) and pend when the controllers buffer is full. The querying
    /// of the controller only occurs once, after that it uses the values already queued for.
    pub async fn flow_ctrl_channel<HI>(self: Arc<Self>, handle: common::ConnectionHandle)
    -> impl crate::l2cap::ConnectionChannel
    {
        flow_ctrl::HciLeUChannel
            ::<I,Arc<Self>,flow_ctrl::flow_manager::HciDataPacketFlowManager<M>>
            ::new_le_flow_manager(self, handle)
            .await
    }
}

#[derive(Debug)]
enum OutputErr<TargErr, CmdErr>
where TargErr: Display + Debug,
      CmdErr: Display + Debug,
{
    /// An error occurred at the target specific HCI implementation
    TargetSpecificErr(TargErr),
    /// Cannot convert the data from the HCI packed form into its useable form.
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

impl<TargErr, CmdErr> Display for OutputErr<TargErr, CmdErr>
where TargErr: Display + Debug,
      CmdErr: Display + Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            OutputErr::TargetSpecificErr(reason) => {
                core::write!(f, "{}", reason)
            },
            OutputErr::CommandDataConversionError(reason) => {
                core::write!(f, "{}", reason)
            },
            OutputErr::ReceivedIncorrectEvent(expected_event) => {
                core::write!(f, "Received unexpected event '{:?}'", expected_event )
            },
            OutputErr::ResponseHasNoAssociatedCommand => {
                core::write!(f,"Event Response contains no data and is not associated with \
                    a HCI command. This should have been handled by the driver and not received \
                    here")
            },
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
    fn packet_space(&self) -> usize;
}

/// Flow control data extracted from the command status event
struct StatusFlowControlInfo(usize);

impl FlowControlInfo for StatusFlowControlInfo {
    fn packet_space(&self) -> usize { self.0 }
}

macro_rules! event_pattern_creator {
    ( $event_path:path, $( $data:pat ),+ ) => { $event_path ( $($data),+ ) };
    ( $event_path:path ) => { $event_path };
}

macro_rules! impl_returned_future {
    // these inputs match the inputs from crate::hci::events::impl_get_data_for_command
    ($return_type: ty, $event:path, $data:pat, $error:ty, $to_do: block) => {

        struct ReturnedFuture<'a, I, CD, P>( CommandFutureReturn<'a, I, CD, P> )
        where I: HostControllerInterface,
              CD: CommandParameter + Unpin,
              P: EventMatcher + Send + Sync + 'static;

        impl<'a, I, CD, P> core::future::Future for ReturnedFuture<'a, I, CD, P>
        where I: HostControllerInterface,
              CD: CommandParameter + Unpin,
              P: EventMatcher + Send + Sync + 'static,
        {
            type Output = core::result::Result< $return_type, crate::hci::OutputErr<SendCommandError<I>,$error>>;

            fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> core::task::Poll<Self::Output> {
                if let core::task::Poll::Ready(result) = self.get_mut().0.fut_poll(cx) {
                    match result {
                        Ok( event_pattern_creator!($event, $data) ) => $to_do,
                        Ok(event @ _) => {
                            let ret = Err(crate::hci::OutputErr::ReceivedIncorrectEvent(event.get_event_name()));

                            core::task::Poll::Ready(ret)
                        },
                        Err(reason) =>
                            core::task::Poll::Ready(Err(crate::hci::OutputErr::TargetSpecificErr(reason))),
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
                use crate::hci::OutputErr::{
                    ResponseHasNoAssociatedCommand,
                    CommandDataConversionError
                };

                match unsafe {
                    crate::hci::events::GetDataForCommand::<$data_type>::get_return(&data)
                } {
                    Ok(Some(ret_val)) => core::task::Poll::Ready(Ok(ret_val)),
                    Ok(None) =>
                        core::task::Poll::Ready(Err(ResponseHasNoAssociatedCommand)),
                    Err(reason) =>
                        core::task::Poll::Ready(Err(CommandDataConversionError(reason))),
                }
            }
        );
    };
    ($data: ty, $try_from_err_ty:ty) => { impl_command_complete_future!($data, $data, $try_from_err_ty); };
}

macro_rules! impl_command_status_future {
    () => {
        impl_returned_future!{
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
            fn packet_space(&self) -> usize { self.0 }
        }

        impl ReturnData {
            fn try_from( (raw, packet_cnt): (u8, u8) ) -> Result<ReturnType, error::Error> {

                let status = error::Error::from(raw);

                if let error::Error::NoError = status {
                    Ok(ReturnType(packet_cnt.into()))
                }
                else {
                    Err(status)
                }
            }
        }

        impl_get_data_for_command!($command, u8, ReturnData, ReturnType, error::Error);

        impl_command_complete_future!(ReturnData, ReturnType, error::Error);
    }
}

// All these are down here for the macros
pub mod le;
pub mod link_control;
pub mod link_policy;
pub mod cb;
pub mod info_params;
pub mod status_prams;
pub mod testing;