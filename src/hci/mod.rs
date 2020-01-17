//! The Host Controller Interface (HCI)
//!
//! The HCI is the primary way of interacting with the controller for this library.

mod opcodes;
pub mod common;
pub mod error;
#[macro_use] pub mod events;

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::fmt::Display;
use core::future::Future;
use core::pin::Pin;
use core::time::Duration;
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
    /// # Note
    /// This is not the entire packet sent to the interface as there may be additional information
    /// that needs to be sent for the HCI transport layer (such as the HCI packet indicator).
    fn as_command_packet<'a>(&self) -> alloc::boxed::Box<[u8]> {
        use core::mem::size_of;

        let parameter_size = size_of::<Self::Parameter>();

        // Allocating a vector to the exact size of the packet. The 3 bytes come from the opcode
        // field (2 bytes) and the length field (1 byte)
        let mut buffer:alloc::vec::Vec<u8> = alloc::vec::Vec::with_capacity( parameter_size + 3);

        let parameter = self.get_parameter();

        let p_bytes_p = &parameter as *const Self::Parameter as *const u8;

        let parm_bytes = unsafe { core::slice::from_raw_parts( p_bytes_p, parameter_size ) };

        let opcode_bytes = Self::COMMAND.as_opcode_pair().as_opcode().to_le();

        buffer.extend_from_slice(&opcode_bytes.to_le_bytes());

        buffer.push(parm_bytes.len() as u8);

        buffer.extend_from_slice(parm_bytes);

        buffer.into_boxed_slice()
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

#[derive(Debug)]
pub struct HciAclData {
    connection_handle: common::ConnectionHandle,
    packet_boundary_flag: AclPacketBoundary,
    broadcast_flag: AclBroadcastFlag,
    /// This is always a L2CAP ACL packet
    payload: Vec<u8>,
}

impl HciAclData {

    /// The minimum number of bytes that must be in the start fragment for LE-U logical link
    ///
    /// Per the specification, any L2CAP message cannot be fragmented if it is less then 27 bytes
    /// (v5.0 | Vol 2, Part E, Section 4.1.1 [at the very end of the section] )
    pub const MINIMUM_LE_U_FRAGMENT_START_SIZE: usize = 27;

    pub fn new(
        connection_handle: common::ConnectionHandle,
        packet_boundary_flag: AclPacketBoundary,
        broadcast_flag: AclBroadcastFlag,
        payload: Vec<u8>
    ) -> Self
    {
        HciAclData { connection_handle, packet_boundary_flag, broadcast_flag, payload }
    }

    pub fn get_handle(&self) -> &common::ConnectionHandle {
        &self.connection_handle
    }

    pub fn get_payload(&self) -> &[u8] { &self.payload }

    pub fn get_packet_boundary_flag(&self) -> AclPacketBoundary { self.packet_boundary_flag }

    pub fn get_broadcast_flag(&self) -> AclBroadcastFlag { self.broadcast_flag }

    /// Convert the HciAclData into a packet
    ///
    /// This will convert HciAclData into a packet that can be sent between the host and controller.
    ///
    /// # Panics (TODO to remove)
    /// For now this panics if the length of data is greater then 2^16 because this library only
    /// supports LE.
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

    fn into_acl_fragment(self) -> crate::l2cap::AclDataFragment {
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
/// # Implemenation
///
/// ## [send_command](#send_command)
/// This is used for sending the command to the Bluetooth controller by the HostInterface object.
/// It is provided with a input that implements the
/// [`CommandParameter`] which contains all the information required
/// for sending the command packet to the Bluetooth controller. This information is not in the
/// packet format and needs to be implemented as such.
///
/// The funciton should return Ok if there were no errors sending the command.
///
/// ## [receive_event](#receive_event)
/// receive_event is used for implementing a future around the controller's event process. When
/// called it needs to check if the event is available to the Host or not. If the event is not not
/// immediately available, the implementation of receive_event needs to call wake on the provided
/// `waker` input when the event is accepted by the Host.
///
/// It is suggested, but not necessary, for the implementor to provide a means of timing out while
/// waiting for the event to be received by the host. The duration of the timeout shall be the
/// input `timeout` if set to some value, otherwise there is no timeout when the value is None.
/// When the timeout occurs, the wake function of the provided Waker input will be called. When
/// receive_event is called the next time (with the same event), it will return an error to
/// indicate a timeout.
///
/// If the timeout functionality isn't implemented, then the only value accepted should be None
/// and any Duration value provided should cause the function to return an Error stating that
/// timeouts are not available for this implementation.
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
    /// If None is returned, the waker will be used to indicate that the event was received. But to
    /// get the events data, the exact same event and matcher reference (the matcher may be cloned)
    /// must be used to gaurentee that the event data is returned.
    ///
    /// The function requires a
    /// [`Waker`](https://doc.rust-lang.org/core/task/struct.Waker.html) object because
    /// it will call wake when the event has been received after the event is received or a timeout
    /// occurs (if available). At which point the function must be called again to receive the
    /// EventData.
    fn receive_event<P>(
        &self,
        event: events::Events,
        waker: &Waker,
        matcher: Pin<Arc<P>>,
        timeout: Option<Duration>
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
    timeout: Option<Duration>,
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

        match self.interface.receive_event(self.event, cx.waker(), self.matcher.clone(), self.timeout) {
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
    event: events::Events,
    matcher: Pin<Arc<P>>,
    timeout: Option<Duration>,
}

impl<'a, I, P> Future for EventReturnFuture<'a, I, P>
where I: HostControllerInterface,
P: EventMatcher + Send + Sync + 'static
{
    type Output = Result<events::EventsData, I::ReceiveEventError>;

    fn poll(self: core::pin::Pin<&mut Self>, cx: &mut core::task::Context) -> Poll<Self::Output> {
        match self.interface.receive_event(self.event, cx.waker(), self.matcher.clone(), self.timeout) {
            Some(evnt_rspn) => Poll::Ready(evnt_rspn),
            None => Poll::Pending,
        }
    }
}

/// The host interface
///
/// This is used by the host to interact with the interface between itself and the Bluetooth
/// Controller.
#[derive(Clone)]
pub struct HostInterface<I>
{
    interface: I
}

impl<I> AsRef<I> for HostInterface<I> {
    fn as_ref(&self) -> &I {
        &self.interface
    }
}

impl<I> AsMut<I> for HostInterface<I> {
    fn as_mut(&mut self) -> &mut I {
        &mut self.interface
    }
}

impl<I> HostInterface<I> {
    pub fn into_inner(self) -> I { self.interface }
}

impl<I> From<I> for HostInterface<I>
{
    fn from(interface: I) -> Self {
        HostInterface { interface }
    }
}

impl<T> ::core::default::Default for HostInterface<T> where T: Default {

    fn default() -> Self {
        HostInterface { interface: T::default() }
    }
}

impl<I> HostInterface<I>
where I: HostControllerInterface
{
    /// Send a command to the controller
    ///
    /// The command data will be used in the command packet to determine what HCI command is sent
    /// to the controller. The events specified should be the events directly returned by the
    /// controller in response to the command, they should not be events that will come later as
    /// a timeout may occur before the event is sent from the controller.
    ///
    /// A future is returned for waiting on the event generated from the controller in *direct*
    /// response to the sent command.
    fn send_command<'a, CD, D>( &'a self, cmd_data: CD, event: events::Events, timeout: D )
    -> CommandFutureReturn<'a, I, CD, impl EventMatcher + Send + Sync + 'static>
    where CD: CommandParameter + Unpin + 'static,
          D: Into<Option<Duration>>,
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
            timeout: timeout.into(),
        }
    }

    /// Get a future for a Bluetooth Event
    ///
    /// The event provided to the method will be the event to waited upon, and an optional timeout
    /// can be provided for the case were the event isn't gaurenteed to be returned to the Host.
    ///
    /// # Limitations
    /// Calling this multiple times with the same event is OK only when the returned future is
    /// polled to completion before the next call to this method *with the same event* is made.
    /// Not doing this with multiple events results in undefined behavior.
    ///
    /// If multiple of the same event need to be made, use
    /// [`wait_for_event_with_matcher`](#method.wait_for_event_with_matcher)
    /// to match the data returned with the event.
    pub fn wait_for_event<'a,D>(&'a self, event: events::Events, timeout: D)
    -> impl Future<Output=Result<events::EventsData, <I as HostControllerInterface>::ReceiveEventError >> + 'a
    where D: Into<Option<Duration>>,
    {
        fn default_matcher(_: &events::EventsData) -> bool { true }

        EventReturnFuture {
            interface: &self.interface,
            event,
            matcher: Arc::pin(default_matcher),
            timeout: timeout.into(),
        }
    }

    /// Get a future for a *more* specific Bluetooth Event
    ///
    /// This is the same as the function
    /// `[wait_for_event](#wait_for_event)` except an additional matcher is used to filter same
    /// events based on the data sent with the event. See
    /// `[EventMatcher](../EventMatcher/index.html)`
    /// for information on implementing a matcher, but you can use a closure that borrows
    /// `[EventsData](/hci/events/EventsData)`
    /// as an input and returns a `bool` as a matcher.
    ///
    /// # Limitations
    /// While this can be used to further specify what event data gets returned by a future, its
    /// really just further filters the event data. The same exact limitation scenerio happens when
    /// muliple futures are created to wait upon the same event with matchers that *possibly* have
    /// the same functionality. **Two matchers will have the same functionality if for a given
    /// event data, the method `match_event` returns true.**
    ///
    /// Using a matcher that always returns true results in `wait_for_event_with_matcher`
    /// functioning the same way as
    /// `[wait_for_event](wait_for_event)`
    pub fn wait_for_event_with_matcher<'a,P,D>(&'a self, event: events::Events, timeout: D, matcher: P)
    -> impl Future<Output=Result<events::EventsData, <I as HostControllerInterface>::ReceiveEventError >> + 'a
    where P: EventMatcher + Send + Sync + 'static,
          D: Into<Option<Duration>>,
    {
        EventReturnFuture {
            interface: &self.interface,
            event,
            matcher: Arc::pin(matcher),
            timeout: timeout.into(),
        }
    }
}


struct LeAclHciChannel<'a, I> where I: HciAclDataInterface {
    handle: common::ConnectionHandle,
    hi: &'a HostInterface<I>
}

impl<'a, I> LeAclHciChannel<'a, I> where I: HciAclDataInterface {

    fn new(hi: &'a HostInterface<I>, handle: common::ConnectionHandle) -> Self {

        hi.interface.start_receiver(handle);

        LeAclHciChannel { handle, hi }
    }
}

impl<'a,I> crate::l2cap::ConnectionChannel for LeAclHciChannel<'a, I>
where I: HciAclDataInterface
{
    fn send<Pdu>(&self, data: Pdu ) where Pdu: Into<crate::l2cap::L2capPdu> {

        let l2cap_pdu = data.into();

        if let Some(mtu) = l2cap_pdu.get_mtu() {
            log::trace!("fragmenting l2cap data for transmission");

            let payload = l2cap_pdu.into_data();

            let fragment_size = core::cmp::min(mtu, HciAclData::MINIMUM_LE_U_FRAGMENT_START_SIZE);

            payload.chunks(fragment_size).enumerate().for_each(|(i, chunk)| {
                let hci_acl_data = if i == 0 {
                    log::trace!("Start packet");
                    HciAclData::new(
                        self.handle,
                        AclPacketBoundary::FirstNonFlushable,
                        AclBroadcastFlag::NoBroadcast,
                        chunk.to_vec()
                    )
                } else {
                    HciAclData::new(
                        self.handle,
                        AclPacketBoundary::ContinuingFragment,
                        AclBroadcastFlag::NoBroadcast,
                        chunk.to_vec()
                    )
                };

                self.hi.interface.send(hci_acl_data).expect("Failed to send hci acl data");
            })
        } else {
            let hci_acl_data = HciAclData::new(
                self.handle,
                AclPacketBoundary::FirstNonFlushable,
                AclBroadcastFlag::NoBroadcast,
                l2cap_pdu.into_data()
            );

            self.hi.interface.send(hci_acl_data).expect("Failed to send hci acl data");
        }
    }

    fn receive(&self, waker: &core::task::Waker) -> Option<alloc::vec::Vec<crate::l2cap::AclDataFragment>> {
        use crate::l2cap::AclDataFragment;

        self.hi.interface
        .receive(&self.handle, waker)
        .and_then( |received| match received {
            Ok( packets ) => packets.into_iter()
                .map( |packet| packet.into_acl_fragment() )
                .collect::<Vec<AclDataFragment>>()
                .into(),
            Err( e ) => {
                log::error!("Failed to receive data: {}", e);
                Vec::new().into()
            },
        })
    }
}



impl<'a,I> core::ops::Drop for LeAclHciChannel<'a,I> where I: HciAclDataInterface {
    fn drop(&mut self) {
        self.hi.interface.stop_receiver(&self.handle)
    }
}

impl<I> HostInterface<I> where I: HciAclDataInterface {

    /// Create a new connection-oriented data channel
    ///
    /// Make a connection channel for the provided connection handle.
    pub fn new_connection_channel<'a>(&'a self, connection_handle: common::ConnectionHandle)
    -> impl crate::l2cap::ConnectionChannel + 'a
    {
        LeAclHciChannel::new(self, connection_handle)
    }
}

/// For commands that only return a status
macro_rules! impl_status_return {
    ($command:expr) => {
        #[doc(hidden)]
        pub struct Return;

        impl Return {
            fn try_from( raw: u8 ) -> Result<(), error::Error> {
                let status = error::Error::from(raw);

                if let error::Error::NoError = status {
                    Ok(())
                }
                else {
                    Err(status)
                }
            }
        }

        impl_get_data_for_command!($command, u8, Return, (), error::Error);

        impl_command_data_future!(Return, (), error::Error);
    }
}

 #[derive(Debug)]
enum OutputErr<TargErr, CmdErr>
where TargErr: Display + Debug,
      CmdErr: Display + Debug,
{
    /// An error occured at the target specific HCI implementation
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
                            let ret = Err(crate::hci::OutputErr::ReceivedIncorrectEvent(event.get_enum_name()));

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

macro_rules! impl_command_data_future {
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
                    (&data as &dyn crate::hci::events::GetDataForCommand<$data_type>)
                        .get_return()
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
    ($data: ty, $try_from_err_ty:ty) => { impl_command_data_future!($data, $data, $try_from_err_ty); };
}

macro_rules!  impl_command_status_future {
    () => {
        impl_returned_future!{
            (),
            crate::hci::events::EventsData::CommandStatus,
            data,
            &'static str,
            {
                use crate::hci::OutputErr::CommandStatusErr;

                if let crate::hci::error::Error::NoError = data.status {
                    core::task::Poll::Ready(Ok(()))
                } else {
                    core::task::Poll::Ready(Err(CommandStatusErr(data.status)))
                }
            }
        }
    };
}

pub mod le;
pub mod link_control;
pub mod link_policy;
pub mod cb;
pub mod info_params;
pub mod status_prams;
pub mod testing;
