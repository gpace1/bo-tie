//! A local channel with statically allocated buffers
//!
//! A static channel contains buffers that are on the stack instead of dynamically allocated. This
//! creates the limitation on the number of entries the channel can buffer, but it doesn't mean the
//! channel will error or panic if the buffer fills to full. Instead the channel will await when the
//! user tries to send when the buffer is full.
//!
//! This is a local channel so it can only be used between async tasks running on the same thread.
//! Furthermore, The channel must be created before the asynchronous tasks are because the buffer is
//! allocated on the stack. Tasks must use the channel through a reference to it in order to
//! guarantee the lifetime of the buffer.

use super::LocalSendFutureError;
use crate::local_channel::local_stack::buffered_channel::{
    LocalBufferedChannel, ReservedBuffer, TakeBuffer, UnsafeReservedBuffer,
};
use crate::local_channel::local_stack::channel::LocalChannel;
use crate::local_channel::local_stack::receiver::LocalChannelReceiver;
use crate::local_channel::local_stack::sender::LocalChannelSender;
use crate::{
    BufferReserve, Channel, ChannelReserve, ConnectionChannelEnds as ChannelEndsTrait, ConnectionHandle, FlowControlId,
    FlowCtrlReceiver, FromConnectionIntraMessage, FromHostIntraMessage, FromInterface, HostChannel,
    HostChannelEnds as HostChannelEndsTrait, InterfaceReceivers, TaskId, ToConnectionIntraMessage,
    ToHostCommandIntraMessage, ToHostGeneralIntraMessage,
};
use bo_tie_util::buffer::stack::{
    BufferReservation, DeLinearBuffer, LinearBuffer, Reservation, StackHotel, UnsafeBufferReservation,
    UnsafeReservation,
};
use core::cell::RefCell;
use core::fmt::{Display, Formatter};

mod buffered_channel;
mod channel;
mod receiver;
mod sender;

// *******************
// Shortcut types
//
// Many of the channel and message types have the constant generics repeated multiple times within
// themselves. To ease in implementation these aliases were used to consolidate the constant
// generics into a single declaration.

type ToHostGenMsg<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    ToHostGeneralIntraMessage<ConnectionEnds<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>;

type UnsafeToHostGenMsg<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    ToHostGeneralIntraMessage<UnsafeConnectionEnds<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>;

type FromHostMsg<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    FromHostIntraMessage<BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>;

type UnsafeFromHostMsg<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    FromHostIntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>;

type ToConnMsg<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    ToConnectionIntraMessage<
        ReservedBuffer<
            'a,
            TASK_COUNT,
            CHANNEL_SIZE,
            DeLinearBuffer<BUFFER_SIZE, u8>,
            UnsafeToConnMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        >,
    >;

// This requires the usage of keyword `Self` so this cannot be a type
// alias and needs to be declared as a structure
#[doc(hidden)]
pub struct UnsafeToConnMsg<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>(
    ToConnectionIntraMessage<UnsafeReservedBuffer<TASK_COUNT, CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, Self>>,
);

type FromConnMsg<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    FromConnectionIntraMessage<BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>;

type UnsafeFromConnMsg<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    FromConnectionIntraMessage<UnsafeBufferReservation<DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>>;

type ToHostCmdChannel<const CHANNEL_SIZE: usize> = LocalChannel<CHANNEL_SIZE, ToHostCommandIntraMessage>;

type ToHostGenChannel<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    LocalChannel<CHANNEL_SIZE, ToHostGeneralIntraMessage<UnsafeConnectionEnds<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>>;

type FromHostChannel<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    LocalBufferedChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, UnsafeFromHostMsg<CHANNEL_SIZE, BUFFER_SIZE>>;

type ToConnectionChannel<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    LocalBufferedChannel<
        CHANNEL_SIZE,
        DeLinearBuffer<BUFFER_SIZE, u8>,
        UnsafeToConnMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >;

type FromConnectionChannel<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> =
    LocalBufferedChannel<CHANNEL_SIZE, DeLinearBuffer<BUFFER_SIZE, u8>, UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>>;

type FlowControlReceiver<'a, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> = FlowCtrlReceiver<
    <&'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE> as Channel>::Receiver,
    <&'a FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE> as Channel>::Receiver,
>;

/// Data used for managing a connection async task
///
/// This contains the channel used for sending data to a connection async task along with the flow
/// control information for messages sent from it.
struct ConnectionData<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    channel: Reservation<'z, ToConnectionChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    handle: ConnectionHandle,
    flow_ctrl_id: FlowControlId,
}

/// Ends of channel for a connection async task
///
/// These are the channel ends used by a connection async task to communicate with the interface
/// async task.
pub struct ConnectionEnds<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    sender_channel: &'z FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    receiver: LocalChannelReceiver<
        CHANNEL_SIZE,
        Reservation<'z, ToConnectionChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >,
}

impl<'z, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelEndsTrait
    for ConnectionEnds<'z, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type ToBuffer = BufferReservation<'z, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type FromBuffer = ReservedBuffer<
        'z,
        TASK_COUNT,
        CHANNEL_SIZE,
        DeLinearBuffer<BUFFER_SIZE, u8>,
        UnsafeToConnMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >;

    type TakeBuffer = TakeBuffer<&'z FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>>;

    type Sender = LocalChannelSender<
        CHANNEL_SIZE,
        &'z FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
        UnsafeFromConnMsg<CHANNEL_SIZE, BUFFER_SIZE>,
    >;

    type Receiver = LocalChannelReceiver<
        CHANNEL_SIZE,
        Reservation<'z, ToConnectionChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
        UnsafeToConnMsg<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    >;

    fn get_sender(&self) -> Self::Sender {
        (&self.sender_channel).get_sender()
    }

    fn take_buffer<F, B>(&self, front_capacity: F, back_capacity: B) -> Self::TakeBuffer
    where
        F: Into<Option<usize>>,
        B: Into<Option<usize>>,
    {
        self.sender_channel.take(front_capacity, back_capacity)
    }

    fn get_receiver(&self) -> &Self::Receiver {
        &self.receiver
    }

    fn get_mut_receiver(&mut self) -> &mut Self::Receiver {
        &mut self.receiver
    }
}

/// Unsafe `StackChannelEnds`
///
/// Because `StackChannelEnds` contains a lifetime, it cannot be part of the type
/// `LocalStackChannelReserveData` as it would be self-referential. An `UnsafeStackChannelEnds` is
/// used as the intermediary
pub struct UnsafeConnectionEnds<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    sender_channel: *const FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    unsafe_receive_channel: UnsafeReservation<ToConnectionChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    UnsafeConnectionEnds<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    unsafe fn from(ends: ConnectionEnds<'_, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>) -> Self {
        let sender_channel = ends.sender_channel as *const _;

        let reservation: Reservation<'_, _, TASK_COUNT> = ends.receiver.forget_and_unwrap();

        let unsafe_receive_channel = Reservation::to_unsafe(reservation);

        UnsafeConnectionEnds {
            sender_channel,
            unsafe_receive_channel,
        }
    }

    unsafe fn into<'a>(self) -> ConnectionEnds<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE> {
        let receiver_reservation = UnsafeReservation::rebind(self.unsafe_receive_channel);

        // new is deliberately not called to create the receiver.
        // This method is intended to act like a 'rebuilding' of a
        // StackChannelEnds, not the creation a 'new' StackChannelEnds.
        let receiver = LocalChannelReceiver::new(receiver_reservation);

        let sender_channel = self.sender_channel.as_ref().unwrap();

        ConnectionEnds {
            sender_channel,
            receiver,
        }
    }
}

/// Channels for messages sent from the interface async task
struct Outgoing<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    connections: StackHotel<ToConnectionChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>,
    host_cmd: ToHostCmdChannel<CHANNEL_SIZE>,
    host_gen: ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
}

/// Channels for messages received by the interface async task
struct Incoming<const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    cmd: FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    acl: FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    sco: FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    le_acl: FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    le_iso: FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>,
}

/// [`LocalStackChannelReserve`] data
///
/// This is the data that is allocating on the stack for a LocalStackChannelReserve. The main
/// purpose of a `LocalStackChannelReserveData` is to not hold the data, but to give the
/// [`LocalStackChannelReserve`] something to refer to. This is a limitation of a `StackHotel` as it
/// needs something to put a lifetime to when taking a reservation, and a reserve is made up of
/// multiple `StackHotels`.
pub struct LocalStackChannelReserveData<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    outgoing: Outgoing<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    incoming: Incoming<CHANNEL_SIZE, BUFFER_SIZE>,
}

impl<const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserveData`
    ///
    /// The inputs `max_header_size` and `max_tail_size` are the maximum size of the header and the
    /// maximum size of the tail applied to the HCI packets by the interface driver.
    pub fn new() -> Self {
        let outgoing = Outgoing {
            connections: StackHotel::new(),
            host_cmd: ToHostCmdChannel::new(),
            host_gen: ToHostGenChannel::new(),
        };

        let incoming = Incoming {
            cmd: FromHostChannel::new(),
            acl: FromConnectionChannel::new(),
            sco: FromConnectionChannel::new(),
            le_acl: FromConnectionChannel::new(),
            le_iso: FromConnectionChannel::new(),
        };

        Self { outgoing, incoming }
    }
}

/// A reserve of static channels for local communication
///
/// These are channels that are buffered through static allocation instead of dynamic allocation.
/// This means both the maximum number of channels and the size of the buffers of each channel must
/// be known at compile time and fully be allocated at runtime (static memory structures cannot
/// "grow" to their maximum size). `LocalStackChannels` is intended to be used only where dynamic
/// allocation is not possible.
pub struct LocalStackChannelReserve<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    data: &'a LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
    connection_data: RefCell<LinearBuffer<TASK_COUNT, ConnectionData<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>>,
    flow_ctrl_receiver: FlowControlReceiver<'a, CHANNEL_SIZE, BUFFER_SIZE>,
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    LocalStackChannelReserve<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    /// Create a new `LocalStackChannelReserve`
    ///
    /// This creates a new `LocalStackChannelReserve` from the provided `rx_channel` and
    /// `tx_channel`. While these objects may be put on the heap, the references are expected to be
    /// of stack allocated types. Otherwise using a
    /// [`LocalChannelReserve`](crate::local_channel::local_dynamic::LocalChannelReserve) is
    /// preferred.
    ///
    /// The inputs `max_header_size` and `max_tail_size` are the maximum size of the header and tail
    /// that is applied to HCI packets by the interface driver in order to create the packet that is
    /// transferred over the interface. These values are implementation specific to the kind of
    /// interface used. If there is no header or tail applied to HCI packets, then set the value to
    /// zero. **The value of the constant `BUFFER_SIZE` should factor in the values of
    /// `max_header_size` and `max_tail_size`.
    pub fn new(
        data: &'a LocalStackChannelReserveData<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>,
        max_header_size: usize,
        max_tail_size: usize,
    ) -> (Self, impl HostChannelEndsTrait + 'a) {
        let task_data = RefCell::new(LinearBuffer::new());

        let host_ends = HostChannelEnds {
            driver_front_capacity: max_header_size,
            driver_back_capacity: max_tail_size,
            from_host_channel: &data.incoming.cmd,
            to_host_cmd_recv: (&data.outgoing.host_cmd).take_receiver().unwrap(),
            to_host_gen_recv: (&data.outgoing.host_gen).take_receiver().unwrap(),
        };

        let receivers = InterfaceReceivers {
            cmd_receiver: (&data.incoming.cmd).take_receiver().unwrap(),
            acl_receiver: (&data.incoming.acl).take_receiver().unwrap(),
            sco_receiver: (&data.incoming.sco).take_receiver().unwrap(),
            le_acl_receiver: (&data.incoming.le_acl).take_receiver().unwrap(),
            le_iso_receiver: (&data.incoming.le_iso).take_receiver().unwrap(),
        };

        let flow_ctrl_receiver = FlowCtrlReceiver::new(receivers);

        let this = Self {
            data,
            connection_data: task_data,
            flow_ctrl_receiver,
        };

        (this, host_ends)
    }
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> ChannelReserve
    for LocalStackChannelReserve<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type Error = LocalStackChannelsError;

    type SenderError = LocalSendFutureError;

    type ToHostCmdChannel = &'a ToHostCmdChannel<CHANNEL_SIZE>;

    type ToHostGenChannel = &'a ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;

    type FromHostChannel = &'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>;

    type ToConnectionChannel = Reservation<'a, ToConnectionChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>, TASK_COUNT>;

    type FromConnectionChannel = &'a FromConnectionChannel<CHANNEL_SIZE, BUFFER_SIZE>;

    type ConnectionChannelEnds = ConnectionEnds<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;

    fn try_remove(&mut self, connection_handle: ConnectionHandle) -> Result<(), Self::Error> {
        if let Ok(at) = self
            .connection_data
            .get_mut()
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
        {
            self.connection_data
                .get_mut()
                .try_remove(at)
                .map(|_| ())
                .map_err(|_| unreachable!())
        } else {
            Err(LocalStackChannelsError::ChannelForIdDoesNotExist)
        }
    }

    fn add_new_connection(
        &self,
        connection_handle: ConnectionHandle,
        flow_ctrl_id: FlowControlId,
    ) -> Result<Self::ConnectionChannelEnds, Self::Error> {
        let sender_channel = match flow_ctrl_id {
            FlowControlId::Cmd => return Err(LocalStackChannelsError::InvalidFlowControlForConnection),
            FlowControlId::Acl => &self.data.incoming.acl,
            FlowControlId::Sco => &self.data.incoming.sco,
            FlowControlId::LeAcl => &self.data.incoming.le_acl,
            FlowControlId::LeIso => &self.data.incoming.le_iso,
        };

        let insertion_index = self
            .connection_data
            .borrow()
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
            .expect_err("handle already associated to another async task");

        let new_channel = self
            .data
            .outgoing
            .connections
            .take(ToConnectionChannel::new())
            .ok_or(LocalStackChannelsError::TaskCountReached)?;

        let new_channel_clone = new_channel.clone();

        let new_task_data = ConnectionData {
            channel: new_channel,
            handle: connection_handle,
            flow_ctrl_id,
        };

        self.connection_data
            .borrow_mut()
            .try_insert(new_task_data, insertion_index)
            .map_err(|_| LocalStackChannelsError::TaskCountReached)?;

        let receiver = new_channel_clone.take_receiver().unwrap();

        Ok(ConnectionEnds {
            sender_channel,
            receiver,
        })
    }

    fn get_channel(
        &self,
        id: TaskId,
    ) -> Option<FromInterface<Self::ToHostCmdChannel, Self::ToHostGenChannel, Self::ToConnectionChannel>> {
        match id {
            TaskId::Host(HostChannel::Command) => Some(FromInterface::HostCommand(&self.data.outgoing.host_cmd)),
            TaskId::Host(HostChannel::General) => Some(FromInterface::HostGeneral(&self.data.outgoing.host_gen)),
            TaskId::Connection(connection_handle) => {
                let ref_task_data = self.connection_data.borrow();

                ref_task_data
                    .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
                    .ok()
                    .and_then(|index| ref_task_data.get(index))
                    .map(|ConnectionData { channel, .. }| FromInterface::Connection(channel.clone()))
            }
        }
    }

    fn get_flow_control_id(&self, connection_handle: ConnectionHandle) -> Option<FlowControlId> {
        let ref_task_data = self.connection_data.borrow();

        ref_task_data
            .binary_search_by(|ConnectionData { handle, .. }| handle.cmp(&connection_handle))
            .ok()
            .and_then(|index| ref_task_data.get(index))
            .map(|ConnectionData { flow_ctrl_id, .. }| *flow_ctrl_id)
    }

    fn get_flow_ctrl_receiver(
        &mut self,
    ) -> &mut FlowCtrlReceiver<
        <Self::FromHostChannel as Channel>::Receiver,
        <Self::FromConnectionChannel as Channel>::Receiver,
    > {
        &mut self.flow_ctrl_receiver
    }
}

struct HostChannelEnds<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> {
    driver_front_capacity: usize,
    driver_back_capacity: usize,
    from_host_channel: &'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE>,
    to_host_cmd_recv: <&'a ToHostCmdChannel<CHANNEL_SIZE> as Channel>::Receiver,
    to_host_gen_recv: <&'a ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE> as Channel>::Receiver,
}

impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize> HostChannelEndsTrait
    for HostChannelEnds<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>
{
    type ToBuffer = BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type FromBuffer = BufferReservation<'a, DeLinearBuffer<BUFFER_SIZE, u8>, CHANNEL_SIZE>;

    type TakeBuffer = <&'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE> as BufferReserve>::TakeBuffer;

    type Sender = <&'a FromHostChannel<CHANNEL_SIZE, BUFFER_SIZE> as Channel>::Sender;

    type CmdReceiver = <&'a ToHostCmdChannel<CHANNEL_SIZE> as Channel>::Receiver;

    type GenReceiver = <&'a ToHostGenChannel<TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE> as Channel>::Receiver;

    type ConnectionChannelEnds = ConnectionEnds<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>;

    fn driver_buffer_capacities(&self) -> (usize, usize) {
        (self.driver_front_capacity, self.driver_back_capacity)
    }

    fn get_sender(&self) -> Self::Sender {
        self.from_host_channel.get_sender()
    }

    fn take_buffer<C>(&self, front_capacity: C) -> Self::TakeBuffer
    where
        C: Into<Option<usize>>,
    {
        self.from_host_channel
            .take(front_capacity.into().unwrap_or_default(), None)
    }

    fn get_cmd_recv(&self) -> &Self::CmdReceiver {
        &self.to_host_cmd_recv
    }

    fn get_mut_cmd_recv(&mut self) -> &mut Self::CmdReceiver {
        &mut self.to_host_cmd_recv
    }

    fn get_gen_recv(&self) -> &Self::GenReceiver {
        &self.to_host_gen_recv
    }

    fn get_mut_gen_recv(&mut self) -> &mut Self::GenReceiver {
        &mut self.to_host_gen_recv
    }
}

#[derive(Debug)]
pub enum LocalStackChannelsError {
    TaskCountReached,
    ChannelIdAlreadyUsed,
    ChannelForIdDoesNotExist,
    InvalidFlowControlForConnection,
}

impl Display for LocalStackChannelsError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            LocalStackChannelsError::TaskCountReached => f.write_str("reached maximum channel count"),
            LocalStackChannelsError::ChannelIdAlreadyUsed => f.write_str("id already used"),
            LocalStackChannelsError::ChannelForIdDoesNotExist => {
                f.write_str("no channel is associated with the provided id")
            }
            LocalStackChannelsError::InvalidFlowControlForConnection => {
                f.write_str("flow control for HCI commands cannot be used for connections")
            }
        }
    }
}
