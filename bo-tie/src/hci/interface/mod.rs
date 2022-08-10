//! Implementation for the interface between the host and controller
//!
//! The host is split up between a host functional component and an interface component. The host
//! functional part contains the controller commanding and data processing portions which are
//! referred to the host-controller async task and connection async task respectively. The interface
//! portion of the host is referred to as the interface async task. Its job is to constantly service
//! the driver and controller for messages to and from it.
//!
//! An interface async task is platform specific. It is needs to include the driver to the interface
//! as well as an `Interface`. It needs to be implemented to constantly listen to both data coming
//! from the other async tasks and data coming from the interface.
//!
//! ## Messaging
//! The interface async task is the gateway to the interface. HCI packets to and from the controller
//! must go through the interface async task and consequently HCI packets from other async tasks
//! must also go through the interface. The interface async task's job is to constantly await the
//! physical interface, so its the only safe way to handle messaging to the controller. The main
//! reason is so that it can quickly serve the interface driver (usually to flush peripheral
//! buffers), but also to capture HCI events not awaited upon by another async task.
//!
//! Messaging between the interface async task and the other async tasks is done through
//! asynchronous multiple producer single consumer (mpsc) channels. There is always two of these
//! channels for the host async task and every connection async task. This is what allows for the
//! async tasks to be separated from monitoring the controller. This library classifies channels
//! into two kinds, 'send safe' and 'local'. If the channels are send safe, then all async tasks
//! will be send safe (assuming the user doesn't have `!Send` implementation), because channels
//! happen to be the defining component for the HCI async tasks to implement `Send`. A Local channel
//! does not `Send` (which means the async tasks are also !Send) but they're designed to run
//! efficiently within the same thread. They also do not require allocation when using a local
//! static channel.
//!
//! ## Specification Defined Interfaces
//! There are four types of interfaces mentioned within the Bluetooth Specification (v5.2) but
//! interfacing between the host and controller can be done via any interface so long as the host
//! to controller functional specification can be applied to it. As a general rule any interface
//! can work so long as there is a way to send and receive data between the host and controller
//! asynchronously in respect to either side's CPU.
//!
//! UART, USB, Secure Digital (SD), and Three-Wire UART interfaces have defined specification for
//! how to use them with the functional specification. Everything that is defined within the
//! specification is implemented within this library, but this only covers the data encapsulation
//! and some of configuration details.

use crate::hci::common::ConnectionHandle;
use crate::hci::events::Events;
use crate::hci::interface::flow_control::FlowControlQueues;
use crate::hci::{events, Buffer, BufferReserve, CommandEventMatcher};
use core::borrow::Borrow;
use core::fmt::{Debug, Display, Formatter};
use core::future::Future;
use core::mem::take;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll};

mod flow_control;
pub(super) mod local_channel;
pub mod uart;

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
    const fn to_mask(&self) -> usize {
        match self {
            FlowControlId::Cmd => 1 << 0,
            FlowControlId::Acl => 1 << 1,
            FlowControlId::Sco => 1 << 2,
            FlowControlId::LeAcl => 1 << 3,
            FlowControlId::LeIso => 1 << 4,
        }
    }

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

/// Trait for retreiving the size of a payload
trait PayloadSize {
    fn payload_size(&self) -> usize;
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
    fn halt(&mut self) {
        if let FlowControl::DataBlocks { halted, .. } = self {
            *halted = true
        }
    }

    /// Release from the halted state
    fn release(&mut self) {
        if let FlowControl::DataBlocks { halted, .. } = self {
            *halted = false
        }
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
    type SenderError: Debug;

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
pub trait ChannelEnds {
    /// The buffer type of messages *to* the interface async task
    type ToBuffer: Buffer;

    /// The buffer type of messages *from* the interface async task
    type FromBuffer: Buffer;

    /// The future for acquiring a buffer from the channel to send
    type TakeBuffer: Future<Output = Self::ToBuffer>;

    /// The type used to send messages to the interface async task
    type Sender: Sender<Message = IntraMessage<Self::ToBuffer>>;

    /// The type used for receiving messages from the interface async task
    type Receiver: Receiver<Message = IntraMessage<Self::FromBuffer>>;

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
    type Error;

    /// The error returned by the implementation of Sender
    ///
    /// This is the same type as `Error` of [`Sender`]
    type SenderError: Debug;

    /// The error that occurs when trying to extend a buffer fails
    type TryExtendError: Debug;

    /// The buffer for creating a message sent from the interface async task *to* another
    /// async task
    type ToBuffer<'a>: Unpin + crate::TryExtend<u8, Error = Self::TryExtendError> + Deref<Target = [u8]>
    where
        Self: 'a;

    /// The mpsc channel type for sending messages from the interface async task *to* another async
    /// task
    type ToChannel<'a>: BufferReserve<Buffer = Self::ToBuffer<'a>>
        + Channel<SenderError = Self::SenderError, Message = IntraMessage<Self::ToBuffer<'a>>>
    where
        Self: 'a;

    /// The buffer for creating a message sent *from* another async task to the interface async
    /// task
    type FromBuffer: Unpin + crate::TryExtend<u8, Error = Self::TryExtendError> + Deref<Target = [u8]>;

    /// The mpsc channel type for the interface async task to receiving messages *from* another
    /// async task
    type FromChannel: BufferReserve<Buffer = Self::FromBuffer>
        + Channel<SenderError = Self::SenderError, Message = IntraMessage<Self::FromBuffer>>;

    /// The ends of the channels used by another async task to communicate with the interface async
    /// task.
    type OtherTaskEnds<'a>: ChannelEnds<ToBuffer = Self::FromBuffer>
    where
        Self: 'a;

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
        &mut self,
        task_id: TaskId,
        flow_control_id: FlowControlId,
    ) -> Result<Self::OtherTaskEnds<'_>, Self::Error>;

    /// Get the channel for sending messages *to* the async task associated by the specified task ID
    ///
    /// `None` is returned if no channel is associated with the input identifier.
    fn get(&self, id: TaskId) -> Option<Self::ToChannel<'_>>;

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

trait ChannelReserveExt: ChannelReserve {
    /// Prepare for sending a message
    ///
    /// If there is a channel with provided `ChannelId` in this `ChannelReserve`, then a
    /// `GetPrepareSend` is returned. The return is a future that outputs a `PrepareSend` when it
    /// can acquire a message from this buffer reserve. The output `PrepareSend` can then be used
    /// to modify the message before it can be used as a future to send the message.
    fn prepare_send(
        &self,
        id: TaskId,
        front_capacity: usize,
    ) -> Option<
        GetPrepareSend<<Self::ToChannel<'_> as Channel>::Sender, <Self::ToChannel<'_> as BufferReserve>::TakeBuffer>,
    > {
        self.get(id)
            .map(|channel| GetPrepareSend::from_channel(&channel, front_capacity))
    }

    /// Receive the next message
    fn receive_next(&mut self) -> ReceiveNext<'_, <Self::FromChannel as Channel>::Receiver> {
        self.get_flow_ctrl_receiver().receive_next()
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
pub struct GetPrepareSend<S, T> {
    sender: Option<S>,
    take_buffer: T,
}

impl<S, T> GetPrepareSend<S, T> {
    fn from_channel<'a, C>(channel: &'a C, front_capacity: usize) -> Self
    where
        C: Channel<Sender = S> + BufferReserve<TakeBuffer = T>,
        T: 'a,
    {
        let take_buffer = channel.take(front_capacity);
        let sender = Some(channel.get_sender());

        GetPrepareSend { sender, take_buffer }
    }

    fn new(take_buffer: T, sender: S) -> Self {
        let sender = Some(sender);

        GetPrepareSend { sender, take_buffer }
    }
}

impl<S, T> Future for GetPrepareSend<S, T>
where
    T: Future,
{
    type Output = PrepareSend<S, T::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        unsafe { Pin::new_unchecked(&mut this.take_buffer) }
            .poll(cx)
            .map(|buffer| {
                let sender = this.sender.take().expect("GetPrepareSend already polled to completion");

                PrepareSend::new(sender, buffer)
            })
    }
}

/// A Preparer for sending a message
///
/// The point of a `PrepareSend` is to write the message before sending the message. The main point
/// of this is for optimizing where buffers reserves benefit being written in-place, such as static
/// allocated memory.
///
/// A `PrepareSend` contains the message to be sent. It can be modified through `AsRef`/`AsMut` as
/// well as the crate traits `TryExtend`/`TryRemove`/`TryFrontExtend`/`TryFrontRemove`. Once
/// modification of the message is done, a `PrepareSend` can be converted into a future with the
/// function [`and_send`](PrepareSend::and_send) to send the message.
pub struct PrepareSend<S, B> {
    sender: S,
    buffer: B,
}

impl<S, B> PrepareSend<S, B> {
    fn new(sender: S, buffer: B) -> Self {
        Self { sender, buffer }
    }

    /// Take a `PrepareSend` and return a future to send a message
    ///
    /// This take a `PrepareSend` and a closure `f` to convert the buffered data into a message (of
    /// type M) and return a future for sending the message.
    pub async fn and_send<F>(ps: Self, f: F) -> Result<(), S::Error>
    where
        S: Sender<Message = IntraMessage<B>>,
        F: FnOnce(B) -> IntraMessage<B>,
    {
        let message = f(ps.buffer);

        ps.sender.send(message).await
    }
}

impl<S, B> AsRef<B> for PrepareSend<S, B> {
    fn as_ref(&self) -> &B {
        &self.buffer
    }
}

impl<S, B> AsMut<B> for PrepareSend<S, B> {
    fn as_mut(&mut self) -> &mut B {
        &mut self.buffer
    }
}

impl<S, B> Deref for PrepareSend<S, B>
where
    B: Deref<Target = [u8]>,
{
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.buffer
    }
}

impl<S, B> crate::TryExtend<u8> for PrepareSend<S, B>
where
    B: crate::TryExtend<u8>,
{
    type Error = B::Error;

    fn try_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        self.buffer.try_extend(iter)
    }
}

impl<S, B> crate::TryRemove<u8> for PrepareSend<S, B>
where
    B: crate::TryRemove<u8>,
{
    type Error = B::Error;
    type RemoveIter<'a> = B::RemoveIter<'a> where Self: 'a;

    fn try_remove(&mut self, how_many: usize) -> Result<Self::RemoveIter<'_>, Self::Error> {
        self.buffer.try_remove(how_many)
    }
}

impl<S, B> crate::TryFrontExtend<u8> for PrepareSend<S, B>
where
    B: crate::TryFrontExtend<u8>,
{
    type Error = B::Error;

    fn try_front_extend<T>(&mut self, iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = u8>,
    {
        self.buffer.try_front_extend(iter)
    }
}

impl<S, B> crate::TryFrontRemove<u8> for PrepareSend<S, B>
where
    B: crate::TryFrontRemove<u8>,
{
    type Error = B::Error;
    type FrontRemoveIter<'a> = B::FrontRemoveIter<'a> where Self: 'a;

    fn try_front_remove(&mut self, how_many: usize) -> Result<Self::FrontRemoveIter<'_>, Self::Error> {
        self.buffer.try_front_remove(how_many)
    }
}

/// Receivers used by an interface async task
struct InterfaceReceivers<R> {
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
    fn new(receivers: InterfaceReceivers<R>) -> Self {
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

    fn receive_next(&mut self) -> ReceiveNext<'_, R> {
        ReceiveNext(self)
    }
}

/// A future for receiving from a async task
///
/// This is the receiver for receiving messages from any other async task.
///
/// # Note
/// When all async tasks are closed, when polled `RecvNext` will return `None`.
struct ReceiveNext<'a, R: Receiver>(&'a mut FlowCtrlReceiver<R>);

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

/// The interface
///
/// An `Interface` is the component of the host that must run with the interface driver. Its the
/// part of the host that must perpetually await upon the
pub struct Interface<R> {
    channel_reserve: R,
}

impl Interface<local_channel::local_dynamic_channel::LocalChannelManager> {
    /// Create a new local `Interface`
    ///
    /// This host controller interface is local to a single thread. The interface, host, and
    /// connections async tasks must run on an local executor or other type of executor that does
    /// not require async tasks to be thread safe.
    ///
    /// # Note
    /// A local interface uses dynamic memory allocation for buffering and messages between async
    /// tasks. A pure `no_std` implementation can be created with
    /// [`new_local_static`](Interface::new_local_static).
    ///
    /// # Panic
    /// Input `task_count` must be greater or equal to one.
    pub(super) fn new_local(task_count: usize) -> Self {
        let mut channel_reserve = local_channel::local_dynamic_channel::LocalChannelManager::new(task_count);

        Interface { channel_reserve }
    }
}

#[cfg(feature = "unstable")]
impl<'a, const TASK_COUNT: usize, const CHANNEL_SIZE: usize, const BUFFER_SIZE: usize>
    Interface<local_channel::local_stack_channel::LocalStackChannelReserve<'a, TASK_COUNT, CHANNEL_SIZE, BUFFER_SIZE>>
{
    /// Create a statically sized local interface
    ///
    /// This host controller interface is local to a single thread. The interface, host, and
    /// connections async tasks must run on an local executor or other type of executor that does
    /// not require async tasks to be thread safe.
    ///
    /// The number of channels is defined by the constant `CHANNEL_COUNT`. The interface task has
    /// two channels to ever other task, this constant must be equal to two times the number of
    /// connection async tasks plus two for the channels to the host async task.
    pub(super) fn new_stack_local(
        channel_reserve_data: &'a local_channel::local_stack_channel::LocalStackChannelReserveData<
            TASK_COUNT,
            CHANNEL_SIZE,
            BUFFER_SIZE,
        >,
    ) -> Self {
        let mut channel_reserve =
            local_channel::local_stack_channel::LocalStackChannelReserve::new(channel_reserve_data);

        Interface { channel_reserve }
    }
}

impl<R> Interface<R>
where
    R: ChannelReserve,
{
    /// Get the channel reserve
    pub(super) fn get_mut_reserve(&mut self) -> &mut R {
        &mut self.channel_reserve
    }

    /// Buffer received HCI packet from the interface until it can be sent upwards
    ///
    /// An interface may be unable to receive complete HCI packets from the interface. Instead of
    /// having the driver process the fragmented HCI packet into complete fragment, a buffered send
    /// can be used to do this. This buffers interface data until a complete packet is held within
    /// the buffer. The buffered send is consumed and then the HCI packet is sent upward (either to
    /// the host or connection async task).
    ///
    /// ```
    /// # #![feature(generic_associated_types)]
    /// # use std::future::Future;
    /// # use std::pin::Pin;
    /// # use std::task::{Context, Poll};
    /// # use std::fmt::Debug;
    /// # use crate::bo_tie::hci::interface::{BufferSend, Channel, TaskId, ChannelReserve, HciPacket, HciPacketType, Interface, Receiver, Sender};
    /// #
    /// # struct Sf;
    /// # impl Future for Sf {
    /// #     type Output = Result<(), ()>;
    /// #
    /// #     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct Rf;
    /// # impl Future for Rf {
    /// #     type Output = Option<HciPacket<()>>;
    /// #
    /// #     fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct S;
    /// # impl Sender for S {
    /// #     type Error = ();
    /// #     type Payload = ();
    /// #     type SendFuture<'a> = Sf;
    /// #
    /// #     fn send<'a>(&'a mut self, t: HciPacket<Self::Message>) -> Self::SendFuture<'a> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct R;
    /// # impl Receiver for R {
    /// # type Message = ();
    /// # type ReceiveFuture<'a> = Rf;
    /// #
    /// #     fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a> {
    /// #         unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # struct C;
    /// # impl Channel for C {
    /// #    type Sender<'a> = S;
    /// #    type Receiver<'a> = R;
    /// #    
    /// #    fn get_to_sender<'a>(&'a self) -> Self::Sender<'a> {
    /// #        unimplemented!()
    /// #    }
    /// #    
    /// #    fn get_to_receiver<'a>(&'a self) -> Self::Receiver<'a> {
    /// #        unimplemented!()
    /// #    }
    /// # }
    /// #
    /// # struct CM;
    /// # impl ChannelReserve for CM {
    /// #    type Error = usize;
    /// #    type ToChannel = C;
    /// #
    /// #    fn get_self_receiver(&self) -> &Self::ToChannel {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn try_add(&mut self, id: TaskId) -> Result<usize, Self::Error> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn try_remove(&mut self, id: TaskId) -> Result<Self::ToChannel, Self::Error> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn get(&self, id: TaskId) -> Option<&Self::ToChannel> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn get_by_index(&self, index: usize) -> Option<&Self::ToChannel> {
    /// #        unimplemented!()
    /// #    }
    /// # }
    /// #
    /// # struct Driver;
    /// # impl Driver {
    /// #    fn read_packet_type(&self) -> HciPacketType { unimplemented!() }
    /// #
    /// #    async fn read_byte(&self) -> u8 { unimplemented!() }
    /// # }
    /// #
    /// # async {
    /// # let mut interface = Interface::<Vec<u8>>::new_local(0);
    /// # let driver = Driver;
    /// # let packet_type = HciPacketType::Command;
    /// # let _ = {
    /// // The Bluetooth Specification leaves how to determine the type
    /// // of a HCI packet to the interface implementation. Here this
    /// // is magically done in the dummy method `read_packet_type`. How
    /// // it is done for a driver is a bit more complicated.
    /// let packet_type: HciPacketType = driver.read_packet_type();
    ///
    /// let mut buffer_send = interface.buffer_send(packet_type);
    ///
    /// // Bytes are
    /// while !buffer_send.add(driver.read_byte().await) {}
    ///
    /// buffer_send.send().await
    /// # }.ok();
    /// # };
    /// ```
    pub fn buffered_send(&mut self, packet_type: HciPacketType) -> BufferedSend<'_, R> {
        BufferedSend::new(self, packet_type)
    }

    /// Send a complete HCI packet
    ///
    /// This sends a complete `HciPacket` to the correct destination (either the host or a
    /// connection async task). It is up to the implementation to guarantee that the data within
    /// the packet is complete.
    pub async fn send(&mut self, packet_type: HciPacketType, packet: &[u8]) -> Result<(), SendError<R>> {
        match packet_type {
            HciPacketType::Command => Err(SendError::<R>::Command),
            HciPacketType::Acl => self.send_acl(packet).await.map_err(|e| e.into()),
            HciPacketType::Sco => Err(SendError::<R>::Unimplemented(HciPacketType::Sco)),
            HciPacketType::Event => self.maybe_send_event(packet).await.map_err(|e| e.into()),
            HciPacketType::Iso => Err(SendError::<R>::Unimplemented(HciPacketType::Iso)),
        }
    }

    /// Receive a HCI packet
    ///
    /// Await for the next `HciPacket` to be sent to the interface.
    ///
    /// This method returns `None` when there are no more Senders associated with the underlying
    /// receiver. The interface async task should exit after `None` is received.
    pub async fn recv<I>(&mut self, driver: &mut I) -> Option<I::Message>
    where
        I: InterfaceDriver<R::FromBuffer>,
    {
        self.channel_reserve
            .receive_next()
            .await
            .map(|intra_message| intra_message.into_driver_message(driver).unwrap())
    }

    /// Parse an event for information that is relevant to this interface
    ///
    /// The interface needs to know of a few things from certain events.
    ///
    /// `true` is returned if the event is to be returned to the host.
    ///
    /// # Processed Events
    /// * *Command Complete* and *Command Status* events contain the information on how many HCI
    ///   commands can be sent to the controller.
    /// * *Number of Completed Packets* event contains information on the number of packets sent for
    ///   a specific connection.
    /// * *Number of Completed Data Blocks* event contains information on the number of packets sent
    ///   and
    fn parse_event<E>(&mut self, event_data: &[u8]) -> Result<bool, SendMessageError<E>> {
        let first_byte = *event_data
            .get(0)
            .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Event))?;

        let len = 2usize
            + *event_data
                .get(1)
                .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Event))? as usize;

        let event_parameter = event_data
            .get(2..len)
            .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Event))?;

        match Events::try_from_event_codes(first_byte, 0 /* does not matter */) {
            Ok(Events::CommandComplete) => self.parse_command_complete_event(event_parameter),
            Ok(Events::CommandStatus) => self.parse_command_status_event(event_parameter),
            Ok(Events::NumberOfCompletedPackets) => self.parse_number_of_completed_packets_event(event_parameter),
            Ok(Events::NumberOfCompletedDataBlocks) => {
                self.parse_number_of_completed_data_blocks_event(event_parameter)
            }
            _ => Ok(true),
        }
    }

    /// Parse a command complete event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_command_complete_event<E>(&mut self, event_parameter: &[u8]) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::CommandCompleteData;
        use core::convert::TryFrom;

        let cc_data = CommandCompleteData::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::CommandComplete))?;

        if 0 != cc_data.number_of_hci_command_packets {
            self.channel_reserve
                .inc_cmd_flow_ctrl(cc_data.number_of_hci_command_packets.into());
        }

        Ok(cc_data.command_opcode.is_some())
    }

    /// Parse a command status event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_command_status_event<E>(&mut self, event_parameter: &[u8]) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::CommandStatusData;
        use core::convert::TryFrom;

        let cs_data = CommandStatusData::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::CommandStatus))?;

        if 0 != cs_data.number_of_hci_command_packets {
            self.channel_reserve
                .inc_cmd_flow_ctrl(cs_data.number_of_hci_command_packets.into());
        }

        Ok(cs_data.command_opcode.is_some())
    }

    /// Parse a Number of Completed Packets event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_number_of_completed_packets_event<E>(
        &mut self,
        event_parameter: &[u8],
    ) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::{Multiple, NumberOfCompletedPacketsData};
        use core::convert::TryFrom;

        let ncp_data = Multiple::<NumberOfCompletedPacketsData>::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::NumberOfCompletedPackets))?;

        for ncp in ncp_data {
            if 0 != ncp.completed_packets {
                let how_many: usize = ncp.completed_packets.into();

                let task_id = TaskId::Connection(ncp.connection_handle);

                match self
                    .channel_reserve
                    .get_flow_control_id(task_id)
                    .ok_or(SendMessageError::UnknownConnectionHandle(ncp.connection_handle))?
                {
                    FlowControlId::Acl => self.channel_reserve.inc_acl_flow_ctrl(how_many),
                    FlowControlId::Sco => self.channel_reserve.inc_sco_flow_control(how_many),
                    FlowControlId::LeAcl => self.channel_reserve.inc_le_acl_flow_control(how_many),
                    FlowControlId::LeIso => self.channel_reserve.inc_le_iso_flow_control(how_many),
                    FlowControlId::Cmd => panic!("unexpected flow control id 'Cmd'"),
                }
            }
        }

        Ok(false)
    }

    /// Parse a Number of Completed Data Blocks event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    ///
    /// If the return is `Ok` then it always contains `false`.
    fn parse_number_of_completed_data_blocks_event<E>(
        &mut self,
        event_parameter: &[u8],
    ) -> Result<bool, SendMessageError<E>> {
        use crate::hci::events::{CompletedDataPacketsAndBlocks, NumberOfCompletedDataBlocksData};
        use core::convert::TryFrom;

        let ncdb_data = NumberOfCompletedDataBlocksData::try_from(event_parameter)
            .map_err(|_| SendMessageError::InvalidHciEvent(Events::NumberOfCompletedDataBlocks))?;

        // This algorithm for flow control of the block buffers just
        // counts the total number of *bytes* that the controller can
        // accept (of one or more HCI payloads) within those buffers.
        // The total number of data blocks does not need to be counted
        // **unless** the controller sends back the need for the host
        // to re-check the block buffer information via the *Read Data
        // Block Size* command.
        if let None = ncdb_data.total_data_blocks {
            self.channel_reserve.get_flow_ctrl_receiver().acl_flow_control.halt();

            self.channel_reserve.get_flow_ctrl_receiver().le_acl_flow_control.halt();

            todo!("process of re-reading the data block buffer sizes not implemented yet")
        }

        for ncdb in ncdb_data.completed_packets_and_blocks {
            if 0 != ncdb.completed_blocks {
                let how_many: usize =
                    self.channel_reserve.get_flow_ctrl_receiver().block_size * <usize>::from(ncdb.completed_blocks);

                let task_id = TaskId::Connection(ncdb.connection_handle);

                match self
                    .channel_reserve
                    .get_flow_control_id(task_id)
                    .ok_or(SendMessageError::UnknownConnectionHandle(ncdb.connection_handle))?
                {
                    FlowControlId::Acl => self.channel_reserve.inc_acl_flow_ctrl(how_many),
                    FlowControlId::Sco => self.channel_reserve.inc_sco_flow_control(how_many),
                    FlowControlId::LeAcl => self.channel_reserve.inc_le_acl_flow_control(how_many),
                    FlowControlId::LeIso => self.channel_reserve.inc_le_iso_flow_control(how_many),
                    FlowControlId::Cmd => panic!("unexpected flow control id 'Cmd'"),
                }
            }
        }

        Ok(false)
    }

    /// Send an event to the host
    ///
    /// This will send the prepared event to the host so long it is not one of the events purely
    /// about the buffers on the controller.
    ///
    /// ## Informational Events
    /// The events *Number of Completed Packets*, *Number of Completed Data Blocks*, and when either
    /// *Command Complete* and *Command Status* does not contain a command code are not sent to the
    /// host. All the information within those events is only relevant to the interface async task.
    async fn maybe_send_event(&mut self, packet: &[u8]) -> Result<(), SendError<R>> {
        use crate::TryExtend;

        if self.parse_event(&packet)? {
            let mut prepare_send = self
                .channel_reserve
                .prepare_send(TaskId::Host, 0)
                .ok_or(SendError::<R>::HostClosed)?
                .await;

            prepare_send
                .try_extend(packet.iter().cloned())
                .map_err(|e| SendError::<R>::BufferExtend(e))?;

            PrepareSend::and_send(prepare_send, |buffer| IntraMessageType::Event(buffer).into())
                .await
                .map_err(|e| SendMessageError::ChannelError(e))?
        }

        Ok(())
    }

    async fn send_acl(&mut self, packet: &[u8]) -> Result<(), SendError<R>> {
        use crate::TryExtend;
        use core::convert::TryFrom;

        let raw_handle = <u16>::from_le_bytes([
            *packet
                .get(0)
                .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Acl))?,
            *packet
                .get(1)
                .ok_or(SendMessageError::InvalidHciPacket(HciPacketType::Acl))?,
        ]);

        let connection_handle =
            ConnectionHandle::try_from(raw_handle).map_err(|_| SendMessageError::InvalidConnectionHandle)?;

        let mut prepare_send = self
            .channel_reserve
            .prepare_send(TaskId::Connection(connection_handle), 0)
            .ok_or(SendError::<R>::HostClosed)?
            .await;

        prepare_send
            .try_extend(packet.iter().cloned())
            .map_err(|e| SendError::<R>::BufferExtend(e))?;

        PrepareSend::and_send(prepare_send, |buffer| IntraMessageType::Acl(buffer).into())
            .await
            .map_err(|e| SendMessageError::ChannelError(e).into())
    }
}

#[derive(Debug)]
pub enum SendErrorReason<C, B> {
    ChannelError(C),
    BufferExtend(B),
    Command,
    InvalidHciPacket(HciPacketType),
    InvalidHciEvent(Events),
    InvalidConnectionHandle,
    UnknownConnectionHandle(ConnectionHandle),
    HostClosed,
    Unimplemented(HciPacketType),
}

impl<C, B> Display for SendErrorReason<C, B>
where
    C: Display,
    B: Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            SendErrorReason::ChannelError(c) => Display::fmt(c, f),
            SendErrorReason::BufferExtend(b) => Display::fmt(b, f),
            SendErrorReason::Command => f.write_str("cannot send command to host"),
            SendErrorReason::InvalidHciEvent(event) => write!(f, "received invalid HCI event for '{}'", event),
            SendErrorReason::InvalidHciPacket(ty) => write!(f, "invalid HCI packet for '{}'", ty),
            SendErrorReason::InvalidConnectionHandle => f.write_str("invalid connection handle"),
            SendErrorReason::UnknownConnectionHandle(h) => write!(f, "no connection for handle: {}", h),
            SendErrorReason::HostClosed => f.write_str("Host task is closed"),
            SendErrorReason::Unimplemented(p_type) => write!(f, "HCI message type {} is unimplemented", p_type),
        }
    }
}

impl<C, B> From<SendMessageError<C>> for SendErrorReason<C, B> {
    fn from(sme: SendMessageError<C>) -> Self {
        match sme {
            SendMessageError::ChannelError(c) => SendErrorReason::ChannelError(c),
            SendMessageError::InvalidHciEvent(event) => SendErrorReason::InvalidHciEvent(event),
            SendMessageError::InvalidHciPacket(ty) => SendErrorReason::InvalidHciPacket(ty),
            SendMessageError::HostClosed => SendErrorReason::HostClosed,
            SendMessageError::InvalidConnectionHandle => SendErrorReason::InvalidConnectionHandle,
            SendMessageError::Unimplemented(packet_type) => SendErrorReason::Unimplemented(packet_type),
            SendMessageError::UnknownConnectionHandle(h) => SendErrorReason::UnknownConnectionHandle(h),
        }
    }
}

impl<C, B> From<MessageError<B>> for SendErrorReason<C, B> {
    fn from(me: MessageError<B>) -> Self {
        match me {
            MessageError::BufferExtend(e) => SendErrorReason::BufferExtend(e),
            MessageError::HostClosed => SendErrorReason::HostClosed,
            MessageError::InvalidConnectionHandle => SendErrorReason::InvalidConnectionHandle,
            MessageError::UnknownConnectionHandle(handle) => SendErrorReason::UnknownConnectionHandle(handle),
        }
    }
}

/// Error returned by operations of [`Interface`] or [`BufferedSend`]
pub type SendError<R> = SendErrorReason<<R as ChannelReserve>::SenderError, <R as ChannelReserve>::TryExtendError>;

enum SendMessageError<T> {
    ChannelError(T),
    InvalidHciEvent(Events),
    InvalidHciPacket(HciPacketType),
    HostClosed,
    InvalidConnectionHandle,
    Unimplemented(HciPacketType),
    UnknownConnectionHandle(ConnectionHandle),
}

enum MessageError<B> {
    BufferExtend(B),
    HostClosed,
    InvalidConnectionHandle,
    UnknownConnectionHandle(ConnectionHandle),
}

impl<B> From<TaskId> for MessageError<B> {
    fn from(task_id: TaskId) -> Self {
        match task_id {
            TaskId::Host => MessageError::HostClosed,
            TaskId::Connection(handle) => MessageError::UnknownConnectionHandle(handle),
        }
    }
}

/// Type for method `maybe_send`
///
/// A `BufferedSend` is used whenever the interface cannot send complete HCI packets. Either the
/// buffers for the interface is too small or data is sent indiscriminately. The only requirement
/// is that bytes are fed to a `BufferedSend` in correct order. Trying to "overfeed" with more bytes
/// than necessary will result in the `BufferedSend` ignoring them.
///
/// For information on how to use this see the method [`buffer_send`](Interface::buffered_send)
pub struct BufferedSend<'a, R: ChannelReserve> {
    interface: &'a mut Interface<R>,
    packet_type: HciPacketType,
    packet_len: core::cell::Cell<Option<usize>>,
    task_id_state: core::cell::RefCell<BufferedTaskId>,
    buffer: core::cell::RefCell<Option<R::ToBuffer<'a>>>,
}

/// Get the channel
///
/// # Error
/// An error is returned if the channel no longer exists
///
/// # Panic
/// This will panic if `self.task_id_state` cannot be converted into a `TaskId`.
macro_rules! get_channel {
    ($buffered_send:expr, $R:ty) => {{
        let task_id = $buffered_send.task_id_state.borrow().try_into_task_id().unwrap();

        let channel: Result<<$R>::ToChannel<'_>, MessageError<<$R>::TryExtendError>> = $buffered_send
            .interface
            .channel_reserve
            .get(task_id)
            .map(|channel| channel)
            .ok_or(MessageError::<<$R>::TryExtendError>::from(task_id));

        channel
    }};
}
impl<'a, R> BufferedSend<'a, R>
where
    R: ChannelReserve,
{
    /// Create a new `BufferSend`
    fn new(interface: &'a mut Interface<R>, packet_type: HciPacketType) -> Self {
        BufferedSend {
            interface,
            packet_type,
            packet_len: core::cell::Cell::new(None),
            task_id_state: core::cell::RefCell::new(BufferedTaskId::None),
            buffer: core::cell::RefCell::new(None),
        }
    }

    /// Add bytes before the *parameter length* in the Command packet or Event packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once three bytes of the Command packet are processed.
    #[inline]
    async fn add_initial_command_or_event_byte(&'a self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        use crate::TryExtend;

        let packet_type = self.packet_type;

        let mut buffer_borrow = Some(self.buffer.borrow_mut());

        let prepare_send;

        if let Some(ref mut ps) = **buffer_borrow.as_mut().unwrap() {
            prepare_send = ps;
        } else {
            buffer_borrow.take();

            self.task_id_state.replace(BufferedTaskId::Host);

            let buffer = get_channel!(self, R)?.take(None).await;

            self.buffer.replace(Some(buffer));

            buffer_borrow = Some(self.buffer.borrow_mut());

            prepare_send = buffer_borrow.as_mut().unwrap().as_mut().unwrap();
        }

        prepare_send
            .try_extend_one(byte)
            .map_err(|e| MessageError::BufferExtend(e))?;

        match packet_type {
            HciPacketType::Command => {
                if 3 == prepare_send.len() {
                    self.packet_len.set(Some(3usize + prepare_send[2] as usize));
                }
            }
            HciPacketType::Event => {
                if 2 == prepare_send.len() {
                    self.packet_len.set(Some(2usize + prepare_send[2] as usize));
                }
            }
            HciPacketType::Acl | HciPacketType::Sco | HciPacketType::Iso => unreachable!(),
        }

        Ok(())
    }

    /// A generic function over adding the initial bytes for (ACL, SCO, and ISO) HCI packets.
    ///
    /// All HCI data packets happen to start with the connection handle with a data length field
    /// starting at the byte after. This is for adding bytes to the intra message buffer until the
    /// length bytes are added to the buffer. Once the length is known the member field `packet_len`
    /// will be set and this method cannot be called again.
    async fn add_initial_data_byte(&'a self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        use crate::TryExtend;

        let mut buffer_borrow = self.buffer.borrow_mut();

        match *buffer_borrow {
            None => {
                if let Some(handle) = self
                    .task_id_state
                    .borrow_mut()
                    .add_byte(byte)
                    .map_err(|_| MessageError::InvalidConnectionHandle)?
                {
                    drop(buffer_borrow);

                    let buffer = get_channel!(self, R)?.take(None).await;

                    self.buffer.replace(Some(buffer));

                    self.buffer
                        .borrow_mut()
                        .as_mut()
                        .unwrap()
                        .try_extend(handle.get_raw_handle().to_le_bytes())
                        .map_err(|e| MessageError::BufferExtend(e))?;
                }
            }
            Some(ref mut prepare_send) => {
                prepare_send
                    .try_extend_one(byte)
                    .map_err(|e| MessageError::BufferExtend(e))?;

                match self.packet_type {
                    HciPacketType::Acl => {
                        if 4 == prepare_send.len() {
                            let len = <u16>::from_le_bytes([prepare_send[2], prepare_send[3]]);

                            self.packet_len.set(Some(4usize + len as usize));
                        }
                    }
                    HciPacketType::Iso => {
                        if 4 == prepare_send.len() {
                            let len_bytes = <u16>::from_le_bytes([prepare_send[2], prepare_send[3]]);

                            let len = len_bytes & 0x3FFF;

                            self.packet_len.set(Some(4usize + len as usize));
                        }
                    }
                    HciPacketType::Sco => {
                        // There is no len check because checking
                        // if the len is 3 is trivial

                        let len = prepare_send[2];

                        self.packet_len.set(Some(3usize + len as usize));
                    }
                    HciPacketType::Command | HciPacketType::Event => unimplemented!(),
                };
            }
        }

        Ok(())
    }

    /// Add initial bytes to the buffer
    ///
    /// These are bytes that are added before the length field has been buffered. Essentially this
    /// is called when `packet_len` is `None`.
    #[inline]
    async fn add_initial_byte(&'a self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        match self.packet_type {
            HciPacketType::Command => self.add_initial_command_or_event_byte(byte).await,
            HciPacketType::Acl => self.add_initial_data_byte(byte).await,
            HciPacketType::Sco => self.add_initial_data_byte(byte).await,
            HciPacketType::Event => self.add_initial_command_or_event_byte(byte).await,
            HciPacketType::Iso => self.add_initial_data_byte(byte).await,
        }
    }

    /// Add a byte to the buffer
    ///
    /// This adds a single byte to the buffer. If the added byte is determined to be the last byte
    /// of the HCI packet, `true` is returned to indicate that this `BufferedSend` is ready to send.
    ///
    /// ```
    /// use bo_tie::hci::interface::{HciPacketType, Interface};
    ///
    /// # let mut interface = Interface::new_local(1);
    /// # async fn example() {
    /// let mut buffered_send = interface.buffered_send(HciPacketType::Event);
    ///
    /// for byte in driver_bytes {
    ///     if buffered_send.add(*byte).await {
    ///         break
    ///     }
    /// }
    ///
    /// buffered_send.send().await
    /// # }
    /// ```
    ///
    /// # Error
    /// An error is returned if this `BufferedSend` already has a complete HCI Packet.
    pub async fn add(&'a self, byte: u8) -> Result<bool, SendError<R>> {
        use crate::TryExtend;

        match self.packet_len.get() {
            None => {
                self.add_initial_byte(byte).await?;

                Ok(false)
            }
            // prepared_send should be Some(_) when packet_len is Some(_)
            Some(len) if len != self.buffer.borrow().as_ref().unwrap().len() => {
                self.buffer
                    .borrow_mut()
                    .as_mut()
                    .unwrap()
                    .try_extend_one(byte)
                    .map_err(|e| SendError::<R>::BufferExtend(e))?;

                Ok(len == self.buffer.borrow().as_ref().unwrap().len())
            }
            _ => Err(SendError::<R>::InvalidHciPacket(self.packet_type)),
        }
    }

    /// Add bytes to the buffer
    ///
    /// This add multiple bytes to the buffer, stopping iteration of `iter` early when a complete
    /// HCI Packet is formed.
    ///
    /// # Return
    /// `true` is returned if the this `BufferSend` contains a complete HCI Packet.
    pub async fn add_bytes<I: IntoIterator<Item = u8>>(&'a mut self, iter: I) -> Result<bool, SendError<R>> {
        for i in iter {
            if self.add(i).await? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a complete HCI packet is stored and ready to be sent
    pub fn is_ready(&self) -> bool {
        self.packet_len
            .get()
            .as_ref()
            .and_then(|len| Some(*len == self.buffer.borrow().as_ref()?.len()))
            .unwrap_or_default()
    }

    /// Send the HCI Packet to its destination
    ///
    /// When a complete packet is sored within this `BufferSend`, this method is called to transfer
    /// the packet to its destination. An error is returned if this method is called before a
    /// complete HCI packet is stored within this `BufferedSend`.
    pub async fn send(self) -> Result<(), SendError<R>> {
        buffered_send::send(self).await
    }
}

/// The state of a connection handle within a buffered
#[derive(Copy, Clone)]
enum BufferedTaskId {
    /// Connection handle has not been set or acquired yet
    None,
    /// First byte of a connection handle
    ConnectionHandleFirstByte(u8),
    /// Host
    Host,
    /// Complete connection handle
    ConnectionHandle(ConnectionHandle),
}

impl BufferedTaskId {
    /// Add a byte to the connection handle
    ///
    /// Add a byte to the buffered connection handle. When a
    /// # Error
    /// An error is returned when the connection handle is invalid
    ///
    /// # Panics
    /// * This method will panic if self is enum `Unused` or `ConnectionHandle`
    fn add_byte(
        &mut self,
        byte: u8,
    ) -> Result<Option<ConnectionHandle>, <ConnectionHandle as core::convert::TryFrom<[u8; 2]>>::Error> {
        use core::convert::TryFrom;

        match core::mem::replace(self, BufferedTaskId::None) {
            BufferedTaskId::None => {
                *self = BufferedTaskId::ConnectionHandleFirstByte(byte);

                Ok(None)
            }
            BufferedTaskId::ConnectionHandleFirstByte(first) => {
                let connection_handle = ConnectionHandle::try_from([first, byte])?;

                *self = BufferedTaskId::ConnectionHandle(connection_handle);

                Ok(Some(connection_handle))
            }
            BufferedTaskId::ConnectionHandle(_) | BufferedTaskId::Host => unreachable!(),
        }
    }

    fn try_into_task_id(&self) -> Option<TaskId> {
        match self {
            BufferedTaskId::None | BufferedTaskId::ConnectionHandleFirstByte(_) => None,
            BufferedTaskId::Host => Some(TaskId::Host),
            BufferedTaskId::ConnectionHandle(handle) => Some(TaskId::Connection(*handle)),
        }
    }
}

/// module for containing methods that do not fit within the `impl` for [`BufferedSendSetup`]
mod buffered_send {
    use super::*;

    pub async fn send<R>(bs: BufferedSend<'_, R>) -> Result<(), SendError<R>>
    where
        R: ChannelReserve,
    {
        if bs.is_ready() {
            match bs.packet_type {
                HciPacketType::Acl => from_acl(bs).await,
                HciPacketType::Sco => Err(SendError::<R>::Unimplemented(HciPacketType::Sco)),
                HciPacketType::Event => from_event(bs).await,
                HciPacketType::Iso => Err(SendError::<R>::Unimplemented(HciPacketType::Iso)),
                HciPacketType::Command => unreachable!(),
            }
        } else {
            Err(SendError::<R>::InvalidHciPacket(bs.packet_type))
        }
    }

    async fn from_event<R>(bs: BufferedSend<'_, R>) -> Result<(), SendError<R>>
    where
        R: ChannelReserve,
    {
        let buffer = match bs.buffer.take() {
            Some(buffer) => buffer,
            None => return Err(SendError::<R>::InvalidHciPacket(bs.packet_type)),
        };

        match bs.interface.parse_event(&buffer) {
            Err(e) => Err(e.into()),
            Ok(true) => {
                let message = IntraMessageType::Event(buffer).into();

                get_channel!(bs, R)?
                    .get_sender()
                    .send(message)
                    .await
                    .map_err(|e| SendError::<R>::ChannelError(e))
            }
            Ok(false) => Ok(()),
        }
    }

    async fn from_acl<R>(bs: BufferedSend<'_, R>) -> Result<(), SendError<R>>
    where
        R: ChannelReserve,
    {
        let buffer = match bs.buffer.take() {
            Some(buffer) => buffer,
            None => return Err(SendError::<R>::InvalidHciPacket(bs.packet_type)),
        };

        let message = IntraMessageType::Acl(buffer).into();

        get_channel!(bs, R)?
            .get_sender()
            .send(message)
            .await
            .map_err(|e| SendError::<R>::ChannelError(e))
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
/// use bo_tie::hci::interface::Sender;
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
/// use bo_tie::hci::interface::{Sender, HciPacket};
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
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            HciPacketType::Command => f.write_str("Command"),
            HciPacketType::Acl => f.write_str("ACL"),
            HciPacketType::Sco => f.write_str("SCO"),
            HciPacketType::Event => f.write_str("Event"),
            HciPacketType::Iso => f.write_str("ISO"),
        }
    }
}

/// Message sent from the Host to the Controller
///
/// The host sends these HCI messages to the controller. It is up to the interface driver to
/// convert this enum into the format for the interface.
pub enum HostMessage<T> {
    Command(T),
    Acl(T),
    Sco(T),
    Iso(T),
}

pub trait InterfaceDriver<T> {
    type Message;

    /// Convert a [`HostMessage`] into a `Message`
    fn convert_host_message(&mut self, host_message: HostMessage<T>) -> Self::Message;
}

/// Inner interface messaging
///
/// This is the type for messages sent between the interface async task and either the host or a
/// connection async tasks. HCI packets are the most common message, but there is also other types
/// of messages sent for task related things.
#[repr(transparent)]
pub struct IntraMessage<T> {
    pub(crate) ty: IntraMessageType<T>,
}

impl<T> IntraMessage<T> {
    /// Convert an IntraMessage into the message type used by the driver
    fn into_driver_message<I>(self, id: &mut I) -> Result<I::Message, &'static str>
    where
        I: InterfaceDriver<T>,
        T: Deref<Target = [u8]>,
    {
        let host_message = match self.ty {
            IntraMessageType::Command(_, t) => Ok(HostMessage::Command(t)),
            IntraMessageType::Acl(t) => Ok(HostMessage::Acl(t)),
            IntraMessageType::Sco(t) => Ok(HostMessage::Sco(t)),
            IntraMessageType::Iso(t) => Ok(HostMessage::Iso(t)),
            _ => Err(self.kind()),
        }?;

        Ok(id.convert_host_message(host_message))
    }

    /// Get a mutable reference to the buffer
    ///
    /// This will return a mutable reference the buffer if the `IntraMessageType` contains a buffer.
    pub(crate) fn get_mut_buffer(&mut self) -> Option<&mut T> {
        match &mut self.ty {
            IntraMessageType::Command(_, t) => Some(t),
            IntraMessageType::Acl(t) => Some(t),
            IntraMessageType::Sco(t) => Some(t),
            IntraMessageType::Event(t) => Some(t),
            IntraMessageType::Iso(t) => Some(t),
            _ => None,
        }
    }

    /// Print the kind of message
    ///
    /// This is used for debugging purposes
    pub(crate) const fn kind(&self) -> &'static str {
        match self.ty {
            IntraMessageType::Command(_, _) => "Command",
            IntraMessageType::Acl(_) => "Acl",
            IntraMessageType::Sco(_) => "Sco",
            IntraMessageType::Event(_) => "Event",
            IntraMessageType::Iso(_) => "Iso",
            IntraMessageType::Disconnect => "Disconnect",
            IntraMessageType::Connection(_) => "(BR/EDR) Connection",
            IntraMessageType::LeConnection(_) => "LE Connection",
            IntraMessageType::LeEnhancedConnection(_) => "LE Enhanced Connection",
        }
    }

    /// Map the buffer type to another type
    fn map<V, F>(self, f: F) -> IntraMessage<V>
    where
        F: FnOnce(T) -> V,
    {
        match self.ty {
            IntraMessageType::Command(p, t) => IntraMessageType::Command(p, f(t)).into(),
            IntraMessageType::Acl(t) => IntraMessageType::Acl(f(t)).into(),
            IntraMessageType::Sco(t) => IntraMessageType::Sco(f(t)).into(),
            IntraMessageType::Event(t) => IntraMessageType::Event(f(t)).into(),
            IntraMessageType::Iso(t) => IntraMessageType::Iso(f(t)).into(),
            IntraMessageType::Disconnect => IntraMessageType::Disconnect.into(),
            IntraMessageType::Connection(c) => IntraMessageType::Connection(c).into(),
            IntraMessageType::LeConnection(c) => IntraMessageType::LeConnection(c).into(),
            IntraMessageType::LeEnhancedConnection(c) => IntraMessageType::LeEnhancedConnection(c).into(),
        }
    }
}

impl<T> From<IntraMessageType<T>> for IntraMessage<T> {
    fn from(ty: IntraMessageType<T>) -> Self {
        Self { ty }
    }
}

impl<T: Deref<Target = [u8]>> GetDataPayloadSize for IntraMessage<T> {
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

/// An enum of the type of message sent between two async tasks
pub(crate) enum IntraMessageType<T> {
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
    ///
    /// Connection events are sent
    Event(T),
    /// HCI isochronous Data Packet
    Iso(T),
    /*----------------------------
     Connection specific messages
    ----------------------------*/
    /// The interface async task sends this message to the connection async task who's connection
    /// has disconnected.
    Disconnect,
    /// BR/EDR Connection Complete event sent to the host
    Connection(events::ConnectionCompleteData),
    /// LE Connection Complete event sent to the host
    LeConnection(events::LEConnectionCompleteData),
    /// LE Enhanced Connection Complete event sent to the host
    LeEnhancedConnection(events::LEEnhancedConnectionCompleteData),
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
