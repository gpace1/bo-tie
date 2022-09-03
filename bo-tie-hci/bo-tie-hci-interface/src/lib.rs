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
//! # The Physical Interface
//! The type `Interface` is a high-level implementation of the interface requirements for
//! interacting with the other async tasks of the Host. It does not provide capability for
//! controlling and driving the physical interface used for communication between the Host and
//! Controller. This must be implemented by a separate crate and integrated into the user's
//! application of this library (TBD Note: there may be an exception in the future when both the
//! host and controller are built by `bo-tie` and run on the same CPU).
//!
//! There are four types of interfaces mentioned within the Bluetooth Specification (v5.2) but
//! interfacing between the host and controller can be done via any interface so long as the host
//! to controller functional specification can be applied to it. Any interface should work so long
//! as there is a way to asynchronously send and receive data between the host and controller.
//!
//! ## Specification Defined Interfaces
//! UART, USB, Secure Digital (SD), and Three-Wire UART interfaces have specification defined for
//! them within the Bluetooth Specification. This library only provides wrappers around an
//! `Interface` for converting [`HciPacket`] data into the data format for these interfaces (TBD:
//! only [`UART`](uart::UartInterface) is currently implemented). The rest of the driver is left to
//! be implemented by another crate. The methods of the wrappers are designed to mirror the methods
//! of `Interface` as they have the same name, but they accept/return data pre-formatted to be used
//! for the interface.
//!
//! ## Custom Interfaces
//! An interface not defined by the Bluetooth Specification must have its own data format,
//! regardless of the interface not requiring this. The Bluetooth Specification does not define a
//! way to differentiate the different kinds of HCI packets. HCI packets contain no marker within
//! them to indicate what HCI packet they are, so the interface driver must be able to find out
//! the HCI packet type itself.
//!
//! The simplest way for an interface to label HCI packets is to just repurpose the
//! implementation for [`UART`](uart::UartInterface) or one of the other wrappers used for
//! specification defined interfaces. Otherwise an interface must be able to convert data from its
//! interface format to a [`HciPacket`] format (or at least the [`HciPacketType`] when using a
//! buffered) used by `Interface`.
//!
//! ## Buffering
//! Many interfaces in embedded systems can only store less bytes than a complete HCI packet
//!

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

extern crate alloc;

pub use bo_tie_hci_util::{
    events, local_channel, ChannelReserve, ChannelReserveExt, CommandEventMatcher, ConnectionHandle,
};
use bo_tie_hci_util::{FlowControlId, HciPacket, HciPacketType, IntraMessageType, Sender, TaskId};
use bo_tie_util::buffer::{BufferReserve, TryExtend};
use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;

mod flow_control;
pub mod uart;

/// The interface
///
/// An `Interface` is the component of the host that must run with the interface driver. Its the
/// part of the host that must perpetually await upon the
pub struct Interface<R> {
    channel_reserve: core::cell::RefCell<R>,
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
    pub fn new_local(task_count: usize) -> Self {
        let channel_reserve = core::cell::RefCell::new(local_channel::local_dynamic_channel::LocalChannelManager::new(
            task_count,
        ));

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
    pub fn new_stack_local(
        channel_reserve_data: &'a local_channel::local_stack_channel::LocalStackChannelReserveData<
            TASK_COUNT,
            CHANNEL_SIZE,
            BUFFER_SIZE,
        >,
    ) -> Self {
        let channel_reserve = core::cell::RefCell::new(
            local_channel::local_stack_channel::LocalStackChannelReserve::new(channel_reserve_data),
        );

        Interface { channel_reserve }
    }
}

impl<R> Interface<R>
where
    R: ChannelReserve,
{
    /// Send a complete HCI packet from the controller to the Host
    ///
    /// After the interface driver converts an interface packet into a *complete* [`HciPacket`], it
    /// must call this method to send the `HciPacket` to it's destination async task. If the
    /// interface driver cannot receive a complete HCI packet, it may buffer the data with a
    /// [`BufferedUpSend`] which can be acquired by the method `buffered_up_send`.
    ///
    /// # Error
    /// The data within the `HciPacket` is expected to be a properly formatted HCI packet. If it is
    /// not formatted correctly, or there are no other async tasks, `up_send` will return an error.
    pub async fn up_send<T>(&mut self, packet: &HciPacket<T>) -> Result<(), SendError<R>>
    where
        T: Deref<Target = [u8]>,
    {
        match packet {
            HciPacket::Command(_) => Err(SendError::<R>::Command),
            HciPacket::Acl(packet) => self.send_acl(packet).await.map_err(|e| e.into()),
            HciPacket::Sco(_packet) => Err(SendError::<R>::Unimplemented("HCI SCO packets are unimplemented")),
            HciPacket::Event(packet) => self.maybe_send_event(packet).await.map_err(|e| e.into()),
            HciPacket::Iso(_packet) => Err(SendError::<R>::Unimplemented("HCI SCO packets are unimplemented")),
        }
    }

    /// Buffer HCI packet data from the controller.
    ///
    /// A `BufferedUpSend` is used for interfaces that do not send a single complete HCI packet as
    /// part of the interface's payload. This can be because the interface can only support sending
    /// less data than the minimum size of a HCI packet (which is the minimum size of a command
    /// packet, 259 bytes) or it sends multiple HCI data packets within a single interface packet.
    /// Either way a `BufferedUpSend` will buffer bytes within itself until it has determined to
    /// contain a complete HCI packet.
    ///
    /// Bytes are added to a `BufferedUpSend` through the method [`add`](BufferedUpSend::add) for a
    /// single byte or via method [`add_bytes`](BufferedUpSend::add_bytes) for a chunk of bytes.
    /// Both of these methods will add bytes to the buffer until the buffer contains a complete
    /// HCI Packet. Further calls to either of these methods when there is a complete HCI packet
    /// results in both methods doing nothing. Instead the `BufferedUpSend` must be consumed by the
    /// method [`up_send`](BufferedUpSend::up_send) to send the HCI packet to its destination.
    ///
    /// # Usage Requirements
    /// There are some requirements for using a `BufferedUpSend`. First, the type of HCI packet must
    /// be known upon creation of a `BufferedUpSend`. HCI packets have no self labeling information
    /// in them, so without knowing the packet type, a `BufferedUpSend` would not be able to figure
    /// when the buffered data is a complete HCI packet. Secondly, data must be fed in the order
    /// they should appear in the HCI packet. It is impossible for a `BufferedUpSend` to order the
    /// bytes fed to it, so providing unordered data would just create undefined HCI packets.
    /// Lastly, and most importantly, a `BufferedUpSend` can only really be dropped when the
    /// interface async task is exiting. If a `BufferedUpSend contains any bytes within it and it id
    /// dropped then those bytes are gone. At best this would mess up the protocols further up the
    /// Bluetooth stack, at worst every following HCI packet will be badly formatted.
    ///
    /// ```
    /// use bo_tie_hci_util::{HciPacketType};
    /// use bo_tie_hci_interface::{Interface, SendError};
    ///
    /// # use bo_tie_hci_interface::InitHostTaskEnds;
    /// # let doc_test = async {
    /// # let mut interface = Interface::new_local(1);
    /// # let _host_ends = interface.init_host_task_ends();
    ///
    /// // This is two HCI ACL data packets with
    /// // a part of a third ACL data packet.
    /// let data: &[u8] = &[
    ///     0x1, 0x0, 0x3, 0x0, 0xa, 0xb, 0xc, // first packet
    ///     0x1, 0x0, 0x2, 0x0, 0x10, 0x11,    // second packet
    ///     0x1, 0x0, 0x2,                     // part of the third packet
    /// ];
    ///
    /// let mut buffer_send_1 = interface.buffered_up_send(HciPacketType::Acl);
    ///
    /// assert!(!buffer_send_1.add(data[0]).await.unwrap());
    /// assert!(!buffer_send_1.add(data[1]).await.unwrap());
    /// assert!(!buffer_send_1.add(data[2]).await.unwrap());
    /// assert!(!buffer_send_1.add(data[3]).await.unwrap());
    /// assert!(!buffer_send_1.add(data[4]).await.unwrap());
    /// assert!(!buffer_send_1.add(data[5]).await.unwrap());
    /// assert!( buffer_send_1.add(data[6]).await.unwrap());
    ///
    /// buffer_send_1.up_send().await.unwrap();
    ///
    /// let mut buffer_send_2 = interface.buffered_up_send(HciPacketType::Acl);
    ///
    /// assert!(buffer_send_2.add_bytes(data[7..].iter().copied()).await.unwrap());
    ///
    /// buffer_send_2.up_send().await.unwrap();
    ///
    /// let mut buffer_send_3 = interface.buffered_up_send(HciPacketType::Acl);
    ///
    /// // `add_bytes` returns false because the third packet is incomplete
    /// assert!(!buffer_send_3.add_bytes(data[13..].iter().copied()).await.unwrap());
    ///
    /// assert!(!buffer_send_3.is_ready());
    ///
    /// // This produces an error as method up_send can only be called
    /// // when a `BufferedUpSend` contains a complete HCI packet.
    /// assert!(buffer_send_3.up_send().await.is_err())
    /// # };
    /// # tokio_test::block_on(doc_test);
    /// ```
    pub fn buffered_up_send(&mut self, packet_type: HciPacketType) -> BufferedUpSend<'_, R> {
        BufferedUpSend::new(self, packet_type)
    }

    /// Get the next HCI packet to send to the controller
    ///
    /// Awaiting on `next` returns a `HostMessage` that is ready to be sent to the controller. This
    /// message should be immediately sent to the controller before `next` is awaited upon again.
    /// HCI Packets can be ordered, so they *must* be sent in the order in which they are received
    /// from calls to `next`.
    ///
    /// HCI flow control is built into the polling process for `next`, so for concerning the
    /// controller, it is always safe to immediately send the message to it. Flow control for the
    /// interface is not dealt with, so that must be done by the interface driver.
    ///
    /// This method returns `None` when there are no more Senders associated with the underlying
    /// receiver. The interface async task should exit after `None` is received.
    pub async fn down_send(&mut self) -> Option<HciPacket<impl Deref<Target = [u8]>>> {
        self.channel_reserve
            .get_mut()
            .receive_next()
            .await
            .map(|intra_message| intra_message.into_hci_packet())
    }

    /// Parse a command complete event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_command_complete_event(
        &self,
        cc_data: &events::parameters::CommandCompleteData,
    ) -> Result<bool, SendError<R>> {
        if 0 != cc_data.number_of_hci_command_packets {
            self.channel_reserve
                .borrow_mut()
                .inc_cmd_flow_ctrl(cc_data.number_of_hci_command_packets.into());
        }

        Ok(cc_data.command_opcode.is_some())
    }

    /// Parse a command status event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_command_status_event(
        &self,
        cs_data: &events::parameters::CommandStatusData,
    ) -> Result<bool, SendError<R>> {
        if 0 != cs_data.number_of_hci_command_packets {
            self.channel_reserve
                .borrow_mut()
                .inc_cmd_flow_ctrl(cs_data.number_of_hci_command_packets.into());
        }

        Ok(cs_data.command_opcode.is_some())
    }

    /// Parse a Number of Completed Packets event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    fn parse_number_of_completed_packets_event(
        &self,
        ncp_data: &events::parameters::Multiple<events::parameters::NumberOfCompletedPacketsData>,
    ) -> Result<(), SendError<R>> {
        for ncp in ncp_data {
            if 0 != ncp.completed_packets {
                let how_many: usize = ncp.completed_packets.into();

                let task_id = TaskId::Connection(ncp.connection_handle);

                let fc_id = self
                    .channel_reserve
                    .borrow()
                    .get_flow_control_id(task_id)
                    .ok_or(SendError::<R>::UnknownConnectionHandle(ncp.connection_handle))?;

                match fc_id {
                    FlowControlId::Acl => self.channel_reserve.borrow_mut().inc_acl_flow_ctrl(how_many),
                    FlowControlId::Sco => self.channel_reserve.borrow_mut().inc_sco_flow_control(how_many),
                    FlowControlId::LeAcl => self.channel_reserve.borrow_mut().inc_le_acl_flow_control(how_many),
                    FlowControlId::LeIso => self.channel_reserve.borrow_mut().inc_le_iso_flow_control(how_many),
                    FlowControlId::Cmd => panic!("unexpected flow control id 'Cmd'"),
                }
            }
        }

        Ok(())
    }

    /// Parse a Number of Completed Data Blocks event
    ///
    /// Parsing this event is only enabled with feature `unstable`.
    #[cfg(not(feature = "unstable"))]
    fn parse_number_of_completed_data_blocks_event(
        &self,
        _: &events::parameters::NumberOfCompletedDataBlocksData,
    ) -> Result<(), SendError<R>> {
        Err(SendError::<R>::Unimplemented(
            "Block-based flow control is unimplemented",
        ))
    }

    /// Parse a Number of Completed Data Blocks event
    ///
    /// The input `event_parameter` is a byte slice of the event parameter within a HCI event
    /// packet.
    ///
    /// If the return is `Ok` then it always contains `false`.
    ///
    /// # TODO Note
    /// This is unlikely to be a correct implementation.
    #[cfg(feature = "unstable")]
    fn parse_number_of_completed_data_blocks_event(
        &self,
        ncdb_data: &events::parameters::NumberOfCompletedDataBlocksData,
    ) -> Result<(), SendError<R>> {
        // This algorithm for flow control of the block buffers just
        // counts the total number of *bytes* that the controller can
        // accept (of one or more HCI payloads) within those buffers.
        // The total number of data blocks does not need to be counted
        // **unless** the controller sends back the need for the host
        // to re-check the block buffer information via the *Read Data
        // Block Size* command.
        if let None = ncdb_data.total_data_blocks {
            self.channel_reserve
                .borrow_mut()
                .get_flow_ctrl_receiver()
                .get_mut_acl_flow_control()
                .halt();

            self.channel_reserve
                .borrow_mut()
                .get_flow_ctrl_receiver()
                .get_mut_le_acl_flow_control()
                .halt();

            todo!("process of re-reading the data block buffer sizes not implemented yet")
        }

        for ncdb in &ncdb_data.completed_packets_and_blocks {
            if 0 != ncdb.completed_blocks {
                let block_size = self
                    .channel_reserve
                    .borrow_mut()
                    .get_flow_ctrl_receiver()
                    .get_block_size();

                let how_many: usize = block_size * <usize>::from(ncdb.completed_blocks);

                let task_id = TaskId::Connection(ncdb.connection_handle);

                let fc_id = self
                    .channel_reserve
                    .borrow()
                    .get_flow_control_id(task_id)
                    .ok_or(SendError::<R>::UnknownConnectionHandle(ncdb.connection_handle))?;

                match fc_id {
                    FlowControlId::Acl => self.channel_reserve.borrow_mut().inc_acl_flow_ctrl(how_many),
                    FlowControlId::Sco => self.channel_reserve.borrow_mut().inc_sco_flow_control(how_many),
                    FlowControlId::LeAcl => self.channel_reserve.borrow_mut().inc_le_acl_flow_control(how_many),
                    FlowControlId::LeIso => self.channel_reserve.borrow_mut().inc_le_iso_flow_control(how_many),
                    FlowControlId::Cmd => panic!("unexpected flow control id 'Cmd'"),
                }
            }
        }

        Ok(())
    }

    /// Initiate a connection async task
    ///
    /// This creates the channels ends required for creating a new connection async task and sends
    /// this information within a [`IntraMessageType::Connection`] message to the host async task.
    pub async fn create_connection(&self, task_id: TaskId, flow_control_id: FlowControlId) -> Result<(), SendError<R>> {
        let channel_ends = self
            .channel_reserve
            .borrow()
            .add_new_task(task_id, flow_control_id)
            .map_err(|_| SendError::<R>::InvalidConnectionHandle)?;

        let message = IntraMessageType::Connection(channel_ends).into();

        self.channel_reserve
            .borrow()
            .get_sender(TaskId::Host)
            .ok_or(SendError::<R>::HostClosed)?
            .send(message)
            .await
            .map_err(|e| SendError::<R>::ChannelError(e))
    }

    pub async fn parse_connection_complete_event(
        &self,
        data: &events::parameters::ConnectionCompleteData,
    ) -> Result<(), SendError<R>> {
        let task_id = TaskId::Connection(data.connection_handle);

        let flow_control_id = match data.link_type {
            events::parameters::LinkType::AclConnection => FlowControlId::Acl,
            events::parameters::LinkType::ScoConnection => FlowControlId::Sco,
            events::parameters::LinkType::EscoConnection => unreachable!(),
        };

        self.create_connection(task_id, flow_control_id).await
    }

    pub async fn parse_synchronous_connection_complete_event(
        &self,
        data: &events::parameters::SynchronousConnectionCompleteData,
    ) -> Result<(), SendError<R>> {
        let task_id = TaskId::Connection(data.connection_handle);

        let flow_control_id = FlowControlId::Sco;

        self.create_connection(task_id, flow_control_id).await
    }

    pub async fn parse_le_connection_complete_event(
        &self,
        data: &events::parameters::LeConnectionCompleteData,
    ) -> Result<(), SendError<R>> {
        let task_id = TaskId::Connection(data.connection_handle);

        let flow_control_id = FlowControlId::Acl;

        self.create_connection(task_id, flow_control_id).await
    }

    pub async fn parse_le_enhanced_connection_complete_event(
        &self,
        data: &events::parameters::LeEnhancedConnectionCompleteData,
    ) -> Result<(), SendError<R>> {
        let task_id = TaskId::Connection(data.connection_handle);

        let flow_control_id = FlowControlId::Acl;

        self.create_connection(task_id, flow_control_id).await
    }

    pub async fn parse_disconnect(
        &self,
        disconnect: &events::parameters::DisconnectionCompleteData,
    ) -> Result<(), SendError<R>> {
        let task_id = TaskId::Connection(disconnect.connection_handle);

        let error = bo_tie_util::errors::Error::from(disconnect.reason);

        if let Some(sender) = self.channel_reserve.borrow().get_sender(task_id) {
            sender
                .send(IntraMessageType::Disconnect(error).into())
                .await
                .map_err(|e| SendError::<R>::ChannelError(e))?;

            self.channel_reserve
                .borrow_mut()
                .try_remove(task_id)
                .map_err(|e| SendError::<R>::ReserveError(e))
        } else {
            Ok(())
        }
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
    async fn parse_event(&self, data: &[u8]) -> Result<Option<events::EventsData>, SendError<R>> {
        use events::{EventsData, LeMetaData};

        let ed = EventsData::try_from_packet(data).map_err(|e| SendError::<R>::InvalidHciEventData(e))?;

        match &ed {
            EventsData::CommandComplete(data) => self.parse_command_complete_event(data).map(|b| b.then_some(ed)),
            EventsData::CommandStatus(data) => self.parse_command_status_event(data).map(|b| b.then_some(ed)),
            EventsData::NumberOfCompletedPackets(data) => {
                self.parse_number_of_completed_packets_event(data).map(|_| None)
            }
            EventsData::NumberOfCompletedDataBlocks(data) => {
                self.parse_number_of_completed_data_blocks_event(data).map(|_| None)
            }
            EventsData::ConnectionComplete(data) => self.parse_connection_complete_event(data).await.map(|_| Some(ed)),
            EventsData::SynchronousConnectionComplete(data) => self
                .parse_synchronous_connection_complete_event(data)
                .await
                .map(|_| Some(ed)),
            EventsData::LeMeta(LeMetaData::ConnectionComplete(data)) => {
                self.parse_le_connection_complete_event(data).await.map(|_| Some(ed))
            }
            EventsData::LeMeta(LeMetaData::EnhancedConnectionComplete(data)) => self
                .parse_le_enhanced_connection_complete_event(data)
                .await
                .map(|_| Some(ed)),
            EventsData::DisconnectionComplete(data) => self.parse_disconnect(data).await.map(|_| Some(ed)),
            _ => Ok(Some(ed)),
        }
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
        if let Some(events_data) = self.parse_event(&packet).await? {
            let message = IntraMessageType::Event(events_data).into();

            self.channel_reserve
                .borrow()
                .get_sender(TaskId::Host)
                .ok_or(SendError::<R>::HostClosed)?
                .send(message)
                .await
                .map_err(|e| SendError::<R>::ChannelError(e))?
        }

        Ok(())
    }

    async fn send_acl(&mut self, packet: &[u8]) -> Result<(), SendError<R>> {
        let raw_handle = <u16>::from_le_bytes([
            *packet
                .get(0)
                .ok_or(SendError::<R>::InvalidHciPacket(HciPacketType::Acl))?,
            *packet
                .get(1)
                .ok_or(SendError::<R>::InvalidHciPacket(HciPacketType::Acl))?,
        ]);

        let connection_handle =
            ConnectionHandle::try_from(raw_handle).map_err(|_| SendError::<R>::InvalidConnectionHandle)?;

        let reserve_ref = self.channel_reserve.borrow();

        let (mut buffer, sender) = reserve_ref
            .prepare_buffer_msg(TaskId::Connection(connection_handle), 0)
            .ok_or(SendError::<R>::HostClosed)?
            .await;

        buffer
            .try_extend(packet.iter().cloned())
            .map_err(|e| SendError::<R>::BufferExtend(e))?;

        let message = IntraMessageType::Acl(buffer).into();

        sender
            .send(message)
            .await
            .map_err(|e| SendError::<R>::ChannelError(e).into())
    }
}

#[derive(Debug)]
pub enum SendErrorReason<E, C, B> {
    ReserveError(E),
    ChannelError(C),
    BufferExtend(B),
    Command,
    InvalidHciPacket(HciPacketType),
    InvalidHciEventData(events::EventError),
    InvalidConnectionHandle,
    UnknownConnectionHandle(ConnectionHandle),
    HostClosed,
    Unimplemented(&'static str),
}

impl<E, C, B> Display for SendErrorReason<E, C, B>
where
    E: Display,
    C: Display,
    B: Display,
{
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            SendErrorReason::ReserveError(e) => Display::fmt(e, f),
            SendErrorReason::ChannelError(c) => Display::fmt(c, f),
            SendErrorReason::BufferExtend(b) => Display::fmt(b, f),
            SendErrorReason::Command => f.write_str("cannot send command to host"),
            SendErrorReason::InvalidHciPacket(packet) => write!(f, "Invalid packet {packet}"),
            SendErrorReason::InvalidHciEventData(e) => Display::fmt(e, f),
            SendErrorReason::InvalidConnectionHandle => f.write_str("invalid connection handle"),
            SendErrorReason::UnknownConnectionHandle(h) => write!(f, "no connection for handle: {h}"),
            SendErrorReason::HostClosed => f.write_str("Host task is closed"),
            SendErrorReason::Unimplemented(reason) => f.write_str(reason),
        }
    }
}

impl<E, C, B> From<MessageError<B>> for SendErrorReason<E, C, B> {
    fn from(me: MessageError<B>) -> Self {
        match me {
            MessageError::BufferExtend(e) => SendErrorReason::BufferExtend(e),
            MessageError::HostClosed => SendErrorReason::HostClosed,
            MessageError::InvalidConnectionHandle => SendErrorReason::InvalidConnectionHandle,
            MessageError::UnknownConnectionHandle(handle) => SendErrorReason::UnknownConnectionHandle(handle),
        }
    }
}

/// Error returned by operations of [`Interface`] or [`BufferedUpSend`]
pub type SendError<R> = SendErrorReason<
    <R as ChannelReserve>::Error,
    <R as ChannelReserve>::SenderError,
    <R as ChannelReserve>::TryExtendError,
>;

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
/// A `BufferedUpSend` is used whenever the interface cannot send complete HCI packets. Either the
/// buffers for the interface is too small or data is sent indiscriminately. The only requirement
/// is that bytes are fed to a `BufferedUpSend` in correct order. Trying to "overfeed" with more bytes
/// than necessary will result in the `BufferedUpSend` ignoring them.
///
/// For information on how to use this see the method [`buffer_send`](Interface::buffered_send)
pub struct BufferedUpSend<'a, R: ChannelReserve> {
    interface: &'a Interface<R>,
    packet_type: HciPacketType,
    packet_len: core::cell::Cell<Option<usize>>,
    task_id_state: core::cell::RefCell<BufferedTaskId>,
    buffer: core::cell::RefCell<Option<R::ToBuffer>>,
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

        let channel: Result<<$R>::ToChannel, MessageError<<$R>::TryExtendError>> = $buffered_send
            .interface
            .channel_reserve
            .borrow()
            .get(task_id)
            .map(|channel| channel)
            .ok_or(MessageError::<<$R>::TryExtendError>::from(task_id));

        channel
    }};
}
impl<'a, R> BufferedUpSend<'a, R>
where
    R: ChannelReserve,
{
    /// Create a new `BufferedUpSend`
    fn new(interface: &'a mut Interface<R>, packet_type: HciPacketType) -> Self {
        BufferedUpSend {
            interface,
            packet_type,
            packet_len: core::cell::Cell::new(None),
            task_id_state: core::cell::RefCell::new(BufferedTaskId::None),
            buffer: core::cell::RefCell::new(None),
        }
    }

    /// Buffer the bytes before the *parameter length* field in the Command packet or Event packet
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once three bytes of the Command packet or two bytes of the Event packet are
    /// processed.
    #[inline]
    async fn add_initial_command_or_event_byte(&self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
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
                    self.packet_len.set(Some(2usize + prepare_send[1] as usize));
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
    async fn add_initial_data_byte(&self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
        let mut buffer_borrow = self.buffer.borrow_mut();

        match *buffer_borrow {
            None => {
                let opt_handle = self
                    .task_id_state
                    .borrow_mut()
                    .add_byte(byte)
                    .map_err(|_| MessageError::InvalidConnectionHandle)?;

                if let Some(handle) = opt_handle {
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
    async fn add_initial_byte(&self, byte: u8) -> Result<(), MessageError<R::TryExtendError>> {
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
    /// of the HCI packet, `true` is returned to indicate that this `BufferedUpSend` is ready to
    /// be sent.
    ///
    /// ```
    /// use bo_tie_hci_interface::Interface;
    /// use bo_tie_hci_util::HciPacketType;
    /// # use bo_tie_hci_interface::InitHostTaskEnds;
    /// # let doc_test = async {
    /// # let mut interface = Interface::new_local(1);
    /// # let _host_ends = interface.init_host_task_ends();
    ///
    /// let mut buffered_send = interface.buffered_up_send(HciPacketType::Event);
    ///
    /// // Adding the bytes of an HCI Event packet
    /// // containing the "Inquiry Complete" event
    /// assert!(!buffered_send.add(0x1).await.unwrap());
    /// assert!(!buffered_send.add(0x1).await.unwrap());
    /// assert!( buffered_send.add(0x0).await.unwrap());
    ///
    /// buffered_send.up_send().await.unwrap();
    /// # };
    /// # tokio_test::block_on(doc_test)
    /// ```
    ///
    /// # Error
    /// An error is returned if this `BufferedUpSend` already has a complete HCI Packet.
    pub async fn add(&self, byte: u8) -> Result<bool, SendError<R>> {
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
    /// This add multiple bytes to the buffer, stopping the iteration of `iter` early when a
    /// complete HCI Packet is formed within this `BufferedUpSend`.
    ///
    /// # Return
    /// `true` is returned if the this `BufferedUpSend` contains a complete HCI Packet.
    pub async fn add_bytes<I: IntoIterator<Item = u8>>(&mut self, iter: I) -> Result<bool, SendError<R>> {
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
    /// When a complete packet is sored within this `BufferedUpSend`, this method is must be called
    /// to transfer the packet to its destination. An error is returned if this method is called
    /// and this `BufferedUpSend` does not contain a complete HCI packet.
    pub async fn up_send(self) -> Result<(), SendError<R>> {
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
    use bo_tie_hci_util::Channel;

    pub async fn send<R>(bs: BufferedUpSend<'_, R>) -> Result<(), SendError<R>>
    where
        R: ChannelReserve,
    {
        if bs.is_ready() {
            match bs.packet_type {
                HciPacketType::Acl => from_acl(bs).await,
                HciPacketType::Sco => Err(SendError::<R>::Unimplemented("SCO packets are unimplemented")),
                HciPacketType::Event => from_event(bs).await,
                HciPacketType::Iso => Err(SendError::<R>::Unimplemented("ISO packets are unimplemented")),
                HciPacketType::Command => unreachable!(),
            }
        } else {
            Err(SendError::<R>::InvalidHciPacket(bs.packet_type))
        }
    }

    async fn from_event<R>(bs: BufferedUpSend<'_, R>) -> Result<(), SendError<R>>
    where
        R: ChannelReserve,
    {
        let buffer = match bs.buffer.take() {
            Some(buffer) => buffer,
            None => return Err(SendError::<R>::InvalidHciPacket(bs.packet_type)),
        };

        match bs.interface.parse_event(&buffer).await {
            Err(e) => Err(e.into()),
            Ok(Some(event)) => {
                let message = IntraMessageType::Event(event).into();

                get_channel!(bs, R)?
                    .get_sender()
                    .send(message)
                    .await
                    .map_err(|e| SendError::<R>::ChannelError(e))
            }
            Ok(None) => Ok(()),
        }
    }

    async fn from_acl<R>(bs: BufferedUpSend<'_, R>) -> Result<(), SendError<R>>
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

/// Get channel ends for the host async task
pub trait InitHostTaskEnds {
    type TaskChannelEnds;
    type Error;

    /// Get the channel ends for the host async task
    ///
    /// Gets the channel ends for the host async task. These channel ends can only be acquired once,
    /// so calling this method multiple times for the same identifier will return an error.
    ///
    /// # Error
    /// Either `id` was already has channel ends created for it or an implementation specific error
    /// occurred while trying to create them.
    fn init_host_task_ends(&mut self) -> Result<Self::TaskChannelEnds, Self::Error>;
}

impl<R: ChannelReserve> InitHostTaskEnds for Interface<R> {
    type TaskChannelEnds = R::TaskChannelEnds;
    type Error = R::Error;

    fn init_host_task_ends(&mut self) -> Result<Self::TaskChannelEnds, Self::Error> {
        self.channel_reserve
            .borrow_mut()
            .add_new_task(TaskId::Host, FlowControlId::Cmd)
    }
}
