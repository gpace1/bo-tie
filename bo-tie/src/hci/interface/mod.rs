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

use core::fmt::{Debug, Display, Formatter};
use core::future::Future;
use core::ops::Deref;
use crate::hci::{CommandEventMatcher, events};
use crate::hci::events::EventsData;

mod local_channel;
pub mod uart;

/// Identifiers of channels
///
/// The interface has a collection of channels for sending data to either the host or connection.
/// A `ChannelId` is used for identifying the channels in this collection.
#[derive(Eq, PartialEq, PartialOrd, Ord)]
pub enum ChannelId {
    Host,
    Connection(usize),
}

/// A message channel
pub trait Channel {
    type Sender<'a>: Sender
    where
        Self: 'a;

    type Receiver<'a>: Receiver
    where
        Self: 'a;

    fn get_sender<'a>(&'a self) -> Self::Sender<'a>;

    fn get_receiver<'a>(&'a self) -> Self::Receiver<'a>;
}

/// Channels Management
///
/// Channels need to be managed from the perspective of the interface. This trait is used for adding
/// and removing channels on various channel managements.
pub trait ChannelsManagement {
    type Error;
    type Channel: Channel;

    /// Get the channel for sending to this interface
    ///
    /// This returns the channel used for sending data to this interface
    fn get_rx_channel(&self) -> &Self::Channel;

    /// Try to add a new channel
    ///
    /// If a new channel is added, a reference to the channel is returned.
    ///
    /// # Errors
    /// The identifier `id` must not already be within the channels manager.
    fn try_add(&mut self, id: ChannelId) -> Result<usize, Self::Error>;

    /// Try to remove a channel
    fn try_remove(&mut self, id: ChannelId) -> Result<Self::Channel, Self::Error>;

    /// Get a channel by its id
    fn get(&self, id: ChannelId) -> Option<&Self::Channel>;

    /// Get a channel by index
    fn get_by_index(&self, index: usize) -> Option<&Self::Channel>;
}

/// The interface
///
/// An `Interface` is the component of the host that must run with the interface driver. Its the
/// part of the host that must perpetually await upon the
pub struct Interface<T> {
    channel_manager: T,
}

impl<T> Interface<T>
where
    T: ChannelsManagement,
{
    /// The generic `new` implementation
    ///
    /// This creates an interface and initializes the
    fn new_inner(mut channel_manager: T) -> Self {
        channel_manager.try_add(ChannelId::Host).ok().unwrap();

        Self { channel_manager }
    }

    /// Create channels for a new connection
    pub fn new_connection(
        &mut self,
        handle: usize,
    ) -> Result<
        (
            <T::Channel as Channel>::Sender<'_>,
            <T::Channel as Channel>::Receiver<'_>,
        ),
        T::Error,
    > {
        let rx_index = self.channel_manager.try_add(ChannelId::Connection(handle))?;

        let sender = self.channel_manager.get_rx_channel().get_sender();

        let receiver = self.channel_manager.get_by_index(rx_index).unwrap().get_receiver();

        Ok((sender, receiver))
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
    /// # use crate::bo_tie::hci::interface::{BufferSend, Channel, ChannelId, ChannelsManagement, HciPacket, HciPacketType, Interface, Receiver, Sender};
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
    /// #    fn get_sender<'a>(&'a self) -> Self::Sender<'a> {
    /// #        unimplemented!()
    /// #    }
    /// #    
    /// #    fn get_receiver<'a>(&'a self) -> Self::Receiver<'a> {
    /// #        unimplemented!()
    /// #    }
    /// # }
    /// #
    /// # struct CM;
    /// # impl ChannelsManagement for CM {
    /// #    type Error = usize;
    /// #    type Channel = C;
    /// #
    /// #    fn get_rx_channel(&self) -> &Self::Channel {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn try_add(&mut self, id: ChannelId) -> Result<usize, Self::Error> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn try_remove(&mut self, id: ChannelId) -> Result<Self::Channel, Self::Error> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn get(&self, id: ChannelId) -> Option<&Self::Channel> {
    /// #        unimplemented!()
    /// #    }
    /// #
    /// #    fn get_by_index(&self, index: usize) -> Option<&Self::Channel> {
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
    pub fn buffered_send<'a>(
        &'a mut self,
        packet_type: HciPacketType,
    ) -> BufferedSend<'a, T, <<T::Channel as Channel>::Sender<'a> as Sender>::Message>
    where
        <<T::Channel as Channel>::Sender<'a> as Sender>::Message: Deref<Target = [u8]> + Extend<u8> + Default,
    {
        BufferedSend::new(self, packet_type)
    }

    /// Send a complete HCI packet
    ///
    /// This sends a complete `HciPacket` to the correct destination (either the host or a
    /// connection async task). It is up to the implementation to guarantee that the data within
    /// the packet is complete.
    pub async fn send<'a>(
        &'a mut self,
        packet: HciPacket<<<T::Channel as Channel>::Sender<'a> as Sender>::Message>,
    ) -> Result<(), SendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        match packet.packet_type {
            HciPacketType::Command | HciPacketType::Event => self
                .channel_manager
                .get(ChannelId::Host)
                .unwrap()
                .get_sender()
                .send(packet)
                .await
                .map_err(|e| SendError::ChannelError(e)),
            _ => Ok(()),
        }
    }

    /// Receive a HCI packet
    ///
    /// Await for the next `HciPacket` to be sent to the interface.
    ///
    /// This method returns `None` when there are no more Senders associated with the underlying
    /// receiver. The interface async task should exit after `None` is received.
    pub async fn recv(&mut self) -> Option<HciPacket<<<T::Channel as Channel>::Receiver<'_> as Receiver>::Message>> {
        self.channel_manager.get_rx_channel().get_receiver().recv().await
    }
}

impl<T> Interface<T> {
    /// Create a new local `Interface`
    ///
    /// A local interface is used whenever the interface driver is not `Send` safe. Using this
    /// means the host, interface driver, and connection async tasks all run within the same thread.
    pub fn new_local(channel_size: usize) -> Interface<local_channel::LocalChannelManager<HciPacket<T>>> {
        Interface::<local_channel::LocalChannelManager<HciPacket<T>>>::new_inner(
            local_channel::LocalChannelManager::new(channel_size),
        )
    }

    /// Create a statically sized local interface
    ///
    /// This interface uses statically allocated buffers to create a message channel system between
    /// the host, interface, and connection async tasks. This messaging is not `Send` safe so the
    /// host, interface, and connection async tasks must run within the same thread.
    ///
    /// The number of channels is defined by the constant `CHANNEL_COUNT`. The interface task has
    /// two channels to ever other task, this constant must be equal to two times the number of
    /// connection async tasks plus two for the channels to the host async task.
    ///
    ///
    pub fn new_local_static<const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize>(
    ) -> Interface<local_channel::LocalStaticChannelManager<HciPacket<T>, CHANNEL_COUNT, CHANNEL_SIZE>> {
        Interface::<local_channel::LocalStaticChannelManager<HciPacket<T>, CHANNEL_COUNT, CHANNEL_SIZE>>::new_inner(
            local_channel::LocalStaticChannelManager::new(),
        )
    }
}

#[derive(Debug)]
pub enum SendError<T> {
    ChannelError(T),
    UnknownConnectionHandle(u16),
}

impl<T> Display for SendError<T>
where
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            SendError::ChannelError(e) => e.fmt(f),
            SendError::UnknownConnectionHandle(handle) => {
                write!(f, "no known connection handle {}", handle)
            }
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
pub struct BufferedSend<'a, T, B> {
    interface: &'a mut Interface<T>,
    packet_type: HciPacketType,
    buffer: B,
    packet_len: Option<usize>,
}

impl<'a, T> BufferedSend<'a, T, <<T::Channel as Channel>::Sender<'a> as Sender>::Message>
where
    T: ChannelsManagement,
    <<T::Channel as Channel>::Sender<'a> as Sender>::Message: Deref<Target = [u8]> + Extend<u8>,
{
    /// Create a new `BufferSend`
    ///
    /// todo use pre-allocated buffers instead of creating them from default
    fn new(interface: &'a mut Interface<T>, packet_type: HciPacketType) -> Self
    where
        <<T::Channel as Channel>::Sender<'a> as Sender>::Message: Default,
    {
        BufferedSend {
            interface,
            packet_type,
            buffer: Default::default(),
            packet_len: None,
        }
    }

    /// Add bytes before the *parameter length* in the Command packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once three bytes of the Command packet are processed.
    #[inline]
    fn add_initial_command_byte(&mut self, byte: u8) {
        self.buffer.extend(core::iter::once(byte));

        if 3 == self.buffer.len() {
            self.packet_len = Some(3usize + self.buffer[2] as usize);
        }
    }

    /// Add bytes before the *data total length* in the ACL Data packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once four bytes of the ACL Data packet are processed.
    #[inline]
    fn add_initial_acl_data_byte(&mut self, byte: u8) {
        self.buffer.extend(core::iter::once(byte));

        if 4 == self.buffer.len() {
            let len = <u16>::from_le_bytes([self.buffer[2], self.buffer[3]]);

            self.packet_len = Some(4usize + len as usize);
        }
    }

    /// Add bytes before the *data_total_length* in the Synchronous Data packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once three bytes of the Synchronous Data packet are processed.
    #[inline]
    fn add_initial_sco_data_byte(&mut self, byte: u8) {
        // methods are the same by coincidence
        self.add_initial_command_byte(byte);
    }

    /// Add bytes before the *parameter total length* in the Event packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once two bytes of the Event packet are processed.
    #[inline]
    fn add_initial_event_byte(&mut self, byte: u8) {
        self.buffer.extend(core::iter::once(byte));

        if 2 == self.buffer.len() {
            self.packet_len = Some(2usize + self.buffer[2] as usize);
        }
    }

    /// Add bytes before the *ISO_Data_Load_Length* in the ISO Data packet is acquired
    ///
    /// This method is called when member `packet_len` is still `None`. It will set `packet_len` to
    /// a value once four bytes of the ISO Data are processed.
    #[inline]
    fn add_initial_iso_data_byte(&mut self, byte: u8) {
        self.buffer.extend(core::iter::once(byte));

        if 4 == self.buffer.len() {
            // The length field only has 12 bits
            let len = <u16>::from_le_bytes([self.buffer[2], self.buffer[3]]) & 0x3FFF;

            self.packet_len = Some(4usize + len as usize);
        }
    }

    /// Add initial bytes to the buffer
    ///
    /// These are bytes that are added before the length field has been buffered. Essentially this
    /// is called when `packet_len` is `None`.
    #[inline]
    fn add_initial_byte(&mut self, byte: u8) {
        match self.packet_type {
            HciPacketType::Command => self.add_initial_command_byte(byte),
            HciPacketType::Acl => self.add_initial_acl_data_byte(byte),
            HciPacketType::Sco => self.add_initial_sco_data_byte(byte),
            HciPacketType::Event => self.add_initial_event_byte(byte),
            HciPacketType::Iso => self.add_initial_iso_data_byte(byte),
        }
    }

    /// Add a byte to the buffer
    ///
    /// If the byte is an "overfeed" then it is ignored.
    ///
    /// # Return
    /// `true` is returned if the this `BufferSend` contains a complete HCI Packet.
    ///
    /// # Note
    /// `byte` is ignored if this already has a complete HCI Packet.
    pub fn add(
        &mut self,
        byte: u8,
    ) -> Result<bool, BufferedSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        match self.packet_len {
            None => {
                self.add_initial_byte(byte);

                Ok(false)
            }
            Some(len) if len != self.buffer.len() => {
                self.buffer.extend(core::iter::once(byte));

                Ok(len == self.buffer.len())
            }
            _ => Err(BufferedSendError::BufferReadyToSend),
        }
    }

    /// Add bytes to the buffer
    ///
    /// This add multiple bytes to the buffer, stopping iteration of `iter` early if a complete HCI
    /// Packet is formed.
    ///
    /// # Return
    /// `true` is returned if the this `BufferSend` contains a complete HCI Packet.
    pub fn add_bytes<I: IntoIterator<Item = u8>>(
        &mut self,
        iter: I,
    ) -> Result<bool, BufferedSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        for i in iter {
            if self.add(i)? {
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Check if a complete HCI packet is stored and ready to be sent
    pub fn is_ready(&self) -> bool {
        self.packet_len
            .as_ref()
            .map(|len| *len == self.buffer.len())
            .unwrap_or_default()
    }

    /// Send the HCI Packet to its destination
    ///
    /// When a complete packet is sored within this `BufferSend`, this method is called to transfer
    /// the packet to its
    pub async fn send(self) -> Result<(), BufferedSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        self.packet_len.ok_or(BufferedSendError::IncompleteHciPacket)?;

        let hci_packet = HciPacket {
            packet_type: self.packet_type,
            data: self.buffer,
        };

        self.interface
            .send(hci_packet)
            .await
            .map_err(|e| BufferedSendError::SendError(e))
    }
}

impl<'a, T> Extend<u8> for BufferedSend<'a, T, <<T::Channel as Channel>::Sender<'a> as Sender>::Message>
where
    T: ChannelsManagement,
    <<T::Channel as Channel>::Sender<'a> as Sender>::Message: Deref<Target = [u8]> + Extend<u8>,
{
    fn extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) {
        self.add_bytes(iter);
    }
}

#[derive(Debug)]
pub enum BufferedSendError<E> {
    BufferReadyToSend,
    IncompleteHciPacket,
    SendError(SendError<E>),
}

impl<E> Display for BufferedSendError<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferedSendError::BufferReadyToSend => f.write_str("buffer contains a complete HCI packet"),
            BufferedSendError::IncompleteHciPacket => f.write_str("cannot send incomplete HCI packet"),
            BufferedSendError::SendError(e) => e.fmt(f),
        }
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
/// use futures::channel::mpsc;
/// use futures::sink;
/// use bo_tie::hci::interface::Sender;
///
/// struct FuturesSender<T>(mpsc::Sender<T>);
///
/// impl<T> Sender for FuturesSender<T> {
///     type Error = mpsc::SendError;
///     type Message = T;
///     type SendFuture<'a> = sink::Feed<'a, mpsc::Sender<T>, T> where T: 'a;
///
///     fn send<'a>(&'a mut self, t: Self::Message) -> Self::SendFuture<'a> {
///         // Sending an item does not await until the item is received
///         sink::SinkExt::feed(&mut self.0, t)
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
///     fn send<'a>(&'a mut self, t: Self::Message) -> Self::SendFuture<'a> {
///         // Since `send` is an async method, its return type is hidden.
///         self.0.send(t)
///    }
/// }
/// ```
pub trait Sender {
    type Error;
    type Message: Unpin;
    type SendFuture<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    fn send<'a>(&'a mut self, t: Self::Message) -> Self::SendFuture<'a>;
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
/// use futures::channel::mpsc;
/// use futures::stream;
/// use futures::FutureExt;
/// use bo_tie::hci::interface::Receiver;
///
/// struct FuturesReceiver<T>(mpsc::Receiver<T>);
///
/// impl<T> Receiver for FuturesReceiver<T> {
///     type Message = T;
///     type ReceiveFuture<'a> = stream::Next<'a, mpsc::Receiver<T>> where T: 'a;
///
///     fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a> {
///         stream::StreamExt::next(&mut self.0)
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
///     fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a> {
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

    fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a>;
}

/// The types of HCI packets
pub enum HciPacketType<T> {
    /// Command packet
    Command(T),
    /// Asynchronous Connection-Oriented Data Packet
    Acl(T),
    /// Synchronous Connection-Oriented Data Packet
    Sco(T),
    /// Event Packet
    Event(T),
    /// Isochronous Data Packet
    Iso(T),
}

/// Inner interface messaging
///
/// This is the type for messages sent between the interface async task and either the host or a
/// connection async tasks. HCI packets are the most common message, but there is also other types
/// of messages sent for task related things.
#[repr(transparent)]
pub struct IntraMessage<T> {
    pub(crate) ty: T,
}

impl<T> IntraMessage<T> {
    pub(crate) fn into_buffer(self) -> Option<T> {
        match self.0 {
            IntraMessageType::Command(_, t) => Some(t),
            IntraMessageType::Acl(t) => Some(t),
            IntraMessageType::Sco(t) => Some(t),
            IntraMessageType::Event(t) => Some(t),
            IntraMessageType::Iso(t) => Some(t),
            _ => None,
        }
    }
}

impl<T> From<IntraMessageType<T>> for IntraMessage<T> {
    fn from(ty: IntraMessageType<T>) -> Self {
        Self { ty }
    }
}

impl<T> From<HciPacket<T>> for IntraMessage<T> {
    fn from(packet: HciPacket<T>) -> Self {
        let ty = IntraMessageType::Hci(packet);

        Self { ty }
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
    /// HCI Event Packet
    Event(T),
    /// HCI isochronous Data Packet
    Iso(T),

    /*----------------------------
       Meta information messages
      ----------------------------*/

    /// Finished command
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

        let mut sender = channel.get_sender();
        let mut receiver = channel.get_receiver();

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
