//! Implementation for the interface between the host and controller
//!
//! There are four types of interfaces mentioned within the Bluetooth Specification (v5.2) but
//! interfacing between the host and controller can be done via any interface so long as the host
//! to controller functional specification can be applied to it. As a general rule any interface
//! can work so long as there is a way to send and receive data between the host and controller
//! asynchronously in respect to either side's CPU.
//!
//! The Host Controller Interface is broken up within this library between the interface and the
//! functional specification. The functional specification is defined within this library but the
//! interfaces are always going to have some part of them that is platform specific. Even the four
//! kinds of interfaces defined within the Specification are not completely implemented within this
//! library. There is always some part, whether it is something related to memory mapping or some
//! API details that must be implemented by a platform for using the interface between the Host and
//! Controller with this library
//!
//! ## Specification Defined Interfaces
//! UART, USB, Secure Digital (SD), and Three-Wire UART interfaces have defined specification for
//! how to use them with the functional specification. Everything that is defined within the
//! specification is implemented within this library, but this only covers the data encapsulation
//! and some of configuration details.

use core::future::Future;
use std::fmt::{Debug, Display, Formatter};
use std::ops::Deref;

mod buffer;
mod local_channel;

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
/// The interface is the component of the host that runs with the interface driver.
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

    /// Buffer and send a HCI packet from the interface
    ///
    /// Packets are processed and sent from the interface to their appropriate receiving async task
    /// by this method. Unfortunately however, in order to facilitate as many different types of
    /// interfaces as possible this send method needs to be a bit weird. Because some interface are
    /// not able to transfer a complete HCI packet, `maybe_send` can be called multiple times. The
    /// input bytes are buffered until `maybe_send` can form a complete packet before sending that
    /// to its destination.
    ///
    /// `maybe_send` works by greedily consuming bytes until a complete HCI packet formed.
    pub fn buffer_send<'a>(
        &'a mut self,
        packet_type: HciPacketType,
    ) -> BufferSend<T, <<T::Channel as Channel>::Sender<'a> as Sender>::Payload>
    where
        <<T::Channel as Channel>::Sender<'a> as Sender>::Payload: Deref<Target = [u8]> + Extend<u8> + Default,
    {
        BufferSend::new(self, packet_type)
    }

    /// Send a complete HCI packet
    pub async fn send<'a>(
        &'a mut self,
        packet: HciPacket<<<T::Channel as Channel>::Sender<'a> as Sender>::Payload>,
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
    pub async fn recv(&mut self) -> Option<HciPacket<<<T::Channel as Channel>::Receiver<'_> as Receiver>::Payload>> {
        self.channel_manager.get_rx_channel().get_receiver().recv().await
    }
}

impl<T> Interface<local_channel::LocalChannelManager<HciPacket<T>>> {
    /// Create a new local `Interface`
    ///
    /// A local interface is used whenever the interface driver is not `Send` safe. Using this
    /// means the host, interface driver, and connection async tasks all run within the same thread.
    pub fn new_local(channel_size: usize) -> Self {
        Self::new_inner(local_channel::LocalChannelManager::new(channel_size))
    }
}

impl<T, const CHANNEL_COUNT: usize, const CHANNEL_SIZE: usize>
    Interface<local_channel::LocalStaticChannelManager<HciPacket<T>, CHANNEL_COUNT, CHANNEL_SIZE>>
{
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
    pub fn new_local_static() -> Self {
        Self::new_inner(local_channel::LocalStaticChannelManager::new())
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
pub struct BufferSend<'a, T, B> {
    interface: &'a mut Interface<T>,
    packet_type: HciPacketType,
    buffer: B,
    packet_len: Option<usize>,
}

impl<'a, T> BufferSend<'a, T, <<T::Channel as Channel>::Sender<'a> as Sender>::Payload>
where
    T: ChannelsManagement,
    <<T::Channel as Channel>::Sender<'a> as Sender>::Payload: Deref<Target = [u8]> + Extend<u8>,
{
    /// Create a new `BufferSend`
    ///
    /// todo use pre-allocated buffers instead of creating them from default
    fn new(interface: &'a mut Interface<T>, packet_type: HciPacketType) -> Self
    where
        <<T::Channel as Channel>::Sender<'a> as Sender>::Payload: Default,
    {
        BufferSend {
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
    pub fn add(&mut self, byte: u8) -> bool {
        match self.packet_len {
            None => {
                self.add_initial_byte(byte);

                false
            }
            Some(len) if len != self.buffer.len() => {
                self.buffer.extend(core::iter::once(byte));

                len == self.buffer.len()
            }
            _ => true,
        }
    }

    /// Add bytes to the buffer
    ///
    /// This add multiple bytes to the buffer, stopping early if a complete HCI Packet is formed.
    ///
    /// # Return
    /// `true` is returned if the this `BufferSend` contains a complete HCI Packet.
    pub fn add_bytes<I: IntoIterator<Item = u8>>(&mut self, iter: I) -> bool {
        for i in iter {
            if self.add(i) {
                return true;
            }
        }

        false
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
    pub async fn send(self) -> Result<(), BufferSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        self.packet_len.ok_or(BufferSendError::IncompleteHciPacket)?;

        let hci_packet = HciPacket {
            packet_type: self.packet_type,
            data: self.buffer,
        };

        self.interface
            .send(hci_packet)
            .await
            .map_err(|e| BufferSendError::SendError(e))
    }
}

impl<'a, T> Extend<u8> for BufferSend<'a, T, <<T::Channel as Channel>::Sender<'a> as Sender>::Payload>
where
    T: ChannelsManagement,
    <<T::Channel as Channel>::Sender<'a> as Sender>::Payload: Deref<Target = [u8]> + Extend<u8>,
{
    fn extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) {
        self.add_bytes(iter);
    }
}

#[derive(Debug)]
pub enum BufferSendError<E> {
    IncompleteHciPacket,
    SendError(SendError<E>),
}

impl<E> Display for BufferSendError<E>
where
    E: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferSendError::IncompleteHciPacket => f.write_str("cannot send incomplete HCI packet"),
            BufferSendError::SendError(e) => e.fmt(f),
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
/// use temp_::{Sender, HciPacket};
///
/// struct FuturesSender<T>(mpsc::Sender<HciPacket<T>>);
///
/// impl<T> Sender for FuturesSender<T> {
///     type Error = mpsc::SendError;
///     type Payload = T;
///     type SendFuture<'a> = sink::Feed<'a, mpsc::Sender<HciPacket<T>>, HciPacket<T>> where T: 'a;
///
///     fn send<'a>(&'a mut self, t: HciPacket<Self::Payload>) -> Self::SendFuture<'a> {
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
/// use temp_::{Sender, HciPacket};
///
/// struct TokioSender<T>(mpsc::Sender<HciPacket<T>>);
///
/// impl<T> Sender for TokioSender<T> {
///     type Error = mpsc::error::SendError<HciPacket<T>>;
///     type Payload = T;
///     type SendFuture<'a> = impl Future<Output = Result<(), Self::Error>> + 'a where T: 'a;
///
///     fn send<'a>(&'a mut self, t: HciPacket<Self::Payload>) -> Self::SendFuture<'a> {
///         // Since `send` is an async method, its return type is hidden.
///         self.0.send(t)
///    }
/// }
/// ```
pub trait Sender {
    type Error;
    type Payload;
    type SendFuture<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    fn send<'a>(&'a mut self, t: HciPacket<Self::Payload>) -> Self::SendFuture<'a>;
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
/// use temp_::{Receiver, HciPacket};
///
/// struct FuturesReceiver<T>(mpsc::Receiver<HciPacket<T>>);
///
/// impl<T> Receiver for FuturesReceiver<T> {
///     type Payload = T;
///     type ReceiveFuture<'a> = stream::Next<'a, mpsc::Receiver<HciPacket<T>>> where T: 'a;
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
/// use temp_::{Receiver, HciPacket};
///
/// struct TokioSender<T>(mpsc::Receiver<HciPacket<T>>);
///
/// impl<T> Receiver for TokioSender<T> {
///     type Payload = T;
///     type ReceiveFuture<'a> = impl Future<Output = Option<HciPacket<T>>> + 'a where T: 'a;
///
///     fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a> {
///         // Since `send` is an async method, its return type is hidden.
///         self.0.recv()
///    }
/// }
/// ```
pub trait Receiver {
    type Payload;
    type ReceiveFuture<'a>: Future<Output = Option<HciPacket<Self::Payload>>>
    where
        Self: 'a;

    fn recv<'a>(&'a mut self) -> Self::ReceiveFuture<'a>;
}

/// The types of HCI packets
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

/// An HCI packet
pub struct HciPacket<T> {
    packet_type: HciPacketType,
    data: T,
}

impl<T> HciPacket<T>
where
    T: Deref<Target = [u8]>,
{
    /// Get the size of the HCI packet
    pub fn len(&self) -> usize {
        self.data.len()
    }
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
