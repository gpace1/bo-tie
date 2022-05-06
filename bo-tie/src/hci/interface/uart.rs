//! UART interface implementation for HCI
//!
//! UART is one of the interfaces within the Bluetooth Specification. It states that HCI Packets are
//! transferred over UART with an indicator at the beginning of the message. This indicator is a
//! single byte prepended to the HCI Packet.
//!
//! A `UartInterface` is a wrapper around an `Interface` to integrate processing of this packet
//! indicator into the sending and reception of packets from the host or connection async tasks.

use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;
use futures::SinkExt;
use crate::hci::events::PacketType;
use crate::hci::interface::{BufferedSend, BufferedSendError, Channel, ChannelsManagement, HciPacketType, Interface, Sender};

/// UART wrapper around an [`Interface`](Interface)
///
/// The is the implementation for UART as specified within Bluetooth Specification. This wrapper
/// adds the processing of the packet indicator to the processing of data received from the
/// interface. The methods to send to another async task will assume that a one byte byte packet
/// indicator prepends the HCI packet.
///
///
struct UartInterface<T> {
    interface: Interface<T>,
}

impl<T> UartInterface<T>
where
    T: ChannelsManagement,
{
    /// Create a new `UartInterface`
    pub fn new(interface: Interface<T>) -> Self {
        Self { interface }
    }

    /// Process a received byte
    ///
    /// This the `UartInterface` equivalent of the method [`buffered_send`] within `Interface` with
    /// the exception that it does not need to be initialized with the HCI packet type. Instead it
    /// is able to determine the packet type by assuming the first byte put into the buffer is the
    /// packet indicator. Otherwise the returned `UartBufferedSend` acts the same as the return of
    /// method `buffered_send` within `Interface`.
    pub async fn buffered_send(&mut self) -> UartBufferedSend<T, <<T::Channel as Channel>::Sender as Sender>::Payload> {
        UartBufferedSend::new(self)
    }

    /// Proce
}

impl<T> From<Interface<T>> for UartInterface<T> {
    fn from(interface: Interface<T>) -> Self {
        UartInterface { interface }
    }
}

fn match_uart_packet(byte: u8) -> Result<HciPacketType, UartInterfaceError> {
    match byte {
        1 => Ok(HciPacketType::Command),
        2 => Ok(HciPacketType::Acl),
        3 => Ok(HciPacketType::Sco),
        4 => Ok(HciPacketType::Event),
        5 => Ok(HciPacketType::Iso),
        _ => Err(UartInterfaceError(byte))
    }
}

/// Error for a UART interface
///
/// This error only occurs when an invalid packet indicator is sent
struct UartInterfaceError(u8);

impl Debug for UartInterfaceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Invalid packet indicator {}", self.0)
    }
}

impl Display for UartInterfaceError {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Invalid packet indicator {}", self.0)
    }
}

/// A buffered sender for UART
///
/// This is the return of the method [`buffered_send`](UartInterface::buffered_send) within
/// `UartInterface`.
struct UartBufferedSend<'a, T, B> {
    // being lazy and just using a result for an enum of two type
    buffered_send: Result<BufferedSend<'a, T, B>, &'a mut Interface<T>>
}

impl<'a, T> UartBufferedSend<'a, T, <<T::Channel as Channel>::Sender<'a> as Sender>::Payload>
    where
        T: ChannelsManagement,
        <<T::Channel as Channel>::Sender<'a> as Sender>::Payload: Deref<Target = [u8]> + Extend<u8>,
{

    fn new(interface: &'a mut Interface<T>) -> Self {
        let buffered_send = Err(interface);

        Self {
            buffered_send,
        }
    }

    /// Add a byte to the buffer
    ///
    /// This adds a byte to the buffer. The first byte added to the buffer is always assumed to be
    /// the indicator byte and any following bytes to be HCI packet. `add` will return true when it
    /// is determined that the buffer contains a complete HCI packet
    pub fn add(&mut self, byte: u8) -> Result<bool, UartBufferedSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        match self.buffered_send {
            Err(interface) => {
                let packet_type = match_uart_packet(byte)?;

                let buffered_sender = interface.buffered_send(packet_type);

                self.buffered_send = Ok(buffered_sender);

                Ok(false)
            }
            Ok(ref mut buffered_sender) => buffered_sender.add(byte)
        }
    }

    /// Add bytes to the buffer
    ///
    /// This add multiple bytes to the buffer, stopping iteration of `iter` early if a complete HCI
    /// Packet is formed.
    ///
    /// # Note
    /// The first byte added to a UartBufferedSend is expected to be the packet identifier.
    ///
    /// # Return
    /// `true` is returned if the this `BufferSend` contains a complete HCI Packet.
    pub fn add_bytes<I: IntoIterator<Item = u8>>(&mut self, iter: I) -> Result<bool, UartBufferedSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
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

    pub fn send(self) -> Result<(), UartBufferedSendError<<<T::Channel as Channel>::Sender<'a> as Sender>::Error>> {
        match self.buffered_send {
            Err(_) => Err(UartBufferedSendError::BufferedSendError(BufferedSendError::IncompleteHciPacket)),
            Ok(bs) => bs.send(),
        }
    }
}

#[derive(Debug)]
enum UartBufferedSendError<E> {
    UartInterface(UartInterfaceError),
    BufferedSendError(BufferedSendError<E>),
}

impl Display for UartBufferedSendError<E> where E: Display {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            UartBufferedSendError::UartInterface(e) => e.fmt(f),
            UartBufferedSendError::BufferedSendError(e) => e.fmt(f),
        }
    }
}