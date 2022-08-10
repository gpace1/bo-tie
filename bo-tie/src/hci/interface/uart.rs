//! UART interface implementation for HCI
//!
//! UART is one of the interfaces within the Bluetooth Specification. It states that HCI Packets are
//! transferred over UART with an indicator at the beginning of the message. This indicator is a
//! single byte prepended to the HCI Packet.
//!
//! A `UartInterface` is a wrapper around an `Interface` to integrate processing of this packet
//! indicator into the sending and reception of packets from the host or connection async tasks.


use crate::hci::interface::{BufferedUpSend, ChannelReserve, HciPacketType, Interface, SendError};
use core::fmt::{Debug, Display, Formatter};

/// UART wrapper around an [`Interface`](Interface)
///
/// The is the implementation for UART as specified within Bluetooth Specification. This wrapper
/// adds the processing of the packet indicator to the processing of data received from the
/// interface. The methods to send to another async task will assume that a one byte byte packet
/// indicator prepends the HCI packet.
///
///
pub struct UartInterface<R> {
    interface: Interface<R>,
}

impl<R> UartInterface<R>
where
    R: ChannelReserve,
{
    /// Create a new `UartInterface`
    pub fn new(interface: Interface<R>) -> Self {
        Self { interface }
    }

    /// Process a received byte
    ///
    /// This the `UartInterface` equivalent of the method [`buffered_send`] within `Interface` with
    /// the exception that it does not need to be initialized with the HCI packet type. Instead it
    /// is able to determine the packet type by assuming the first byte put into the buffer is the
    /// packet indicator. Otherwise the returned `UartBufferedUpSend` acts the same as the return of
    /// method `buffered_send` within `Interface`.
    pub async fn buffered_send(&mut self) -> UartBufferedUpSend<'_, R> {
        UartBufferedUpSend::new(&mut self.interface)
    }
}

impl<R> From<Interface<R>> for UartInterface<R> {
    fn from(interface: Interface<R>) -> Self {
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
        _ => Err(UartInterfaceError(byte)),
    }
}

/// Error for a UART interface
///
/// This error only occurs when an invalid packet indicator is sent
pub struct UartInterfaceError(u8);

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

enum UartSendState<'a, R: ChannelReserve> {
    Swap,
    Interface(&'a mut Interface<R>),
    BufferedSender(BufferedUpSend<'a, R>),
}

impl<'a, R: ChannelReserve> UartSendState<'a, R> {
    /// unwrap the interface
    ///
    /// # Panic
    /// A panic occurs if this is not enum `Interface`
    fn unwrap_interface(self) -> &'a mut Interface<R> {
        if let UartSendState::Interface(interface) = self {
            interface
        } else {
            panic!("uart send state is not interface")
        }
    }
}

/// A buffered sender for UART
///
/// This is the return of the method [`buffered_send`](UartInterface::buffered_send) within
/// `UartInterface`.
pub struct UartBufferedUpSend<'a, R: ChannelReserve> {
    state: UartSendState<'a, R>,
}

impl<'a, R> UartBufferedUpSend<'a, R>
where
    R: ChannelReserve,
{
    fn new(interface: &'a mut Interface<R>) -> Self {
        let state = UartSendState::Interface(interface).into();

        Self { state }
    }

    /// Add a byte to the buffer
    ///
    /// This adds a byte to the buffer. The first byte added to the buffer is always assumed to be
    /// the indicator byte and any following bytes to be HCI packet. `add` will return true when it
    /// is determined that the buffer contains a complete HCI packet
    pub async fn add(&'a mut self, byte: u8) -> Result<bool, UartBufferedSendError<R>> {
        use core::mem::replace;

        match self.state {
            UartSendState::Swap => unreachable!(),
            UartSendState::Interface(_) => {
                let packet_type = match_uart_packet(byte)?;

                let buffered_sender = replace(&mut self.state, UartSendState::Swap)
                    .unwrap_interface()
                    .buffered_up_send(packet_type);

                drop(replace(&mut self.state, UartSendState::BufferedSender(buffered_sender)));

                Ok(false)
            }
            UartSendState::BufferedSender(ref mut buffered_sender) => buffered_sender
                .add(byte)
                .await
                .map_err(|e| UartBufferedSendError::BufferedSendError(e)),
        }
    }

    /// Send the HCI Packet to its destination
    ///
    /// When a complete packet is sored within this `UartBufferedSendError`, this method is must be
    /// called to transfer the packet to its destination. An error is returned if this method is
    /// called  and this `UartBufferedSendError` does not contain a complete HCI packet.
    pub async fn up_send(self) -> Result<(), UartBufferedSendError<R>> {
        match self.state {
            UartSendState::BufferedSender(bs) => {
                bs.up_send().await.map_err(|e| UartBufferedSendError::BufferedSendError(e))
            }
            _ => Err(UartBufferedSendError::NothingBuffered),
        }
    }
}

#[derive(Debug)]
pub enum UartBufferedSendError<R: ChannelReserve> {
    NothingBuffered,
    UartInterface(UartInterfaceError),
    BufferedSendError(SendError<R>),
}

impl<R> From<UartInterfaceError> for UartBufferedSendError<R>
where
    R: ChannelReserve,
{
    fn from(e: UartInterfaceError) -> Self {
        Self::UartInterface(e)
    }
}

impl<R: ChannelReserve> Display for UartBufferedSendError<R>
where
    R::SenderError: Display,
    R::TryExtendError: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            UartBufferedSendError::NothingBuffered => f.write_str("uart buffer contains no bytes"),
            UartBufferedSendError::UartInterface(e) => Display::fmt(e, f),
            UartBufferedSendError::BufferedSendError(e) => Display::fmt(e, f),
        }
    }
}
