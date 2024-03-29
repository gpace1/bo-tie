//! UART interface implementation for HCI
//!
//! UART is one of the interfaces within the Bluetooth Specification. It states that HCI Packets are
//! transferred over UART with an indicator at the beginning of the message. This indicator is a
//! single byte prepended to the HCI Packet.
//!
//! A `UartInterface` is a wrapper around an `Interface` to integrate processing of this packet
//! indicator into the sending and reception of packets from the host or connection async tasks.

use crate::{BufferedUpSend, Interface, SendError};
use bo_tie_core::buffer::TryExtend;
use bo_tie_hci_util::{BufferReserve, ChannelReserve, HciPacket, HciPacketType};
use core::fmt::{Debug, Display, Formatter};
use core::ops::Deref;

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

    /// Create a buffer for bytes received from the interface
    ///
    /// This the `UartInterface` equivalent of the method [`buffered_up_send`] within `Interface`
    /// with the exception that it does not need to be initialized with the HCI packet type. Instead
    /// it is able to determine the packet type by assuming the first byte put into the buffer is
    /// the packet indicator. Otherwise the returned `UartBufferedUpSend` acts the same as the
    /// return of method `buffered_send` within `Interface`.
    ///
    /// [`buffered_up_send`]: Interface::buffered_up_send
    pub async fn buffered_send(&mut self) -> UartBufferedUpSend<'_, R> {
        UartBufferedUpSend::new(&mut self.interface)
    }

    /// Get the next HCI packet to send to the controller
    ///
    /// This is equivalent to [`Interface::down_send`].
    ///
    /// [`Interface::down_send`]: crate::Interface::down_send
    #[inline]
    pub async fn down_send(&mut self) -> Option<HciPacket<impl Deref<Target = [u8]>>> {
        self.interface.down_send().await
    }
}

impl<R> From<Interface<R>> for UartInterface<R> {
    fn from(interface: Interface<R>) -> Self {
        UartInterface { interface }
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
                let packet_type = PacketIndicator::translate(byte)?;

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
            UartSendState::BufferedSender(bs) => bs
                .up_send()
                .await
                .map_err(|e| UartBufferedSendError::BufferedSendError(e)),
            _ => Err(UartBufferedSendError::NothingBuffered),
        }
    }
}

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

impl<R: ChannelReserve> Debug for UartBufferedSendError<R>
where
    <<<R as ChannelReserve>::FromHostChannel as BufferReserve>::Buffer as TryExtend<u8>>::Error: Debug,
    <<<R as ChannelReserve>::ToConnectionDataChannel as BufferReserve>::Buffer as TryExtend<u8>>::Error: Debug,
    <<<R as ChannelReserve>::FromConnectionChannel as BufferReserve>::Buffer as TryExtend<u8>>::Error: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            UartBufferedSendError::NothingBuffered => f.write_str("UartBufferedSendError"),
            UartBufferedSendError::UartInterface(e) => write!(f, "UartInterface({:?})", e),
            UartBufferedSendError::BufferedSendError(e) => write!(f, "BufferedSendError({:?})", e),
        }
    }
}

impl<R: ChannelReserve> Display for UartBufferedSendError<R>
where
    R::Error: Display,
    R::SenderError: Display,
    <<<R as ChannelReserve>::FromHostChannel as BufferReserve>::Buffer as TryExtend<u8>>::Error: Display,
    <<<R as ChannelReserve>::ToConnectionDataChannel as BufferReserve>::Buffer as TryExtend<u8>>::Error: Display,
    <<<R as ChannelReserve>::FromConnectionChannel as BufferReserve>::Buffer as TryExtend<u8>>::Error: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            UartBufferedSendError::NothingBuffered => f.write_str("uart buffer contains no bytes"),
            UartBufferedSendError::UartInterface(e) => Display::fmt(e, f),
            UartBufferedSendError::BufferedSendError(e) => Display::fmt(e, f),
        }
    }
}

/// UART packet indicator
///
/// UART packets are marked by a byte prepended to the HCI packet. This byte is an indicator for
/// what kind of HCI packet the rest of the data is.
pub struct PacketIndicator;

impl PacketIndicator {
    /// Get the packet type for the packet indicator
    pub fn translate(byte: u8) -> Result<HciPacketType, UartInterfaceError> {
        match byte {
            1 => Ok(HciPacketType::Command),
            2 => Ok(HciPacketType::Acl),
            3 => Ok(HciPacketType::Sco),
            4 => Ok(HciPacketType::Event),
            5 => Ok(HciPacketType::Iso),
            _ => Err(UartInterfaceError(byte)),
        }
    }

    /// Get the packet indicator for a packet type
    pub fn indicate(packet_type: HciPacketType) -> u8 {
        match packet_type {
            HciPacketType::Command => 1,
            HciPacketType::Acl => 2,
            HciPacketType::Sco => 3,
            HciPacketType::Event => 4,
            HciPacketType::Iso => 5,
        }
    }

    /// Prepend a `HciPacket` with the packet indicator
    ///
    /// The UART packet indicator associated to the enumeration value of the input `HciPacket` is
    /// prepended to the buffer contained within the enumeration.
    ///
    /// ```
    /// # use bo_tie_hci_interface::uart::PacketIndicator;
    /// # use bo_tie_util::buffer::BufferExt;
    /// # use bo_tie_util::buffer::de_vec::DeVec;
    /// # let buffer = DeVec::with_front_capacity(1);
    /// # use bo_tie_hci_util::HciPacket;
    ///
    /// let mut packet = HciPacket::Event(buffer);
    ///
    /// let raw_data = PacketIndicator::prepend(&mut packet).expect("buffer cannot be extended at the front");
    ///
    /// // 4 is the packet indicator for an event
    /// assert_eq!(4, raw_data[0])
    /// ```
    ///
    /// # Error
    /// An error will occur if the buffer `T` cannot be prepend to.
    pub fn prepend<T>(packet: &mut HciPacket<T>) -> Result<&mut T, T::Error>
    where
        T: bo_tie_core::buffer::TryFrontExtend<u8>,
    {
        macro_rules! prepend {
            ($buffer:expr, $enumeration:ident) => {{
                $buffer.try_front_extend_one(PacketIndicator::indicate(HciPacketType::$enumeration))?;

                Ok($buffer)
            }};
        }

        match packet {
            HciPacket::Command(t) => prepend!(t, Command),
            HciPacket::Acl(t) => prepend!(t, Acl),
            HciPacket::Sco(t) => prepend!(t, Sco),
            HciPacket::Event(t) => prepend!(t, Event),
            HciPacket::Iso(t) => prepend!(t, Iso),
        }
    }

    /// Convert a UART packet into a `HciPacket`
    pub fn convert<B>(packet: &B) -> Result<HciPacket<&[u8]>, PacketIndicatorError>
    where
        B: ?Sized + core::borrow::Borrow<[u8]>,
    {
        match packet.borrow().get(0).map(|byte| Self::translate(*byte)).transpose() {
            Ok(None) => Err(PacketIndicatorError::PacketEmpty),
            Ok(Some(HciPacketType::Command)) => Ok(HciPacket::Command(packet.borrow().get(1..).unwrap())),
            Ok(Some(HciPacketType::Acl)) => Ok(HciPacket::Acl(packet.borrow().get(1..).unwrap())),
            Ok(Some(HciPacketType::Sco)) => Ok(HciPacket::Sco(packet.borrow().get(1..).unwrap())),
            Ok(Some(HciPacketType::Event)) => Ok(HciPacket::Event(packet.borrow().get(1..).unwrap())),
            Ok(Some(HciPacketType::Iso)) => Ok(HciPacket::Iso(packet.borrow().get(1..).unwrap())),
            Err(_) => Err(PacketIndicatorError::UnknownIndicator(
                packet.borrow().get(0).copied().unwrap(),
            )),
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum PacketIndicatorError {
    PacketEmpty,
    UnknownIndicator(u8),
}

impl Display for PacketIndicatorError {
    fn fmt(&self, f: &mut Formatter) -> core::fmt::Result {
        match self {
            PacketIndicatorError::PacketEmpty => f.write_str("packet is empty"),
            PacketIndicatorError::UnknownIndicator(val) => write!(f, "unknown indicator {:#x}", val),
        }
    }
}
