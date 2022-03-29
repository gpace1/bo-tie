use crate::TryExtend;

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum Error {
    #[cfg(any(feature = "alloc", feature = "std"))]
    #[error("{0}")]
    Message(alloc::string::String),
    #[error("{}", .0.to_str())]
    LimitedMessage(StaticAllocMessage<256>),
    #[error("{0}")]
    StaticMessage(&'static str),
    #[error("unexpected end of input")]
    Eof,
    #[error("invalid HCI packet, {0}")]
    HciPacket(HciPacketError),
    #[error("invalid HCI transport packet, {0}")]
    HciTransport(HciTransportError),
    #[error("exceeded maximum size")]
    TooLarge,
    #[error("expected boolean")]
    ExpectedBoolean,
    #[error("expected i8")]
    ExpectedI8,
    #[error("expected i16")]
    ExpectedI16,
    #[error("expected i32")]
    ExpectedI32,
    #[error("expected i64")]
    ExpectedI64,
    #[error("expected i128")]
    ExpectedI128,
    #[error("expected u8")]
    ExpectedU8,
    #[error("expected u16")]
    ExpectedU16,
    #[error("expected u32")]
    ExpectedU32,
    #[error("expected u64")]
    ExpectedU64,
    #[error("expected u128")]
    ExpectedU128,
    #[error("expected f32")]
    ExpectedF32,
    #[error("expected f64")]
    ExpectedF64,
    #[error("expected char")]
    ExpectedChar,
    #[error("expected string of UTF8 characters")]
    ExpectedStrUTF8,
    #[error("expected array of {0}")]
    ExpectedArray(&'static str),
    #[error("expected option")]
    ExpectedOption,
    #[error("option variant is invalid")]
    BadOption,
    #[error("expected sequence")]
    ExpectedSeq,
    #[error("expected map")]
    ExpectedMap,
    #[error("`deserialize_any` is not supported")]
    DeserializeAny,
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl serde::ser::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

#[cfg(not(any(feature = "std", feature = "alloc")))]
impl ser::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error::LimitedMessage(StaticAllocMessage::from(msg))
    }
}

#[cfg(any(feature = "std", feature = "alloc"))]
impl serde::de::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error::Message(msg.to_string())
    }
}

#[cfg(not(any(feature = "std", feature = "alloc")))]
impl serde::de::Error for Error {
    fn custom<T: core::fmt::Display>(msg: T) -> Self {
        Error::LimitedMessage(StaticAllocMessage::from(msg))
    }
}

/// Errors related to badly formatted HCI packets
#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum HciPacketError {
    #[error("The length field is incorrect")]
    BadLength,
}

/// Errors specific to the interface that connects the host to the controller
#[derive(Clone, Debug, PartialEq)]
pub struct HciTransportError {
    pub interface: &'static str,
    pub reason: HciTransportErrorReason,
}

impl HciTransportError {
    pub const INTERFACE_UART: &'static str = "UART";
    pub const INTERFACE_USB: &'static str = "USB";
    pub const INTERFACE_SD: &'static str = "Secure Digital (SD)";
    pub const INTERFACE_3_WIRE_UART: &'static str = "Three-wire UART";
}

impl core::fmt::Display for HciTransportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{} for interface {}", self.reason, self.interface)
    }
}

#[derive(Clone, Debug, PartialEq, thiserror::Error)]
pub enum HciTransportErrorReason {
    #[error("Invalid packet indicator ({0})")]
    InvalidPacketIndicator(usize),
}

#[derive(Clone, PartialEq)]
pub struct StaticAllocMessage<const SIZE: usize> {
    buffer: crate::StaticBuffer<SIZE>,
}

impl<const SIZE: usize> StaticAllocMessage<SIZE> {
    fn to_str(&self) -> &str {
        core::str::from_utf8(&self.buffer.buffer[..self.buffer.size]).unwrap()
    }
}

impl<const SIZE: usize> core::fmt::Debug for StaticAllocMessage<SIZE> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.to_str())
    }
}

impl<D, const SIZE: usize> From<D> for StaticAllocMessage<SIZE>
where
    D: core::fmt::Display,
{
    fn from(msg: D) -> Self {
        struct Writer<'a, const SIZE: usize>(&'a mut StaticAllocMessage<SIZE>);

        impl<const SIZE: usize> core::fmt::Write for Writer<'_, SIZE> {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                if s.len().gt(&SIZE) {
                    self.0.buffer.size = SIZE - 3;

                    self.0.buffer.try_extend(&s.as_bytes()[..self.0.buffer.size]).ok();

                    self.0.buffer.try_extend("...".as_bytes()).ok();
                } else {
                    self.0.buffer.size = s.len();

                    self.0.buffer.try_extend(&s.as_bytes()[..self.0.buffer.size]).ok();
                }

                Ok(())
            }
        }

        let mut smb = StaticAllocMessage {
            buffer: crate::StaticBuffer::default(),
        };

        core::fmt::write(&mut Writer(&mut smb), format_args!("{}", msg)).ok();

        smb
    }
}
