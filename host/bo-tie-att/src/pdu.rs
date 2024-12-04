//! Attribute Protocol Data Units (PDUs)
//!
//! This module contains a number of methods that can be used to construct PDUs that are defined
//! in the ATT Profile Specification. The other items (structs and enums) are used to supplement
//! the various parameters of the PDUs.
//!
//! *Commands*, *Requests*, *Notifications*, and *Indications*, are all PDUs that can be sent by
//! the client to the server. *Responses*, and *Confirmations* are sent by the server to the client.

use crate::{
    client::ClientPduName, server::ServerPduName, TransferFormatError, TransferFormatInto, TransferFormatTryFrom,
};
use alloc::{format, vec::Vec};

pub const INVALID_HANDLE: u16 = 0;

#[inline]
pub fn is_valid_handle(handle: u16) -> bool {
    handle != INVALID_HANDLE
}

pub fn is_valid_handle_range<R>(range: &R) -> bool
where
    R: core::ops::RangeBounds<u16>,
{
    use core::ops::Bound;

    let start = range.start_bound();
    let end = range.end_bound();

    (start != Bound::Included(&0))
        && match (start, end) {
            (Bound::Included(s), Bound::Included(e)) => s <= e,
            (Bound::Included(s), Bound::Excluded(e)) => s < e,
            (Bound::Excluded(s), Bound::Included(e)) => s < e,
            (Bound::Excluded(s), Bound::Excluded(e)) => s <= e,
            _ => true,
        }
}

/// An Attribute PDU Opcode
///
/// Every PDU has an identifier opcode associated with it so an Attribute protocol enabled device
/// can identify every ATT PDU sent to it. Higher layer protocols may use the `Custom` enum to send
/// a custom opcode over the ATT protocol, but users of `Custom` should still conform to the fields
/// of an ATT opcode.
///
/// # Fields
/// * bit 7: The Authentication signature flag - Indicates if the PDU contains an authentication
///   signature. The only PDU in ATT to use this field is the
///   [`WriteCommand`](ClientPduName::WriteCommand).
/// * bit 6: The Command Flag - Indicates that this PDU is a command from the client that doesn't
///   invoke a server response.
/// * bits 5-0: The Method - The rest of the bits that make up the OpCode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PduOpcode {
    Client(ClientPduName),
    Server(ServerPduName),
    Custom(u8),
}

impl PduOpcode {
    /// Get the full raw value of the opcode
    pub fn as_raw(&self) -> u8 {
        match *self {
            PduOpcode::Client(client) => client.into(),
            PduOpcode::Server(server) => server.into(),
            PduOpcode::Custom(custom) => custom,
        }
    }

    /// Check if the Opcode indicates an authentication signature
    pub fn has_auth_sig(&self) -> bool {
        self.as_raw() & 1 << 7 != 0
    }

    /// Check if the Opcode indicates a Command message
    pub fn is_command(&self) -> bool {
        self.as_raw() & 1 << 6 != 0
    }

    /// Get the method portion of the Opcode
    pub fn get_method(&self) -> u8 {
        self.as_raw() & 0x3F
    }
}

impl From<u8> for PduOpcode {
    fn from(val: u8) -> Self {
        if let Ok(client) = ClientPduName::try_from(val) {
            PduOpcode::Client(client)
        } else if let Ok(server) = ServerPduName::try_from(val) {
            PduOpcode::Server(server)
        } else {
            PduOpcode::Custom(val)
        }
    }
}

impl core::fmt::Display for PduOpcode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PduOpcode::Server(server) => write!(f, "{:?}", server),
            PduOpcode::Client(client) => write!(f, "{:?}", client),
            PduOpcode::Custom(custom) => write!(f, "{:#x}", custom),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pdu<P> {
    /// The Attribute Opcode
    opcode: PduOpcode,
    /// The Attribute(s) sent with the Pdu
    parameters: P,
}

impl<P> Pdu<P> {
    /// Create a new Pdu
    pub fn new(opcode: PduOpcode, parameters: P) -> Self {
        Pdu { opcode, parameters }
    }

    /// Get the Opcode for the PDU
    pub fn get_opcode(&self) -> PduOpcode {
        self.opcode
    }

    /// Get a reference to the parameters of the PDU
    pub fn get_parameters(&self) -> &P {
        &self.parameters
    }

    /// Get a mutable reference to the parameters of the PDU
    pub fn get_mut_parameters(&mut self) -> &mut P {
        &mut self.parameters
    }

    /// Convert this PDU into its parameters
    pub fn into_parameters(self) -> P {
        self.parameters
    }
}

/// Trait for getting the associated opcode for a parameter type
pub trait ExpectedOpcode {
    fn expected_opcode() -> PduOpcode;
}

impl<P> TransferFormatTryFrom for Pdu<P>
where
    P: TransferFormatTryFrom + ExpectedOpcode,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() > 0 {
            let opcode = PduOpcode::from(raw[0]);

            if opcode == P::expected_opcode() {
                let pdu = Pdu {
                    opcode,
                    parameters: TransferFormatTryFrom::try_from(&raw[1..])?,
                };

                Ok(pdu)
            } else if opcode == ServerPduName::ErrorResponse.into() {
                let e: ErrorResponse = TransferFormatTryFrom::try_from(&raw[1..])?;

                Err(TransferFormatError::error_response(&e))
            } else {
                Err(TransferFormatError::incorrect_opcode(P::expected_opcode(), opcode))
            }
        } else {
            Err(TransferFormatError::from("Pdu with length of zero received"))
        }
    }
}

impl<P> TransferFormatInto for Pdu<P>
where
    P: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        1 + self.parameters.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = self.opcode.as_raw();

        self.parameters.build_into_ret(&mut into_ret[1..]);
    }
}

impl<P> core::fmt::Display for Pdu<P>
where
    P: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Pdu Opcode: {}, Parameter: '{}'", self.opcode, self.parameters)
    }
}

/// Common profile errors
///
/// These error codes are listed within the Bluetooth SIG's *Core Specification Supplement*.
///
/// # Note
/// For the purposes of using this library, [`ReservedForFutureUse`] should not be used. However,
/// due to differences between the Bluetooth Specification used by other system components this  
/// error type may occur for common profile errors this library does not implement.
///
/// [`ReservedForFutureUse`]: CommonProfileError::ReservedForFutureUse
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CommonProfileError {
    /// Write request rejected
    WriteRequestRejected,
    /// Client characteristic configuration descriptor improperly configured
    ClientCharacteristicConfigurationDescriptorImproperlyConfigured,
    /// Procedure already in progress
    ProcedureAlreadyInProgress,
    /// Out of range
    OutOfRange,
    /// Reserved for future use
    ReservedForFutureUse(u8),
}

impl CommonProfileError {
    /// Create a `CommonProfileError`
    ///
    /// # Panic
    /// Input `code` must be in the range of `0xE0..=0xFF`
    fn from_code(code: u8) -> CommonProfileError {
        match code {
            ..0xE0 => unreachable!(),
            0xE0..=0xFB => CommonProfileError::ReservedForFutureUse(code),
            0xFC => CommonProfileError::WriteRequestRejected,
            0xFD => CommonProfileError::ClientCharacteristicConfigurationDescriptorImproperlyConfigured,
            0xFE => CommonProfileError::ProcedureAlreadyInProgress,
            0xFF => CommonProfileError::OutOfRange,
        }
    }

    /// Get the code for `CommonProfileError`
    fn as_code(&self) -> u8 {
        match self {
            CommonProfileError::ReservedForFutureUse(code) => *code,
            CommonProfileError::WriteRequestRejected => 0xFC,
            CommonProfileError::ClientCharacteristicConfigurationDescriptorImproperlyConfigured => 0xFD,
            CommonProfileError::ProcedureAlreadyInProgress => 0xFE,
            CommonProfileError::OutOfRange => 0xFF,
        }
    }
}

impl From<CommonProfileError> for u8 {
    fn from(error: CommonProfileError) -> Self {
        error.as_code()
    }
}

impl core::fmt::Display for CommonProfileError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CommonProfileError::WriteRequestRejected => f.write_str("Write request rejected"),
            CommonProfileError::ClientCharacteristicConfigurationDescriptorImproperlyConfigured => {
                f.write_str("Client characteristic configuration descriptor improperly configured")
            }
            CommonProfileError::ProcedureAlreadyInProgress => f.write_str("Procedure is already in progress"),
            CommonProfileError::OutOfRange => f.write_str("Out of range"),
            CommonProfileError::ReservedForFutureUse(val) => {
                write!(f, "Reserved for future use: {val}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CommonProfileError {}

/// The ATT Protocol errors
///
/// These are the errors defined in the ATT Protocol. These errors are part of the `ATT_ERROR_RSP`
/// PDU. An ATT server will respond with an error upon failure to execute a client's request.
///
/// See the Bluetooth Specification, volume 3, part F, section 3.4.1 for more information on
/// the error codes listed as enums within `Error`.
///
/// # Note
/// For the purposes of using this library, [`ReservedForFutureUse`] should not be used. However,
/// due to differences between the Bluetooth Specification used by other system components this
/// error type may occur for ATT error codes this library does not implement.
///
/// [`ReservedForFutureUse`]: Error::ReservedForFutureUse
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Error {
    /// Operation succeeded placeholder
    ///
    /// This is used to represent code 0x0000. This is not an error code and is shall not be as
    /// part of an `ATT_ERROR_RSP` PDU.
    Success,
    /// The attribute handle given was not valid on this server
    InvalidHandle,
    /// The attribute cannot be read
    ReadNotPermitted,
    /// The attribute cannot be written
    WriteNotPermitted,
    /// The attribute PDU was invalid
    InvalidPDU,
    /// The attribute requires authentication before it can be read or written
    InsufficientAuthentication,
    /// ATT server does not support the request received from the client
    RequestNotSupported,
    /// Offset specified was past the end of the attribute
    InvalidOffset,
    /// The attribute requires authorization before it can be read or written
    InsufficientAuthorization,
    /// Too many prepare writes have been queued
    PrepareQueueFull,
    /// No attribute found within the given attribute handle range
    AttributeNotFound,
    /// The attribute cannot be read using the ATT_READ_BLOB_REQ PDU
    AttributeNotLong,
    /// The *encryption key size* used for encrypting this link is too short
    InsufficientEncryptionKeySize,
    /// The attribute value length is invalid for the operation
    InvalidAttributeValueLength,
    /// The attribute request that was requested has encountered an error that was unlikely, and
    /// therefore could not be completed as requested
    UnlikelyError,
    /// The attribute requires encryption before it can be read or written
    InsufficientEncryption,
    /// The attribute type is not a supported grouping attribute as defined by a higher layer
    /// specification
    UnsupportedGroupType,
    /// Insufficient resources to complete the request
    InsufficientResources,
    /// The server requests the client to rediscover the database.
    DatabaseOutOfSync,
    /// The attribute parameter value was not allowed
    ValueNotAllowed,
    /// Application error code defined by a higher layer specification
    ApplicationError(u8),
    /// Common profile and service error codes defined in the *Core Specification Supplement*
    CommonProfileError(CommonProfileError),
    /// Reserved for future use
    ReservedForFutureUse(u8),
}

impl Error {
    pub(crate) fn from_raw(val: u8) -> Error {
        match val {
            0x00 => Error::Success,
            0x01 => Error::InvalidHandle,
            0x02 => Error::ReadNotPermitted,
            0x03 => Error::WriteNotPermitted,
            0x04 => Error::InvalidPDU,
            0x05 => Error::InsufficientAuthentication,
            0x06 => Error::RequestNotSupported,
            0x07 => Error::InvalidOffset,
            0x08 => Error::InsufficientAuthorization,
            0x09 => Error::PrepareQueueFull,
            0x0A => Error::AttributeNotFound,
            0x0B => Error::AttributeNotLong,
            0x0C => Error::InsufficientEncryptionKeySize,
            0x0D => Error::InvalidAttributeValueLength,
            0x0E => Error::UnlikelyError,
            0x0F => Error::InsufficientEncryption,
            0x10 => Error::UnsupportedGroupType,
            0x11 => Error::InsufficientResources,
            0x12 => Error::DatabaseOutOfSync,
            0x13 => Error::ValueNotAllowed,
            0x14..=0x7F => Error::ReservedForFutureUse(val),
            0x80..=0x9F => Error::ApplicationError(val),
            0xA0..=0xDF => Error::ReservedForFutureUse(val),
            0xE0..=0xFF => Error::CommonProfileError(CommonProfileError::from_code(val)),
        }
    }

    pub(crate) fn get_raw(&self) -> u8 {
        match self {
            Error::Success => 0x00,
            Error::InvalidHandle => 0x01,
            Error::ReadNotPermitted => 0x02,
            Error::WriteNotPermitted => 0x03,
            Error::InvalidPDU => 0x04,
            Error::InsufficientAuthentication => 0x05,
            Error::RequestNotSupported => 0x06,
            Error::InvalidOffset => 0x07,
            Error::InsufficientAuthorization => 0x08,
            Error::PrepareQueueFull => 0x09,
            Error::AttributeNotFound => 0x0A,
            Error::AttributeNotLong => 0x0B,
            Error::InsufficientEncryptionKeySize => 0x0C,
            Error::InvalidAttributeValueLength => 0x0D,
            Error::UnlikelyError => 0x0E,
            Error::InsufficientEncryption => 0x0F,
            Error::UnsupportedGroupType => 0x10,
            Error::InsufficientResources => 0x11,
            Error::DatabaseOutOfSync => 0x12,
            Error::ValueNotAllowed => 0x13,
            Error::ApplicationError(val) => *val,
            Error::CommonProfileError(err) => err.as_code(),
            Error::ReservedForFutureUse(val) => *val,
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Success => {
                write!(f, "No Error")
            }
            Error::InvalidHandle => {
                write!(
                    f,
                    "Invalid handle: the attribute handle given was not valid on this server"
                )
            }
            Error::ReadNotPermitted => {
                write!(f, "Read not permitted: the attribute cannot be read")
            }
            Error::WriteNotPermitted => {
                write!(f, "Write not permitted: the attribute cannot be written")
            }
            Error::InvalidPDU => {
                write!(f, "Invalid PDU: the attribute protocol data unit (PDU) was invalid")
            }
            Error::InsufficientAuthentication => {
                write!(
                    f,
                    "Insufficient authentication: the attribute requires authentication \
                    before it can be read or written"
                )
            }
            Error::RequestNotSupported => {
                write!(
                    f,
                    "Request not supported, the attribute server does not support the \
                    request received from the client"
                )
            }
            Error::InvalidOffset => {
                write!(
                    f,
                    "Invalid offset: the attribute value byte or word offset was not valid"
                )
            }
            Error::InsufficientAuthorization => {
                write!(
                    f,
                    "Insufficient authorization: the attribute requires authorization before \
                    it can be read or written"
                )
            }
            Error::PrepareQueueFull => {
                write!(f, "Prepare queue full: too many prepare writes have been queued")
            }
            Error::AttributeNotFound => {
                write!(
                    f,
                    "Attribute not found: no attribute found within the given attribute \
                    handle range"
                )
            }
            Error::AttributeNotLong => {
                write!(
                    f,
                    "Attribute not long: the attribute cannot be read using the Read Blob \
                    Request"
                )
            }
            Error::InsufficientEncryptionKeySize => {
                write!(
                    f,
                    "Insufficient encryption key size: The Encryption Key Size used for \
                    encrypting was insufficient for reading or writing this attribute"
                )
            }
            Error::InvalidAttributeValueLength => {
                write!(
                    f,
                    "Invalid attribute value length: the attribute value length was invalid \
                    for the operation"
                )
            }
            Error::UnlikelyError => {
                write!(
                    f,
                    "Unlikely error: the request could not be completed because of an \
                    unlikely error"
                )
            }
            Error::InsufficientEncryption => {
                write!(
                    f,
                    "Insufficient encryption: the attribute requires encryption before it \
                    can be read or written"
                )
            }
            Error::UnsupportedGroupType => {
                write!(
                    f,
                    "Unsupported group type: the attribute type is not a supported grouping \
                    type"
                )
            }
            Error::InsufficientResources => {
                write!(
                    f,
                    "Insufficient resources: insufficient Resources to complete the request"
                )
            }
            Error::DatabaseOutOfSync => {
                write!(
                    f,
                    "Database out of sync: the server requests the client to rediscover the database"
                )
            }
            Error::ValueNotAllowed => {
                write!(f, "Value not allowed: the attribute parameter value was not allowed")
            }
            Error::ApplicationError(code) => {
                write!(
                    f,
                    "Application error code: {code:#x} (this error code is defined by a \
                    higher layer specification)"
                )
            }
            Error::CommonProfileError(c) => {
                write!(f, "Common profile error: {c}")
            }
            Error::ReservedForFutureUse(val) => {
                write!(f, "Reserved for future use ({val:#x})")
            }
        }
    }
}

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        super::Error::PduError(err)
    }
}

impl From<u8> for Error {
    fn from(val: u8) -> Self {
        Error::from_raw(val)
    }
}

impl From<Error> for u8 {
    fn from(val: Error) -> Self {
        val.get_raw()
    }
}

/// Attribute Parameters included with the Error PDU
#[derive(Debug, PartialEq)]
pub struct ErrorResponse {
    /// The opcode of the requested
    pub request_opcode: u8,
    /// The attribute handle that generated the error response
    pub requested_handle: u16,
    /// error code
    pub error: Error,
}

impl core::fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "request: {:?}, attribute handle: {:#x}, error: {:?}",
            PduOpcode::from(self.request_opcode),
            self.requested_handle,
            self.error
        )
    }
}

impl ExpectedOpcode for ErrorResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ErrorResponse.into()
    }
}

impl TransferFormatTryFrom for ErrorResponse {
    /// Returns self if the length of the parameters is correct
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 4 {
            Ok(Self {
                request_opcode: raw[0],
                requested_handle: <u16>::from_le_bytes([raw[1], raw[2]]),
                error: Error::from_raw(raw[3]),
            })
        } else {
            Err(TransferFormatError::bad_size("ErrorResponse", 4, raw.len()))
        }
    }
}

impl TransferFormatInto for ErrorResponse {
    fn len_of_into(&self) -> usize {
        4
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = self.request_opcode;
        into_ret[1..3].copy_from_slice(&self.requested_handle.to_le_bytes());
        into_ret[3] = self.error.get_raw();
    }
}

/// Error Response Attribute
///
/// This is sent by the server when ever there is an issue with a client's request
pub fn error_response(request_opcode: u8, requested_handle: u16, error: Error) -> Pdu<ErrorResponse> {
    Pdu {
        opcode: From::from(ServerPduName::ErrorResponse),
        parameters: ErrorResponse {
            request_opcode,
            requested_handle,
            error,
        },
    }
}

/// Parameter for an Exchange MTU Request
#[derive(Debug)]
pub struct MtuRequest(pub u16);

impl ExpectedOpcode for MtuRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ExchangeMtuRequest.into()
    }
}

impl TransferFormatTryFrom for MtuRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(MtuRequest(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for MtuRequest {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Request Maximum Transfer Unit (MTU)
///
/// This is sent by the client to tell the server the MTU that the client can receieve by the
/// server. The server and client will use the smallest mtu size (not less then the minimum
/// defined in the ATT Protocol) as stated by the exchange MTU request and response.
pub fn exchange_mtu_request(mtu: u16) -> Pdu<MtuRequest> {
    Pdu {
        opcode: From::from(ClientPduName::ExchangeMtuRequest),
        parameters: MtuRequest(mtu),
    }
}

/// Parameter for an Exchange MTU Response
#[derive(Debug)]
pub struct MtuResponse(pub u16);

impl ExpectedOpcode for MtuResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ExchangeMTUResponse.into()
    }
}

impl TransferFormatTryFrom for MtuResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(MtuResponse(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for MtuResponse {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Response to a Maximum Transfer Unit (MTU) request
///
/// This is sent by the server in response to a
/// `[exchange mtu request](../exchange_mtu_request/index.html)`
/// sent by the client. This contains the MTU of a ATT protocol data unit that is accepted by
/// the server. The server and client will use the smallest mtu size (not less then the minimum
/// defined in the ATT Protocol) as stated by the exchange MTU request and response.
pub fn exchange_mtu_response(mtu: u16) -> Pdu<MtuResponse> {
    Pdu {
        opcode: From::from(ServerPduName::ExchangeMTUResponse),
        parameters: MtuResponse(mtu),
    }
}

/// The starting and ending handles when trying to get a range of attribute handles
///
/// A HandleRange can be created from anything that implements
/// `[RangeBounds](https://doc.rust-lang.org/nightly/core/ops/trait.RangeBounds.html)`, so the
/// easiest way to make a one is through the range sytax. All the functions that require a
/// HandleRange should be implemented to be able to take anything that can convert into a
/// HandleRange. This happens to be everything that implements `RangeBounds` because HandleRange
/// implements the `From` trait for everything that implements `RangeBounds`.
///
/// # Note
/// For the start of the range, if and only if the value is deliberately set to
/// `[Include](https://doc.rust-lang.org/nightly/core/ops/enum.Bound.html#variant.Included)`
/// zero will the `starting_handle` property of `HandleRange` be set to zero. 0 is a
/// reserved handle value as specified by the ATT Protocol specification and it can lead to errors
/// if uses as the starting attribute handle. When the start of the range is unbounded, then
/// 1 is used as the value for the starting handle.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleRange {
    pub starting_handle: u16,
    pub ending_handle: u16,
}

impl HandleRange {
    /// Check that the handle range is valid
    ///
    /// This will return true if `starting_handle` <= `ending_handle`
    pub fn is_valid(&self) -> bool {
        self.starting_handle != 0 && self.starting_handle <= self.ending_handle
    }

    /// Make a `RangeBounds` from the `HandleRange`
    pub fn to_range_bounds(&self) -> impl core::ops::RangeBounds<u16> {
        self.starting_handle..=self.ending_handle
    }
}

impl TransferFormatTryFrom for HandleRange {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if 4 == raw.len() {
            let range = Self {
                starting_handle: <u16>::from_le_bytes([raw[0], raw[1]]),
                ending_handle: <u16>::from_le_bytes([raw[2], raw[3]]),
            };

            Ok(range)
        } else {
            Err(TransferFormatError::bad_size(stringify!(HandleRange), 4, raw.len()))
        }
    }
}

impl TransferFormatInto for HandleRange {
    fn len_of_into(&self) -> usize {
        4
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.starting_handle.to_le_bytes());

        into_ret[2..].copy_from_slice(&self.ending_handle.to_le_bytes());
    }
}

impl<R> From<R> for HandleRange
where
    R: core::ops::RangeBounds<u16>,
{
    fn from(range: R) -> Self {
        use core::ops::Bound;

        let starting_handle = match range.start_bound() {
            Bound::Included(v) => *v,
            Bound::Excluded(v) => *v + 1,
            Bound::Unbounded => 1,
        };

        let ending_handle = match range.end_bound() {
            Bound::Included(v) => *v,
            Bound::Excluded(v) => *v - 1,
            Bound::Unbounded => <u16>::MAX,
        };

        Self {
            starting_handle,
            ending_handle,
        }
    }
}

/// Parameter for a Find Information Request
#[derive(Debug)]
pub struct FindInfoRequest(pub HandleRange);

impl ExpectedOpcode for FindInfoRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::FindInformationRequest.into()
    }
}

impl TransferFormatTryFrom for FindInfoRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(FindInfoRequest(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for FindInfoRequest {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Find information request
///
/// This is a request from the client for obtaining the mapping of attribute handles on the
/// server to attribute types.
pub fn find_information_request<R>(range: R) -> Pdu<FindInfoRequest>
where
    R: Into<HandleRange>,
{
    Pdu {
        opcode: From::from(ClientPduName::FindInformationRequest),
        parameters: FindInfoRequest(range.into()),
    }
}

/// A struct that contains an attribute handle and attribute type
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct HandleWithType(u16, crate::Uuid);

impl HandleWithType {
    /// Create a new `HandleWithType`
    pub fn new(handle: u16, attribute_type: crate::Uuid) -> Self {
        HandleWithType(handle, attribute_type)
    }

    /// Get the handle of the attribute
    pub fn get_handle(&self) -> u16 {
        self.0
    }

    /// Get the type of the attribute
    pub fn get_type(&self) -> crate::Uuid {
        self.1
    }
}

/// Formatted handle with type
///
/// This struct, when created, will determine if all the UUID's are 16 bit or 128 bit. It is used to
/// create the find information response attribute PDU.
#[derive(Clone)]
pub enum FormattedHandlesWithType {
    HandlesWithShortUuids(Vec<HandleWithType>),
    HandlesWithFullUuids(Vec<HandleWithType>),
}

impl FormattedHandlesWithType {
    const UUID_16_BIT: u8 = 0x1;
    const UUID_128_BIT: u8 = 0x2;
}

impl TransferFormatTryFrom for FormattedHandlesWithType {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        match raw[0] {
            Self::UUID_16_BIT => {
                let chunks = raw[1..].chunks_exact(4);

                if chunks.remainder().len() == 0 {
                    let v = chunks
                        .into_iter()
                        .map(|chunk| {
                            let handle = <u16>::from_le_bytes([chunk[0], chunk[1]]);

                            let uuid = Into::<crate::Uuid>::into(<u16>::from_le_bytes([chunk[2], chunk[3]]));

                            HandleWithType(handle, uuid)
                        })
                        .collect();

                    Ok(FormattedHandlesWithType::HandlesWithShortUuids(v))
                } else {
                    Err(TransferFormatError::bad_exact_chunks(
                        stringify!(FormattedHandlesWithType),
                        4,
                        raw[1..].len(),
                    ))
                }
            }
            Self::UUID_128_BIT => {
                let chunks = raw[1..].chunks_exact(18);

                if chunks.remainder().len() == 0 {
                    let v = chunks
                        .into_iter()
                        .map(|chunk| {
                            let handle = <u16>::from_le_bytes([chunk[0], chunk[1]]);

                            let mut uuid_bytes = [0u8; core::mem::size_of::<u128>()];

                            uuid_bytes.clone_from_slice(&chunk[2..]);

                            let uuid = Into::<crate::Uuid>::into(<u128>::from_le_bytes(uuid_bytes));

                            HandleWithType(handle, uuid)
                        })
                        .collect();

                    Ok(FormattedHandlesWithType::HandlesWithFullUuids(v))
                } else {
                    Err(TransferFormatError::bad_exact_chunks(
                        stringify!(FormattedHandlesWithType),
                        18,
                        raw[1..].len(),
                    ))
                }
            }
            _ => Err(TransferFormatError::from(concat!(
                "Invalid Type for ",
                stringify!(FormattedHandlesWithType)
            ))),
        }
    }
}

impl TransferFormatInto for FormattedHandlesWithType {
    fn len_of_into(&self) -> usize {
        match self {
            FormattedHandlesWithType::HandlesWithShortUuids(v) => 2 + 2 * v.len(),
            FormattedHandlesWithType::HandlesWithFullUuids(v) => 2 + 16 * v.len(),
        }
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        match self {
            FormattedHandlesWithType::HandlesWithShortUuids(v) => {
                into_ret[0] = Self::UUID_16_BIT;

                v.iter()
                    .try_fold(into_ret, |into_ret, hu| -> Result<&mut [u8], ()> {
                        into_ret[..2].copy_from_slice(&hu.0.to_le_bytes());
                        into_ret[2..4].copy_from_slice(&TryInto::<u16>::try_into(hu.1)?.to_le_bytes());
                        Ok(&mut into_ret[4..])
                    })
                    .ok();
            }
            FormattedHandlesWithType::HandlesWithFullUuids(v) => {
                into_ret[0] = Self::UUID_128_BIT;

                v.iter().fold(into_ret, |into_ret, hu| {
                    into_ret[..2].copy_from_slice(&hu.0.to_le_bytes());
                    into_ret[2..18].copy_from_slice(&<u128>::from(hu.1).to_le_bytes());
                    &mut into_ret[18..]
                });
            }
        }
    }
}

impl ExpectedOpcode for FormattedHandlesWithType {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::FindInformationResponse.into()
    }
}

/// Create a Find Information Response PDU
pub fn find_information_response(parameters: FormattedHandlesWithType) -> Pdu<FormattedHandlesWithType> {
    Pdu {
        opcode: ServerPduName::FindInformationResponse.into(),
        parameters,
    }
}

/// Parameter for a Find By Type Value Request
#[derive(Clone)]
pub struct FindByTypeValueRequest<D> {
    handle_range: HandleRange,
    attr_type: u16,
    value: D,
}

impl<D> ExpectedOpcode for FindByTypeValueRequest<D> {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::FindByTypeValueRequest.into()
    }
}

impl<D> TransferFormatTryFrom for FindByTypeValueRequest<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() >= 6 {
            Ok(FindByTypeValueRequest {
                handle_range: TransferFormatTryFrom::try_from(&raw[..4])?,
                attr_type: <u16>::from_le_bytes([raw[4], raw[5]]),
                value: TransferFormatTryFrom::try_from(&raw[6..])?,
            })
        } else {
            Err(TransferFormatError::bad_min_size(
                stringify!(TypeValueRequest),
                6,
                raw.len(),
            ))
        }
    }
}

impl<D> TransferFormatInto for FindByTypeValueRequest<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.handle_range.len_of_into() + 2 + self.value.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let hr_size = self.handle_range.len_of_into();

        self.handle_range.build_into_ret(&mut into_ret[..hr_size]);

        into_ret[hr_size..(hr_size + 2)].copy_from_slice(&self.attr_type.to_le_bytes());

        self.value.build_into_ret(&mut into_ret[(hr_size + 2)..]);
    }
}

/// Find by type value request
///
/// This is sent by the client to the server to find attributes that have a 16 bit UUID as the type
/// and the provided attribute value.
///
/// The uuid must be convertible into a 16 bit assigned number, otherwise this will return an error.
pub fn find_by_type_value_request<R, D>(
    handle_range: R,
    uuid: crate::Uuid,
    value: D,
) -> Result<Pdu<FindByTypeValueRequest<D>>, ()>
where
    R: Into<HandleRange>,
{
    if let Ok(uuid) = core::convert::TryFrom::try_from(uuid) {
        Ok(Pdu {
            opcode: From::from(ClientPduName::FindByTypeValueRequest),
            parameters: FindByTypeValueRequest {
                handle_range: handle_range.into(),
                attr_type: uuid,
                value,
            },
        })
    } else {
        Err(())
    }
}

/// Parameter for a Find By Type Value Response
#[derive(Debug)]
pub struct TypeValueResponse {
    handle: u16,
    group: u16,
}

impl ExpectedOpcode for Vec<TypeValueResponse> {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::FindByTypeValueResponse.into()
    }
}

impl TypeValueResponse {
    pub fn new(handle: u16, group: u16) -> Self {
        TypeValueResponse { handle, group }
    }

    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    pub fn get_end_group_handle(&self) -> u16 {
        self.group
    }
}

impl TransferFormatTryFrom for TypeValueResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 4 {
            Ok(TypeValueResponse {
                handle: <u16>::from_le_bytes([raw[0], raw[1]]),
                group: <u16>::from_le_bytes([raw[2], raw[3]]),
            })
        } else {
            Err(TransferFormatError::bad_size(
                stringify!(TypeValueResponse),
                4,
                raw.len(),
            ))
        }
    }
}

impl TransferFormatInto for TypeValueResponse {
    fn len_of_into(&self) -> usize {
        4
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());
        into_ret[2..].copy_from_slice(&self.group.to_le_bytes());
    }
}

impl_transfer_format_for_vec_of!(TypeValueResponse);

/// Create a Find By Type Value Response PDU
pub fn find_by_type_value_response(type_values: Vec<TypeValueResponse>) -> Pdu<Vec<TypeValueResponse>> {
    Pdu {
        opcode: From::from(ServerPduName::FindByTypeValueResponse),
        parameters: type_values,
    }
}

/// Parameter for a Read By Type Request
#[derive(Clone, Debug)]
pub struct TypeRequest {
    pub handle_range: HandleRange,
    pub attr_type: crate::Uuid,
}

impl TransferFormatTryFrom for TypeRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 6 {
            Ok(Self {
                handle_range: TransferFormatTryFrom::try_from(&raw[..4])?,
                attr_type: Into::<crate::Uuid>::into(<u16>::from_le_bytes([raw[4], raw[5]])),
            })
        } else if raw.len() == 20 {
            Ok(Self {
                handle_range: TransferFormatTryFrom::try_from(&raw[..4])?,
                attr_type: Into::<crate::Uuid>::into(<u128>::from_le_bytes({
                    let mut bytes = [0; 16];
                    bytes.clone_from_slice(&raw[4..]);
                    bytes
                })),
            })
        } else {
            Err(TransferFormatError::bad_size(
                stringify!(TypeRequest),
                "6 or 20",
                raw.len(),
            ))
        }
    }
}

impl TransferFormatInto for TypeRequest {
    fn len_of_into(&self) -> usize {
        self.handle_range.len_of_into() + self.attr_type.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let hr_size = self.handle_range.len_of_into();

        self.handle_range.build_into_ret(&mut into_ret[..hr_size]);

        self.attr_type.build_into_ret(&mut into_ret[hr_size..]);
    }
}

/// Parameter for Read By Type Request
#[derive(Debug)]
pub struct ReadByTypeRequest(pub TypeRequest);

impl ExpectedOpcode for ReadByTypeRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ReadByTypeRequest.into()
    }
}

impl TransferFormatTryFrom for ReadByTypeRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for ReadByTypeRequest {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Create a Read By Type Request PDU
///
/// This is a request from the client for finding attributes by their type within a range of
/// handles.
pub fn read_by_type_request<R>(handle_range: R, attr_type: crate::Uuid) -> Pdu<ReadByTypeRequest>
where
    R: Into<HandleRange>,
{
    Pdu {
        opcode: From::from(ClientPduName::ReadByTypeRequest),
        parameters: ReadByTypeRequest(TypeRequest {
            handle_range: handle_range.into(),
            attr_type,
        }),
    }
}

/// A single read type response
///
/// A list of `ReadTypeResponse`s is sent the client in response to their Read By Type Request.
///
/// `TransferFormatTryFrom` and `TransferFormatInto` are implemented for a vectors of
/// `ReadTypeResponse`. However these implementations assume that the returned data for each
/// response has the same transfer format length, which is required per the Bluetooth specification
/// for the *Read By Type Response*. The other assumption made is that the entire PDU sent has a
/// maximum payload size of 256 bytes and that the TransferFormatInto will not generate a PDU larger
/// than that.
#[derive(Debug)]
pub struct ReadTypeResponse<D> {
    handle: u16,
    data: D,
}

impl<D> ReadTypeResponse<D> {
    /// Create a new `ReadTypeResponse`
    pub fn new(handle: u16, data: D) -> Self {
        ReadTypeResponse { handle, data }
    }

    /// Get the handle
    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    /// Get the inner data
    pub fn into_inner(self) -> D {
        self.data
    }
}

impl<D> core::ops::Deref for ReadTypeResponse<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<D> core::ops::DerefMut for ReadTypeResponse<D> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<D> TransferFormatTryFrom for ReadTypeResponse<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() >= 2 {
            Ok(Self {
                handle: <u16>::from_le_bytes([raw[0], raw[1]]),
                data: TransferFormatTryFrom::try_from(&raw[2..])?,
            })
        } else {
            Err(TransferFormatError::bad_min_size(
                stringify!("ReadTypeResponse"),
                2,
                raw.len(),
            ))
        }
    }
}

impl<D> TransferFormatInto for ReadTypeResponse<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        2 + self.data.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());

        self.data.build_into_ret(&mut into_ret[2..]);
    }
}

impl<D> TransferFormatInto for Vec<ReadTypeResponse<D>>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        let fields_len: usize = self.iter().map(|r| r.len_of_into()).sum();

        fields_len + 1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = self.first().map_or(0u8, |f| f.len_of_into() as u8);

        self.iter().fold(1usize, |acc, r| {
            let end = acc + r.len_of_into();

            r.build_into_ret(&mut into_ret[acc..end]);

            end
        });
    }
}

impl<D> TransferFormatTryFrom for Vec<ReadTypeResponse<D>>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let length = <usize>::from(*raw.get(0).ok_or(TransferFormatError::bad_min_size(
            "Read Type Response missing length field",
            1,
            0,
        ))?);

        raw[1..]
            .chunks(length)
            .map(|chunk| <ReadTypeResponse<D> as TransferFormatTryFrom>::try_from(chunk))
            .collect()
    }
}

/// Parameter for Read By Type Response
#[derive(Debug)]
pub struct ReadByTypeResponse<D>(pub Vec<ReadTypeResponse<D>>);

impl<D> ExpectedOpcode for ReadByTypeResponse<D> {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ReadByTypeResponse.into()
    }
}

impl<D> TransferFormatTryFrom for ReadByTypeResponse<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(ReadByTypeResponse(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl<D> TransferFormatInto for ReadByTypeResponse<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Read attribute by type response
///
/// The response from the server to a read attribute by type request
///
/// # Note
/// This generates a PDU, but that PDU isn't checked if it is larger then the ATT MTU or if the
/// size of type D is greater then 255. Its the responsibility of the caller to make sure that
/// the size of the data sent to the controller is correct.
pub fn read_by_type_response<D>(responses: Vec<ReadTypeResponse<D>>) -> Pdu<ReadByTypeResponse<D>> {
    Pdu {
        opcode: From::from(ServerPduName::ReadByTypeResponse),
        parameters: ReadByTypeResponse(responses),
    }
}

/// Parameter for Read Request
#[derive(Debug)]
pub struct ReadRequest(pub u16);

impl ExpectedOpcode for ReadRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ReadRequest.into()
    }
}

impl TransferFormatTryFrom for ReadRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for ReadRequest {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Create a Read Request PDU
pub fn read_request(handle: u16) -> Pdu<ReadRequest> {
    Pdu {
        opcode: From::from(ClientPduName::ReadRequest),
        parameters: ReadRequest(handle),
    }
}

/// Parameter for a Read Response
#[derive(Debug)]
pub struct ReadResponse<D>(pub D);

impl<D> ExpectedOpcode for ReadResponse<D> {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ReadResponse.into()
    }
}

impl<D> TransferFormatTryFrom for ReadResponse<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl<D> TransferFormatInto for ReadResponse<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Create a Read Response PDU
pub fn read_response<D>(value: D) -> Pdu<ReadResponse<D>> {
    Pdu {
        opcode: From::from(ServerPduName::ReadResponse),
        parameters: ReadResponse(value),
    }
}

/// Parameter for a Read Blob Request
#[derive(Clone)]
pub struct ReadBlobRequest {
    pub handle: u16,
    pub offset: u16,
}

impl ExpectedOpcode for ReadBlobRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ReadBlobRequest.into()
    }
}

impl TransferFormatTryFrom for ReadBlobRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() == 4 {
            Ok(Self {
                handle: <u16>::from_le_bytes([raw[0], raw[1]]),
                offset: <u16>::from_le_bytes([raw[2], raw[3]]),
            })
        } else {
            Err(TransferFormatError::bad_size(stringify!(BlobRequest), 4, raw.len()))
        }
    }
}

impl TransferFormatInto for ReadBlobRequest {
    fn len_of_into(&self) -> usize {
        4
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());
        into_ret[2..].copy_from_slice(&self.offset.to_le_bytes());
    }
}

/// Create a Read Blob Request PDU
pub fn read_blob_request(handle: u16, offset: u16) -> Pdu<ReadBlobRequest> {
    Pdu {
        opcode: From::from(ClientPduName::ReadBlobRequest),
        parameters: ReadBlobRequest { handle, offset },
    }
}

/// Parameter for a Read Blob Response
///
/// Contains a blob of data sent from the server
pub struct ReadBlobResponse {
    blob: Vec<u8>,
}

impl ExpectedOpcode for ReadBlobResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ReadBlobResponse.into()
    }
}

impl ReadBlobResponse {
    pub fn into_inner(self) -> Vec<u8> {
        self.blob
    }
}

impl TransferFormatTryFrom for ReadBlobResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(ReadBlobResponse { blob: raw.to_vec() })
    }
}

/// Create a Read Blob Response
pub fn read_blob_response(parameters: ReadBlobResponse) -> Pdu<ReadBlobResponse> {
    Pdu {
        opcode: ServerPduName::ReadBlobResponse.into(),
        parameters,
    }
}

/// Localized Read Blob Response
///
/// Contains a reference to a blob of data sent from the server
#[derive(Debug)]
pub(crate) struct LocalReadBlobResponse<'a> {
    blob: &'a [u8],
}

impl<'a> LocalReadBlobResponse<'a> {
    pub(crate) fn new(blob: &'a [u8]) -> Self {
        Self { blob }
    }
}

impl TransferFormatInto for LocalReadBlobResponse<'_> {
    fn len_of_into(&self) -> usize {
        self.blob.len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(self.blob)
    }
}

impl<'a> From<LocalReadBlobResponse<'a>> for Pdu<LocalReadBlobResponse<'a>> {
    fn from(rbr: LocalReadBlobResponse<'a>) -> Self {
        Self::new(ServerPduName::ReadBlobResponse.into(), rbr)
    }
}

impl From<LocalReadBlobResponse<'_>> for Vec<u8> {
    fn from(lrbr: LocalReadBlobResponse<'_>) -> Self {
        lrbr.blob.to_vec()
    }
}

/// Parameter for a Read Multiple Request
#[derive(Debug)]
pub struct ReadMultipleRequest(pub Vec<u16>);

impl ExpectedOpcode for ReadMultipleRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ReadMultipleRequest.into()
    }
}

impl TransferFormatTryFrom for ReadMultipleRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for ReadMultipleRequest {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Request multiple reads
///
/// This is sent by the client to requests 2 or more values to read. If the length of the input is
/// less then 2 then the return will be an error.
pub fn read_multiple_request(handles: Vec<u16>) -> Result<Pdu<ReadMultipleRequest>, super::Error> {
    if handles.len() >= 2 {
        Ok(Pdu {
            opcode: From::from(ClientPduName::ReadMultipleRequest),
            parameters: ReadMultipleRequest(handles),
        })
    } else {
        Err(super::Error::Other("Two or more handles required for read multiple"))
    }
}

/// Parameter for a Read Multiple Request
#[derive(Debug)]
pub struct ReadMultipleResponse(pub Vec<u8>);

impl ExpectedOpcode for ReadMultipleResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ReadMultipleResponse.into()
    }
}

impl TransferFormatTryFrom for ReadMultipleResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for ReadMultipleResponse {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Read Multiple Response
///
/// Server response to a read multiple request
pub fn read_multiple_response(set_of_values: Vec<u8>) -> Pdu<ReadMultipleResponse> {
    Pdu {
        opcode: From::from(ServerPduName::ReadMultipleResponse),
        parameters: ReadMultipleResponse(set_of_values),
    }
}

/// Parameter for a Read Multiple Request
#[derive(Debug)]
pub struct ReadByGroupTypeRequest(pub TypeRequest);

impl ExpectedOpcode for ReadByGroupTypeRequest {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ReadByGroupTypeRequest.into()
    }
}

impl TransferFormatTryFrom for ReadByGroupTypeRequest {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatInto for ReadByGroupTypeRequest {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Read an attribute group request
///
/// Client request for reading attributes' data that are under a group specified by a higher layer
/// protocol. The read
pub fn read_by_group_type_request<R>(handle_range: R, group_type: crate::Uuid) -> Pdu<ReadByGroupTypeRequest>
where
    R: Into<HandleRange>,
{
    Pdu {
        opcode: From::from(ClientPduName::ReadByGroupTypeRequest),
        parameters: ReadByGroupTypeRequest(TypeRequest {
            handle_range: handle_range.into(),
            attr_type: group_type,
        }),
    }
}

/// A single read by group type response
///
/// The read by group type response will contain one or more of these
#[derive(Debug, PartialEq)]
pub struct ReadGroupTypeData<D> {
    handle: u16,
    end_group_handle: u16,
    data: D,
}

impl<D> ReadGroupTypeData<D> {
    pub fn new(handle: u16, end_group_handle: u16, data: D) -> Self {
        Self {
            handle,
            end_group_handle,
            data,
        }
    }

    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    pub fn get_end_group_handle(&self) -> u16 {
        self.end_group_handle
    }

    pub fn get_data(&self) -> &D {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut D {
        &mut self.data
    }

    pub fn into_inner(self) -> D {
        self.data
    }
}

impl<D> TransferFormatTryFrom for ReadGroupTypeData<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() >= 4 {
            Ok(Self {
                handle: <u16>::from_le_bytes([raw[0], raw[1]]),
                end_group_handle: <u16>::from_le_bytes([raw[2], raw[3]]),
                data: TransferFormatTryFrom::try_from(&raw[4..])?,
            })
        } else {
            Err(TransferFormatError::bad_min_size(
                stringify!(ReadGroupTypeData),
                4,
                raw.len(),
            ))
        }
    }
}

impl<D> TransferFormatInto for ReadGroupTypeData<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        4 + self.data.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());
        into_ret[2..4].copy_from_slice(&self.end_group_handle.to_le_bytes());
        self.data.build_into_ret(&mut into_ret[4..]);
    }
}

/// The Parameter for a Read By Group Type Response PDU
#[derive(Debug, PartialEq)]
pub struct ReadByGroupTypeResponse<D> {
    data: Vec<ReadGroupTypeData<D>>,
}

impl<D> ExpectedOpcode for ReadByGroupTypeResponse<D> {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ReadByGroupTypeResponse.into()
    }
}

impl<D> ReadByGroupTypeResponse<D> {
    /// Create a new `ReadByGroupTypeResponse`
    ///
    /// # Panics
    /// Input `data` cannot be an empty vector.
    pub fn new(data: Vec<ReadGroupTypeData<D>>) -> Self {
        match data.len() {
            0 => panic!("Input `data` of ReadByGroupTypeResponse::new cannot be an empty vector"),
            _ => ReadByGroupTypeResponse { data },
        }
    }

    pub fn into_inner(self) -> Vec<ReadGroupTypeData<D>> {
        self.data
    }
}

impl<D> TransferFormatTryFrom for ReadByGroupTypeResponse<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() >= 5 {
            let item_len = raw[0] as usize;

            let exact_chunks = raw[1..].chunks_exact(item_len);

            if exact_chunks.remainder().len() == 0 {
                exact_chunks
                    .map(|raw| TransferFormatTryFrom::try_from(raw))
                    .try_fold(Vec::new(), |mut v, rslt| {
                        v.push(rslt?);
                        Ok(v)
                    })
                    .and_then(|v| Ok(ReadByGroupTypeResponse { data: v }))
                    .or_else(|e: TransferFormatError| Err(e.into()))
            } else {
                Err(TransferFormatError::bad_exact_chunks(
                    stringify!(ReadByGroupTypeResponse),
                    item_len,
                    raw[1..].len(),
                ))
            }
        } else {
            Err(TransferFormatError::bad_min_size(
                stringify!(ReadByGroupTypeResponse),
                5,
                raw.len(),
            ))
        }
    }
}

impl<D> TransferFormatInto for ReadByGroupTypeResponse<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        1 + self
            .data
            .first()
            .map(|first| first.len_of_into() * self.data.len())
            .unwrap_or_default()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let mut piter = self.data.iter().peekable();

        let data_size = piter.peek().map(|d| d.len_of_into()).unwrap_or_default();

        into_ret[0] = data_size as u8;

        piter
            .enumerate()
            .for_each(|(c, d)| d.build_into_ret(&mut into_ret[(1 + c * data_size)..(1 + (1 + c) * data_size)]));
    }
}

/// Read an attribute group response
pub fn read_by_group_type_response<D>(response: ReadByGroupTypeResponse<D>) -> Pdu<ReadByGroupTypeResponse<D>> {
    Pdu {
        opcode: From::from(ServerPduName::ReadByGroupTypeResponse),
        parameters: response,
    }
}

/// Data with its Attribute Handle
#[derive(Clone, Debug)]
pub struct HandleWithData<D> {
    handle: u16,
    data: D,
}

impl<D> HandleWithData<D> {
    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    pub fn get_data(&self) -> &D {
        &self.data
    }

    pub fn get_mut_data(&mut self) -> &mut D {
        &mut self.data
    }

    pub fn into_data(self) -> D {
        self.data
    }
}

impl<D> TransferFormatTryFrom for HandleWithData<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() >= 2 {
            Ok(HandleWithData {
                handle: <u16>::from_le_bytes([raw[0], raw[1]]),
                data: TransferFormatTryFrom::try_from(&raw[2..])?,
            })
        } else {
            Err(TransferFormatError::bad_min_size(
                stringify!(HandleWithData),
                2,
                raw.len(),
            ))
        }
    }
}

impl<D> TransferFormatInto for HandleWithData<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        2 + self.data.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());

        self.data.build_into_ret(&mut into_ret[2..]);
    }
}

/// Parameter for a Write Request
#[derive(Debug)]
pub struct WriteRequest<D>(pub HandleWithData<D>);

impl<D> ExpectedOpcode for WriteRequest<D> {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::WriteRequest.into()
    }
}

impl<D> TransferFormatTryFrom for WriteRequest<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl<D> TransferFormatInto for WriteRequest<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Write request to an attribute
pub fn write_request<D>(handle: u16, data: D) -> Pdu<WriteRequest<D>> {
    Pdu {
        opcode: From::from(ClientPduName::WriteRequest),
        parameters: WriteRequest(HandleWithData { handle, data }),
    }
}

/// Parameter for a Write Response
#[derive(Debug)]
pub struct WriteResponse;

impl ExpectedOpcode for WriteResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::WriteResponse.into()
    }
}

impl TransferFormatTryFrom for WriteResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() == 0 {
            Ok(Self)
        } else {
            Err(TransferFormatError::from("Expected no parameter for Write Response"))
        }
    }
}

impl TransferFormatInto for WriteResponse {
    fn len_of_into(&self) -> usize {
        0
    }

    fn build_into_ret(&self, _: &mut [u8]) {}
}

/// Create a Write Response PDU
pub fn write_response() -> Pdu<WriteResponse> {
    Pdu {
        opcode: From::from(ServerPduName::WriteResponse),
        parameters: WriteResponse,
    }
}

/// Parameter for a Write Command
#[derive(Debug)]
pub struct WriteCommand<D>(pub HandleWithData<D>);

impl<D> ExpectedOpcode for WriteCommand<D> {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::WriteCommand.into()
    }
}

impl<D> TransferFormatTryFrom for WriteCommand<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl<D> TransferFormatInto for WriteCommand<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Create a Write Command PDU
pub fn write_command<D>(handle: u16, data: D) -> Pdu<WriteCommand<D>> {
    Pdu {
        opcode: From::from(ClientPduName::WriteCommand),
        parameters: WriteCommand(HandleWithData { handle, data }),
    }
}

/// Create a Signed Write Command PDU (TODO)
///
/// This requires that the signature specification be implemented in bo-tie which isn't done yet.
/// For now this will just panic with the message unimplemented.
pub fn signed_write_command<D, Sig>(_handle: u16, _data: D, _csrk: u128) {
    unimplemented!();
}

/// A prepared Write Request parameter
///
/// This structure can be created as items of an iterator with `iter` method of
/// `PreparedWriteRequests`
#[derive(Debug)]
pub struct PreparedWriteRequest<'a> {
    handle: u16,
    offset: u16,
    data: &'a [u8],
}

impl<'a> PreparedWriteRequest<'a> {
    /// Get the handle of the attribute to be written to
    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    /// Get the offset from the start of the transfer format data for this data fragment
    pub fn get_prepared_offset(&self) -> u16 {
        self.offset
    }

    /// The fragment of data that is sent with this request
    pub fn get_prepared_data(&self) -> &'a [u8] {
        self.data
    }

    /// Try to make a prepared write request from a raw source
    pub fn try_from_raw(raw: &'a [u8]) -> Result<Self, TransferFormatError> {
        if raw.len() < 4 {
            Err(TransferFormatError::bad_min_size("PreparedWriteRequest", 4, raw.len()))
        } else {
            Ok(Self {
                handle: TransferFormatTryFrom::try_from(&raw[..2])?,
                offset: TransferFormatTryFrom::try_from(&raw[2..4])?,
                data: &raw[4..],
            })
        }
    }
}

impl TransferFormatInto for PreparedWriteRequest<'_> {
    fn len_of_into(&self) -> usize {
        4 + self.data.len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());

        into_ret[2..4].copy_from_slice(&self.offset.to_le_bytes());

        into_ret[4..].copy_from_slice(self.data);
    }
}

/// Prepared Write Requests
///
/// Data that must be queued on the server before writing to an attribute must be sent as one or
/// more prepared write requests for the server to queue them. How they are queued is outside the
/// scope of the Attribute Protocol, but most times a prepared write request is used to write
/// attribute value that is too large to send within one attribute protocol data unit (PDU).
///
/// A `PreparedWriteRequests` is generated by taking an attribute handle and value and converting
/// them into multiple requests. These requests are generated from a iterator created from the
/// `iter` method. Each prepared request is a fragment of the total data to be sent for a write a
/// specified attribute. This size of the fragment is set to the maximum that can be sent.
///
/// This is not the only way for data to be sent to the server write queue. There are more ways to
/// use the queue then a waiting area for all data to be sent from the client for a specific
/// attribute. This structure is just an implementation for data that is too large to be sent within
/// one request.
///
/// ```
/// # use bo_tie_att::pdu::PreparedWriteRequests;
/// #
/// # let handle = 0x1;
/// # let mtu = 30;
/// #
/// let data = "Holey cow this is way to much data to be sent within one Attribute protocol data \
///     unit, you need to break this up bud";
///
/// let prepared_writes = PreparedWriteRequests::new(handle, &data, mtu);
///
/// for prepared_write_request in prepared_writes.iter() {
///     // Send each request to the server
/// }
/// ```
///
/// # Server Write Queue
/// The functionality of the write queue is very subjective to the implementation, there isn't much
/// beyond what errors to send due to attribute permissions or offset validity defined within the
/// specification for the attribute protocol. Most of the implementation is left to higher layer
/// protocols by the specification. It may be that `PreparedWriteRequests` does not meet the
/// functionality of the implementations for a connected server.
///
/// # MTU Change
/// A `PreparedWriteRequests` is valid as long as the MTU was not changed to be smaller. Since
/// the process of changing the MTU is started by the client it is generally not a problem for a
/// `PreparedWriteRequest`, but if is needed to be done then the client must update the new MTU
/// with the iterator. If the MTU'
#[derive(Debug)]
pub struct PreparedWriteRequests {
    handle: u16,
    tf_data: Vec<u8>,
    mtu: usize,
}

impl PreparedWriteRequests {
    const REQUEST_HEADER_SIZE: usize = 5;

    /// Create prepared write requests
    ///
    /// # Panic
    /// This will panic if the transfer format of `data` is larger then the maximum for a 16 bit
    /// number. You will need some higher layer or your own implementation for fragmenting over
    /// multiple prepared writes if a panic is produced.
    pub fn new<D>(handle: u16, data: &D, mtu: usize) -> Self
    where
        D: TransferFormatInto,
    {
        let tf_data = TransferFormatInto::into(&data);

        assert!(
            tf_data.len() <= <u16>::MAX.into(),
            "Transfer format data length exceeds the maximum ({})",
            <u16>::MAX
        );

        Self { handle, tf_data, mtu }
    }

    /// Iterator for generating prepared write requests
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = Pdu<PreparedWriteRequest<'a>>> + 'a {
        PreparedWriteRequestIter {
            handle: self.handle,
            offset: 0,
            tf_data: &self.tf_data,
            send_size: self.mtu - Self::REQUEST_HEADER_SIZE,
        }
    }

    /// Set the MTU
    ///
    /// This should be called whenever the mtu changes between the client and server. This does not
    /// check that the MTU is valid.
    pub fn set_mtu(&mut self, mtu: usize) {
        self.mtu = mtu;
    }
}

#[derive(Debug)]
struct PreparedWriteRequestIter<'a> {
    handle: u16,
    tf_data: &'a [u8],
    offset: usize,
    send_size: usize,
}

impl<'a> Iterator for PreparedWriteRequestIter<'a> {
    type Item = Pdu<PreparedWriteRequest<'a>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset == self.tf_data.len() {
            None
        } else {
            let send_start = self.offset;

            let send_end = match send_start.overflowing_add(self.send_size) {
                (val, false) => core::cmp::min(val, self.tf_data.len()),
                (_, true) => self.tf_data.len(),
            };

            let item = PreparedWriteRequest {
                offset: self.offset as u16,
                handle: self.handle,
                data: &self.tf_data[send_start..send_end],
            };

            self.offset = send_end;

            Some(item.into())
        }
    }
}

impl<'a> From<PreparedWriteRequest<'a>> for Pdu<PreparedWriteRequest<'a>> {
    fn from(pwr: PreparedWriteRequest<'a>) -> Self {
        Pdu {
            opcode: From::from(ClientPduName::PrepareWriteRequest),
            parameters: pwr,
        }
    }
}

/// Parameter for a Prepared Write Response
#[derive(Debug)]
pub struct PreparedWriteResponse {
    pub handle: u16,
    pub offset: usize,
    pub data: Vec<u8>,
}

impl PreparedWriteResponse {
    /// Create a Response from a Request
    ///
    /// Since the Response is just an echo's what was in the request packet, this function converts
    /// a `PreparedWriteRequest` into a `PreparedWriteResponse`.
    pub fn pdu_from_request(request: &PreparedWriteRequest<'_>) -> Pdu<Self> {
        prepare_write_response(request.handle, request.offset, request.data.to_vec())
    }
}

impl ExpectedOpcode for PreparedWriteResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::PrepareWriteResponse.into()
    }
}

impl TransferFormatInto for PreparedWriteResponse {
    fn len_of_into(&self) -> usize {
        4 + self.data.len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[..2].copy_from_slice(&self.handle.to_le_bytes());

        into_ret[2..4].copy_from_slice(&(self.offset as u16).to_le_bytes());

        into_ret[4..].copy_from_slice(&self.data);
    }
}

impl TransferFormatTryFrom for PreparedWriteResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() >= 4 {
            Ok(Self {
                handle: TransferFormatTryFrom::try_from(&raw[..2])?,
                offset: <u16 as TransferFormatTryFrom>::try_from(&raw[2..4])?.into(),
                data: raw[4..].to_vec(),
            })
        } else {
            Err(TransferFormatError::bad_min_size(
                stringify!(PreparedWriteResponse),
                4,
                raw.len(),
            ))
        }
    }
}

/// Create a Prepared Write Response PDU
pub fn prepare_write_response(handle: u16, offset: u16, data: Vec<u8>) -> Pdu<PreparedWriteResponse> {
    Pdu {
        opcode: From::from(ServerPduName::PrepareWriteResponse),
        parameters: PreparedWriteResponse {
            handle,
            offset: offset.into(),
            data,
        },
    }
}

/// Parameter for the Execute Write Request
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ExecuteWriteFlag {
    CancelAllPreparedWrites,
    WriteAllPreparedWrites,
}

impl ExpectedOpcode for ExecuteWriteFlag {
    fn expected_opcode() -> PduOpcode {
        ClientPduName::ExecuteWriteRequest.into()
    }
}

impl TransferFormatTryFrom for ExecuteWriteFlag {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() == 1 {
            match raw[0] {
                0 => Ok(ExecuteWriteFlag::CancelAllPreparedWrites),
                1 => Ok(ExecuteWriteFlag::WriteAllPreparedWrites),
                f => Err(TransferFormatError {
                    pdu_err: Error::InvalidPDU,
                    message: format!("Invalid execute write flag {}", f),
                }),
            }
        } else {
            Err(TransferFormatError::bad_size("Execute Write Flag", 1, raw.len()))
        }
    }
}

impl TransferFormatInto for ExecuteWriteFlag {
    fn len_of_into(&self) -> usize {
        1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0] = match self {
            ExecuteWriteFlag::CancelAllPreparedWrites => 0,
            ExecuteWriteFlag::WriteAllPreparedWrites => 1,
        }
    }
}

/// Execute all queued prepared writes
///
/// Send from the client to the server to indicate that all prepared data should be written to the
/// server.
///
/// If the execute flag is false, then everything in the queue is not written and instead the
/// client is indication to the server to drop all data into the queue.
pub fn execute_write_request(execute: ExecuteWriteFlag) -> Pdu<ExecuteWriteFlag> {
    Pdu {
        opcode: From::from(ClientPduName::ExecuteWriteRequest),
        parameters: execute,
    }
}

/// Parameter for an Execute Write Response
#[derive(Debug)]
pub struct ExecuteWriteResponse;

impl ExpectedOpcode for ExecuteWriteResponse {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::ExecuteWriteResponse.into()
    }
}

impl TransferFormatTryFrom for ExecuteWriteResponse {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() == 0 {
            Ok(Self)
        } else {
            Err(TransferFormatError::from(
                "Expected no parameter for an Execute Write Response",
            ))
        }
    }
}

impl TransferFormatInto for ExecuteWriteResponse {
    fn len_of_into(&self) -> usize {
        0
    }

    fn build_into_ret(&self, _: &mut [u8]) {}
}

pub fn execute_write_response() -> Pdu<ExecuteWriteResponse> {
    Pdu {
        opcode: From::from(ServerPduName::ExecuteWriteResponse),
        parameters: ExecuteWriteResponse,
    }
}

/// Parameter for a Handle Value Notification
#[derive(Debug)]
pub struct HandleValueNotification<D>(pub HandleWithData<D>);

impl<D> ExpectedOpcode for HandleValueNotification<D> {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::HandleValueNotification.into()
    }
}

impl<D> TransferFormatTryFrom for HandleValueNotification<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl<D> TransferFormatInto for HandleValueNotification<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Create a server sent notification
pub fn create_notification<D>(handle: u16, data: D) -> Pdu<HandleValueNotification<D>> {
    Pdu {
        opcode: From::from(ServerPduName::HandleValueNotification),
        parameters: HandleValueNotification(HandleWithData { handle, data }),
    }
}

/// Parameter for a Handle Value Indication
#[derive(Debug)]
pub struct HandleValueIndication<D>(pub HandleWithData<D>);

impl<D> ExpectedOpcode for HandleValueIndication<D> {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::HandleValueIndication.into()
    }
}

impl<D> TransferFormatTryFrom for HandleValueIndication<D>
where
    D: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(Self(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl<D> TransferFormatInto for HandleValueIndication<D>
where
    D: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

/// Create a server sent indication
pub fn create_indication<D>(handle: u16, data: D) -> Pdu<HandleValueIndication<D>> {
    Pdu {
        opcode: From::from(ServerPduName::HandleValueIndication),
        parameters: HandleValueIndication(HandleWithData { handle, data }),
    }
}

/// Parameter for an Handle Value Confirmation
#[derive(Debug)]
pub struct HandleValueConfirmation;

impl ExpectedOpcode for HandleValueConfirmation {
    fn expected_opcode() -> PduOpcode {
        ServerPduName::HandleValueNotification.into()
    }
}

impl TransferFormatTryFrom for HandleValueConfirmation {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() == 0 {
            Ok(Self)
        } else {
            Err(TransferFormatError::from(
                "Expected no parameter for a Handle Value Confirmation",
            ))
        }
    }
}

impl TransferFormatInto for HandleValueConfirmation {
    fn len_of_into(&self) -> usize {
        0
    }

    fn build_into_ret(&self, _: &mut [u8]) {}
}

/// Create a client sent confirmation to an indication
pub fn handle_value_confirmation() -> Pdu<HandleValueConfirmation> {
    Pdu {
        opcode: From::from(ClientPduName::HandleValueConfirmation),
        parameters: HandleValueConfirmation,
    }
}
