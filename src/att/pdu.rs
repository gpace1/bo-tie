//! Construct ATT Profile defined Attribute Protocol data units (PDUs)
//!
//! This module contains a number of methods that can be used to construct PDUs that are defined
//! in the ATT Profile Specification. The other items (structs and enums) are used to supplement
//! the builder methods.
//!
//! *Commands*, *Requests*, *Notifications*, and *Indications*, are all PDUs that can be sent by
//! the client to the server. *Responses*, and *Confirmations* are sent by the server to the client.

use super::{
    TransferFormat,
    TransferFormatSize,
    TransferFormatError,
    client::ClientPduName,
    server::ServerPduName
};
use alloc::{
    vec::Vec,
    boxed::Box,
    format,
};

#[inline]
pub fn is_valid_handle(handle: u16) -> bool { handle != 0 }

pub fn is_valid_handle_range<R>(range: &R) -> bool where R: core::ops::RangeBounds<u16> {
    use core::ops::Bound;

    let start = range.start_bound();
    let end = range.end_bound();

    (start != Bound::Included(&0)) && match (start, end) {
        (Bound::Included(s), Bound::Included(e)) => s <= e,
        (Bound::Included(s), Bound::Excluded(e)) => s <  e,
        (Bound::Excluded(s), Bound::Included(e)) => s <  e,
        (Bound::Excluded(s), Bound::Excluded(e)) => s <= e,
        _ => true,
    }
}

#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct PduOpCode {
    /// A boolean to indicate if there is an authentication signature in the Attribute PDU
    sig: bool,
    /// Command flag
    command: bool,
    /// Method
    method: u8,
}

impl PduOpCode {
    pub fn new() -> Self {
        PduOpCode {
            sig: false,
            command: false,
            method: 0,
        }
    }

    pub(crate) fn into_raw(&self) -> u8 {
        self.method & 0x3F |
        (if self.sig {1} else {0}) << 7 |
        (if self.command {1} else {0}) << 6
    }
}

impl From<u8> for PduOpCode {
    fn from(val: u8) -> Self {
        PduOpCode {
            sig: if 0 != (val & (1 << 7)) {true} else {false},
            command: if 0 != (val & (1 << 6)) {true} else {false},
            method: val & 0x3F
        }
    }
}

fn pretty_opcode(opcode: u8, f: &mut core::fmt::Formatter) -> core::fmt::Result {
    use core::convert::TryFrom;

    match ClientPduName::try_from(opcode) {
        Ok(client_opcode) => write!(f, "{}", client_opcode),
        Err(_) => match ServerPduName::try_from(opcode) {
            Ok(server_opcode) => write!(f, "{}", server_opcode),
            Err(_) => write!(f, "{:#x}", opcode),
        },
    }
}

/// Todo implement this
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
pub struct Pdu<P> where P: TransferFormat {
    /// The Attribute Opcode
    opcode: PduOpCode,
    /// The Attribute(s) sent with the Pdu
    parameters: P,
    /// TODO Optional authentication signature, this is not implemented yet
    signature: Option<()>
}

impl<P> Pdu<P> where P: TransferFormat {

    /// Create a new Pdu
    ///
    /// # TODO
    /// The signature has not been implemented yet
    pub fn new( opcode: PduOpCode, parameters: P, signature: Option<()> ) -> Self {
        Pdu { opcode, parameters, signature}
    }

    pub fn get_opcode(&self) -> PduOpCode { self.opcode }
    pub fn get_parameters(&self) -> &P { &self.parameters }
    pub fn get_signature(&self) -> Option<()> { self.signature }
    pub fn into_parameters(self) -> P { self.parameters }
}

impl<P> TransferFormat for Pdu<P> where P: TransferFormat {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() > 0 {
            let opcode = PduOpCode::from(raw[0]);

            Ok(
                Pdu {
                    opcode,
                    parameters: if opcode.sig {
                            TransferFormat::from(&raw[1..(raw.len() - 12)])
                                .or_else(|e|
                                    Err(TransferFormatError::from(format!("PDU parameter: {}", e)))
                                )?
                        } else {
                            TransferFormat::from(&raw[1..])?
                        },
                    signature: None
                }
            )
        } else {
            Err(TransferFormatError::from("Pdu with length of zero received"))
        }
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = Vec::new();

        v.push(self.opcode.into_raw());

        v.extend_from_slice( &TransferFormat::into(&self.parameters) );

        if let Some(ref sig) = self.signature {
            v.extend_from_slice( &TransferFormat::into(sig) )
        }

        v.into_boxed_slice()
    }
}

impl<P> core::fmt::Display for Pdu<P> where P: core::fmt::Display + TransferFormat {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {

        let raw_opcode = self.get_opcode().into_raw();

        write!(f, "Pdu Opcode: '")?;
        pretty_opcode(raw_opcode, f)?;
        write!(f, "', Parameter: '{}'", self.parameters)
    }
}

/// Error when converting a u8 to an `[Error](#Error)`
///
/// Not all error values are for the ATT protocol, some are application level, and some are defined
/// elsewhere. If an error value cannot be converted into an `[Error](#Error)', then this is
/// returned. Usually a protocol above the ATT protocol will take this information and process the
/// error.
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum ErrorConversionError {
    /// Application level error code
    ApplicationError(u8),
    /// Values that are in the "Reserved for future use" range get put here
    Reserved(u8),
    /// Common profile and service error codes that are from the Core Specification Supplement
    CommonErrorCode(u8),
}

impl core::fmt::Display for ErrorConversionError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ErrorConversionError::ApplicationError(val) => {
                write!(f, "Application Error: 0x{:X}", val)
            },
            ErrorConversionError::Reserved(val) => {
                write!(f, "Error value is reserved for future use (0x{:X})", val)
            },
            ErrorConversionError::CommonErrorCode(val) => {
                write!(f, "Common error: 0x{:X} (defined in the Bluetooth Core Specification Supplement)", val)
            },
        }
    }
}

/// The ATT Protocol errors
///
/// These are the errors defined in the ATT Protocol. Higher layer protocols can define their own
/// errors, but the value of those errors must be between 0xA0-DxDF
///
/// See the Bluetooth Specification (V. 5.0) volume 3, part F, section 3.4 for more information on
/// the error codes
#[derive(Clone,Copy,PartialEq,Eq,Debug)]
pub enum Error {
    /// Used to represent 0x0000, this should never be used as an error code
    NoError,
    InvalidHandle,
    ReadNotPermitted,
    WriteNotPermitted,
    InvalidPDU,
    InsufficientAuthentication,
    RequestNotSupported,
    InvalidOffset,
    InsufficientAuthorization,
    PrepareQueueFull,
    AttributeNotFound,
    AttributeNotLong,
    InsufficientEncryptionKeySize,
    InvalidAttributeValueLength,
    UnlikelyError,
    InsufficientEncryption,
    UnsupportedGroupType,
    InsufficientResources,
    /// The rest of the error codes are either reserved for future use, used for higher layer
    /// protocols, or a common error code from the core specification.
    Other(ErrorConversionError)
}

impl Error {
    pub(crate) fn from_raw(val: u8) -> Error {
        match val {
            0x00 => Error::NoError,
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
            0x12 ..= 0x7F => Error::Other(ErrorConversionError::Reserved(val)),
            0x80 ..= 0x9F => Error::Other(ErrorConversionError::ApplicationError(val)),
            0xA0 ..= 0xDF => Error::Other(ErrorConversionError::Reserved(val)),
            0xE0 ..= 0xFF => Error::Other(ErrorConversionError::CommonErrorCode(val)),
        }
    }

    pub(crate) fn get_raw(&self) -> u8 {
        match self {
            Error::NoError => 0x00,
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
            Error::Other(val) => match val {
                ErrorConversionError::ApplicationError(val) => *val,
                ErrorConversionError::Reserved(val) => *val,
                ErrorConversionError::CommonErrorCode(val) => *val,
            },
        }
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::NoError => {
                write!(f, "No Error")
            },
            Error::InvalidHandle => {
                write!(f, "The attribute handle given was not valid on this server")
            },
            Error::ReadNotPermitted => {
                write!(f, "The attribute cannot be read")
            },
            Error::WriteNotPermitted => {
                write!(f, "The attribute cannot be written")
            },
            Error::InvalidPDU => {
                write!(f, "The attribute PDU was invalid")
            },
            Error::InsufficientAuthentication => {
                write!(f, "The attribute requires authentication before it can be read or written")
            },
            Error::RequestNotSupported => {
                write!(f, "Attribute server does not support the request received from the client")
            },
            Error::InvalidOffset => {
                write!(f, "Offset specified was past the end of the attribute")
            },
            Error::InsufficientAuthorization => {
                write!(f, "The attribute requires authorization before it can be read or written")
            },
            Error::PrepareQueueFull => {
                write!(f, "Too many prepare writes have been queued")
            },
            Error::AttributeNotFound => {
                write!(f, "No attribute found within the given attribute handle range")
            },
            Error::AttributeNotLong => {
                write!(f, "The attribute cannot be read using the Read Blob Request")
            },
            Error::InsufficientEncryptionKeySize => {
                write!(f, "The Encryption Key Size used for encrypting this link is insufficient")
            },
            Error::InvalidAttributeValueLength => {
                write!(f, "The attribute value length is invalid for the operation")
            },
            Error::UnlikelyError => {
                write!(f, "The attribute request that was requested has encountered an error that was unlikely, and therefore could not be completed as requested")
            },
            Error::InsufficientEncryption => {
                write!(f, "The attribute requires encryption before it can be read or written")
            },
            Error::UnsupportedGroupType => {
                write!(f, "The attribute type is not a supported grouping attribute as defined by a higher layer specification")
            },
            Error::InsufficientResources => {
                write!(f, "Insufficient Resources to complete the request")
            },
            Error::Other(other) => {
                write!(f, "{}", other)
            }
        }
    }
}

impl From<Error> for super::Error {
    fn from(err: Error) -> Self {
        super::Error::PduError(err)
    }
}

/// Attribute Parameters included with the Error PDU
#[derive(Debug)]
pub struct ErrorAttributeParameter {
    /// The opcode of the requested
    pub request_opcode: u8,
    /// The attribute handle that generated the error response
    pub requested_handle: u16,
    /// error code
    pub error: Error,
}

impl TransferFormat for ErrorAttributeParameter {

    /// Returns self if the length of the parameters is correct
    fn from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 4 {
            Ok( Self {
                request_opcode: raw[0],
                requested_handle: <u16>::from_le_bytes( [raw[1], raw[2]] ),
                error: Error::from_raw(raw[3]),
            })
        } else {
            Err(TransferFormatError::bad_size(stringify!(ErrorAttributeParameter), 4, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = alloc::vec::Vec::new();

        v.push(self.request_opcode);

        self.requested_handle.to_le_bytes().iter().for_each(|b| v.push(*b) );

        v.push(self.error.get_raw());

        v.into_boxed_slice()
    }
}

impl core::fmt::Display for ErrorAttributeParameter {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Requested Opcode: ")?;
        pretty_opcode(self.request_opcode, f)?;
        write!(f, ", Requested Handle: ")?;
        core::fmt::Display::fmt(&self.requested_handle, f)?;
        write!(f, ", Error: ")?;
        core::fmt::Display::fmt(&self.error, f)
    }
}

/// Error Response Attribute
///
/// This is sent by the server when ever there is an issue with a client's request
pub fn error_response(request_opcode: u8, requested_handle: u16, error: Error) -> Pdu<ErrorAttributeParameter> {
    Pdu {
        opcode: From::from(ServerPduName::ErrorResponse),
        parameters: ErrorAttributeParameter { request_opcode, requested_handle, error },
        signature: None,
    }
}

/// Request Maximum Transfer Unit (MTU)
///
/// This is sent by the client to tell the server the MTU that the client can receieve by the
/// server. The server and client will use the smallest mtu size (not less then the minimum
/// defined in the ATT Protocol) as stated by the exchange MTU request and response.
pub fn exchange_mtu_request(mtu: u16) -> Pdu<u16> {
    Pdu {
        opcode: From::from(ClientPduName::ExchangeMtuRequest),
        parameters: mtu,
        signature: None
    }
}

/// Response to a Maximum Transfer Unit (MTU) request
///
/// This is sent by the server in response to a
/// `[exchange mtu request](../exchange_mtu_request/index.html)`
/// sent by the client. This contains the MTU of a ATT protocol data unit that is accepted by
/// the server. The server and client will use the smallest mtu size (not less then the minimum
/// defined in the ATT Protocol) as stated by the exchange MTU request and response.
pub fn exchange_mtu_response(mtu: u16) -> Pdu<u16> {
    Pdu {
        opcode: From::from(ServerPduName::ExchangeMTUResponse),
        parameters: mtu,
        signature: None
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
/// reserved handle value as specified by the ATT Protocol specification. It can lead to errors
/// if 0 is uses as the starting attribute handle. If the start of the range is unbounded, then
/// 1 is used as the value for the starting handle.
#[derive(Clone)]
pub struct HandleRange {
    pub starting_handle: u16,
    pub ending_handle: u16
}

impl HandleRange {

    /// Check that the handle range is valid
    ///
    /// This will return true if `starting_handle` <= `ending_handle`
    pub fn is_valid(&self) -> bool {
        self.starting_handle <= self.ending_handle
    }
}

impl TransferFormat for HandleRange {
    fn from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if 4 == raw.len() {
            Ok(Self {
                starting_handle: <u16>::from_le_bytes( [raw[0], raw[1]] ),
                ending_handle: <u16>::from_le_bytes( [raw[2], raw[3]] ),
            })
        } else {
            Err(TransferFormatError::bad_size(stringify!(HandleRange), 4, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = Vec::new();

        self.starting_handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        self.ending_handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.into_boxed_slice()
    }
}

impl<R> From<R> for HandleRange where R: core::ops::RangeBounds<u16> {
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
            Bound::Unbounded => 0xFFFF,
        };

        Self { starting_handle, ending_handle }
    }
}

/// Find information request
///
/// This is a request from the client for obtaining the mapping of attribute handles on the
/// server to attribute types.
pub fn find_information_request<R>( range: R ) -> Pdu<HandleRange>
where R: Into<HandleRange>
{
    Pdu {
        opcode: From::from(ClientPduName::FindInformationRequest),
        parameters: range.into(),
        signature: None,
    }
}

/// A struct that contains an attrube handle and attribute type
#[derive(Clone,Copy,PartialEq,Eq)]
pub struct HandleWithType( u16, crate::UUID);

/// Formatted handle with type
///
/// This struct, when created with determine if all the UUID's are 16 bit or 128 bit, and
/// is used to create the find information response attribute PDU.
#[derive(Clone)]
pub struct FormattedHandlesWithType {
    handles_with_uuids: Box<[HandleWithType]>,
}

impl FormattedHandlesWithType {
    const UUID_16_BIT: u8 = 0x1;
    const UUID_128_BIT: u8 = 0x2;
}

impl TransferFormat for FormattedHandlesWithType {
    fn from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        match raw[0] {
            Self::UUID_16_BIT => {
                let chunks = raw[1..].chunks_exact(4);

                if chunks.remainder().len() == 0 {
                    let mut v = Vec::new();

                    for chunk in chunks {
                        let handle = <u16>::from_le_bytes( [chunk[0], chunk[1]] );

                        let uuid = Into::<crate::UUID>::into(
                            <u16>::from_le_bytes( [chunk[2], chunk[3]] )
                        );

                        v.push( HandleWithType(handle, uuid))
                    }

                    Ok(FormattedHandlesWithType { handles_with_uuids: v.into_boxed_slice() })
                } else {
                    Err(TransferFormatError::bad_exact_chunks(stringify!(FormattedHandlesWithType),
                        4, raw[1..].len() ))
                }
            },
            Self::UUID_128_BIT => {
                let chunks = raw[1..].chunks_exact(18);

                if chunks.remainder().len() == 0 {
                    let mut v = Vec::new();

                    for chunk in chunks {
                        let handle = <u16>::from_le_bytes( [chunk[0], chunk[1]] );

                        let mut uuid_bytes = [0u8;core::mem::size_of::<u128>()];

                        uuid_bytes.clone_from_slice(&chunk[2..]);

                        let uuid = Into::<crate::UUID>::into( <u128>::from_le_bytes(uuid_bytes));

                        v.push( HandleWithType(handle, uuid) );
                    }

                    Ok(FormattedHandlesWithType { handles_with_uuids: v.into_boxed_slice() })

                } else {
                    Err(TransferFormatError::bad_exact_chunks(stringify!(FormattedHandlesWithType),
                        18, raw[1..].len()))
                }
            },
            _ => Err(TransferFormatError::from(concat!("Invalid Type for ",
                stringify!(FormattedHandlesWithType)))),
        }
    }

    fn into(&self) -> Box<[u8]> {

        let mut ret_v = Vec::new();

        let vec16: Result<Vec<u8>, ()> = self.handles_with_uuids.iter().try_fold( Vec::new(), | mut v, hwu| {
            use core::convert::TryInto;

            hwu.0.to_le_bytes().iter().for_each(|b| v.push(*b) );

            TryInto::<u16>::try_into(hwu.1)?.to_le_bytes().iter().for_each( |b| v.push(*b) );

            Ok(v)
        });

        match vec16 {
            Ok(v) => {
                ret_v.push(Self::UUID_16_BIT);
                ret_v.extend_from_slice(v.as_slice());
                ret_v.into_boxed_slice()
            },
            Err(_) => {
                ret_v.push(Self::UUID_128_BIT);

                self.handles_with_uuids.iter().for_each( |hwu| {

                    hwu.0.to_le_bytes().iter().for_each(|b| ret_v.push(*b) );

                    Into::<u128>::into(hwu.1).to_le_bytes().iter().for_each( |b| ret_v.push(*b) );
                });

                ret_v.into_boxed_slice()
            }
        }
    }
}

/// Find information response
///
/// This is the response from a server due to a find information request sent by a client
///
/// The parameter is a slice reference of attribute handles with the attribute type. If every
/// type can be converted into a
pub fn find_information_response<R>( handles_with_uuids: &[HandleWithType] )
-> Pdu<FormattedHandlesWithType>
{
    Pdu {
        opcode: From::from(ServerPduName::FindInformationResponse),
        parameters: FormattedHandlesWithType { handles_with_uuids: From::from(handles_with_uuids) },
        signature: None,
    }
}

#[derive(Clone)]
pub struct TypeValueRequest<D> where D: TransferFormat {
    handle_range: HandleRange,
    attr_type: u16,
    value: D,
}

impl<D> TransferFormat for TypeValueRequest<D> where D: TransferFormat {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() >= 6 {
            Ok( TypeValueRequest {
                handle_range: TransferFormat::from( &raw[..4] )?,
                attr_type: <u16>::from_le_bytes( [ raw[4], raw[5] ] ),
                value: TransferFormat::from( &raw[6..] )?,
            })
        } else {
            Err( TransferFormatError::bad_min_size(stringify!(TypeValueRequest), 6, raw.len()) )
        }
    }

    fn into(&self) -> Box<[u8]> {

        let mut v = Vec::new();

        v.extend_from_slice( &TransferFormat::into(&self.handle_range) );

        self.attr_type.to_le_bytes().iter().for_each(|b| v.push(*b));

        v.extend_from_slice( &TransferFormat::into(&self.value) );

        v.into_boxed_slice()
    }
}

/// Find by type value request
///
/// This is sent by the client to the server to find attributes that have a 16 bit UUID as the type
/// and the provided attribute value.
///
/// The uuid must be convertable into a 16 bit assigned number, otherwise this will return an error.
pub fn find_by_type_value_request<R,D>(handle_range: R, uuid: crate::UUID, value: D)
-> Result< Pdu<TypeValueRequest<D>>, ()>
where R: Into<HandleRange>,
      D: TransferFormat,
{
    use core::convert::TryFrom;

    if let Ok(uuid) = <u16>::try_from(uuid) {
        Ok(
            Pdu {
                opcode: From::from(ClientPduName::FindByTypeValueRequest),
                parameters: TypeValueRequest{
                    handle_range: handle_range.into(),
                    attr_type: uuid,
                    value: value,
                },
                signature: None,
            }
        )
    } else {
        Err(())
    }
}

pub struct TypeValueResponse {
    handle: u16,
    group: u16,
}

impl TransferFormat for TypeValueResponse {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() != 4 {
            Ok(
                TypeValueResponse {
                    handle: <u16>::from_le_bytes( [ raw[0], raw[1] ]),
                    group:  <u16>::from_le_bytes( [ raw[2], raw[3] ]),
                }
            )
        } else {
            Err(TransferFormatError::bad_size(stringify!(TypeValueResponse), 4, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = Vec::new();

        self.handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        self.group.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.into_boxed_slice()
    }
}

impl TransferFormatSize for TypeValueResponse {
    const SIZE: usize = 4;
}

pub fn find_by_type_value_response( type_values: Box<[TypeValueResponse]> )
-> Pdu<Box<[TypeValueResponse]>>
{
    Pdu {
        opcode: From::from(ServerPduName::FindByTypeValueResponse),
        parameters: type_values,
        signature: None,
    }
}

/// The parameter for the type request ATT PDU
#[derive(Clone)]
pub struct TypeRequest {
    pub handle_range: HandleRange,
    pub attr_type: crate::UUID,
}

impl TransferFormat for TypeRequest {
    fn from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 6 {
            Ok(Self {
                handle_range: TransferFormat::from(&raw[..4])?,
                attr_type: Into::<crate::UUID>::into(<u16>::from_le_bytes( [raw[4], raw[5]] )),
            })
        } else if raw.len() == 20 {
            Ok(Self {
                handle_range: TransferFormat::from(&raw[..4])?,
                attr_type: Into::<crate::UUID>::into(<u128>::from_le_bytes(
                    {
                        let mut bytes = [0;16];
                        bytes.clone_from_slice(&raw[4..]);
                        bytes
                    }
                ))
            })
        } else {
            Err(TransferFormatError::bad_size(stringify!(TypeRequest), "6 or 20", raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {

        let mut v = Vec::new();

        self.handle_range.starting_handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        self.handle_range.starting_handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        match core::convert::TryInto::<u16>::try_into(self.attr_type) {
            Ok(val) => val.to_le_bytes()
                        .iter()
                        .fold( v, |mut v,b| { v.push(*b); v } )
                        .into_boxed_slice(),
            Err(_) => Into::<u128>::into(self.attr_type)
                        .to_le_bytes()
                        .iter()
                        .fold(v, |mut v,b| { v.push(*b); v } )
                        .into_boxed_slice(),
        }
    }
}

/// Read attributes by type
///
/// This is a request from the client for finding attributes by their type within a range of
/// handles.
pub fn read_by_type_request<R>(handle_range: R, attr_type: crate::UUID) -> Pdu<TypeRequest>
where R: Into<HandleRange>
{
    Pdu {
        opcode: From::from(ClientPduName::ReadByTypeRequest),
        parameters: TypeRequest {
            handle_range: handle_range.into(),
            attr_type: attr_type
        },
        signature: None,
    }
}

/// A single read type response
///
/// The read type response will contain one or more of these
pub struct ReadTypeResponse<D> where D: TransferFormat {
    handle: u16,
    data: D
}

impl<D> TransferFormat for ReadTypeResponse<D> where D: TransferFormat {

    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> where Self: Sized {
        if raw.len() == 2 + core::mem::size_of::<D>() {
            Ok( Self{
                handle: <u16>::from_le_bytes( [ raw[0], raw[1] ]),
                data: TransferFormat::from( &raw[2..] )?,
            })
        } else {
            Err( TransferFormatError::bad_size(stringify!("ReadTypeResponse"),
                2 + core::mem::size_of::<D>(), raw.len()) )
        }
    }

    fn into(&self) -> Box<[u8]> where Self: Sized {

        let mut v = Vec::new();

        self.handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.extend_from_slice(TransferFormat::into(&self.data).as_ref());

        v.into_boxed_slice()
    }
}

impl<D> TransferFormatSize for ReadTypeResponse<D> where D: TransferFormatSize + TransferFormat {
    const SIZE: usize = 2 + D::SIZE;
}

/// Read attribute by type response
///
/// The response from the server to a read attribute by type request
///
/// # Note
/// This generates a PDU, but that PDU isn't checked if it is larger then the ATT MTU or if the
/// size of type D is greater then 255. Its the responsibility of the caller to make sure that
/// the size of the data sent to the controller is correct.
pub fn read_by_type_response<D>( responses: Box<[ReadTypeResponse<D>]>) -> Pdu<Box<[ReadTypeResponse<D>]>>
where D: TransferFormat + TransferFormatSize
{
    Pdu {
        opcode: From::from(ServerPduName::ReadByTypeResponse),
        parameters: responses,
        signature: None,
    }
}

pub fn read_request( handle: u16 ) -> Pdu<u16> {
    Pdu {
        opcode: From::from(ClientPduName::ReadRequest),
        parameters: handle,
        signature: None,
    }
}

pub fn read_response<D>( value: D ) -> Pdu<D> where D: TransferFormat {
    Pdu {
        opcode: From::from(ServerPduName::ReadResponse),
        parameters: value,
        signature: None,
    }
}

#[derive(Clone)]
pub struct BlobRequest {
    handle: u16,
    offset: u16
}

impl TransferFormat for BlobRequest {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> where Self: Sized {
        if raw.len() == 4 {
            Ok( Self {
                handle: <u16>::from_le_bytes( [ raw[0], raw[1] ]),
                offset: <u16>::from_le_bytes( [ raw[2], raw[3] ]),
            })
        } else {
            Err(TransferFormatError::bad_size(stringify!(BlobRequest), 4, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> where Self: Sized {
        let mut v = Vec::new();

        self.handle.to_le_bytes().iter().for_each( |b| v.push(*b) );
        self.offset.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.into_boxed_slice()
    }
}

pub fn read_blob_request( handle: u16, offset: u16) -> Pdu<BlobRequest> {
    Pdu {
        opcode: From::from(ClientPduName::ReadBlobRequest),
        parameters: BlobRequest { handle, offset },
        signature: None,
    }
}

pub fn read_blob_response<D>( value: D, offset: usize, att_mtu: usize ) -> Pdu<Box<[u8]>>
where D: TransferFormat
{
    let start = offset;
    let end   = offset + att_mtu;

    Pdu {
        opcode: From::from(ServerPduName::ReadBlobResponse),
        parameters: From::from(&TransferFormat::into(&value)[start..end]),
        signature: None,
    }
}


/// Request multiple reads
///
/// This is sent by the client to requests 2 or more values to read. If the length of the input is
/// less then 2 then the return will be an error.
pub fn read_multiple_request( handles: Vec<u16> ) -> Result<Pdu<Vec<u16>>, super::Error> {
    if handles.len() >= 2 {
        Ok(Pdu {
            opcode: From::from(ClientPduName::ReadMultipleRequest),
            parameters: handles,
            signature: None,
        })
    } else {
        Err(super::Error::Other("Two or more handles required for read multiple"))
    }
}

/// Read Multiple Response
///
/// Server response to a read multiple request
pub fn read_multiple_response( values: Box<[Box<dyn TransferFormat>]> )
-> Pdu<Box<[Box<dyn TransferFormat>]>>
{
    Pdu {
        opcode: From::from(ServerPduName::ReadMultipleResponse),
        parameters: values,
        signature: None,
    }
}

/// Read an attribute group request
///
/// Client request for reading attributes' data that are under a group specified by a higher layer
/// protocol. The read
pub fn read_by_group_type_request<R>(handle_range: R, group_type: crate::UUID) -> Pdu<TypeRequest>
where R: Into<HandleRange>
{
    Pdu {
        opcode: From::from(ClientPduName::ReadByGroupTypeRequest),
        parameters: TypeRequest{
            handle_range: handle_range.into(),
            attr_type: group_type,
        },
        signature: None,
    }
}

/// A single read by group type response
///
/// The read by group type response will contain one or more of these
#[derive(Debug)]
pub struct ReadGroupTypeData<D> where D: TransferFormat {
    handle: u16,
    end_group_handle: u16,
    data: D
}

impl<D> ReadGroupTypeData<D> where D: TransferFormat {
    pub fn new( handle: u16, end_group_handle: u16, data: D) -> Self {
        Self { handle, end_group_handle, data}
    }
}

impl<D> TransferFormat for ReadGroupTypeData<D> where D: TransferFormat {

    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() >= 4 {
            Ok( Self{
                handle: <u16>::from_le_bytes( [ raw[0], raw[1] ]),
                end_group_handle: <u16>::from_le_bytes( [ raw[2], raw[3] ] ),
                data: TransferFormat::from( &raw[4..] )?,
            })
        } else {
            Err( TransferFormatError::bad_min_size(stringify!(ReadGroupTypeData), 4, raw.len()) )
        }
    }

    fn into(&self) -> Box<[u8]> {

        let mut v = Vec::new();

        self.handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        self.end_group_handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.extend_from_slice(TransferFormat::into(&self.data).as_ref());

        v.into_boxed_slice()
    }
}

/// The full list of response data for read by group type
#[derive(Debug)]
pub struct ReadByGroupTypeResponse<D> where D: TransferFormat {
    data: Vec<ReadGroupTypeData<D>>,
}

impl<D> ReadByGroupTypeResponse<D> where D: TransferFormat {

    /// Create a new `ReadByGroupTypeResponse`
    ///
    /// Returns a `ReadByGroupTypeResponse` if input `data` is not empty, otherwise an `Err` is
    /// returned.
    pub fn new(data: Vec<ReadGroupTypeData<D>>) -> Result<Self, ()> {
        match data.len() {
            0 => Err(()),
            _ => Ok( ReadByGroupTypeResponse { data } )
        }
    }
}

impl<D> TransferFormat for ReadByGroupTypeResponse<D> where D: TransferFormat {
    fn from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() >= 5 {
            let item_len = raw[0] as usize;

            let exact_chunks = raw[1..].chunks_exact(item_len);

            if exact_chunks.remainder().len() == 0 {

                exact_chunks
                .map( |raw| TransferFormat::from(raw) )
                .try_fold( Vec::new(), |mut v, rslt| { v.push(rslt?); Ok(v) } )
                .and_then( |v| Ok(ReadByGroupTypeResponse { data: v }) )
                .or_else( |e: TransferFormatError| Err(e.into()) )

            } else {
                Err( TransferFormatError::bad_exact_chunks(
                    stringify!(ReadByGroupTypeResponse), item_len, raw[1..].len() ) )
            }
        } else {
            Err( TransferFormatError::bad_min_size(stringify!(ReadByGroupTypeResponse), 5, raw.len()) )
        }
    }

    /// # Panic
    /// This can panic if
    fn into(&self) -> Box<[u8]> {

        let first = self.data.first().unwrap();

        let first_raw = TransferFormat::into( first );

        let mut v = alloc::vec!( first_raw.len() as u8 );

        v.extend_from_slice( &first_raw );

        self.data[1..].iter()
        .map( |d| TransferFormat::into(d) )
        .fold(v, |mut v,rd| { v.extend_from_slice(&rd); v } )
        .into_boxed_slice()
    }
}

/// Read an attribute group response
pub fn read_by_group_type_response<D>( response: ReadByGroupTypeResponse<D>)
-> Pdu<ReadByGroupTypeResponse<D>>
where D: TransferFormat
{
    Pdu {
        opcode: From::from(ServerPduName::ReadByGroupTypeResponse),
        parameters: response,
        signature: None,
    }
}

pub struct HandleWithData<D> {
    handle: u16,
    data: D,
}

impl<D> TransferFormat for HandleWithData<D> where D: TransferFormat {

    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() >= 2 {
            Ok(
                HandleWithData {
                    handle: <u16>::from_le_bytes( [ raw[0], raw[1] ]),
                    data: TransferFormat::from( &raw[2..] )?,
                }
            )
        } else {
            Err(TransferFormatError::bad_min_size(stringify!(HandleWithData), 2, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = Vec::new();

        self.handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.extend_from_slice(&TransferFormat::into(&self.data));

        v.into_boxed_slice()
    }
}

/// Write request to an attribute
pub fn write_request<D>(handle: u16, data: D) -> Pdu<HandleWithData<D>> where D: TransferFormat {
    Pdu {
        opcode: From::from(ClientPduName::WriteRequest),
        parameters: HandleWithData{ handle, data },
        signature: None,
    }
}

/// Write response
pub fn write_response() -> Pdu<()> {
    Pdu {
        opcode: From::from(ServerPduName::WriteResponse),
        parameters: (),
        signature: None,
    }
}

pub fn write_command<D>(handle: u16, data: D) -> Pdu<HandleWithData<D>> where D: TransferFormat {
    Pdu {
        opcode: From::from(ClientPduName::WriteCommand),
        parameters: HandleWithData{ handle, data },
        signature: None,
    }
}

/// TODO
/// this requires that the signature specification be implemented in bo-tie which isn't done yet
///
/// for now this will just panic with the message unimplementd.
pub fn signed_write_command<D,Sig>(_handle: u16, _data: D, _signature: Sig) -> !
where D: TransferFormat,
      Sig: Into<()>
{
    unimplemented!();

    // Pdu {
    //     opcode: From::from(0xD2),
    //     parameters: HandleWithData{ handle, data },
    //     signature: signature.into(),
    // }
}

pub struct PrepareWriteRequest<D> where D: TransferFormat {
    handle: u16,
    offset: u16,
    data: D
}

impl<D> TransferFormat for PrepareWriteRequest<D> where D: TransferFormat {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() >= 4 {
            Ok(
                PrepareWriteRequest {
                    handle: <u16>::from_le_bytes( [ raw[0], raw[1] ] ),
                    offset: <u16>::from_le_bytes( [ raw[2], raw[3] ] ),
                    data: TransferFormat::from( &raw[4..] )?,
                }
            )
        } else {
            Err(TransferFormatError::bad_min_size(stringify!(PrepareWriteRequest), 4, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = Vec::new();

        self.handle.to_le_bytes().iter().for_each( |b| v.push(*b) );

        self.offset.to_le_bytes().iter().for_each( |b| v.push(*b) );

        v.extend_from_slice( &TransferFormat::into( &self.data ) );

        v.into_boxed_slice()
    }
}

pub fn prepare_write_request<D>(handle: u16, offset: u16, data: D ) -> Pdu<PrepareWriteRequest<D>>
where D: TransferFormat
{
    Pdu {
        opcode: From::from(ClientPduName::PrepareWriteRequest),
        parameters: PrepareWriteRequest{ handle, offset, data },
        signature: None
    }
}

pub fn prepare_write_response<D>(handle: u16, offset: u16, data: D ) -> Pdu<PrepareWriteRequest<D>>
where D: TransferFormat {
    Pdu {
        opcode: From::from(ServerPduName::PrepareWriteResponse),
        parameters: PrepareWriteRequest{ handle, offset, data },
        signature: None
    }
}

/// Execute all queued prepared writes
///
/// Send from the client to the server to indicate that all prepared data should be written to the
/// server.
///
/// If the execute flag is false, then everything in the queue is not written and instead the
/// client is indication to the server to drop all data into the queue.
pub fn execute_write_request( execute: bool ) -> Pdu<u8> {
    Pdu {
        opcode: From::from(ClientPduName::ExecuteWriteRequest),
        parameters: if execute {0x1} else {0x0},
        signature: None,
    }
}

pub fn execute_write_response() -> Pdu<()> {
    Pdu {
        opcode: From::from(ServerPduName::ExecuteWriteResponse),
        parameters: (),
        signature: None,
    }
}

/// A server sent notification
pub fn handle_value_notification<D>(handle: u16, data: D ) -> Pdu<HandleWithData<D>>
where D: TransferFormat
{
    Pdu {
        opcode: From::from(ServerPduName::HandleValueNotification),
        parameters: HandleWithData { handle, data },
        signature: None,
    }
}

/// A server sent indication
pub fn handle_value_indication<D>(handle: u16, data: D) -> Pdu<HandleWithData<D>>
where D: TransferFormat
{
    Pdu {
        opcode: From::from(ServerPduName::HandleValueIndication),
        parameters: HandleWithData { handle, data },
        signature: None,
    }
}

/// A client sent confirmation to an indication
pub fn handle_value_confirmation() -> Pdu<()> {
    Pdu {
        opcode: From::from(ClientPduName::HandleValueConfirmation),
        parameters: (),
        signature: None,
    }
}
