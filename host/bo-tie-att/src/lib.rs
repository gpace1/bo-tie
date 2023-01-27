#![doc = include_str!("../README.md")]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::borrow::Borrow;

pub mod client;
pub mod server;

pub use bo_tie_host_util::{Uuid, UuidFormatError, UuidVersion};
use bo_tie_util::buffer::stack::LinearBuffer;
pub use client::Client;
pub use server::Server;

//==================================================================================================
// Macros that are used within submodules
//==================================================================================================

/// Implement transfer format for `Vec<$data_type>`.
///
/// $data_type must have a constant size for the transfer format. The second input `$data_size` is
/// an optional input for the size of the transfer format of $data_type. If `$data_size` is omitted
/// then the size is inferred from the `core::mem::size_of` method.
macro_rules! impl_transfer_format_for_vec_of {
    ($data_type: ty, $data_size: expr) => {
        impl TransferFormatTryFrom for Vec<$data_type> {
            fn try_from(raw: &[u8]) -> Result<Self, crate::TransferFormatError> {
                raw.chunks($data_size).try_fold(Vec::new(), |mut v, chunk| {
                    v.push(<$data_type as TransferFormatTryFrom>::try_from(chunk)?);
                    Ok(v)
                })
            }
        }

        impl TransferFormatInto for Vec<$data_type> {
            fn len_of_into(&self) -> usize {
                self.iter().map(|t| t.len_of_into()).sum()
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                self.iter().fold(0usize, |start, t| {
                    let end: usize = start + t.len_of_into();

                    t.build_into_ret(&mut into_ret[start..end]);

                    end
                });
            }
        }
    };

    ($data_type: ty) => {
        impl_transfer_format_for_vec_of! { $data_type, core::mem::size_of::<$data_type>() }
    };
}

//==================================================================================================
// Submodules that use the above macros
//==================================================================================================

pub mod pdu;

//==================================================================================================
// End submodules that use the above macros
//==================================================================================================

pub const L2CAP_CHANNEL_ID: bo_tie_l2cap::ChannelIdentifier =
    bo_tie_l2cap::ChannelIdentifier::Le(bo_tie_l2cap::LeUserChannelIdentifier::AttributeProtocol);

/// Advanced Encryption Standard (AES) key sizes
#[derive(Clone, Copy, Debug, PartialEq, Eq, bo_tie_macros::DepthCount)]
pub enum EncryptionKeySize {
    Bits128,
    Bits192,
    Bits256,
}

impl EncryptionKeySize {
    /// Used to force an ordering such that Bits128 < Bits192 < Bits256
    fn forced_order_val(&self) -> usize {
        match self {
            EncryptionKeySize::Bits128 => 0,
            EncryptionKeySize::Bits192 => 1,
            EncryptionKeySize::Bits256 => 2,
        }
    }
}

impl PartialOrd for EncryptionKeySize {
    fn partial_cmp(&self, other: &EncryptionKeySize) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for EncryptionKeySize {
    fn cmp(&self, other: &EncryptionKeySize) -> core::cmp::Ordering {
        self.forced_order_val().cmp(&other.forced_order_val())
    }
}

/// Attribute permission restrictions
///
/// Attributes permissions can restrictions regarding reading and writing permissions. These are the
/// possible attribute restrictions that can be enforced, with `None` representing no restriction
/// on the operation.
///
/// There are three type of restrictions, `Encryption` (with the size of the encryption key),
/// `Authentication`, and `Authorization`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, bo_tie_macros::DepthCount)]
pub enum AttributeRestriction {
    None,
    Encryption(EncryptionKeySize),
    Authentication,
    Authorization,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, bo_tie_macros::DepthCount)]
pub enum AttributePermissions {
    /// Readable Access
    Read(AttributeRestriction),
    /// Writeable Access
    Write(AttributeRestriction),
}

impl Borrow<[AttributePermissions]> for AttributePermissions {
    fn borrow(&self) -> &[AttributePermissions] {
        core::slice::from_ref(self)
    }
}

impl Borrow<[AttributePermissions]> for &AttributePermissions {
    fn borrow(&self) -> &[AttributePermissions] {
        core::slice::from_ref(*self)
    }
}

/// Full restrictions
pub const FULL_RESTRICTIONS: [AttributeRestriction; AttributeRestriction::full_depth()] = [
    AttributeRestriction::None,
    AttributeRestriction::Encryption(EncryptionKeySize::Bits128),
    AttributeRestriction::Encryption(EncryptionKeySize::Bits192),
    AttributeRestriction::Encryption(EncryptionKeySize::Bits256),
    AttributeRestriction::Authentication,
    AttributeRestriction::Authorization,
];

/// Full read-only permissions
pub const FULL_READ_PERMISSIONS: [AttributePermissions; AttributePermissions::full_depth() / 2] = [
    AttributePermissions::Read(AttributeRestriction::None),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits128)),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits192)),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    AttributePermissions::Read(AttributeRestriction::Authorization),
    AttributePermissions::Read(AttributeRestriction::Authentication),
];

/// Full write-only permissions
pub const FULL_WRITE_PERMISSIONS: [AttributePermissions; AttributePermissions::full_depth() / 2] = [
    AttributePermissions::Write(AttributeRestriction::None),
    AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits128)),
    AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits192)),
    AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    AttributePermissions::Write(AttributeRestriction::Authorization),
    AttributePermissions::Write(AttributeRestriction::Authentication),
];

/// Full permissions for read and write
pub const FULL_PERMISSIONS: [AttributePermissions; AttributePermissions::full_depth()] = [
    AttributePermissions::Read(AttributeRestriction::None),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits128)),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits192)),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    AttributePermissions::Read(AttributeRestriction::Authorization),
    AttributePermissions::Read(AttributeRestriction::Authentication),
    AttributePermissions::Write(AttributeRestriction::None),
    AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits128)),
    AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits192)),
    AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    AttributePermissions::Write(AttributeRestriction::Authorization),
    AttributePermissions::Write(AttributeRestriction::Authentication),
];

/// An Attribute
///
/// Attributes contain the information required for a client to get data from a server device. Each
/// attribute contains an attribute type, an attribute handle, and permissions for accessing the
/// attribute data.
///
/// # Attribute Type
/// An attribute type is a UUID used for labeling what the attribute is. It is essentially a
/// 'common noun' for the attribute, so that the client can gather a basic understanding of what
/// the attribute refers too.
///
/// # Handle
/// A reference to the attribute on the server. The client can access specific attributes through
/// the handle value as all handle values on a server are guaranteed to be unique. This can be
/// handy or required to refer to different attributes (e.g. multiple attributes with the same
/// types ).
///
/// # Permissions
/// Permissions define the accessibility and requirements for accessibility of the Attribute. The
/// permissions `Read` and `Write` define how the user can access the data, where as the
/// permissions `Encryption`, `Authentication`, and `Authorization` define the conditions where
/// `Read` and `Write` permissions are available to the client.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attribute<V> {
    /// The Attribute type
    ty: Uuid,

    /// The attribute handle
    ///
    /// The handle is like an address to an attribute. Its how a client refers to and accesses
    /// a specific attribute on a server.
    handle: Option<u16>,

    /// Access Permissions
    permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,

    /// Attribute value
    value: V,
}

impl<V> Attribute<V> {
    /// Create an Attribute
    ///
    /// There are four components to an attribute, the type of the attribute, the handle of the
    /// attribute, the access permissions of the attribute, and the value of it. Every part except
    /// for the handle is assigned with the inputs. The handle will be set once the attribute is
    /// pushed on to the server.
    ///
    /// Ihe input 'permissions' will have all duplicates removed.
    pub fn new<P>(attribute_type: Uuid, attribute_permissions: P, value: V) -> Self
    where
        P: Borrow<[AttributePermissions]>,
    {
        let mut permissions = LinearBuffer::new();

        for permission in attribute_permissions.borrow().iter() {
            if !permissions.contains(permission) {
                permissions.try_push(*permission).unwrap();
            }
        }

        Attribute {
            ty: attribute_type,
            handle: None,
            permissions,
            value,
        }
    }

    /// Get the UUID of the attribute
    pub fn get_uuid(&self) -> &crate::Uuid {
        &self.ty
    }

    /// Get the attribute permissions
    pub fn get_permissions(&self) -> &[AttributePermissions] {
        &*self.permissions
    }

    /// Get a reference to the value
    pub fn get_value(&self) -> &V {
        &self.value
    }

    /// Get a mutable reference to the value
    pub fn get_mut_value(&mut self) -> &mut V {
        &mut self.value
    }

    /// Get the handle
    ///
    /// This will only return a handle if the attribute was retrieved from an attribute server. A
    /// free attribute will not have an associated handle.
    pub fn get_handle(&self) -> Option<u16> {
        self.handle.clone()
    }
}

/// General Attribute Error type
#[derive(PartialEq, Debug)]
pub enum Error {
    Other(&'static str),
    /// Returned when there is no connection to the bluetooth controller
    NotConnected,
    /// A PDU exceeds the MTU set between the client and server
    MtuExceeded,
    /// The desired MTU is smaller then the minimum value
    TooSmallMtu,
    /// An Error PDU is received
    Pdu(pdu::Pdu<pdu::ErrorResponse>),
    /// A different pdu was expected
    ///
    /// This contains the opcode value of the unexpectedly received pdu
    UnexpectedPdu(u8),
    /// A Transfer format error
    TransferFormatTryFrom(TransferFormatError),
    /// An empty PDU
    Empty,
    /// Unknown opcode
    ///
    /// An `UnknownOpcode` is for opcodes that are not recognized by the ATT protocol. They may
    /// be valid for a higher layer protocol.
    UnknownOpcode(u8),
    /// Custom opcode is already used by the Att protocol
    AttUsedOpcode(u8),
    /// Incorrect Channel Identifier
    IncorrectChannelId(bo_tie_l2cap::ChannelIdentifier),
    /// Pdu Error
    PduError(pdu::Error),
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Other(r) => write!(f, "{}", r),
            Error::NotConnected => write!(f, "Not Connected"),
            Error::MtuExceeded => write!(f, "Maximum Transmission Unit exceeded"),
            Error::TooSmallMtu => write!(f, "Minimum Transmission Unit larger then specified"),
            Error::Pdu(pdu) => write!(f, "Received Error PDU: {}", pdu),
            Error::UnexpectedPdu(val) => write!(f, "{}", val),
            Error::TransferFormatTryFrom(t_e) => write!(f, "{}", t_e),
            Error::Empty => write!(f, "Received an empty PDU"),
            Error::UnknownOpcode(op) => write!(f, "Opcode not known to the attribute protocol ({:#x})", op),
            Error::AttUsedOpcode(op) => write!(f, "Opcode {:#x} is already used by the Attribute Protocol", op),
            Error::IncorrectChannelId(id) => {
                write!(f, "The channel identifier '{id}' is not for the Attribute Protocol")
            }
            Error::PduError(err) => write!(f, "Attribute PDU error '{}'", err),
        }
    }
}

// impl core::fmt::Debug for Error {
//     fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
//         core::fmt::Display::fmt(self, f)
//     }
// }

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<pdu::Pdu<pdu::ErrorResponse>> for Error {
    fn from(err: pdu::Pdu<pdu::ErrorResponse>) -> Error {
        Error::Pdu(err)
    }
}

impl From<TransferFormatError> for Error {
    fn from(err: TransferFormatError) -> Self {
        Error::TransferFormatTryFrom(err)
    }
}

/// Connection Channel Attribute Error
///
/// This is used by the Attribute client and server implementations when dealing with a
/// [`ConnectionChannel`]
///
/// [`ConnectionChannel`]: bo_tie_l2cap::ConnectionChannel
pub enum ConnectionError<C: bo_tie_l2cap::ConnectionChannel> {
    AttError(Error),
    RecvError(bo_tie_l2cap::BasicFrameError<<C::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>),
    SendError(bo_tie_l2cap::send_future::Error<C::SendFutErr>),
}

impl<C> PartialEq for ConnectionError<C>
where
    C: bo_tie_l2cap::ConnectionChannel,
    <C::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error: PartialEq,
    C::SendFutErr: PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        use ConnectionError::*;

        match (self, other) {
            (AttError(e1), AttError(e2)) => e1.eq(e2),
            (RecvError(r1), RecvError(r2)) => r1.eq(r2),
            (SendError(s1), SendError(s2)) => s1.eq(s2),
            _ => false,
        }
    }
}

impl<C: bo_tie_l2cap::ConnectionChannel, E: Into<Error>> From<E> for ConnectionError<C> {
    fn from(e: E) -> Self {
        Self::AttError(e.into())
    }
}

impl<C: bo_tie_l2cap::ConnectionChannel>
    From<bo_tie_l2cap::BasicFrameError<<C::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>>
    for ConnectionError<C>
{
    fn from(e: bo_tie_l2cap::BasicFrameError<<C::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>) -> Self {
        Self::RecvError(e)
    }
}

impl<C: bo_tie_l2cap::ConnectionChannel> From<bo_tie_l2cap::send_future::Error<C::SendFutErr>> for ConnectionError<C> {
    fn from(e: bo_tie_l2cap::send_future::Error<C::SendFutErr>) -> Self {
        Self::SendError(e)
    }
}

impl<C: bo_tie_l2cap::ConnectionChannel> core::fmt::Debug for ConnectionError<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::AttError(e) => write!(f, "AttError({e:?})"),
            Self::RecvError(e) => write!(f, "RecvError({e:?})"),
            Self::SendError(e) => write!(f, "SendError({e:?})"),
        }
    }
}

impl<C: bo_tie_l2cap::ConnectionChannel> core::fmt::Display for ConnectionError<C> {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::AttError(e) => core::fmt::Display::fmt(e, f),
            Self::RecvError(rx) => core::fmt::Display::fmt(rx, f),
            Self::SendError(tx) => core::fmt::Display::fmt(tx, f),
        }
    }
}

#[cfg(feature = "std")]
impl<C: bo_tie_l2cap::ConnectionChannel> std::error::Error for ConnectionError<C> {}

#[derive(PartialEq)]
pub struct TransferFormatError {
    pub pdu_err: pdu::Error,
    pub message: String,
}

impl TransferFormatError {
    /// Create a `TransferFormatError` for incorrect size
    pub fn bad_size<D1, D2>(name: &'static str, expected_len: D1, incorrect_len: D2) -> Self
    where
        D1: core::fmt::Display,
        D2: core::fmt::Display,
    {
        TransferFormatError {
            pdu_err: pdu::Error::InvalidAttributeValueLength,
            message: format!(
                "Expected a size of {} bytes for {}, data length is {}",
                expected_len, name, incorrect_len
            ),
        }
    }

    /// Create a `TransferFormatError` when the size is smaller than the minimum
    pub fn bad_min_size<D1, D2>(name: &'static str, min_size: D1, data_len: D2) -> Self
    where
        D1: core::fmt::Display,
        D2: core::fmt::Display,
    {
        TransferFormatError {
            pdu_err: pdu::Error::InvalidAttributeValueLength,
            message: format!(
                "Expected a minimum size of {} bytes for {}, data \
                length is {}",
                min_size, name, data_len
            ),
        }
    }
    /// Create a `TransferFormattedError` for when
    /// [`chunks_exact`](slice::chunks_exact) has a remainder that is not zero
    pub fn bad_exact_chunks<D1, D2>(name: &'static str, chunk_size: D1, data_len: D2) -> Self
    where
        D1: core::fmt::Display,
        D2: core::fmt::Display,
    {
        TransferFormatError {
            pdu_err: pdu::Error::InvalidAttributeValueLength,
            message: format!(
                "Cannot split data for {}, data of length {} is not a \
                multiple of {}",
                name, data_len, chunk_size
            ),
        }
    }

    /// Create a `TransferFormatError` from an [`ErrorResponse`](pdu::ErrorResponse)
    pub fn error_response(err: &pdu::ErrorResponse) -> Self {
        TransferFormatError {
            pdu_err: err.error,
            message: format!("({})", err),
        }
    }

    pub fn incorrect_opcode(expected: pdu::PduOpcode, received: pdu::PduOpcode) -> Self {
        TransferFormatError {
            pdu_err: pdu::Error::InvalidPDU,
            message: format!("Expected ATT PDU opcode {:?}, received opcode {:?}", expected, received),
        }
    }
}

impl From<String> for TransferFormatError {
    /// Create a `TransferFormatError` with the given message
    ///
    /// The member `pdu_err` will be set to `InvalidPDU`
    fn from(message: String) -> Self {
        TransferFormatError {
            pdu_err: pdu::Error::InvalidPDU,
            message,
        }
    }
}

impl From<&'_ str> for TransferFormatError {
    /// Create a `TransferFormatError` with the given message
    ///
    /// The member `pdu` will be set to `InvalidPDU`
    fn from(msg: &'_ str) -> Self {
        TransferFormatError {
            pdu_err: pdu::Error::InvalidPDU,
            message: msg.to_string(),
        }
    }
}

impl From<pdu::Error> for TransferFormatError {
    /// Create a `TransferFormatError` with the input `err`
    ///
    /// The member message will just be set to 'unspecified'
    fn from(err: pdu::Error) -> Self {
        TransferFormatError {
            pdu_err: err,
            message: "unspecified".to_string(),
        }
    }
}

impl core::fmt::Debug for TransferFormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::fmt::Display for TransferFormatError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}, {}", self.pdu_err, self.message)
    }
}
/// ATT Protocol try from transmission format
///
/// Structures that implement `TransferFormatTryFrom` can be constructed from the attribute protocol raw
/// transmitted data.
pub trait TransferFormatTryFrom {
    /// Make Self from the attribute parameter
    ///
    /// This will attempt to take the passed byte slice and convert it into Self. The byte slice
    /// needs to only be the attribute parameter, it cannot contain either the attribute opcode
    /// or the attribute signature.
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized;
}

/// ATT Protocol Into transmission format
///
/// Structures that implement `TransferFormatInto` can be converted into the attribute protocol's
/// transmitted format.
///
/// The functions `len_of_into`, and `build_into_ret` must be implemented. The default
/// implementation of function `into` uses `len_of_into` and `build_into_ret` to generate data that
/// can be sent between a Server and Client.
///
/// Many things that implement `TransferFormatTryFrom` act like a container type for other types that
/// implement `TransferFormatTryFrom`. The combination of `len_of_into` and `build_into_ret` is used so
/// that only one buffer is created when `into` is called (usually only called on the
/// [`pdu`](crate::pdu) structures). Both `len_of_into` and `build_into_ret` act like pseudo
/// recursion around the containing generic type. If `TransferFormatTryFrom` is implemented for something
/// that is generic, these functions will be implemented based on the generic types implementation
/// of `TransferFormatTryFrom`.
pub trait TransferFormatInto {
    /// Get the length of the return of function `into`
    ///
    /// This is mainly used for `build_into` and things that call `build_into` to generate a vector
    /// for use as the parameter of `build_into`
    fn len_of_into(&self) -> usize;

    /// Build the return of into
    ///
    /// This takes a buffer that is used to construct the return of function `into`.
    ///
    /// # Panic
    /// This should panic if the size of slice referenced by `into_ret` is not the same as
    /// the return of `len_of_into`.
    fn build_into_ret(&self, into_ret: &mut [u8]);

    /// Convert Self into the transferred bytes
    fn into(&self) -> Vec<u8> {
        let len = self.len_of_into();

        let mut buff = Vec::with_capacity(len);

        buff.resize(len, 0);

        self.build_into_ret(&mut buff);

        buff
    }
}

/// Implements transfer format for the given
macro_rules! impl_transfer_format_for_number {
    ( $num: ty ) => {
        impl TransferFormatTryFrom for $num {
            fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
                if raw.len() == core::mem::size_of::<$num>() {
                    let mut bytes = <[u8; core::mem::size_of::<$num>()]>::default();

                    bytes.clone_from_slice(raw);

                    Ok(Self::from_le_bytes(bytes))
                } else {
                    Err(TransferFormatError::bad_size(
                        stringify!($num),
                        core::mem::size_of::<$num>(),
                        raw.len(),
                    ))
                }
            }
        }

        impl TransferFormatInto for $num {
            fn len_of_into(&self) -> usize {
                core::mem::size_of::<$num>()
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                into_ret.copy_from_slice(&self.to_le_bytes())
            }
        }

        impl_transfer_format_for_vec_of!($num);
    };
}

impl_transfer_format_for_number! {i8}
impl_transfer_format_for_number! {u8}
impl_transfer_format_for_number! {i16}
impl_transfer_format_for_number! {u16}
impl_transfer_format_for_number! {i32}
impl_transfer_format_for_number! {u32}
impl_transfer_format_for_number! {i64}
impl_transfer_format_for_number! {u64}
impl_transfer_format_for_number! {isize}
impl_transfer_format_for_number! {usize}
impl_transfer_format_for_number! {i128}
impl_transfer_format_for_number! {u128}
impl_transfer_format_for_number! {f32}
impl_transfer_format_for_number! {f64}

impl TransferFormatInto for bool {
    fn len_of_into(&self) -> usize {
        1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        if *self {
            into_ret[0] = 1
        } else {
            into_ret[0] = 0
        }
    }
}

impl TransferFormatTryFrom for bool {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() != 1 {
            return Err(TransferFormatError::bad_size("bool", 1, raw.len()));
        }
        match raw[0] {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(TransferFormatError::from("Invalid raw value for bool")),
        }
    }
}

impl TransferFormatTryFrom for String {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        String::from_utf8(raw.to_vec()).map_err(|e| TransferFormatError::from(format!("{:?}", e)))
    }
}

impl TransferFormatInto for str {
    fn len_of_into(&self) -> usize {
        self.bytes().len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(self.as_bytes())
    }
}

impl TransferFormatInto for String {
    fn len_of_into(&self) -> usize {
        self.as_str().len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.as_str().build_into_ret(into_ret)
    }
}

impl<T> TransferFormatInto for [T]
where
    T: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.iter().map(|t| t.len_of_into()).sum()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.iter().map(|t| (t.len_of_into(), t)).fold(0usize, |off, (len, t)| {
            let end = off + len;

            t.build_into_ret(&mut into_ret[off..end]);

            end
        });
    }
}

impl<T> TransferFormatInto for alloc::borrow::Cow<'_, T>
where
    T: TransferFormatInto + ToOwned + ?Sized,
{
    fn len_of_into(&self) -> usize {
        Borrow::<T>::borrow(self).len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        Borrow::<T>::borrow(self).build_into_ret(into_ret)
    }
}

impl<T> TransferFormatTryFrom for alloc::borrow::Cow<'_, T>
where
    T: ToOwned + ?Sized,
    T::Owned: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        Ok(alloc::borrow::Cow::Owned(TransferFormatTryFrom::try_from(raw)?))
    }
}

impl TransferFormatTryFrom for crate::Uuid {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        use core::mem::size_of;

        macro_rules! err_fmt {
            () => {
                "Failed to create UUID, {}"
            };
        }

        if raw.len() == size_of::<u16>() {
            TransferFormatTryFrom::try_from(raw)
                .and_then(|uuid_16: u16| Ok(crate::Uuid::from_u16(uuid_16)))
                .or_else(|e| Err(TransferFormatError::from(format!(err_fmt!(), e))))
        } else if raw.len() == size_of::<u128>() {
            TransferFormatTryFrom::try_from(raw)
                .and_then(|uuid_128: u128| Ok(crate::Uuid::from_u128(uuid_128)))
                .or_else(|e| Err(TransferFormatError::from(format!(err_fmt!(), e))))
        } else {
            Err(TransferFormatError::from(format!(
                err_fmt!(),
                "raw data is not 16 or 128 bits"
            )))
        }
    }
}

impl TransferFormatInto for crate::Uuid {
    fn len_of_into(&self) -> usize {
        if self.can_be_16_bit() {
            core::mem::size_of::<u16>()
        } else {
            core::mem::size_of::<u128>()
        }
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        match core::convert::TryInto::<u16>::try_into(*self) {
            Ok(raw) => raw.build_into_ret(&mut into_ret[..2]),

            Err(_) => <u128>::from(*self).build_into_ret(&mut into_ret[..16]),
        }
    }
}

impl<T> TransferFormatTryFrom for Box<T>
where
    T: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        <T as TransferFormatTryFrom>::try_from(raw).and_then(|v| Ok(Box::new(v)))
    }
}

impl<T> TransferFormatInto for Box<T>
where
    T: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        self.as_ref().len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.as_ref().build_into_ret(into_ret)
    }
}

impl TransferFormatTryFrom for Box<str> {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        core::str::from_utf8(raw)
            .and_then(|s| Ok(Box::<str>::from(s)))
            .or_else(|e| Err(TransferFormatError::from(format!("{}", e))))
    }
}

impl TransferFormatInto for Box<str> {
    fn len_of_into(&self) -> usize {
        self.len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(self.as_bytes())
    }
}

impl TransferFormatTryFrom for () {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 0 {
            Ok(())
        } else {
            Err(TransferFormatError::from("length must be zero for type '()'"))
        }
    }
}

impl TransferFormatInto for () {
    fn len_of_into(&self) -> usize {
        0
    }

    fn build_into_ret(&self, _: &mut [u8]) {}
}

impl TransferFormatInto for Box<dyn TransferFormatInto> {
    fn len_of_into(&self) -> usize {
        self.as_ref().len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.as_ref().build_into_ret(into_ret);
    }
}

impl<T> TransferFormatInto for &T
where
    T: TransferFormatInto + ?Sized,
{
    fn len_of_into(&self) -> usize {
        (*self).len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        (*self).build_into_ret(into_ret)
    }
}

/// Option implementation for TransferFormatTryFrom
///
/// # Note
/// * `Some(..)` is transferred with a byte followed by the transfer format of the contained data.
///   The first byte is a marker byte for Some however its value is undefined.
/// * `None` is transferred as an empty slice.
impl<T> TransferFormatTryFrom for Option<T>
where
    T: TransferFormatTryFrom,
{
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 0 {
            Ok(None)
        } else {
            Ok(Some(T::try_from(&raw[1..])?))
        }
    }
}

/// Option implementation for TransferFormatTryFrom
///
/// # Note
/// * `Some(..)` is transferred with a byte followed by the transfer format of the contained data.
///   The first byte is a marker byte for Some however its value is undefined.
/// * `None` is transferred as an empty slice.
impl<T> TransferFormatInto for Option<T>
where
    T: TransferFormatInto,
{
    fn len_of_into(&self) -> usize {
        match self {
            None => 0,
            Some(t) => t.len_of_into() + 1,
        }
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        match self {
            None => debug_assert_eq!(0, into_ret.len()),
            Some(t) => t.build_into_ret(&mut into_ret[1..]),
        }
    }
}

impl TransferFormatInto for bo_tie_util::BluetoothDeviceAddress {
    fn len_of_into(&self) -> usize {
        6
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&self.0)
    }
}

impl TransferFormatTryFrom for bo_tie_util::BluetoothDeviceAddress {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let mut address = [0u8; 6];

        if raw.len() != 6 {
            Err(TransferFormatError::bad_size("BluetoothDeviceAddress", 6, raw.len()))
        } else {
            address.copy_from_slice(raw);

            Ok(Self(address))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bo_tie_l2cap::{BasicFrameError, BasicInfoFrame, ConnectionChannelExt, L2capFragment, MinimumMtu};
    use bo_tie_util::buffer::de_vec::DeVec;
    use bo_tie_util::buffer::TryExtend;
    use std::sync::{Arc, Mutex};

    use std::{
        future::Future,
        pin::Pin,
        task::{Context, Poll, Waker},
    };

    struct TwoWayChannel {
        b1: Option<Vec<u8>>,
        w1: Option<Waker>,

        b2: Option<Vec<u8>>,
        w2: Option<Waker>,
    }

    struct DummySendFut<const DIRECTION: usize>(Arc<Mutex<TwoWayChannel>>, Vec<u8>);

    impl<const DIRECTION: usize> Future for DummySendFut<DIRECTION> {
        type Output = Result<(), bo_tie_l2cap::send_future::Error<usize>>;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();

            let mut gaurd = this.0.lock().expect("Failed to acquire lock");

            macro_rules! poll {
                ($b_field:ident, $w_field:ident) => {{
                    gaurd.$b_field = Some(core::mem::take(&mut this.1));

                    if let Some(waker) = gaurd.$w_field.take() {
                        waker.wake();
                    }

                    Poll::Ready(Ok(()))
                }};
            }

            match DIRECTION {
                1 => poll!(b1, w1),
                2 => poll!(b2, w2),
                _ => panic!("unknown channel direction"),
            }
        }
    }

    struct DummyRecvFut<const DIRECTION: usize>(Arc<Mutex<TwoWayChannel>>);

    impl<const DIRECTION: usize> Future for DummyRecvFut<DIRECTION> {
        type Output = Option<Result<L2capFragment<DeVec<u8>>, BasicFrameError<<DeVec<u8> as TryExtend<u8>>::Error>>>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();

            let mut gaurd = this.0.lock().expect("Failed to acquire lock");

            macro_rules! poll {
                ($b_field:ident, $w_field:ident) => {
                    if let Some(data) = gaurd.$b_field.take() {
                        let mut buffer = DeVec::<u8>::new();

                        buffer.try_extend(data).unwrap();

                        Poll::Ready(Some(Ok(L2capFragment::new(true, buffer))))
                    } else {
                        gaurd.$w_field = Some(cx.waker().clone());
                        Poll::Pending
                    }
                };
            }

            match DIRECTION {
                1 => poll!(b1, w1),
                2 => poll!(b2, w2),
                _ => panic!("unknown channel direction"),
            }
        }
    }

    /// Channel 1 sends to b1 and receives from b2
    struct Channel1 {
        two_way: Arc<Mutex<TwoWayChannel>>,
    }

    /// Channel 2 sends to b2 and receives from b1
    struct Channel2 {
        two_way: Arc<Mutex<TwoWayChannel>>,
    }

    impl TwoWayChannel {
        fn new() -> (Channel1, Channel2) {
            let tc = TwoWayChannel {
                b1: None,
                w1: None,
                b2: None,
                w2: None,
            };

            let am_tc = Arc::new(Mutex::new(tc));

            let c1 = Channel1 { two_way: am_tc.clone() };
            let c2 = Channel2 { two_way: am_tc.clone() };

            (c1, c2)
        }
    }

    impl bo_tie_l2cap::ConnectionChannel for Channel1 {
        type SendBuffer = DeVec<u8>;
        type SendFut<'a> = DummySendFut<1>;
        type SendFutErr = usize;
        type RecvBuffer = DeVec<u8>;
        type RecvFut<'a> = DummyRecvFut<2>;

        fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
            DummySendFut(self.two_way.clone(), data.try_into_packet().unwrap())
        }

        fn set_mtu(&mut self, _: u16) {}

        fn get_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn max_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn min_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn receive(&mut self) -> Self::RecvFut<'_> {
            DummyRecvFut(self.two_way.clone())
        }
    }

    impl bo_tie_l2cap::ConnectionChannel for Channel2 {
        type SendBuffer = DeVec<u8>;
        type SendFut<'a> = DummySendFut<2>;
        type SendFutErr = usize;
        type RecvBuffer = DeVec<u8>;
        type RecvFut<'a> = DummyRecvFut<1>;

        fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
            DummySendFut(self.two_way.clone(), data.try_into_packet().unwrap())
        }

        fn set_mtu(&mut self, _: u16) {}

        fn get_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn max_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn min_mtu(&self) -> usize {
            bo_tie_l2cap::LeU::MIN_MTU
        }

        fn receive(&mut self) -> Self::RecvFut<'_> {
            DummyRecvFut(self.two_way.clone())
        }
    }

    #[tokio::test]
    async fn test_att_connection() {
        use super::client::ResponseProcessor;
        use bo_tie_host_util::Uuid;
        use std::sync::{atomic, Arc};

        const UUID_1: Uuid = Uuid::from_u16(1);
        const UUID_2: Uuid = Uuid::from_u16(2);
        const UUID_3: Uuid = Uuid::from_u16(3);

        let test_val_1 = 33usize;
        let test_val_2 = 64u64;
        let test_val_3 = -11i8;

        let kill_opcode = 0xFFu8;

        let (mut c1, mut c2) = TwoWayChannel::new();

        let thread_panicked = Arc::new(atomic::AtomicBool::new(false));

        let thread_panicked_clone = thread_panicked.clone();

        // temporary util a better error is produced by the compiler. See
        // rust issue https://github.com/rust-lang/rust/issues/102211 for
        // what I think is the issue of this.
        struct ForceSafeSend<T>(T);

        unsafe impl<T> Send for ForceSafeSend<T> {}

        impl<T: std::future::Future> std::future::Future for ForceSafeSend<T> {
            type Output = T::Output;

            fn poll(self: std::pin::Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
                unsafe { self.map_unchecked_mut(|this| &mut this.0).poll(cx) }
            }
        }

        let task = async move {
            use AttributePermissions::*;

            let mut server = server::Server::new(None, server::NoQueuedWrites);

            let attribute_0 = Attribute::new(
                UUID_1,
                [Read(AttributeRestriction::None), Write(AttributeRestriction::None)].to_vec(),
                0usize,
            );

            let attribute_1 = Attribute::new(
                UUID_2,
                [Read(AttributeRestriction::None), Write(AttributeRestriction::None)].to_vec(),
                0u64,
            );

            let attribute_3 = Attribute::new(
                UUID_3,
                [Read(AttributeRestriction::None), Write(AttributeRestriction::None)].to_vec(),
                0i8,
            );

            server.push(attribute_0); // has handle value of 1
            server.push(attribute_1); // has handle value of 2
            server.push(attribute_3); // has handle value of 3

            let client_permissions: &[AttributePermissions] =
                &[Read(AttributeRestriction::None), Write(AttributeRestriction::None)];

            server.give_permissions_to_client(client_permissions);

            if let Err(e) = 'server_loop: loop {
                use std::convert::TryFrom;

                match c2.receive_b_frame().await {
                    Ok(l2cap_data_vec) => {
                        for l2cap_pdu in l2cap_data_vec {
                            match server.process_acl_data(&mut c2, &l2cap_pdu).await {
                                Err(ConnectionError::AttError(super::Error::UnknownOpcode(op)))
                                    if op == kill_opcode =>
                                {
                                    break 'server_loop Ok(())
                                }
                                Err(e) => {
                                    break 'server_loop Err(format!(
                                        "Pdu error: {:?}, att pdu op: {:?}",
                                        e,
                                        client::ClientPduName::try_from(l2cap_pdu.get_payload()[0])
                                    ))
                                }
                                _ => (),
                            }
                        }
                    }
                    Err(e) => break 'server_loop Err(format!("Future Receiver Error: {:?}", e)),
                }
            } {
                thread_panicked_clone.store(true, atomic::Ordering::Relaxed);
                panic!("{}", e);
            }
        };

        let mut join_handle = tokio::spawn(ForceSafeSend(task));

        /// Creates a block-on implementation
        ///
        /// # Panics In Returned Closure
        /// Input `t` of 'make_block_on' cannot refer to a `None` *for the lifetime of the returned
        /// closure*.
        async fn task_timeout<'t, F, T>(
            tp: Arc<atomic::AtomicBool>,
            t: &mut tokio::task::JoinHandle<T>,
            f: F,
            err: &str,
        ) -> Result<F::Output, String>
        where
            F: std::future::Future,
        {
            let tf = tokio::time::timeout(std::time::Duration::from_secs(1), f);

            match tf.await {
                Err(timeout_err) => {
                    if tp.load(atomic::Ordering::Relaxed) {
                        Err(format!(
                            "{}, server_error: {:?}",
                            timeout_err,
                            t.await
                                .map(|_| "unexpected early exit")
                                .map_err(|join_error| if join_error.is_panic() {
                                    *join_error.into_panic().downcast::<String>().unwrap()
                                } else {
                                    "task canceled".to_string()
                                })
                                .unwrap_err()
                        ))
                    } else {
                        Err(err.to_string())
                    }
                }
                Ok(output) => Ok(output),
            }
        }

        let le_client_setup = client::ConnectClient::initiate(&c1, 512).await.unwrap();

        let mtu_rsp = task_timeout(
            thread_panicked.clone(),
            &mut join_handle,
            c1.receive_b_frame(),
            "Connect timed out",
        )
        .await
        .unwrap()
        .expect("connect receiver");

        let client = le_client_setup
            .create_client(&mut c1, mtu_rsp.first().unwrap())
            .await
            .unwrap();

        // writing to handle 1
        client
            .write_request(&mut c1, 1, test_val_1)
            .await
            .unwrap()
            .process_response(
                task_timeout(
                    thread_panicked.clone(),
                    &mut join_handle,
                    c1.receive_b_frame(),
                    "write handle 1 timed out",
                )
                .await
                .unwrap()
                .expect("w1 receiver")
                .first()
                .unwrap(),
            )
            .expect("w1 response");

        // writing to handle 2
        client
            .write_request(&mut c1, 2, test_val_2)
            .await
            .unwrap()
            .process_response(
                task_timeout(
                    thread_panicked.clone(),
                    &mut join_handle,
                    c1.receive_b_frame(),
                    "write handle 2 timed out",
                )
                .await
                .unwrap()
                .expect("w2 receiver")
                .first()
                .unwrap(),
            )
            .expect("w2 response");

        // writing to handle 3
        client
            .write_request(&mut c1, 3, test_val_3)
            .await
            .unwrap()
            .process_response(
                task_timeout(
                    thread_panicked.clone(),
                    &mut join_handle,
                    c1.receive_b_frame(),
                    "write handle 3 timed out",
                )
                .await
                .unwrap()
                .expect("w3 receiver")
                .first()
                .unwrap(),
            )
            .expect("w3 response");

        // reading handle 1
        let read_val_1 = client
            .read_request(&mut c1, 1)
            .await
            .unwrap()
            .process_response(
                task_timeout(
                    thread_panicked.clone(),
                    &mut join_handle,
                    c1.receive_b_frame(),
                    "read handle 1 timed out",
                )
                .await
                .unwrap()
                .expect("r1 receiver")
                .first()
                .unwrap(),
            )
            .expect("r1 response");

        let read_val_2 = client
            .read_request(&mut c1, 2)
            .await
            .unwrap()
            .process_response(
                task_timeout(
                    thread_panicked.clone(),
                    &mut join_handle,
                    c1.receive_b_frame(),
                    "read handle 2 timed out",
                )
                .await
                .unwrap()
                .expect("r2 receiver")
                .first()
                .unwrap(),
            )
            .expect("r2 response");

        let read_val_3 = client
            .read_request(&mut c1, 3)
            .await
            .unwrap()
            .process_response(
                task_timeout(
                    thread_panicked.clone(),
                    &mut join_handle,
                    c1.receive_b_frame(),
                    "read handle 3 timed out",
                )
                .await
                .unwrap()
                .expect("r3 receiver")
                .first()
                .unwrap(),
            )
            .expect("r3 response");

        client
            .custom_command(&mut c1, pdu::Pdu::new(kill_opcode.into(), 0u8))
            .await
            .expect("Failed to send kill opcode");

        // Check that the send values equal the read values
        assert_eq!(test_val_1, read_val_1);
        assert_eq!(test_val_2, read_val_2);
        assert_eq!(test_val_3, read_val_3);

        join_handle
            .await
            .map_err(|e| {
                if e.is_panic() {
                    format!("Thread panicked: {}", e.into_panic().downcast_ref::<String>().unwrap())
                } else {
                    "thread was cancelled".to_string()
                }
            })
            .unwrap()
    }
}
