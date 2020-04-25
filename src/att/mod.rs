//! The Attribute Protocol
//!
//! The Attribute Protocol is used to expose the attributes of a device through Bluetooth.
//!
//! The Attribute Protocol is the base for the
//! `[Generic Attribute Profile](../gatt/index.html)
//!
//! This is implementation of the Attribute Protocol as defined in the Bluetooth Specification
//! (version 5.0), Vol. 3, Part F.
//!
//! # Attribute Protocol Permissions
//! When an attribute is created it is given permissions to *to determine* access of if by a
//! client. Permission are *labels for access* to operations, of barriers granting entry for the
//! client. No permission has any relation with any other permission, and no permission is
//! inherently given to an attribute or the user by another permission. It is the operations of the
//! Attribute Protocol or a higher layer protocol that determine what permissions are required to
//! perform said operation.
//!
//! Attributes can only be written to or read from. Permissions restrict reads and writes for
//! attribute protocol operations performed under open access, encryption, authentication, and
//! authorization. Different operations require different restrictions, but most of the implemented
//! Attribute Protocol operations check the permissions of an attribute before performing the
//! operation. Most of these operations require that the attribute either be at least readable or
//! writeable, but will check if those reads or writes also require either encryption,
//! authentication, or authorization.
//!
//! Attribute permissions do not posses hierarchy or hereditary characteristics between one another.
//! This can lead to seeming odd cases where it would seem that because an attribute was given
//! a permissions it should have another, but the server will report an access error. If an
//! attribute was only given the permission `Read(None)`, the server will only read the attribute to
//! the client when the server grants the client the same permission. If the client had any other
//! permissions except for `Read(None)`, such as `Read(Encryption(Bits128))`, the server would not
//! read the attribute and would instead return an error to the client.
//!
//! ## Client Granted Permissions
//! The server matches the required permissions of an operation against the permissions of the
//! client. The server does not determine the permissions of the client, this is done by 'giving'
//! permission to the client through either your application or some higher layer protocol. When a
//! client requests an operation to be performed for specified attributes, the server will check the
//! permissions of the attribute and the permissions of the client. The client will need the
//! permissions required by the operation matched against the permissions of the attribute(s). If a
//! permission check fails, then the server will return an error giving the reason for the failure.
//!
//! Operations will generally check a number of permissions (usually every type of Read or Write)
//! against the permissions of the requested attribute and those given to the client. If any of the
//! permissions to check for are in both the attribute and client, the operation is successfully
//! performed for the client.
//!
//! ## Permission Errors
//! If an operation cannot be performed because the client does not have the permission to access
//! an attribute, an error is returned to the client describing the permission problem. However,
//! it is often the case there are multiple types of permissions that a client can have to access
//! the attribute, but only one of the errors can be described with the error PDU sent from the
//! server to the client.

use alloc::{
    boxed::Box,
    format,
    string::String,
    vec::Vec,
};

pub mod pdu;
pub mod client;
pub mod server;

use crate::l2cap;

pub const L2CAP_CHANNEL_ID: l2cap::ChannelIdentifier =
    l2cap::ChannelIdentifier::LE(l2cap::LeUserChannelIdentifier::AttributeProtocol);

/// The minimum number of data bytes in an attribute protocol based packet for bluetooth le
pub const MIN_ATT_MTU_LE: u16 = 23;

/// The minimum number of data bytes in an attribute protocol based packet for bluetooth BR/EDR
pub const MIN_ATT_MTU_BR_EDR: u16 = 48;

/// Advanced Encryption Standard (AES) key sizes
#[derive(Clone,Copy,Debug,PartialEq,Eq)]
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
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum AttributeRestriction {
    None,
    Encryption(EncryptionKeySize),
    Authentication,
    Authorization,
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum AttributePermissions {
    /// Readable Access
    Read(AttributeRestriction),
    /// Writeable Access
    Write(AttributeRestriction),
}

pub const FULL_READ_PERMISSIONS: &'static [AttributePermissions] = &[
    AttributePermissions::Read(AttributeRestriction::None),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits128)),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits192)),
    AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    AttributePermissions::Read(AttributeRestriction::Authorization),
    AttributePermissions::Read(AttributeRestriction::Authentication),
];

pub const FULL_WRITE_PERMISSIONS: &'static [AttributePermissions] = &[
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
#[derive(Clone,Debug,PartialEq,Eq)]
pub struct Attribute<V> {

    /// The Attribute type
    ty: crate::UUID,

    /// The attribute handle
    ///
    /// The handle is like an address to an attribute. Its how a client refers to and accesses
    /// a specific attribute on a server.
    handle: Option<u16>,

    /// Access Permissions
    permissions: Vec<AttributePermissions>,

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
    pub fn new( attribute_type: crate::UUID, mut permissions: Vec<AttributePermissions>, value: V)
    -> Self
    {
        permissions.sort();
        permissions.dedup();

        Attribute {
            ty: attribute_type,
            handle: None,
            permissions,
            value,
        }
    }

    pub fn get_uuid(&self) -> &crate::UUID {
        &self.ty
    }

    pub fn get_permissions(&self) -> &[AttributePermissions] {
        &self.permissions
    }

    pub fn get_value(&self) -> &V {
        &self.value
    }

    /// Get the handle
    ///
    /// This will only return a handle if the attribute was retrieved from an attribute server. A
    /// free attribute will not have an associated handle.
    pub fn get_handle(&self) -> Option<u16> {
        self.handle.clone()
    }
}

pub enum Error {
    Other(&'static str),
    /// Returned when there is no connection to the bluetooth controller
    NotConnected,
    /// A PDU exceeds the MTU set between the client and server
    MtuExceeded,
    /// The desired MTU is smaller then the minimum value
    TooSmallMtu,
    /// An Error PDU is received
    Pdu(pdu::Pdu<pdu::ErrorAttributeParameter>),
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
    /// An `UnknonwOpcode` is for opcodes that are not recognized by the ATT protocol. They may
    /// be valid for a higher layer protocol.
    UnknownOpcode(u8),
    /// Custom opcode is already used by the Att protocol
    AttUsedOpcode(u8),
    /// Incorrect Channel Identifier
    IncorrectChannelId,
    /// Pdu Error
    PduError(pdu::Error)
}

impl core::fmt::Display for Error{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Error::Other(r) => write!(f, "{}", r),
            Error::NotConnected => write!( f, "Not Connected" ),
            Error::MtuExceeded => write!( f, "Maximum Transmission Unit exceeded" ),
            Error::TooSmallMtu => write!( f, "Minimum Transmission Unit larger then specified" ),
            Error::Pdu(pdu) => write!( f, "Received Error PDU: {}", pdu ),
            Error::UnexpectedPdu(val) => write!( f, "{}", val ),
            Error::TransferFormatTryFrom(t_e) => write!( f, "{}", t_e ),
            Error::Empty => write!( f, "Received an empty PDU" ),
            Error::UnknownOpcode(op) =>
                write!( f, "Opcode not known to the attribute protocol ({:#x})", op),
            Error::AttUsedOpcode(op) =>
                write!(f, "Opcode {:#x} is already used by the Attribute Protocol", op),
            Error::IncorrectChannelId =>
                write!(f, "The channel identifier of the ACL Data does not match the assigned \
                    number for the Attribute Protocol"),
            Error::PduError(err) =>
                write!(f, "Attribute PDU error '{}'", err),
        }
    }
}

impl core::fmt::Debug for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(self,f)
    }
}

impl From<pdu::Pdu<pdu::ErrorAttributeParameter>> for Error {
    fn from(err: pdu::Pdu<pdu::ErrorAttributeParameter>) -> Error {
        Error::Pdu(err)
    }
}

impl From<TransferFormatError> for Error {
    fn from(err: TransferFormatError) -> Self {
        Error::TransferFormatTryFrom(err)
    }
}

pub struct TransferFormatError {
    pub pdu_err: pdu::Error,
    pub message: String,
}

impl TransferFormatError {

    /// Create a `TransferFormatError` for when the processed bytes does not match the expected
    /// number of bytes
    pub(crate) fn bad_size<D1, D2>(name: &'static str, expected_len: D1, incorrect_len: D2) -> Self
    where D1: core::fmt::Display,
          D2: core::fmt::Display,
    {
        TransferFormatError::from( format!("Expected a size of {} bytes for {}, data length is {}",
            expected_len, name, incorrect_len)
        )
    }

    pub(crate) fn bad_min_size<D1, D2>(name: &'static str, min_size: D1, data_len: D2) -> Self
    where D1: core::fmt::Display,
          D2: core::fmt::Display,
    {
        TransferFormatError::from( format!("Expected a minimum size of {} bytes for {}, data \
            length is {}", min_size, name, data_len) )
    }
    /// Create a `TransferFormattedError` for when
    /// `[chunks_exact]`(https://doc.rust-lang.org/nightly/std/primitive.slice.html#method.chunks_exact)
    /// created an `ChunksExact` object that contained a remainder that isn't zero
    pub(crate) fn bad_exact_chunks<D1, D2>(name: &'static str, chunk_size: D1, data_len: D2) -> Self
    where D1: core::fmt::Display,
          D2: core::fmt::Display,
    {
        TransferFormatError::from( format!("Cannot split data for {}, data of length {} is not a \
             multiple of {}", name, data_len, chunk_size))
    }
}

impl From<String> for TransferFormatError {
    /// Create a `TransferFormatError` with the given message
    ///
    /// The member `pdu_err` will be set to `InvalidPDU`
    fn from(message: String) -> Self {
        TransferFormatError { pdu_err: pdu::Error::InvalidPDU, message }
    }
}

impl From<&'_ str> for TransferFormatError {
    /// Create a `TransferFormatError` with the given message
    ///
    /// The member `pdu` will be set to `InvalidPDU`
    fn from(msg: &'_ str) -> Self {
        TransferFormatError { pdu_err: pdu::Error::InvalidPDU, message: msg.into() }
    }
}

impl From<pdu::Error> for TransferFormatError {
    /// Create a `TransferFormatError` with the input `err`
    ///
    /// The member message will just be set to 'unspecified'
    fn from(err: pdu::Error) -> Self {
        TransferFormatError { pdu_err: err, message: "unspecified".into() }
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
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> where Self: Sized;
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
/// [`pdu`](crate::att::pdu) structures). Both `len_of_into` and `build_into_ret` act like pseudo
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

        let mut buff = Vec::with_capacity( len );

        buff.resize(len, 0);

        self.build_into_ret(&mut buff);

        buff
    }
}

macro_rules! impl_transfer_format_for_number {
    ( $num: ty ) => {
        impl TransferFormatTryFrom for $num {
            fn try_from( raw: &[u8]) -> Result<Self, TransferFormatError> {
                if raw.len() == core::mem::size_of::<$num>() {
                    let mut bytes = <[u8;core::mem::size_of::<$num>()]>::default();

                    bytes.clone_from_slice(raw);

                    Ok(Self::from_le_bytes(bytes))
                } else {
                    Err(TransferFormatError::bad_size(stringify!($num), core::mem::size_of::<$num>(), raw.len()))
                }
            }
        }

        impl TransferFormatInto for $num {

            fn len_of_into(&self) -> usize { core::mem::size_of::<$num>() }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                into_ret.copy_from_slice( &self.to_le_bytes() )
            }
        }

        impl TransferFormatCollectible for $num {
            fn chunk(raw: &[u8]) -> Option<Result<(Self, &[u8]), TransferFormatError>> {
                if raw.len() == 0 { None }
                else if raw.len() > core::mem::size_of::<$num>() {
                    let self_ret  = TransferFormatTryFrom::try_from(&raw[..core::mem::size_of::<$num>()]);
                    let slice_ret = &raw[core::mem::size_of::<$num>()..];

                    Some( self_ret.map(|s| (s, slice_ret) ) )
                } else {
                    Some(Err(TransferFormatError::bad_size(stringify!($num), core::mem::size_of::<$num>(), raw.len())))
                }
            }
        }
    }
}

impl_transfer_format_for_number!{i8}
impl_transfer_format_for_number!{u8}
impl_transfer_format_for_number!{i16}
impl_transfer_format_for_number!{u16}
impl_transfer_format_for_number!{i32}
impl_transfer_format_for_number!{u32}
impl_transfer_format_for_number!{i64}
impl_transfer_format_for_number!{u64}
impl_transfer_format_for_number!{isize}
impl_transfer_format_for_number!{usize}
impl_transfer_format_for_number!{i128}
impl_transfer_format_for_number!{u128}

impl TransferFormatTryFrom for alloc::string::String {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        alloc::string::String::from_utf8(raw.to_vec())
            .map_err(|e| TransferFormatError::from(format!("{:?}", e)))
    }
}

impl TransferFormatInto for alloc::string::String {
    fn len_of_into(&self) -> usize { self.len() }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(self.as_bytes())
    }
}

impl TransferFormatTryFrom for crate::UUID {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        use core::mem::size_of;

        macro_rules! err_fmt { () =>  { "Failed to create UUID, {}" } }

        if raw.len() == size_of::<u16>() {

            TransferFormatTryFrom::try_from(raw)
            .and_then( |uuid_16: u16| Ok(crate::UUID::from_u16(uuid_16)) )
            .or_else( |e| Err(TransferFormatError::from(format!(err_fmt!(),e))) )

        } else if raw.len() == size_of::<u128>() {

            TransferFormatTryFrom::try_from(raw)
            .and_then( |uuid_128: u128| Ok(crate::UUID::from_u128(uuid_128)) )
            .or_else( |e| Err(TransferFormatError::from(format!(err_fmt!(),e))) )

        } else {
            Err(TransferFormatError::from(format!(err_fmt!(), "raw data is not 16 or 128 bits")))
        }
    }
}

impl TransferFormatInto for crate::UUID {

    fn len_of_into(&self) -> usize {
        if self.is_16_bit() {
            core::mem::size_of::<u16>()
        } else {
            core::mem::size_of::<u128>()
        }
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        match core::convert::TryInto::<u16>::try_into( *self ) {
            Ok(raw) => raw.build_into_ret(&mut into_ret[..2]),

            Err(_) => <u128>::from(*self).build_into_ret(&mut into_ret[..16]),
        }
    }
}

impl<T> TransferFormatTryFrom for Box<[T]> where T: TransferFormatTryFrom + TransferFormatCollectible {

    fn try_from(raw: &[u8] ) -> Result<Self, TransferFormatError> {
        <alloc::vec::Vec<T> as TransferFormatTryFrom>::try_from(raw).map(|v| v.into_boxed_slice() )
    }
}

impl<T> TransferFormatInto for Box<[T]> where T: TransferFormatInto {

    fn len_of_into(&self) -> usize {
        self.iter().fold(0usize, |v, t| v + t.len_of_into() )
    }

    fn build_into_ret(&self, into_ret: &mut [u8] ){
        let mut start = 0;

        self.iter().for_each(|t| {
            t.build_into_ret(&mut into_ret[start..t.len_of_into()]);

            start += t.len_of_into();
        } )
    }
}

impl<T> TransferFormatTryFrom for Box<T> where T: TransferFormatTryFrom {
    fn try_from(raw: &[u8] ) -> Result<Self, TransferFormatError> {
        <T as TransferFormatTryFrom>::try_from(raw).and_then( |v| Ok(Box::new(v)) )
    }
}

impl<T> TransferFormatInto for Box<T> where T: TransferFormatInto {

    fn len_of_into(&self) -> usize {
        self.as_ref().len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.as_ref().build_into_ret(into_ret)
    }
}

impl TransferFormatTryFrom for Box<str> {
    fn try_from(raw: &[u8] ) -> Result<Self, TransferFormatError> {
        core::str::from_utf8(raw)
            .and_then( |s| Ok( s.into() ) )
            .or_else( |e| {
                Err( TransferFormatError::from(format!("{}", e)))
            })
    }
}

impl TransferFormatInto for Box<str> {

    fn len_of_into(&self) -> usize {
        self.len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8] ) {
        into_ret.copy_from_slice( self.as_bytes() )
    }
}

impl TransferFormatTryFrom for () {

    fn try_from(raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() == 0 {
            Ok(())
        } else {
            Err(TransferFormatError::from("length must be zero for type '()'"))
        }
    }
}

impl TransferFormatInto for () {

    fn len_of_into(&self) -> usize { 0 }

    fn build_into_ret(&self, _: &mut [u8] ) {}
}

impl TransferFormatInto for Box<dyn TransferFormatInto> {

    fn len_of_into(&self) -> usize { self.as_ref().len_of_into() }

    fn build_into_ret(&self, into_ret: &mut [u8] ) {
        self.as_ref().build_into_ret(into_ret);
    }
}

impl TransferFormatInto for &dyn TransferFormatInto {

    fn len_of_into(&self) -> usize { unimplemented!() }

    fn build_into_ret(&self, _: &mut [u8] ) { unimplemented!() }
}

impl<T> TransferFormatTryFrom for Vec<T> where T: TransferFormatTryFrom + TransferFormatCollectible {

    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        T::chunks(raw).try_fold( Vec::new(), |mut v,r| {
            v.push(r?);
            Ok(v)
        })
    }
}

impl<T> TransferFormatInto for Vec<T> where T: TransferFormatInto {

    fn len_of_into(&self) -> usize {
        self.iter().fold(0usize, |v, t| v + t.len_of_into() )
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {

        let mut start = 0;

        self.iter().for_each(|t| {
            t.build_into_ret(&mut into_ret[start..t.len_of_into()]);

            start += t.len_of_into();
        } )
    }
}

/// Transfer Format collections
///
/// Collections can have multiple `?Sized` entries and as a result it can be unknown how many raw
/// interface bytes are required to convert into a data type. This trait provides methods to help
/// `TransferInterface` implementations on collections so they can translate raw interface data
/// into a complete collection
pub trait TransferFormatCollectible {

    /// Cut, translate to `Self`, and return the rest of a full slice of interface data
    ///
    /// Chunk should be implemented to take a slice of any number of bytes and try to translate the
    /// raw data, starting from the first byte, to as many bytes required of `raw`. If the data can
    /// be successfully transformed into `Self` then `Self` is returned along with the remaining
    /// untranslated bytes. If anything goes wrong, say the data in the wrong format or `raw` is
    /// not large enough, then an error is returned.
    ///
    /// For flexibility, the return is optional. `None` should be returned if there is no error
    /// trying to convert the raw data into `Self` but `Self` cannot be created from the raw
    /// data. The typical return of `None` occurs when input `raw` is a reference to an empty slice.
    fn chunk(raw: &[u8]) -> Option<Result<(Self, &[u8]), TransferFormatError>> where Self: Sized;

    /// Chunk the data, iteratively, using function `chunk`
    ///
    /// Unfortunately, because the size of `Self` can be `?Sized`, the return `TransferFormatChunks`
    /// does not have a function to give the remaining bytes.
    fn chunks(raw: &[u8]) -> TransferFormatChunks<'_,Self> where Self: Sized{
        TransferFormatChunks(raw, core::marker::PhantomData)
    }
}

pub struct TransferFormatChunks<'a,T>(&'a [u8], core::marker::PhantomData<T>);

impl<T> core::iter::Iterator for TransferFormatChunks<'_, T> where T: TransferFormatCollectible {
    type Item = Result<T, TransferFormatError>;

    fn next(&mut self) -> Option<Self::Item> {
        T::chunk(self.0).map(|rslt| rslt.map(|(ret, self_0)| { self.0 = self_0; ret }))
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use std::sync::{Arc, Mutex};
    use std::task::Waker;

    struct TwoWayChannel {
        b1: Option<Vec<u8>>,
        w1: Option<Waker>,

        b2: Option<Vec<u8>>,
        w2: Option<Waker>,
    }

    /// Channel 1 sends to b1 and receives from b2
    struct Channel1 {
        two_way: Arc<Mutex<TwoWayChannel>>
    }

    /// Channel 2 sends to b2 and receives from b1
    struct Channel2 {
        two_way: Arc<Mutex<TwoWayChannel>>
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

    impl l2cap::ConnectionChannel for Channel1 {

        fn send<Pdu>(&self, data: Pdu) where Pdu: Into<crate::l2cap::L2capPdu>{
            let mut gaurd = self.two_way.lock().expect("Failed to acquire lock");

            gaurd.b1 = Some(data.into().into_data());

            if let Some(waker) = gaurd.w1.take() {
                waker.wake();
            }
        }

        fn receive(&self, waker: &Waker) -> Option<Vec<crate::l2cap::AclDataFragment>> {
            use crate::l2cap::AclDataFragment;

            let mut gaurd = self.two_way.lock().expect("Failed to acquire lock");

            if let Some(data) = gaurd.b2.take() {
                Some(vec![AclDataFragment::new(true, data)])
            } else {
                gaurd.w2 = Some(waker.clone());
                None
            }
        }
    }

    impl l2cap::ConnectionChannel for Channel2 {

        fn send<Pdu>(&self, data: Pdu) where Pdu: Into<crate::l2cap::L2capPdu>{
            let mut gaurd = self.two_way.lock().expect("Failed to acquire lock");

            gaurd.b2 = Some(data.into().into_data());

            if let Some(waker) = gaurd.w2.take() {
                waker.wake();
            }
        }

        fn receive(&self, waker: &Waker) -> Option<Vec<crate::l2cap::AclDataFragment>> {
            use crate::l2cap::AclDataFragment;

            let mut gaurd = self.two_way.lock().expect("Failed to acquire lock");

            if let Some(data) = gaurd.b1.take() {
                Some(vec![AclDataFragment::new(true, data)])
            } else {
                gaurd.w1 = Some(waker.clone());
                None
            }
        }
    }

    #[test]
    fn test_att_connection() {
        use std::thread;
        use crate::{
            l2cap::ConnectionChannel,
            UUID
        };

        const UUID_1: UUID = UUID::from_u16(1);
        const UUID_2: UUID = UUID::from_u16(2);
        const UUID_3: UUID = UUID::from_u16(3);

        let test_val_1 = 33usize;
        let test_val_2 = 64u64;
        let test_val_3 = -11i8;

        let kill_opcode = 0xFFu8;

        let (c1,c2) = TwoWayChannel::new();

        fn block_on<F: std::future::Future + std::marker::Unpin>(f: F, timeout_err: &str) -> F::Output{

            let tf = async_timer::Timed::platform_new(f, std::time::Duration::from_secs(1));

            futures::executor::block_on(tf).map_err(|_| timeout_err).unwrap()
        }

        let t = thread::spawn( move || {
            use AttributePermissions::*;

            let mut server = server::Server::new( &c2, 256, None );

            let attribute_0 = Attribute::new(
                UUID_1,
                [Read(AttributeRestriction::None), Write(AttributeRestriction::None)].to_vec(),
                0usize
            );

            let attribute_1 = Attribute::new(
                UUID_2,
                [Read(AttributeRestriction::None), Write(AttributeRestriction::None)].to_vec(),
                0u64
            );

            let attribute_3 = Attribute::new(
                UUID_3,
                [Read(AttributeRestriction::None), Write(AttributeRestriction::None)].to_vec(),
                0i8
            );

            server.push(attribute_0); // has handle value of 1
            server.push(attribute_1); // has handle value of 2
            server.push(attribute_3); // has handle value of 3

            if let Err(e) = 'server_loop: loop {

                match futures::executor::block_on(c2.future_receiver()) {
                    Ok(l2cap_data_vec) => for l2cap_pdu in l2cap_data_vec {

                        match server.process_acl_data(&l2cap_pdu) {
                            Err(super::Error::UnknownOpcode(op)) if op == kill_opcode =>
                                break 'server_loop Ok(()),
                            Err(e) =>
                                break 'server_loop Err(
                                    format!("Pdu error: {:?}, att pdu op: {}", e, l2cap_pdu.get_payload()[0])),
                            _ => (),
                        }
                    },
                    Err(e) => break 'server_loop Err(format!("Future Receiver Error: {:?}", e)),
                }
            } {
                panic!("{}", e);
            }
        });

        let client = client::Client::connect(&c1, 512)
            .process_response(block_on(c1.future_receiver(), "Connect timed out")
                    .expect("connect receiver").first().unwrap()
            )
            .expect("connect response");

        // writing to handle 1
        client.write_request(1, test_val_1).unwrap()
            .process_response( block_on(c1.future_receiver(), "write handle 1 timed out")
                .expect("w1 receiver")
                .first()
                .unwrap() )
            .expect("w1 response");

        // writing to handle 2
        client.write_request(2, test_val_2).unwrap()
            .process_response( block_on(c1.future_receiver(), "write handle 2 timed out")
                .expect("w2 receiver")
                .first()
                .unwrap() )
            .expect("w2 response");

        // writing to handle 3
        client.write_request(3, test_val_3).unwrap()
            .process_response( block_on(c1.future_receiver(), "write handle 3 timed out")
                .expect("w3 receiver")
                .first()
                .unwrap() )
            .expect("w3 response");

        // reading handle 1
        let read_val_1 = client.read_request(1).unwrap()
            .process_response( block_on(c1.future_receiver(), "read handle 1 timed out")
                .expect("r1 receiver")
                .first()
                .unwrap() )
            .expect("r1 response");

        let read_val_2 = client.read_request(2).unwrap()
            .process_response( block_on(c1.future_receiver(), "read handle 2 timed out")
                .expect("r2 receiver")
                .first()
                .unwrap() )
            .expect("r2 response");

        let read_val_3 = client.read_request(3).unwrap()
            .process_response( block_on(c1.future_receiver(), "read handle 3 timed out")
                .expect("r3 receiver")
                .first()
                .unwrap() )
            .expect("r3 response");

        client.custom_command( pdu::Pdu::new(kill_opcode.into(), 0u8, None) )
            .expect("Failed to send kill opcode");

        // Check that the send values equal the read values
        assert_eq!(test_val_1, read_val_1);
        assert_eq!(test_val_2, read_val_2);
        assert_eq!(test_val_3, read_val_3);

        t.join()
            .map_err(|e| format!("Thread Failed to join: {}", e.downcast_ref::<String>().unwrap()) )
            .unwrap();
    }
}
