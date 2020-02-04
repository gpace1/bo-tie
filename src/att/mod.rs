//! The Attribute Protocol
//!
//! The Attribute Protocol is used to expose the attributes of a device through Bluetooth.
//!
//! The Attribute Protocol is the base for the
//! `[Generic Attribute Profile](../gatt/index.html)
//!
//! This is implementation of the Attribute Protocol as defined in the Bluetooth Specification
//! (version 5.0), Vol. 3, Part F.

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

/// Avanced Encryption Standard (AES) key sizes
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

/// Attribute premission restriction
///
/// Some attributes permissions are restrictions regarding reading and writing permissions. For
/// those permissions this enum will be used to specify whether the restriction is for reading,
/// writing, or both.
#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum AttributeRestriction {
    Read,
    Write
}

#[derive(Clone,Copy,Debug,PartialEq,Eq,PartialOrd,Ord)]
pub enum AttributePermissions {
    /// Readable attributes
    Read,
    /// Writeable attributes
    Write,
    /// Encryption Requirement
    ///
    /// Encryption is required to access the specified attribute permission(s)
    /// A minimum key size may also be requred to access the specified
    Encryption(AttributeRestriction, EncryptionKeySize),
    /// Authentication Requirement
    ///
    /// Authentication is required to access the specified attribute permission(s)
    Authentication(AttributeRestriction),
    /// Authorization Requirement
    ///
    /// Authorization is required to access the specified attribute permission(s)
    Authorization(AttributeRestriction),
}

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
/// the handle value as all handle values on a server are gaurenteed to be unique. This can be
/// handy or required to refer to different attributes (e.g. multiple attributes with the same
/// types ).
///
/// # Permissions
/// Permissions define the accessability and requirements for accessability of the Attribute. The
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
    value: V
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
    TransferFormat(TransferFormatError),
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
            Error::TransferFormat(t_e) => write!( f, "{}", t_e ),
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
        Error::TransferFormat(err)
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
/// ATT Protocol Transmission format
///
/// Structures that implement `TransferFormat` can be converted into the transmitted format
/// (between the server and client) or be constructed from the raw transmitted data.
pub trait TransferFormat {
    /// Make Self from the attribute parameter
    ///
    /// This will attempt to take the passed byte slice and convert it into Self. The byte slice
    /// needs to only be the attribute parameter, it cannot contain either the attribute opcode
    /// or the attribute signature.
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> where Self: Sized;

    /// Convert Self into the attribute parameter
    fn into(&self) -> Box<[u8]>;
}

/// The size of Formatted Transfer
///
/// This is required for vectors or slices of transfered data.
pub trait TransferFormatSize {

    /// The size of the data in its transferred format
    const SIZE: usize;
}

macro_rules! impl_transfer_format_for_number {
    ( $num: ty ) => {
        impl TransferFormat for $num {
            fn from( raw: &[u8]) -> Result<Self, TransferFormatError> {
                if raw.len() == core::mem::size_of::<$num>() {
                    let mut bytes = <[u8;core::mem::size_of::<$num>()]>::default();

                    bytes.clone_from_slice(raw);

                    Ok(Self::from_le_bytes(bytes))
                } else {
                    Err(TransferFormatError::from(concat!("Invalid length for ", stringify!($ty))))
                }
            }

            fn into(&self) -> Box<[u8]> {
                From::<&'_ [u8]>::from(&self.to_le_bytes())
            }
        }

        impl TransferFormatSize for $num {
            const SIZE: usize = core::mem::size_of::<$num>();
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

impl TransferFormat for alloc::string::String {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        alloc::string::String::from_utf8(raw.to_vec())
            .map_err( |e| TransferFormatError::from(format!("{:?}", e)) )
    }

    fn into( &self ) -> Box<[u8]> {
        From::from(self.as_bytes())
    }
}

impl TransferFormat for crate::UUID {
    fn from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        use core::mem::size_of;

        macro_rules! err_fmt { () =>  { "Failed to create UUID, {}" } }

        if raw.len() == size_of::<u16>() {

            TransferFormat::from(raw)
            .and_then( |uuid_16: u16| Ok(crate::UUID::from_u16(uuid_16)) )
            .or_else( |e| Err(TransferFormatError::from(format!(err_fmt!(),e))) )

        } else if raw.len() == size_of::<u128>() {

            TransferFormat::from(raw)
            .and_then( |uuid_128: u128| Ok(crate::UUID::from_u128(uuid_128)) )
            .or_else( |e| Err(TransferFormatError::from(format!(err_fmt!(),e))) )

        } else {
            Err(TransferFormatError::from(format!(err_fmt!(), "raw data is not 16 or 128 bits")))
        }
    }

    fn into(&self) -> Box<[u8]> {
        match core::convert::TryInto::<u16>::try_into( *self ) {
            Ok(raw) => TransferFormat::into( &raw ),
            Err(_) => TransferFormat::into( &Into::<u128>::into(*self) ),
        }
    }
}

impl<T> TransferFormat for Box<[T]> where T: TransferFormat + TransferFormatSize {

    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        <alloc::vec::Vec<T> as TransferFormat>::from(raw).map(|v| v.into_boxed_slice() )
    }

    fn into(&self) -> Box<[u8]> {
        let mut v = alloc::vec::Vec::new();

        self.iter().for_each(|t| v.extend_from_slice(&TransferFormat::into(t)) );

        v.into_boxed_slice()
    }
}

impl<T> TransferFormat for Box<T> where T: TransferFormat {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        <T as TransferFormat>::from(raw).and_then( |v| Ok(Box::new(v)) )
    }

    fn into(&self) -> Box<[u8]> {
        TransferFormat::into( self.as_ref() )
    }
}

impl TransferFormat for Box<str> {
    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        core::str::from_utf8(raw)
            .and_then( |s| Ok( s.into() ) )
            .or_else( |e| {
                Err( TransferFormatError::from(format!("{}", e)))
            })
    }

    fn into(&self) -> Box<[u8]> {
        self.clone().into_boxed_bytes()
    }
}

impl TransferFormat for () {

    fn from( raw: &[u8] ) -> Result<Self, TransferFormatError> {
        if raw.len() == 0 {
            Ok(())
        } else {
            Err(TransferFormatError::from("length must be zero for type '()'"))
        }
    }

    fn into(&self) -> Box<[u8]> {
        From::<&[u8]>::from(&[])
    }
}

impl TransferFormat for Box<dyn TransferFormat> {
    /// It is impossible to convert data from its raw form into a Box<dyn TransferFormat>. This
    /// will always return `Err(..)`
    fn from( _: &[u8]) -> Result<Self, TransferFormatError> {
        Err(TransferFormatError::from("Impossible to convert raw data to a 'Box<dyn TransferFormat>'"))
    }

    fn into(&self) -> Box<[u8]> {
        TransferFormat::into(self.as_ref())
    }
}

impl<T> TransferFormat for Vec<T> where T: TransferFormat + TransferFormatSize {

    fn from( raw: &[u8]) -> Result<Self, TransferFormatError> {
        let mut chunks = raw.chunks_exact(T::SIZE);

        if chunks.remainder().len() == 0 {
            Ok( chunks.try_fold( Vec::new(), |mut v,c| {
                v.push(TransferFormat::from(&c)?);
                Ok(v)
            })
                .or_else(|e: TransferFormatError| Err(TransferFormatError::from(
                    format!("Failed to make boxed slice, {}", e))))?
            )
        } else {
            Err(TransferFormatError::bad_exact_chunks("{generic}", T::SIZE, raw.len()))
        }
    }

    fn into(&self) -> Box<[u8]> {
        self.iter()
            // todo when return of `into` 
            .map(|t| TransferFormat::into(t).to_vec() )
            .flatten()
            .collect::<Vec<u8>>()
            .into_boxed_slice()
    }
}

impl TransferFormatSize for Box<dyn TransferFormat> {
    /// This is not the actual size, but because the size is unknown this is set to zero
    const SIZE: usize = 0;
}

trait AnyAttribute {

    fn get_type(&self) -> crate::UUID;

    fn get_permissions(&self) -> Vec<AttributePermissions>;

    fn get_handle(&self) -> u16;

    fn set_val_from_raw(&mut self, raw: &[u8]) -> Result<(), TransferFormatError>;

    fn get_val_as_transfer_format<'a>(&'a self) -> &'a dyn TransferFormat;
}

impl<V> AnyAttribute for Attribute<V> where V: TransferFormat + Sized  {

    fn get_type(&self) -> crate::UUID { self.ty }

    fn get_permissions(&self) -> Vec<AttributePermissions> { self.permissions.clone() }

    /// This will panic if the handle value hasn't been set yet
    fn get_handle(&self) -> u16 { self.handle.expect("Handle value not set") }

    fn set_val_from_raw(&mut self, raw: &[u8]) -> Result<(), TransferFormatError> {

        self.value = TransferFormat::from(raw)?;

        Ok(())
    }

    fn get_val_as_transfer_format<'a>(&'a self) -> &'a dyn TransferFormat {
        &self.value
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
        use crate::l2cap::ConnectionChannel;

        const UUID_1: u16 = 1;
        const UUID_2: u16 = 2;
        const UUID_3: u16 = 3;

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
                From::from(UUID_1),
                [Read, Write].to_vec(),
                0usize
            );

            let attribute_1 = Attribute::new(
                From::from(UUID_2),
                [Read, Write].to_vec(),
                0u64
            );

            let attribute_3 = Attribute::new(
                From::from(UUID_3),
                [Read, Write].to_vec(),
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
            .map_err(|e| panic!("Thread Failed to join: {}", e.downcast_ref::<String>().unwrap()) );
    }
}
