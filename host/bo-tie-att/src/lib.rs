#![doc = include_str!("../README.md")]
//! # L2CAP Dependency
//! This module relies on the implementation of a L2CAP within `bo-tie` in order to send data between
//! the ATT server and client. Both the `Server` and `Client` require an Attribute bearer. Within
//! the L2CAP implementation, an Attribute bearer is either a [`BasicChannel`] or a
//! [`CreditBasedChannel`] (todo). While being the most commonly used Attribute channel, a
//! `BasicChannel` can only be created from a `LeULogicalLink`, whereas a `CreditBasedChannel` can
//! be created from either a LE-U or ACL-U logical link.
//!
//! ### Basic Channel
//! For an LE logical link, there is a single fixed channel for the Attribute protocol. This channel
//! can be retrieved using the `get_att_channel` command.
//!
//! ```
//! use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
//! use bo_tie_att::Server;
//! use bo_tie_att::server::NoQueuedWrites;
//!
//! async fn run_server<P: PhysicalLink>(physical_link: P) {
//!     let logical_link = LeULogicalLink::new(physical_link);
//!
//!     let mut att_channel = logical_link.get_att_channel();
//!
//!     // note: for a real server you're going
//!     // to need to add attributes to it
//!     let mut server = Server::new_fixed(256, None, NoQueuedWrites);
//!
//!     loop {
//!         let basic_frame = att_channel.receive()
//!             .await
//!             .expect("unexpected failure in receiving ATT data");
//!
//!         server.process_att_pdu(&mut att_channel, &basic_frame).await
//!     }
//! }
//! ```
//!
// //! ### Credit Based Channel (todo: a credit based channel is not currently supported)
// //!
// //! A credit based channel must be created via the signalling commands of L2CAP. There are two sets
// //! of commands for establishing a `CreditBasedChannel`. These commands are used to create a L2CAP
// //! credit based connection which can then be used as a channel.
// //!
// //! A LE-U logical link can create a `CreditBasedChannel` by either initiating a LE credit based
// //! connection or an enhanced credit based connection. An ACL-U logical link can only create a
// //! `CreditBasedChannel` from an enhanced credit based connection.
// //!
// //! ```
// //! use bo_tie_att::ConnectClient;
// //! use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
// //! use bo_tie_l2cap::channel::id::DynChannelId;
// //! use bo_tie_l2cap::channel::signalling::ReceivedSignal;
// //! use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
// //! use bo_tie_l2cap::signals::packets::{LeCreditBasedConnectionRequest, SimplifiedProtocolServiceMultiplexer};
// //!
// //! // In this example a LE credit based connection is
// //! // established before the credit based connection
// //! async fn run_server<P: PhysicalLink>(physical_link: P) {
// //!     let logical_link = LeULogicalLink::new(physical_link);
// //!
// //!     let mut signalling_channel = logical_link.get_signalling_channel();
// //!
// //!     // These are just arbitrary values
// //!     let request = LeCreditBasedConnectionRequest {
// //!         identifier: 1u8.try_into().unwrap(),
// //!         spsm: SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
// //!         source_dyn_cid: DynChannelId::new_dyn_le(0x40).unwrap(),
// //!         mtu: LeULink::SUPPORTED_MTU.into(),
// //!         mps: 256u16.into(),
// //!         initial_credits: 32,
// //!     };
// //!
// //!     signalling_channel.init_le_credit_connection(&request)
// //!         .await
// //!         .expect("failed to initialize LE credit based connection");
// //!
// //!     // need to await the signalling response
// //!     let mut credit_based_channel = loop {
// //!         match signalling_channel.receive().await.expect("failed to receive") {
// //!             ReceivedSignal::LeCreditBasedConnectionResponse(response) => {
// //!                 break response.create_le_credit_connection(&request, &logical_link);
// //!             }
// //!             signal => signal.reject_or_ignore(&mut signalling_channel),
// //!         }
// //!     };
// //!
// //!     // now the credit based channel can be used
// //!     // as an ATT bearer
// //!     let client = ConnectClient::connect(&mut credit_based_channel, 256)
// //!         .await
// //!         .expect("failed to init client");
// //! }
// //! ```
// //!
//! # The Attribute Client
//! An Attribute client is used for retrieving the Attribute information from an ATT protocol
//! Server. To create a [`Client`] you need to initiate an ATT protocol connection to the Server.
//! This is done using the [`ConnectFixedClient`] type.
//!
//! ```
//! use bo_tie_att::ConnectFixedClient;
//! use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
//!
//! # use bo_tie_l2cap::{LeULogicalLink, PhysicalLink};
//! # async fn run_client<P: PhysicalLink>(physical_link: P) {
//! let link = LeULogicalLink::new(physical_link);
//!
//! let mut att_channel = link.get_att_channel();
//!
//! let client = ConnectFixedClient::connect(&mut att_channel, LeULink::SUPPORTED_MTU, None);
//! # }
//!
//! ```
//!
// ### Attribute Bearers using dynamic L2CAP channel IDs
//
// (todo) these kinds of Attribute bearers are not supported yet, the following it the intended
// implementation for the future.
//
// These bearers do not perform a MTU exchange nor have a default MTU *at the ATT protocol level*.
// The MTU is determined at the at the L2CAP level. Creating a `Client` does not go through the
// `CreateFixedClient` process and instead a client is directly created through a corresponding
// `new_*` method.
//
// ```
// // Create a client for an Attribute Bearer
// // using a credit based L2CAP channel
// let client = Client::new_credit_based(&credit_channel);
// ```
//
//! # The Attribute Server
//! The server contains a series of Attributes that can be interacted with by the Client. The
//! Server implementation of this library contains
//!
//! ### Attribute Protocol Permissions
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
//! #### Client Granted Permissions
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
//! #### Permission Errors
//! If an operation cannot be performed because the client does not have the permission to access
//! an attribute, an error is returned to the client describing the permission problem. However,
//! it is often the case there are multiple types of permissions that a client can have to access
//! the attribute, but only one of the errors can be described with the error PDU sent from the
//! server to the client.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(any(test, feature = "std")), no_std)]

extern crate alloc;

use alloc::{boxed::Box, format, string::String, vec::Vec};
use core::borrow::Borrow;

pub mod client;
pub mod server;

use crate::server::ServerPduName;
use bo_tie_core::buffer::stack::LinearBuffer;
pub use bo_tie_host_util::{Uuid, UuidFormatError, UuidVersion};
use bo_tie_l2cap::PhysicalLink;
pub use client::{Client, ConnectFixedClient};
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

/// The fixed Channel Identifier for the Attribute protocol
///
/// This is the fixed channel identifier for the Attribute (ATT) protocol. There can be multiple ATT
/// bearers using channels with dynamically assigned channel identifiers, but in L2CAP there is only
/// one fixed channel identifier given to the ATT protocol
pub const L2CAP_FIXED_CHANNEL_ID: bo_tie_l2cap::cid::ChannelIdentifier =
    bo_tie_l2cap::cid::ChannelIdentifier::Le(bo_tie_l2cap::cid::LeCid::AttributeProtocol);

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
    UnexpectedServerPdu(ServerPduName),
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
    IncorrectChannelId(bo_tie_l2cap::cid::ChannelIdentifier),
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
            Error::UnexpectedServerPdu(val) => write!(f, "{}", val),
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
/// This is used by the Attribute client and server implementations when dealing with the L2CAP
/// channel for the Attribute Protocol.
pub enum ConnectionError<T: bo_tie_l2cap::LogicalLink> {
    AttError(Error),
    RecvError(<T::PhysicalLink as PhysicalLink>::RecvErr),
    SendError(<T::PhysicalLink as PhysicalLink>::SendErr),
    InvalidMtuInputs,
}

impl<T: bo_tie_l2cap::LogicalLink, E: Into<Error>> From<E> for ConnectionError<T> {
    fn from(e: E) -> Self {
        Self::AttError(e.into())
    }
}

impl<T> core::fmt::Debug for ConnectionError<T>
where
    T: bo_tie_l2cap::LogicalLink,
    <T::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
    <T::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::AttError(e) => write!(f, "AttError({e:?})"),
            Self::RecvError(e) => write!(f, "RecvError({e:?})"),
            Self::SendError(e) => write!(f, "SendError({e:?})"),
            Self::InvalidMtuInputs => f.write_str("InvalidMtuInputs"),
        }
    }
}

impl<T> core::fmt::Display for ConnectionError<T>
where
    T: bo_tie_l2cap::LogicalLink,
    <T::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
    <T::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            Self::AttError(e) => core::fmt::Display::fmt(e, f),
            Self::RecvError(rx) => core::fmt::Display::fmt(rx, f),
            Self::SendError(tx) => core::fmt::Display::fmt(tx, f),
            Self::InvalidMtuInputs => f.write_str("both the default and requested MTU values cannot be None"),
        }
    }
}

#[cfg(feature = "std")]
impl<T> std::error::Error for ConnectionError<T>
where
    T: bo_tie_l2cap::LogicalLink,
    <T::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error,
    <T::PhysicalLink as PhysicalLink>::SendErr: std::error::Error,
{
}

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

#[cfg(feature = "std")]
impl std::error::Error for TransferFormatError {}

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

                    bytes.copy_from_slice(raw);

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
impl_transfer_format_for_number! {i128}
impl_transfer_format_for_number! {u128}
impl_transfer_format_for_number! {f32}
impl_transfer_format_for_number! {f64}

impl TransferFormatTryFrom for isize {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 8 {
            let mut bytes = <[u8; core::mem::size_of::<isize>()]>::default();

            bytes.copy_from_slice(raw);

            let mut val_bytes = <[u8; core::mem::size_of::<usize>()]>::default();

            val_bytes.iter_mut().zip(bytes.iter()).for_each(|(v, b)| *v = *b);

            Ok(Self::from_le_bytes(bytes))
        } else {
            Err(TransferFormatError::bad_size(
                stringify!($num),
                core::mem::size_of::<isize>(),
                raw.len(),
            ))
        }
    }
}

impl TransferFormatInto for isize {
    fn len_of_into(&self) -> usize {
        8
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        assert!(
            *self as usize <= <u64>::MAX as usize,
            "cannot transfer an isize larger than <i64>::MAX or less than <i64>::MIN"
        );

        into_ret.copy_from_slice(&self.to_le_bytes())
    }
}

impl TransferFormatTryFrom for usize {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError> {
        if raw.len() == 8 {
            let mut bytes = <[u8; 8]>::default();

            bytes.copy_from_slice(raw);

            let mut val_bytes = <[u8; core::mem::size_of::<usize>()]>::default();

            val_bytes.iter_mut().zip(bytes.iter()).for_each(|(v, b)| *v = *b);

            Ok(Self::from_le_bytes(val_bytes))
        } else {
            Err(TransferFormatError::bad_size(
                stringify!($num),
                core::mem::size_of::<isize>(),
                raw.len(),
            ))
        }
    }
}

impl TransferFormatInto for usize {
    fn len_of_into(&self) -> usize {
        8
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        assert!(
            *self <= <u64>::MAX as usize,
            "cannot transfer an usize larger than <u64>::MAX"
        );

        into_ret.copy_from_slice(&self.to_le_bytes())
    }
}

impl_transfer_format_for_vec_of!(isize);
impl_transfer_format_for_vec_of!(usize);

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

impl TransferFormatInto for bo_tie_core::BluetoothDeviceAddress {
    fn len_of_into(&self) -> usize {
        6
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&self.0)
    }
}

impl TransferFormatTryFrom for bo_tie_core::BluetoothDeviceAddress {
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
    #[tokio::test]
    async fn test_fixed_att_connection() {
        use bo_tie_host_util::Uuid;

        const UUID_1: Uuid = Uuid::from_u16(1);

        const UUID_2: Uuid = Uuid::from_u16(2);

        const UUID_3: Uuid = Uuid::from_u16(3);

        const UUID_4: Uuid = Uuid::from_u16(4);

        let test_val_1 = 33usize;

        let test_val_2 = 64u64;

        let test_val_3 = -11i8;

        // the formatting does not matter, all that is needed is a large piece of data
        let test_val_4 = b"\
            Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aliquam lobortis ipsum ac 
            ornare fringilla. Vestibulum ante ipsum primis in faucibus orci luctus et ultrices 
            posuere cubilia curae; Maecenas est dolor, mollis vitae dictum ut, malesuada sit amet 
            odio. Nam id molestie tellus, interdum molestie ante. Sed varius ante in velit cursus 
            rutrum. Aliquam erat volutpat. Vestibulum vel tellus ut ante scelerisque placerat sed 
            sed massa. Pellentesque non fringilla nisl. In vestibulum finibus accumsan. Vestibulum 
            nec semper dolor. Nullam placerat, tortor eu vulputate tempus, leo elit porta arcu, ut 
            aliquet elit odio at augue. Aenean cursus faucibus metus, et convallis eros commodo 
            quis. In hac habitasse platea dictumst. Donec rhoncus vestibulum nulla, at viverra 
            justo efficitur quis. Suspendisse semper eleifend aliquam. In vel est in nisi suscipit 
            malesuada.

            Nulla ipsum leo, cursus vitae molestie id, pretium id tortor. Vestibulum ante ipsum 
            primis in faucibus orci luctus et ultrices posuere cubilia curae; Nam placerat 
            condimentum ante, eu condimentum odio ornare in. Nulla facilisi. Phasellus suscipit 
            magna ac fringilla interdum. Donec lacinia eu nibh in varius. Nullam quis faucibus orci,
            et efficitur eros. Aenean vitae odio sed diam viverra condimentum. Suspendisse in magna 
            tortor. Etiam et sapien et ipsum lacinia varius quis nec libero. Sed rutrum magna velit. 
            Nam faucibus at diam et egestas. Donec tincidunt non leo in fringilla. Class aptent 
            taciti sociosqu ad litora torquent per conubia nostra, per inceptos himenaeos.

            Suspendisse non vehicula mauris. Donec dignissim, magna sit amet sollicitudin commodo, 
            enim augue laoreet tellus, ac aliquam odio magna vitae lorem. Praesent consectetur 
            pellentesque ligula nec varius. Sed arcu sapien, tempus hendrerit dui ac, mattis luctus 
            eros. Sed pulvinar condimentum dui, vitae accumsan orci. In vestibulum odio erat, eget 
            consectetur ex tristique nec. Nullam a urna nec lorem placerat lacinia. Nam tristique 
            libero augue, non eleifend risus varius vitae. Aenean maximus consequat ipsum. 
            Suspendisse sit amet lectus sit amet est tristique vestibulum. Ut placerat leo vitae 
            urna eleifend, a eleifend enim tempus. In ut arcu tincidunt, maximus odio eget, congue 
            nibh. Quisque sagittis diam nec justo vestibulum dapibus. Donec interdum fringilla eros, 
            in ornare justo mollis eget. Praesent magna enim, euismod at consectetur elementum, 
            sollicitudin nec eros.

            Etiam pulvinar risus eget pulvinar pulvinar. Donec sodales convallis lorem eu luctus. 
            Maecenas porttitor, libero iaculis maximus dictum, risus purus ultrices mauris, non 
            bibendum erat tellus vitae felis. Vivamus vulputate risus eu magna dapibus, a lobortis 
            massa feugiat. Proin tincidunt augue odio. Duis a lacinia diam, et tincidunt sapien. 
            Suspendisse potenti. Morbi commodo imperdiet venenatis.

            In libero nunc, vehicula in felis molestie, feugiat suscipit erat. In vehicula erat 
            quam, in cursus leo consectetur varius. Quisque tempus justo tincidunt purus venenatis 
            luctus. Sed pellentesque arcu vitae nibh vestibulum, ac hendrerit arcu congue. Integer 
            elementum massa quis nisi suscipit porta. Mauris eget sapien lectus. Sed tempor nulla 
            rutrum, bibendum quam ut, ultricies purus. Maecenas a lorem mauris. 
        ";

        fixed_att_test_setup! (
            server_setup => {
                use AttributePermissions::*;

                let mut server_attributes = ServerAttributes::new();

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

                server_attributes.push(attribute_0); // has handle value of 1
                server_attributes.push(attribute_1); // has handle value of 2
                server_attributes.push(attribute_3); // has handle value of 3

                let mut server = Server::new_fixed(23, 256, server_attributes, NoQueuedWrites);

                let client_permissions: &[AttributePermissions] =
                    &[Read(AttributeRestriction::None), Write(AttributeRestriction::None)];

                server.give_permissions_to_client(client_permissions);

                server
            },
            server_status => (status) {
                match status {
                    Status::None => (),
                    _ => panic!("unexpected {status:?}")
                }
            },
            client_actions => (client, channel, pdu) {
                {
                    client
                },
                {}
            }
        );
    }
}
