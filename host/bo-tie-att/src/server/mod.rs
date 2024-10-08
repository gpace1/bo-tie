//! Attribute Server
//!
//! The attribute server for this library is dynamic. It utilizes trait objects for the attribute
//! data with the only requirements that the data implement [`TransferFormatInto`], and
//! [`TransferFormatTryFrom`]. The server organizes the data as a vectored list, all attributes are
//! forced into a consecutive order. The client can query the server using the requests specified
//! within the specification except for 'Read By Group Type Request' as groups are not specified by
//! the attribute protocol.
//!
//! Creating a `Server` requires two things, a L2CAP [`ConnectionChannel`] and a
//! [`ServerAttributes`]. A `ConnectionChannel` comes from something that implements a data link
//! layer. `ServerAttributes` is the list of attributes that will be used within the server. Any
//! type that implements `TransferFormatInto` and `TransferFormatTryFrom` and is wrapped within an
//! [`Attribute`] can be pushed to a `ServerAttributes`.
//!
//! # Concurrency
//! Reading and writing to the attributes of a server are atomic. The same attribute cannot be
//! cannot be written to at the same time by two different connections. The easiest way to do this
//! is to use a `Mutex`. The recommended way of ensuring this is to isolate each attribute
//! individually.
//!
//! # Data Blobbing
//! Data becomes 'blobbed' when a response to a read request meets or exceeds the maximum payload
//! size (MTU) of the connection. One way to prevent this is to change the MTU, but the client needs
//! to initiate this change with an 'Exchange MTU Request'. Regardless of what MTU value the
//! connection has currently agreed to, whenever the server sends a response that contains the MTU
//! number of bytes, the client may need to assume that more bytes are to be sent. But blobbing can
//! only for certain request, and sometimes only with special conditions. This table gives the
//! conditions for what read request will initiate blobbing.
//!
//! | Request            | Circumstances for data blobbing |
//! |--------------------|-------------------------------------------------------------------------|
//! | Read By Type       | The Read By Type Response contains only one element and the size of the response is the same as the connection MTU. |
//! | Read               | The size of the Read Response is the same as the connection MTU         |
//! | Read Blob          | The size of the Read Blob Response is the same as the connection MTU    |
//! | Read By Group Type | The Read By Group Type Response contains only one element and the size of the response is the same as the connection MTU. 'Read By Group Type' is only implemented by a higher layer protocol, so these rules may change depending on the protocols implementation.    |
//!
//! Blobbing is effectively fragmenting the data over multiple responses. While a 'blob request' is
//! not the only way for a request to initiate data blobbing, it is the only way for the client to
//! continue getting the data fragments of the blob. Blobs last for as long as the client requests
//! for blobs from the *same* attribute until the final blob is sent from the server. The server
//! determines the final blob when the last blob sent does not fill up the entire payload space in
//! the response message. If a client requests for a read operation from another attribute, if and
//! only if that read would cause blobbing, the previous blob is considered lost. It is safe for the
//! client to read from other attributes if it knows that the returned response will not trigger
//! blobbing. In rust terms, calling a blob lost is equivalent to saying the blob dropped.
//!
//! When data is blobbed, the blob is liberated from the underlying data as changes to the
//! attribute's data will not modify the blob. This ensures that the client will receive valid blobs
//! to assemble into data so long as the blob is not lost. If the data is modified, the client must
//! re-read the attribute from the beginning to get the modified data. However, once a blob is lost,
//! there is no guarantee that performing a blob request will return a valid blob. When a blob is
//! lost, it essentially means there is no saved blob information in the server for that handle. The
//! server must re-read the attribute data to create a new blob, giving no guarantee that the data
//! stayed the same in between the creation of the lost blob and the new blob.
//!
//! The client does not need to send 'Read Blob Requests' until the entire blob is received by the
//! client.
//!
//! [`TransferFormatInto`]: crate::TransferFormatInto
//! [`TransferFormatTryFrom`]: crate::TransferFormatTryFrom
//! [`ConnectionChannel`]: bo_tie_l2cap::ConnectionChannel
//! [`ServerAttributes`]: crate::server::ServerAttributes
//! [`Attribute`]: crate::Attribute

mod access_value;

use crate::{
    client::ClientPduName, pdu, AttributePermissions, AttributeRestriction, ConnectionError, TransferFormatInto,
    TransferFormatTryFrom,
};
#[cfg(feature = "async-trait")]
pub use access_value::AsyncAccessValue;
pub use access_value::{AccessReadOnly, AccessValue, ReadGuard, TrivialAccessor};
use access_value::{AccessibleValue, ReadOnly};
use alloc::{boxed::Box, vec::Vec};
use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::{BasicFrameChannel, LogicalLink, PhysicalLink};
use core::{future::Future, pin::Pin};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
pub enum ServerPduName {
    ErrorResponse,
    ExchangeMTUResponse,
    FindInformationResponse,
    FindByTypeValueResponse,
    ReadByTypeResponse,
    ReadResponse,
    ReadBlobResponse,
    ReadMultipleResponse,
    ReadByGroupTypeResponse,
    ReadMultipleVariableResponse,
    WriteResponse,
    PrepareWriteResponse,
    ExecuteWriteResponse,
    HandleValueNotification,
    HandleValueIndication,
}

impl TryFrom<pdu::PduOpcode> for ServerPduName {
    type Error = ();

    fn try_from(opcode: super::pdu::PduOpcode) -> Result<Self, Self::Error> {
        Self::try_from(opcode.as_raw())
    }
}

impl From<ServerPduName> for pdu::PduOpcode {
    fn from(pdu_name: ServerPduName) -> pdu::PduOpcode {
        pdu::PduOpcode::Server(pdu_name)
    }
}

impl From<ServerPduName> for u8 {
    fn from(name: ServerPduName) -> Self {
        match name {
            ServerPduName::ErrorResponse => 0x1,
            ServerPduName::ExchangeMTUResponse => 0x3,
            ServerPduName::FindInformationResponse => 0x5,
            ServerPduName::FindByTypeValueResponse => 0x7,
            ServerPduName::ReadByTypeResponse => 0x9,
            ServerPduName::ReadResponse => 0xB,
            ServerPduName::ReadBlobResponse => 0xD,
            ServerPduName::ReadMultipleResponse => 0xF,
            ServerPduName::ReadByGroupTypeResponse => 0x11,
            ServerPduName::ReadMultipleVariableResponse => 0x21,
            ServerPduName::WriteResponse => 0x13,
            ServerPduName::PrepareWriteResponse => 0x17,
            ServerPduName::ExecuteWriteResponse => 0x19,
            ServerPduName::HandleValueNotification => 0x1B,
            ServerPduName::HandleValueIndication => 0x1D,
        }
    }
}

impl TryFrom<u8> for ServerPduName {
    type Error = ();

    fn try_from(val: u8) -> Result<Self, Self::Error> {
        match val {
            0x1 => Ok(ServerPduName::ErrorResponse),
            0x3 => Ok(ServerPduName::ExchangeMTUResponse),
            0x5 => Ok(ServerPduName::FindInformationResponse),
            0x7 => Ok(ServerPduName::FindByTypeValueResponse),
            0x9 => Ok(ServerPduName::ReadByTypeResponse),
            0xB => Ok(ServerPduName::ReadResponse),
            0xD => Ok(ServerPduName::ReadBlobResponse),
            0xF => Ok(ServerPduName::ReadMultipleResponse),
            0x11 => Ok(ServerPduName::ReadByGroupTypeResponse),
            0x21 => Ok(ServerPduName::ReadMultipleVariableResponse),
            0x13 => Ok(ServerPduName::WriteResponse),
            0x17 => Ok(ServerPduName::PrepareWriteResponse),
            0x19 => Ok(ServerPduName::ExecuteWriteResponse),
            0x1B => Ok(ServerPduName::HandleValueNotification),
            0x1D => Ok(ServerPduName::HandleValueIndication),
            _ => Err(()),
        }
    }
}

impl core::fmt::Display for ServerPduName {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ServerPduName::ErrorResponse => write!(f, "Error Response"),
            ServerPduName::ExchangeMTUResponse => write!(f, "Exchange MTU Response"),
            ServerPduName::FindInformationResponse => write!(f, "Find Information Response"),
            ServerPduName::FindByTypeValueResponse => write!(f, "Find By Type Value Response"),
            ServerPduName::ReadByTypeResponse => write!(f, "Read By Type Response"),
            ServerPduName::ReadResponse => write!(f, "Read Response"),
            ServerPduName::ReadBlobResponse => write!(f, "Read Blob Response"),
            ServerPduName::ReadMultipleResponse => write!(f, "Read Multiple Response"),
            ServerPduName::ReadByGroupTypeResponse => write!(f, "Read By Group Type Response"),
            ServerPduName::ReadMultipleVariableResponse => write!(f, "Read Multiple Variable Response"),
            ServerPduName::WriteResponse => write!(f, "Write Response"),
            ServerPduName::PrepareWriteResponse => write!(f, "Prepare Write Response"),
            ServerPduName::ExecuteWriteResponse => write!(f, "Execute Write Response"),
            ServerPduName::HandleValueNotification => write!(f, "Handle Value Notification"),
            ServerPduName::HandleValueIndication => write!(f, "Handle Value Indication"),
        }
    }
}

impl ServerPduName {
    /// Check if the `raw_pdu` is this PDU
    ///
    /// This just checks the first byte to see if it matches the `ServerPduName`.
    pub(super) fn is(&self, raw_pdu: &[u8]) -> bool {
        match self {
            ServerPduName::ErrorResponse => raw_pdu[0] == ServerPduName::ErrorResponse.into(),
            ServerPduName::ExchangeMTUResponse => raw_pdu[0] == ServerPduName::ExchangeMTUResponse.into(),
            ServerPduName::FindInformationResponse => raw_pdu[0] == ServerPduName::FindInformationResponse.into(),
            ServerPduName::FindByTypeValueResponse => raw_pdu[0] == ServerPduName::FindByTypeValueResponse.into(),
            ServerPduName::ReadByTypeResponse => raw_pdu[0] == ServerPduName::ReadByTypeResponse.into(),
            ServerPduName::ReadResponse => raw_pdu[0] == ServerPduName::ReadResponse.into(),
            ServerPduName::ReadBlobResponse => raw_pdu[0] == ServerPduName::ReadBlobResponse.into(),
            ServerPduName::ReadMultipleResponse => raw_pdu[0] == ServerPduName::ReadMultipleResponse.into(),
            ServerPduName::ReadByGroupTypeResponse => raw_pdu[0] == ServerPduName::ReadByGroupTypeResponse.into(),
            ServerPduName::ReadMultipleVariableResponse => {
                raw_pdu[0] == ServerPduName::ReadMultipleVariableResponse.into()
            }
            ServerPduName::WriteResponse => raw_pdu[0] == ServerPduName::WriteResponse.into(),
            ServerPduName::PrepareWriteResponse => raw_pdu[0] == ServerPduName::PrepareWriteResponse.into(),
            ServerPduName::ExecuteWriteResponse => raw_pdu[0] == ServerPduName::ExecuteWriteResponse.into(),
            ServerPduName::HandleValueNotification => raw_pdu[0] == ServerPduName::HandleValueNotification.into(),
            ServerPduName::HandleValueIndication => raw_pdu[0] == ServerPduName::HandleValueIndication.into(),
        }
    }
}

/// Blob read or Queued write data
///
/// Blob read or Queued write data are reads and writes that are performed over multiple requests
/// from the client. The server needs to keep track of the data while the client continues to
/// perform these requests. `MultiReqData` is a structure used for holding onto the data until the
/// entire operation is ended (successfully or otherwise).
struct MultiReqData {
    handle: u16,
    /// Data in its transfer format form
    tf_data: Vec<u8>,
    /// Temporary restrictions (used only by [`send_notification_with`] and [`send_indication_with`]
    ///
    /// [`send_notification_with`]: Server::send_notification_with
    /// [`send_indication_with`]: Server::send_indication_with
    temporary_read_restrictions:
        Option<bo_tie_core::buffer::stack::LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>>,
}

/// An Attribute server
///
/// This is an implementation of the server role for the Attribute protocol. A server is made up of
/// attributes, which consist of a handle, a UUID, and a value.
///
/// ## Attribute Handles
/// A handle is much like an index of an array and is used to address the attribute. Per the
/// specification an handle is a `u16` value with zero being reserved (attributes will start at
/// handle one). This server forcibly put all attributes in sequential order, as a vector is used
/// for the attributes collection.
///
/// ## Unique Instances
/// Each `Server` is unique for the connection to the client. Making the server this way allows for a
/// unique state for each connection, allowing the commands being processed independent of other
/// connections. Things like the maximum transfer unit (MTU) and client permissions might be
/// different per connection. Most importantly, because servers are independent, they can be used
/// within separate threads.
///
/// However, the issue with this is that it is up to you to ensure that the handles remain
/// consistent between `Server` instances. Different connections need to seem the same to each
/// client as per the Bluetooth Specification.
///
/// ## Default Client Permissions
/// When a new `Server` is created, the client will be given the permissions
/// `AttributePermissions::Read(AttributeRestriction::None)`, and
/// `AttributePermissions::Write(AttributeRestriction::None)`. These permissions can be revoked
/// via the method [`revoke_permissions_of_client`] (Note: these permissions only allow the client
/// to access Attributes that also have these permissions).
///
/// [`revoke_permissions_of_client`]: Server::revoke_permissions_of_client
pub struct Server<Q> {
    /// The maximum transmission unit
    mtu: usize,
    /// The maximum, maximum transmission unit. The server will not
    max_mtu: usize,
    /// The attributes of the server
    attributes: ServerAttributes,
    /// The permissions the client currently has
    ///
    /// This is sorted and de-duplicated, to make things marginally faster for linear search. Most
    /// permission checks will be for permissions sorted towards the front (Unencrypted Read/Write,
    /// Encrypted Read/Write,
    given_permissions: Vec<super::AttributePermissions>,
    /// Blob data
    ///
    /// A blob request is a request for data that is too large to be sent within one PDU packet. It
    /// is chopped up across multiple blob requests and re-stitched together at the client side.
    /// All read responses double as the start of a blob read when the data is too large to be
    /// completely sent within the read response. Whenever a blob read is started, `blob_data` is
    /// updated with the full data to be read **whether or not the prior data was fully read by
    /// the client**.
    ///
    /// See the doc for `Server` for more information on blob data.
    blob_data: Option<MultiReqData>,
    queued_writer: Q,
}

/// Validate the permissions of the attribute
///
/// This is used to validate a list of possible permissions required to perform an operation.
/// The `att` and client need to share at least one of the permissions in `permissions` for
/// this function to return without an error.
///
/// If there is a permission issue, an error corresponding to the missing permission is
/// returned. This error will be the first permission in `permissions` that is also a part of
/// the permission list for the attribute. If the attribute does not have any of the permissions
/// in `permissions` then an `Authorization` error is returned.
///
/// If 'None' is returned the client and attribute have the required permissions to proceed with
/// the operation.
///
/// # Inputs
/// $this: `self` for `Server`
/// $attribute_permissions: `&[AttributePermissions]`
/// $operation_permissions: &[AttributePermissions]
macro_rules! validate_permissions {
    ($this:expr, $attribute_permissions:expr, $operation_permissions:expr $(,)?) => {
        match $this
            .given_permissions
            .iter()
            .find(|&p| $attribute_permissions.contains(p) && $operation_permissions.contains(p))
        {
            Some(_) => None,
            None => $operation_permissions
                .iter()
                .find(|&p| $attribute_permissions.contains(p))
                .map(|&p| // Map the invalid permission to it's corresponding error
                    match p {
                        $crate::AttributePermissions::Read($crate::AttributeRestriction::None) =>
                            pdu::Error::ReadNotPermitted,

                        $crate::AttributePermissions::Write($crate::AttributeRestriction::None) =>
                            pdu::Error::WriteNotPermitted,

                        $crate::AttributePermissions::Read($crate::AttributeRestriction::Encryption(_)) =>
                            $this.given_permissions.iter().find(|&&x| {
                                match x {
                                    AttributePermissions::Read($crate::AttributeRestriction::Encryption(_)) => true,
                                    _ => false
                                }
                            })
                                .and_then(|_| Some($crate::pdu::Error::InsufficientEncryptionKeySize))
                                .or_else(|| Some($crate::pdu::Error::InsufficientEncryption))
                                .unwrap(),

                        $crate::AttributePermissions::Write($crate::AttributeRestriction::Encryption(_)) =>
                            $this.given_permissions.iter().find(|&&x| {
                                match x {
                                    $crate::AttributePermissions::Write($crate::AttributeRestriction::Encryption(_)) => true,
                                    _ => false
                                }
                            })
                                .and_then(|_| Some($crate::pdu::Error::InsufficientEncryptionKeySize))
                                .or_else(|| Some($crate::pdu::Error::InsufficientEncryption))
                                .unwrap(),

                        $crate::AttributePermissions::Read($crate::AttributeRestriction::Authorization) |
                        $crate::AttributePermissions::Write($crate::AttributeRestriction::Authorization) =>
                            $crate::pdu::Error::InsufficientAuthorization,

                        $crate::AttributePermissions::Read($crate::AttributeRestriction::Authentication) |
                        $crate::AttributePermissions::Write($crate::AttributeRestriction::Authentication) =>
                            $crate::pdu::Error::InsufficientAuthentication,
                    })
                .or(Some($crate::pdu::Error::InsufficientAuthorization)),
        }
    }
}

/// Check if the client has acceptable permissions for the attribute with the provided handle
///
/// see [`check_permissions`]
///
/// # Inputs
/// $this: `self` for `Server`
/// $handle: `u16`
/// $operation_permissions: `&[AttributePermissions]`
///
/// [`check_permissions`]: Server::check_permissions
macro_rules! check_permissions {
    (
    $this:expr,
    $handle:expr,
    $operation_permissions:expr $(,)?
) => {{
        $this
            .attributes
            .get($handle)
            .map(
                |att| match validate_permissions!($this, att.get_permissions(), $operation_permissions) {
                    None => Ok(()),
                    Some(e) => Err(e),
                },
            )
            .unwrap_or(Err($crate::pdu::Error::InvalidHandle))
    }};
}

/// Check if a client can read the given attribute
///
/// Returns the error as to why the client couldn't read the attribute
macro_rules! client_can_read_attribute {
    ($this:expr, $att:expr $(,)?) => {
        match validate_permissions!($this, $att.get_permissions(), &$crate::FULL_READ_PERMISSIONS) {
            None => Ok(()),
            Some(e) => Err(e),
        }
    };
}

/// Check if a client can write the given attribute
///
/// Returns the error as to why the client cannot write to the the attribute
///
/// # Inputs
/// $this: `self` for `Server`
/// $att: `&super::Attribute<_>`
macro_rules! client_can_write_attribute {
    ( $this:expr, $att:expr $(,)?) => {
        match validate_permissions!($this, $att.get_permissions(), &$crate::FULL_WRITE_PERMISSIONS) {
            None => Ok(()),
            Some(e) => Err(e),
        }
    };
}

/// Send an attribute PDU to the client
///
/// # Inputs
/// $this: `self` for `Server`
/// $channel: `impl ConnectionChannel`,
/// $pdu: `pdu::Pdu<_>`,
macro_rules! send_pdu {
    ( $channel:expr, $pdu:expr $(,)?) => {{
        log::info!("(ATT) sending {:?}", $pdu);

        send_pdu!(SKIP_LOG, $channel, $pdu)
    }};

    (SKIP_LOG, $channel:expr, $pdu:expr $(,)?) => {{
        let data = $crate::TransferFormatInto::into(&$pdu);

        $channel.send(data).await.map_err(|e| ConnectionError::SendError(e))
    }};
}

/// Send an error the the client
///
/// # Inpus
/// channel: `impl ConnectionChannel`,
/// handle: `u16`,
/// received_opcode: `ClientPduName`,
/// pdu_error: `pdu::Error`,
macro_rules! send_error {
    (
    $channel:expr,
    $handle:expr,
    $received_opcode:expr,
    $pdu_error:expr $(,)?
) => {{
        log::info!(
            "(ATT) sending error response. Received Op Code: '{:#x}', Handle: '{:?}', error: '{}'",
            Into::<u8>::into($received_opcode),
            $handle,
            $pdu_error
        );

        send_pdu!(
            SKIP_LOG,
            $channel,
            $crate::pdu::error_response($received_opcode.into(), $handle, $pdu_error),
        )
    }};
}

impl<Q> Server<Q>
where
    Q: QueuedWriter,
{
    /// Create a new `Server` for a fixed L2CAP channel
    ///
    /// This is used for creating a `Server` on a L2CAP channel that uses a fixed L2CAP channel ID.
    /// These channels do not have a MTU defined at the L2CAP layer and so the ATT protocol will
    /// manage the MTU.
    ///
    /// # Maximum Transmission Unit (MTU)
    /// For fixed channels, the MTU is determined either by a default MTU (determined by a higher
    /// layer protocol) or through an exchange process to use a different MTU.
    ///
    /// Input `max_mtu` is the maximum, maximum transmission unit (MTU) supported by this `Server`.
    /// The client will be able to negotiate to set the MTU up to this value by sending a *MTU
    /// exchange* PDU to this Server.
    ///
    /// ### Default MTU
    /// The default MTU, practically speaking, should be no less than 21. This is the size of a
    /// *read by type request* or *read by group type request* with a sixteen bit attribute group
    /// type. A smaller default MTU can be used, but limitations of functionality will be put on the
    /// `Server`. There is no minimum size of the `default_mtu` but trying to process request or
    /// send responses may induce errors if the packet cannot be formed due to the minimum size of
    /// the packet being larger then the `default_mtu` (this includes the exchange MTU
    /// request/response).
    ///
    /// # Panic
    /// Input `default_mtu` must be less than or equal to `max_mtu`.
    pub fn new_fixed<A>(default_mtu: u16, max_mtu: u16, server_attributes: A, queued_writer: Q) -> Self
    where
        A: Into<Option<ServerAttributes>>,
    {
        assert!(default_mtu <= max_mtu);

        let mtu = default_mtu.into();

        let max_mtu = max_mtu.into();

        let attributes = server_attributes.into().unwrap_or(ServerAttributes::new());

        let given_permissions = alloc::vec![
            AttributePermissions::Read(AttributeRestriction::None),
            AttributePermissions::Write(AttributeRestriction::None),
        ];

        Self {
            mtu,
            max_mtu,
            attributes,
            given_permissions,
            blob_data: None,
            queued_writer,
        }
    }

    /// Get a reference to the attributes of the server
    pub fn get_attributes(&self) -> &ServerAttributes {
        &self.attributes
    }

    /// Get a mutable reference to the attributes of the server
    pub fn get_mut_attributes(&mut self) -> &mut ServerAttributes {
        &mut self.attributes
    }

    /// Get the current MTU
    ///
    /// # Note
    /// The return can be safely casted to a `u16`
    pub fn get_mtu(&self) -> usize {
        self.mtu
    }

    /// Give a permission to the client
    ///
    /// This doesn't check that the client is qualified to receive the permission, it just adds an
    /// indication on the server that the client has it.
    pub fn give_permissions_to_client<P>(&mut self, permissions: P)
    where
        P: core::borrow::Borrow<[AttributePermissions]>,
    {
        permissions.borrow().iter().for_each(|p| {
            if let Err(pos) = self.given_permissions.binary_search(&p) {
                self.given_permissions.insert(pos, *p);
            }
        })
    }

    /// Remove one or more permission given to the client
    ///
    /// This will remove every permission in `permissions` from the client.
    pub fn revoke_permissions_of_client<P>(&mut self, permissions: P)
    where
        P: core::borrow::Borrow<[AttributePermissions]>,
    {
        self.given_permissions = self
            .given_permissions
            .iter()
            .filter(|p| !permissions.borrow().contains(p))
            .copied()
            .collect();
    }

    /// Check if the client has acceptable permissions for the attribute with the provided handle
    ///
    /// This function is used to check the permissions of a specified attribute against the
    /// permissions given to the client to perform an operation. If a client has been given access
    /// to perform the operation with the attribute, then the return will be `Ok`. When the client
    /// does not have permission to perform the operation, an error is returned.
    ///
    /// Input `permissions` is the list of permissions acceptable for an operation. The permissions
    /// list is tested against both the permissions list of the attribute and the list of
    /// permissions granted to the client. If any of the permissions within `permissions` is also
    /// in both of the other permissions lists, then this method will return `Ok(_)`.
    ///
    /// # Error
    /// The returned error is a bit of a best guess by the method. It gives the most general reason
    /// for why a permission was not satisfied.
    ///
    /// ### Bad Handle
    /// If there is no attribute with the handle `handle`, then the error
    /// [`InvalidHandle`](super::pdu::Error::InvalidHandle) is returned.
    ///
    /// ### Read and Write
    /// Read and write are the two gatekeeper permissions. Permissions for read do not extend to
    /// write and vise versa. Every permission must be granted individually. However when an
    /// attribute doesn't have any permissions associated with a Read or a Write, this method will
    /// return one of these errors.
    /// - [`Read`](super::AttributePermissions::Read) ->
    ///   [`ReadNotPermitted`](super::pdu::Error::ReadNotPermitted)
    /// - [`Write`](super::AttributePermissions::Write) ->
    ///   [`WriteNotPermitted`](super::pdu::Error::WriteNotPermitted)
    ///
    /// ### Read and Write Restrictions
    /// Attribute restrictions are used to further refine when a Read or a Write is available to
    /// a client. As an example, writing to the attribute may require the encryption permissions
    /// specific to writing to be granted. These are the errors that are returned whenever a client
    /// doesn't have the appropriate access restriction granted to them for the specific read or
    /// write operation.
    /// - [`Encryption`](super::AttributeRestriction::Encryption) ->
    ///   [`InsufficientEncryption`](pdu::Error::InsufficientEncryption)
    /// - [`Authentication`](super::AttributeRestriction::Authentication) ->
    ///   [`InsufficientAuthentication`](pdu::Error::InsufficientAuthentication)
    /// - [`Authorization`](super::AttributeRestriction::Authorization) ->
    ///   [`InsufficientAuthorization`](pdu::Error::InsufficientAuthorization)
    ///
    /// ##### Encryption Key Size
    /// Encryption is further divided into level of encryption. The error `InsufficientEncryption`
    /// is used whenever the client does not have any encryption and tries to perform an operation,
    /// but the error
    /// [`InsufficientEncryptionKeySize`](pdu::Error::InsufficientEncryptionKeySize) is returned
    /// when the client does not have the encryption permission with (one of) the accepted key size.
    pub fn check_permissions(
        &self,
        handle: u16,
        operation_permissions: &[AttributePermissions],
    ) -> Result<(), pdu::Error> {
        check_permissions!(self, handle, operation_permissions)
    }

    /// Process a received ATT PDU
    ///
    /// The packet is assumed to be in the form of an Attribute protocol request packet. This
    /// function will then process the request and send to the client the appropriate response
    /// packet.
    ///
    /// This function is a combination of the methods
    /// [`parse_att_pdu`](crate::server::Server::parse_att_pdu) and
    /// [`process_parsed_acl_data`](crate::server::Server::process_parsed_att_pdu). It is
    /// recommended to use this function over those two functions when this `Server` is at the top
    /// of your server stack (you're not using GATT or some other custom higher layer protocol).
    pub async fn process_att_pdu<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        pdu: &l2cap::pdu::BasicFrame<Vec<u8>>,
    ) -> Result<Status, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        let (pdu_type, payload) = self.parse_att_pdu(pdu)?;

        self.process_parsed_att_pdu(channel, pdu_type, payload).await
    }

    /// Parse an ATT PDU
    ///
    /// This checks the following things
    /// * The ACL packet has the correct channel identifier for the Attribute Protocol
    /// * The payload of the packet is not empty
    /// * The pdu type is a [`ClientPduName`](super::client::ClientPduName) enum
    ///
    /// # Note
    /// This is meant to be used by implementations of higher layer protocols for interfacing with
    /// the attribute protocol. Use
    /// [`process_acl_data`](crate::server::Server::process_att_pdu) when directly using this
    /// server for communication with a client device.
    pub fn parse_att_pdu<'a>(
        &self,
        acl_packet: &'a l2cap::pdu::BasicFrame<Vec<u8>>,
    ) -> Result<(ClientPduName, &'a [u8]), super::Error> {
        use l2cap::cid::{ChannelIdentifier, LeCid};

        match acl_packet.get_channel_id() {
            ChannelIdentifier::Le(LeCid::AttributeProtocol) => {
                let (att_type, payload) = acl_packet.get_payload().split_at(1);

                if att_type.len() > 0 {
                    let pdu_type = super::client::ClientPduName::try_from(att_type[0])
                        .or(Err(super::Error::UnknownOpcode(att_type[0])))?;

                    Ok((pdu_type, payload))
                } else {
                    Err(super::Error::Empty)
                }
            }
            _ => Err(super::Error::IncorrectChannelId(acl_packet.get_channel_id())),
        }
    }

    /// Process a parsed ATT PDU
    ///
    /// This will take the data from the Ok result of [`parse_acl_packet`](Server::parse_att_pdu).
    /// This is otherwise equivalent to the function [`process_acl_data`](Server::parse_att_pdu)
    /// (really `process_acl_data` is just `parse_acl_packet` followed by this function) and is
    /// useful for higher layer protocols that need to parse an ACL packet before performing their
    /// own calculations on the data and *then* have the Attribute server processing the data.
    ///
    /// # Note
    /// This is meant to be used by implementations of higher layer protocols for interfacing with
    /// the attribute protocol. Use
    /// [`process_acl_data`](crate::server::Server::process_att_pdu) when directly using this
    /// server for communication with a client device.
    pub async fn process_parsed_att_pdu<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        pdu_type: ClientPduName,
        payload: &[u8],
    ) -> Result<Status, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        match pdu_type {
            ClientPduName::ExchangeMtuRequest => {
                self.process_exchange_mtu_request(channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await?
            }

            ClientPduName::WriteRequest => self.process_write_request(channel, &payload).await?,

            ClientPduName::ReadRequest => {
                self.process_read_request(channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await?
            }

            ClientPduName::FindInformationRequest => {
                self.process_find_information_request(channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await?
            }

            ClientPduName::FindByTypeValueRequest => self.process_find_by_type_value_request(channel, &payload).await?,

            ClientPduName::ReadByTypeRequest => {
                self.process_read_by_type_request(channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await?
            }

            ClientPduName::ReadBlobRequest => {
                return self
                    .process_read_blob_request(channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await;
            }

            ClientPduName::PrepareWriteRequest => self.process_prepare_write_request(channel, &payload).await?,

            ClientPduName::ExecuteWriteRequest => {
                self.process_execute_write_request(channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await?
            }

            ClientPduName::HandleValueConfirmation => return Ok(Status::IndicationConfirmed),

            ClientPduName::ReadMultipleRequest
            | ClientPduName::WriteCommand
            | ClientPduName::SignedWriteCommand
            | ClientPduName::ReadByGroupTypeRequest
            | ClientPduName::ReadMultipleVariable => {
                send_error!(channel, 0, pdu_type, pdu::Error::RequestNotSupported)?
            }
        };

        Ok(Status::None)
    }

    /// Send out a notification
    ///
    /// The attribute value at the given handle will be sent out as a notification.
    ///
    /// If the transfer format of the attribute value is larger than the maximum transfer format
    /// size for the notification, the client must send one or more a read blob request to get the
    /// entire value. Sending a notification does not require the client and attribute to have read
    /// permissions, but *in order to enable a blob request, the attribute must be readable and the
    /// client must have been granted sufficient read permissions*. Depending on the implementation
    /// of the [`QueuedWrite`] used by this `Server`, notifications and indications may need to be
    /// halted until a [`Status::ReadBlobComplete`] is returned by a client PDU processing method.
    ///
    /// `true` is returned if the notification contains the entire attribute value.
    ///
    /// # Error
    /// An error is returned if there is not an attribute at `handle` or the notification could not
    /// be sent.
    pub async fn send_notification<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        handle: u16,
    ) -> Result<bool, ServerInitiatedError<T>>
    where
        T: LogicalLink,
    {
        match self.attributes.get_mut(handle) {
            Some(attribute) => {
                let mut ret_val = true;

                let read_fut = attribute.get_mut_value().read();

                let data = read_fut.await.map_err(|e| ServerInitiatedError::FailedToRead(e))?;

                let mut notification = pdu::create_notification(handle, data);

                if notification.get_parameters().0.get_data().len() > (self.mtu - 3) {
                    use core::mem::replace;

                    let sent = notification.get_parameters().0.get_data()[..(self.mtu - 3)].to_vec();

                    self.set_blob_data(
                        replace(notification.get_mut_parameters().0.get_mut_data(), sent),
                        handle,
                    );

                    ret_val = false;
                }

                send_pdu!(channel, notification).map_err(|e| ServerInitiatedError::ConnectionError(e.into()))?;

                Ok(ret_val)
            }
            None => Err(ServerInitiatedError::InvalidHandle(handle)),
        }
    }

    /// Send out a notification with some data
    ///
    /// This sends out a notification with the input `value` as the **Attribute Value** parameter.
    /// The type for `value` does not need to match the type of the data stored within the attribute
    /// at `handle`.
    ///
    /// # Data larger than the MTU
    /// If the transfer format of `value` is larger than the maximum transfer format size for the
    /// notification, the client must send one or more read blob requests to get the entire value.
    /// Depending on the implementation of the [`QueuedWrite`] used by this `Server`, notifications
    /// and indications may need to be halted until a [`Status::ReadBlobComplete`] is returned by a
    /// client PDU processing method.
    ///
    /// `true` is returned if the notification contains the entire attribute value.
    ///
    /// ## Temporary restrictions
    /// Input `restrictions` is used to set temporary read restrictions for a read blob request.
    /// These restrictions only apply to this request, any other read requests from the client for
    /// the attribute at `handle` will use the permissions of the attribute and the temporary
    /// `restrictions` are also dropped.
    ///
    /// If `restrictions` is set to `None` it will refer to the read restrictions of the attribute
    /// at `handle`. But if the attribute at `handle` is not readable, then the restrictions will be
    /// defaulted to the *clients currently granted read permissions*. If `restrictions` is set to
    /// `Some(..)` then it will be the temporary permissions for executing a blob read.
    ///
    /// # Error
    /// An error is returned if there is not an attribute at `handle` or the notification could not
    /// be sent.
    pub async fn send_notification_with<'a, T, V, R>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        handle: u16,
        value: &V,
        restrictions: R,
    ) -> Result<bool, ServerInitiatedError<T>>
    where
        T: LogicalLink,
        V: TransferFormatInto + ?Sized,
        R: Into<Option<&'a [AttributeRestriction]>>,
    {
        if self.attributes.get(handle).is_some() {
            let mut ret_val = true;

            let data = TransferFormatInto::into(&value);

            let mut notification = pdu::create_notification(handle, data);

            if notification.get_parameters().0.get_data().len() > (self.mtu - 3) {
                use core::mem::replace;

                let sent = notification.get_parameters().0.get_data()[..(self.mtu - 3)].to_vec();

                let blob = replace(notification.get_mut_parameters().0.get_mut_data(), sent);

                self.set_blob_for_server_sent_with(blob, handle, restrictions.into());

                ret_val = false;
            }

            send_pdu!(channel, notification).map_err(|e| ServerInitiatedError::ConnectionError(e.into()))?;

            Ok(ret_val)
        } else {
            Err(ServerInitiatedError::InvalidHandle(handle))
        }
    }

    /// Send out a indication
    ///
    /// The attribute value at the given handle will be sent out as a indication.
    ///
    /// If the transfer format of the attribute value is larger than the maximum transfer format
    /// size for the indication, the client must send one or more a read blob request to get the
    /// entire value. Sending a indication does not require the client and attribute to have read
    /// permissions, but *in order to enable a blob request, the attribute must be readable and the
    /// client must have been granted sufficient read permissions*. Depending on the implementation
    /// of the [`QueuedWrite`] used by this `Server`, notifications and indications may need to be
    /// halted until a [`Status::ReadBlobComplete`] is returned by a client PDU processing method.
    ///
    /// `true` is returned if the notification contains the entire attribute value.
    ///
    /// # Note
    /// [`Status::IndicationConfirmed`] is returned by [`process_acl_data`] or
    /// [`process_parsed_acl_data`] whenever they process a
    /// [`ClientPduName::HandleValueConfirmation`].
    ///
    /// # Error
    /// An error is returned if there is not an attribute at `handle` or the notification could not
    /// be sent.
    pub async fn send_indication<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        handle: u16,
    ) -> Result<bool, ServerInitiatedError<T>>
    where
        T: LogicalLink,
    {
        match self.attributes.get_mut(handle) {
            Some(attribute) => {
                let mut ret_val = true;

                let read_fut = attribute.get_mut_value().read();

                let data = read_fut.await.map_err(|e| ServerInitiatedError::FailedToRead(e))?;

                let mut indication = pdu::create_indication(handle, data);

                if indication.get_parameters().0.get_data().len() > (self.mtu - 3) {
                    use core::mem::replace;

                    let sent = indication.get_parameters().0.get_data()[..(self.mtu - 3)].to_vec();

                    self.set_blob_data(replace(indication.get_mut_parameters().0.get_mut_data(), sent), handle);

                    ret_val = false;
                }

                send_pdu!(channel, indication).map_err(|e| ServerInitiatedError::ConnectionError(e.into()))?;

                Ok(ret_val)
            }
            None => Err(ServerInitiatedError::InvalidHandle(handle)),
        }
    }

    /// Send out a indication with some data
    ///
    /// This sends out a indication with the input `value` as the **Attribute Value** parameter.
    /// The type for `value` does not need to match the type of the data stored within the attribute
    /// at `handle`.
    ///
    /// # Data larger than the MTU
    /// If the transfer format of `value` is larger than the maximum transfer format size for the
    /// indication, the client must send one or more read blob requests to get the entire value.
    /// Depending on the implementation of the [`QueuedWrite`] used by this `Server`, notifications
    /// and indications may need to be halted until a [`Status::ReadBlobComplete`] is returned by a
    /// client PDU processing method.
    ///
    /// `true` is returned if the notification contains the entire attribute value.
    ///
    /// ## Temporary restrictions
    /// Input `restrictions` is used to set temporary read restrictions for a read blob request.
    /// These restrictions only apply to this request, any other read requests from the client for
    /// the attribute at `handle` will use the permissions of the attribute and the temporary
    /// `restrictions` are also dropped.
    ///
    /// If `restrictions` is set to `None` it will refer to the read restrictions of the attribute
    /// at `handle`. But if the attribute at `handle` is not readable, then the restrictions will be
    /// defaulted to the *clients currently granted read permissions*. If `restrictions` is set to
    /// `Some(..)` then it will be the temporary permissions for executing a blob read.
    ///
    /// # Note
    /// [`Status::IndicationConfirmed`] is returned by [`process_acl_data`] or
    /// [`process_parsed_acl_data`] whenever they process a
    /// [`ClientPduName::HandleValueConfirmation`].
    ///
    /// # Error
    /// An error is returned if there is not an attribute at `handle` or the notification could not
    /// be sent.
    pub async fn send_indication_with<'a, T, V, R>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        handle: u16,
        value: &V,
        restrictions: R,
    ) -> Result<bool, ServerInitiatedError<T>>
    where
        T: LogicalLink,
        V: TransferFormatInto + ?Sized,
        R: Into<Option<&'a [AttributeRestriction]>>,
    {
        if self.attributes.get(handle).is_some() {
            let mut ret_val = true;

            let data = TransferFormatInto::into(&value);

            let mut indication = pdu::create_indication(handle, data);

            if indication.get_parameters().0.get_data().len() > (self.mtu - 3) {
                use core::mem::replace;

                let sent = indication.get_parameters().0.get_data()[..(self.mtu - 3)].to_vec();

                let blob = replace(indication.get_mut_parameters().0.get_mut_data(), sent);

                self.set_blob_for_server_sent_with(blob, handle, restrictions.into());

                ret_val = false;
            }

            send_pdu!(channel, indication).map_err(|e| ServerInitiatedError::ConnectionError(e.into()))?;

            Ok(ret_val)
        } else {
            Err(ServerInitiatedError::InvalidHandle(handle))
        }
    }

    fn get_att(&self, handle: u16) -> Result<&super::Attribute<Box<dyn ServerAttributeValue>>, pdu::Error> {
        if pdu::is_valid_handle(handle) {
            self.attributes.get(handle).ok_or(pdu::Error::InvalidHandle)
        } else {
            Err(pdu::Error::InvalidHandle)
        }
    }

    fn get_att_mut(&mut self, handle: u16) -> Result<&mut super::Attribute<Box<dyn ServerAttributeValue>>, pdu::Error> {
        if pdu::is_valid_handle(handle) {
            self.attributes.get_mut(handle).ok_or(pdu::Error::InvalidHandle)
        } else {
            Err(pdu::Error::InvalidHandle)
        }
    }

    /// Set the blob data
    ///
    /// Blob data is used by the client to request additional data of a *read* response whenever the
    /// response exceeds either the MTU or the maximum size for the response.
    ///
    /// This method is normally only used by a higher layer profile/protocol implementation. It is
    /// not intended to be directly called by a application as it can be tricky to correctly assign
    /// the blob data. The current blob must be congruent with the specification for the last sent
    /// response to a read-kind request.
    ///
    /// Input `blob` must be the *full* data, in transfer format, of the read response. This client
    /// can technically re-request data that was already sent so `blob` must be the full value.
    ///
    /// `handle` is the handle to the attribute to be read or the starting handle within a request.
    pub fn set_blob_data(&mut self, blob: alloc::vec::Vec<u8>, handle: u16) {
        self.blob_data = MultiReqData {
            tf_data: blob,
            handle,
            temporary_read_restrictions: None,
        }
        .into();
    }

    /// Set the blob data for "server sent with"
    ///
    /// This is used by the method [`send_notification_with`] and [`send_indication_with`]
    ///
    /// [`send_notification_with`]: Server::send_notification_with
    /// [`send_indication_with`]: Server::send_indication_with
    fn set_blob_for_server_sent_with(
        &mut self,
        blob: Vec<u8>,
        handle: u16,
        temporary_restrictions: Option<&[AttributeRestriction]>,
    ) {
        use core::mem::discriminant;

        macro_rules! set_blob_data {
            ($data:expr, $handle:expr) => {
                self.blob_data = MultiReqData {
                    tf_data: $data,
                    handle: $handle,
                    temporary_read_restrictions: None,
                }
                .into()
            };

            ($data:expr, $handle:expr, $restrictions:expr) => {
                self.blob_data = MultiReqData {
                    tf_data: $data,
                    handle: $handle,
                    temporary_read_restrictions: $restrictions
                        .iter()
                        .fold(bo_tie_core::buffer::stack::LinearBuffer::new(), |mut lb, r| {
                            let permission = $crate::AttributePermissions::Read(*r);

                            if !lb.contains(&permission) {
                                lb.try_push(permission).unwrap();
                            }

                            lb
                        })
                        .into(),
                }
                .into()
            };
        }

        if let Some(restrictions) = temporary_restrictions {
            set_blob_data!(blob, handle, restrictions);
        } else if self
            .attributes
            .get(handle)
            .unwrap()
            .get_permissions()
            .iter()
            .any(|p| discriminant(&AttributePermissions::Read(AttributeRestriction::None)) == discriminant(p))
        {
            set_blob_data!(blob, handle);
        } else {
            let mut lb = bo_tie_core::buffer::stack::LinearBuffer::<
                { AttributeRestriction::full_depth() },
                AttributeRestriction,
            >::new();

            self.given_permissions
                .iter()
                .filter_map(|p| {
                    if let AttributePermissions::Read(r) = p {
                        Some(r)
                    } else {
                        None
                    }
                })
                .copied()
                .for_each(|r| lb.try_push(r).unwrap());

            set_blob_data!(blob, handle, lb);
        }
    }

    /// Write the interface data to the attribute
    ///
    /// Returns an error if the client doesn't have the adequate permissions or the handle is
    /// invalid.
    async fn write_att(&mut self, handle: u16, intf_data: &[u8]) -> Result<(), pdu::Error> {
        let opt_write_error = {
            let att = self.get_att(handle)?;

            client_can_write_attribute!(self, att)
        };

        if let Err(err) = opt_write_error {
            Err(err.into())
        } else {
            match self.get_att_mut(handle) {
                Ok(att) => {
                    let value = att.get_mut_value();

                    let fut = value.try_set_value_from_transfer_format(intf_data);

                    fut.await
                }
                Err(_) => Err(pdu::Error::InvalidPDU.into()),
            }
        }
    }

    /// Process a exchange MTU request from the client
    async fn process_exchange_mtu_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        client_mtu: u16,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        log::info!("(ATT) processing PDU ATT_EXCHANGE_MTU_REQ {{ mtu: {} }}", client_mtu);

        let new_mtu = self.max_mtu.min(client_mtu.into());

        self.mtu = new_mtu;

        send_pdu!(channel, pdu::exchange_mtu_response(new_mtu as u16),)
    }

    /// Process a Read Request from the client
    async fn process_read_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        handle: u16,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        log::info!("(ATT) processing PDU ATT_READ_REQ {{ handle: {:#X} }}", handle);

        let read_error_result = check_permissions!(self, handle, &crate::FULL_READ_PERMISSIONS);

        if let Err(e) = read_error_result {
            return send_error!(channel, handle, ClientPduName::ReadRequest, e);
        }

        let future = self.attributes.get_mut(handle).unwrap().get_mut_value().read_response();

        let future_result = future.await;

        let mut read_response = match future_result {
            Ok(read_response) => read_response,
            Err(e) => {
                return send_error!(channel, handle, ClientPduName::ReadRequest, e);
            }
        };

        if read_response.get_parameters().0.len() > (self.mtu - 1) {
            use core::mem::replace;

            let sent = read_response.get_parameters().0[..(self.mtu - 1)].to_vec();

            self.set_blob_data(replace(&mut read_response.get_mut_parameters().0, sent), handle);
        }

        send_pdu!(channel, read_response)
    }

    /// Process a Write Request from the client
    async fn process_write_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        payload: &[u8],
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        // Need to split the handle from the raw data as the data type is not known
        let handle = TransferFormatTryFrom::try_from(&payload[..2]).unwrap();

        log::info!("(ATT) processing PDU ATT_WRITE_REQ {{ handle: {:#X} }}", handle);

        match self.write_att(handle, &payload[2..]).await {
            Ok(_) => send_pdu!(channel, pdu::write_response()),
            Err(e) => send_error!(channel, handle, ClientPduName::WriteRequest, e),
        }
    }

    /// Process a Find Information Request form the client
    async fn process_find_information_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        handle_range: pdu::HandleRange,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        use core::cmp::min;

        log::info!(
            "(ATT) processing PDU ATT_FIND_INFORMATION_REQ {{ start handle: {}, end handle: {} }}",
            handle_range.starting_handle,
            handle_range.ending_handle
        );

        if !handle_range.is_valid() {
            return send_error!(
                channel,
                handle_range.starting_handle,
                ClientPduName::FindInformationRequest,
                pdu::Error::InvalidHandle,
            );
        }

        // Both the start and ending handles cannot be past the actual length of the attributes
        let start = if handle_range.starting_handle as usize <= self.attributes.count() {
            handle_range.starting_handle as usize
        } else {
            return send_error!(
                channel,
                handle_range.starting_handle,
                ClientPduName::FindInformationRequest,
                pdu::Error::AttributeNotFound
            );
        };

        let stop = min(handle_range.ending_handle as usize, self.attributes.count());

        let opt_size = core::cell::Cell::new(None);

        let mut data = self
            .attributes
            .attributes
            .get(start..=stop)
            .into_iter()
            .flatten()
            .take_while(|attribute| match opt_size.get() {
                None => true,
                Some(2) => attribute.get_uuid().can_be_16_bit(),
                Some(16) => !attribute.get_uuid().can_be_16_bit(),
                _ => unreachable!(),
            })
            .take_while(|attribute| client_can_read_attribute!(self, attribute).is_ok())
            .inspect(|att| {
                if opt_size.get().is_none() {
                    if att.get_uuid().can_be_16_bit() {
                        opt_size.set(Some(2))
                    } else {
                        opt_size.set(Some(16))
                    }
                }
            })
            .enumerate()
            .take_while(|(cnt, _)| (cnt + 1) * (opt_size.get().unwrap() + 2) < (self.mtu - 2))
            .fold(vec![0], |mut data, (_, attribute)| {
                let mut buffer = [0u8; 16 + 2];

                let len = opt_size.get().unwrap() + 2;

                attribute.get_handle().unwrap().build_into_ret(&mut buffer[..2]);

                attribute.get_uuid().build_into_ret(&mut buffer[2..len]);

                data.extend_from_slice(&buffer[..len]);

                data
            });

        // This is needed because otherwise opt_size
        // will be added as a 'field' to the generated
        // future because of `send_err!`. `Cell` cannot
        // be shared between threads by a reference
        // which causes the generated future to not
        // implement `Send`.
        let opt_size = opt_size.get();

        match opt_size {
            Some(2) => data[0] = 1,
            Some(16) => data[0] = 2,
            None => {
                // if opt_size is `None`, no attributes were found
                return send_error!(
                    channel,
                    start as u16,
                    ClientPduName::FindInformationRequest,
                    pdu::Error::AttributeNotFound,
                );
            }
            _ => unreachable!(),
        }

        let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), data);

        send_pdu!(channel, pdu)?;

        Ok(())
    }

    /// Process find by type value request
    ///
    /// # Note
    ///
    /// Because the Attribute Protocol doesn't define what a 'group' is this returns the group
    /// end handle with the same found attribute handle.
    async fn process_find_by_type_value_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        payload: &[u8],
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        if payload.len() >= 6 {
            let handle_range: pdu::HandleRange = TransferFormatTryFrom::try_from(&payload[..4]).unwrap();

            let att_type: crate::Uuid = TransferFormatTryFrom::try_from(&payload[4..6]).unwrap();

            log::info!(
                "(ATT) processing PDU ATT_FIND_BY_TYPE_VALUE_REQ {{ start handle: {:#X}, end \
                handle: {:#X}, type: {:?}}}",
                handle_range.starting_handle,
                handle_range.ending_handle,
                att_type
            );

            let raw_value = &payload[6..];

            if handle_range.is_valid() {
                use core::cmp::min;

                let start = if handle_range.starting_handle as usize <= self.attributes.count() {
                    handle_range.starting_handle as usize
                } else {
                    return send_error!(
                        channel,
                        handle_range.starting_handle,
                        ClientPduName::FindByTypeValueRequest,
                        pdu::Error::AttributeNotFound
                    );
                };

                let end = min(handle_range.ending_handle as usize, self.attributes.count());

                let payload_max = self.mtu - 1;

                let mut cnt = 0;

                let mut transfer = Vec::new();

                for att in self.attributes.attributes[start..=end].iter_mut() {
                    if att.get_uuid() == &att_type
                        && client_can_read_attribute!(self, att).is_ok()
                        && att.get_mut_value().cmp_value_to_raw_transfer_format(raw_value).await
                    {
                        cnt += 1;

                        if cnt * 4 < payload_max {
                            // See function doc for why group handle is same as found handle.
                            let response =
                                pdu::TypeValueResponse::new(att.get_handle().unwrap(), att.get_handle().unwrap());

                            transfer.push(response);
                        } else {
                            break;
                        }
                    }
                }

                if transfer.is_empty() {
                    send_error!(
                        channel,
                        handle_range.starting_handle,
                        ClientPduName::FindByTypeValueRequest,
                        pdu::Error::AttributeNotFound,
                    )
                } else {
                    let pdu = pdu::Pdu::new(ServerPduName::FindByTypeValueResponse.into(), transfer);

                    send_pdu!(channel, pdu,)
                }
            } else {
                send_error!(
                    channel,
                    handle_range.starting_handle,
                    ClientPduName::FindByTypeValueRequest,
                    pdu::Error::InvalidHandle,
                )
            }
        } else {
            send_error!(
                channel,
                0,
                ClientPduName::FindInformationRequest,
                pdu::Error::InvalidPDU,
            )
        }
    }

    /// Process Read By Type Request
    async fn process_read_by_type_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        type_request: pdu::TypeRequest,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        macro_rules! enough_room_in_response {
            ($cnt:expr, $size:expr) => {
                ($cnt + 1) * ($size + 2) < self.mtu - 2
            };
        }

        log::info!(
            "(ATT) processing PDU ATT_READ_BY_TYPE_REQ {{ start handle: {:#X}, end handle: {:#X}, \
            type: {:?} }}",
            type_request.handle_range.starting_handle,
            type_request.handle_range.ending_handle,
            type_request.attr_type
        );

        use core::cmp::min;

        let handle_range = type_request.handle_range;

        let desired_att_type = type_request.attr_type;

        if !handle_range.is_valid() {
            return send_error!(
                channel,
                handle_range.starting_handle,
                ClientPduName::ReadByTypeRequest,
                pdu::Error::InvalidHandle,
            );
        }

        let start = if handle_range.starting_handle as usize <= self.attributes.count() {
            handle_range.starting_handle as usize
        } else {
            return send_error!(
                channel,
                handle_range.starting_handle,
                ClientPduName::FindByTypeValueRequest,
                pdu::Error::AttributeNotFound
            );
        };

        let end = min(handle_range.ending_handle as usize, self.attributes.count());

        let payload_max = self.mtu - 2;

        let mut init_iter = self.attributes.attributes[start..=end]
            .iter_mut()
            .filter(|att| att.get_uuid() == &desired_att_type);

        let first = init_iter.next();

        if first.is_none() {
            return send_error!(
                channel,
                handle_range.starting_handle,
                ClientPduName::ReadByTypeRequest,
                pdu::Error::AttributeNotFound,
            );
        }

        let first_match = first.unwrap();

        let read_permissions_result = client_can_read_attribute!(self, first_match);

        if let Err(e) = read_permissions_result {
            return send_error!(
                channel,
                handle_range.starting_handle,
                ClientPduName::ReadByTypeRequest,
                e,
            );
        }

        let first_handle = first_match.get_handle().unwrap();

        let first_val = first_match.get_mut_value();

        let read_fut = first_val.read();

        let future_result = read_fut.await;

        let first_response = match future_result {
            Ok(first_data) => first_data,
            Err(e) => {
                return send_error!(
                    channel,
                    handle_range.starting_handle,
                    ClientPduName::ReadByTypeRequest,
                    e
                )
            }
        };

        let tf_data_len = first_response.len();

        let mut responses = Vec::new();

        let fits_in_pdu = enough_room_in_response!(0, tf_data_len);

        if !fits_in_pdu {
            // This is where the data to be transferred of the first found attribute
            // is too large or equal to the connection MTU (minus the header length).
            // Here, a read by type response is generated with as much of the value
            // transfer format that can fit into the payload. A read blob request from
            // the client is then required to complete the full read.

            // Read type response includes a 2 byte handle, so the maximum byte
            // size for the data is the payload - 2
            let max_size = payload_max - 2;

            let sent = first_response[0..max_size].to_vec();

            // Move the full response to a blob data
            self.set_blob_data(first_response, first_handle);

            responses.push(pdu::ReadTypeResponse::new(first_handle, sent));
        } else {
            responses.push(pdu::ReadTypeResponse::new(first_handle, first_response));

            let mut cnt = 1;

            for att in init_iter {
                // break if there isn't enough room in the
                // response for another attribute value
                if !enough_room_in_response!(cnt, tf_data_len) {
                    break;
                }

                // skip those that the client cannot read
                if client_can_read_attribute!(self, att).is_err() {
                    continue;
                }

                let handle = att.get_handle().unwrap();

                let val = att.get_mut_value();

                let read_response_fut = val.read_type_response(handle, tf_data_len);

                let read_response_result = read_response_fut.await;

                match read_response_result {
                    Ok(None) | Err(_) => continue,
                    Ok(Some(response)) => {
                        cnt += 1;

                        responses.push(response)
                    }
                }
            }
        }

        let pdu = pdu::read_by_type_response(responses);

        send_pdu!(channel, pdu)
    }

    /// Process read blob request
    async fn process_read_blob_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        blob_request: pdu::ReadBlobRequest,
    ) -> Result<Status, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        log::info!(
            "(ATT) processing PDU ATT_READ_BLOB_REQ {{ handle: {:#X}, offset {:#X} }}",
            blob_request.handle,
            blob_request.offset
        );

        let check_permissions_result = check_permissions!(self, blob_request.handle, &super::FULL_READ_PERMISSIONS);

        if let Err(e) = check_permissions_result {
            return send_error!(channel, blob_request.handle, ClientPduName::ReadBlobRequest, e).map(|_| Status::None);
        }

        // Make a new blob if blob data doesn't exist or the blob handle does not match the
        // requested for handle
        let use_old_blob = self
            .blob_data
            .as_ref()
            .map(|bd| bd.handle == blob_request.handle)
            .unwrap_or_default();

        let response_result = match (use_old_blob, blob_request.offset) {
            // No prior blob or start of new blob
            (false, _) | (_, 0) => self
                .create_blob_send_response(channel, &blob_request)
                .await
                .map(|_| Status::None),

            // Continuing reading prior blob
            (true, offset) => self.use_blob_send_response(channel, offset).await,
        };

        if let Err(ConnectionError::AttError(super::Error::PduError(e))) = response_result {
            send_error!(channel, blob_request.handle, ClientPduName::ReadBlobRequest, e,).map(|_| Status::None)
        } else {
            response_result
        }
    }

    /// Create a new blob and send the blob response
    ///
    /// This function is a helper function for process read blob request
    ///
    /// # Warning
    /// This does not check permissions for accessibility of the attribute by the client and assumes
    /// the handle requested is valid.
    #[inline]
    async fn create_blob_send_response<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        br: &pdu::ReadBlobRequest,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        let read_future = {
            let attribute = self.attributes.get_mut(br.handle).unwrap();

            attribute.get_mut_value().read()
        };

        let read_result = read_future.await;

        let data = match read_result {
            Ok(data) => data,
            Err(e) => return send_error!(channel, br.handle, ClientPduName::ReadBlobRequest, e),
        };

        let (response, will_blob) = self.new_read_blob_response(&data, br.offset)?;

        let ret = send_pdu!(channel, response);

        if will_blob {
            self.blob_data = MultiReqData {
                handle: br.handle,
                tf_data: data,
                temporary_read_restrictions: None,
            }
            .into();
        }

        ret
    }

    /// Use the current blob and send the blob response
    ///
    /// This function is a helper function for process read blob request
    ///
    /// # Note
    /// If the entire blob was sent to the client, the blob is deleted from `self`.
    ///
    /// # Warning
    /// This does not check permissions for accessibility of the attribute by the client and assumes
    /// that `blob_data` is `Some(_)`
    #[inline]
    async fn use_blob_send_response<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        offset: u16,
    ) -> Result<Status, ConnectionError<T>>
    where
        T: LogicalLink,
    {
        let data = self.blob_data.as_ref().unwrap();

        let response_return = self.new_read_blob_response(&data.tf_data, offset)?;

        match response_return {
            (rsp, false) => {
                send_pdu!(channel, rsp)?;

                // This is the final piece of the blob
                self.blob_data = None;

                Ok(Status::ReadBlobComplete)
            }

            (rsp, true) => send_pdu!(channel, rsp).map(|_| Status::None),
        }
    }

    /// Create a Read Blob Response
    ///
    /// This return is the Read Blob Response with a boolean to indicate if the response payload has
    /// the maximum number of data bytes that can be sent. If the boolean is false then this is used
    /// to indicate that the last blob is sent.
    #[inline]
    fn new_read_blob_response<'a>(
        &self,
        data: &'a [u8],
        offset: u16,
    ) -> Result<(pdu::Pdu<pdu::LocalReadBlobResponse<'a>>, bool), pdu::Error> {
        let max_payload = self.mtu - 1;

        match offset as usize {
            o if o >= data.len() => Err(pdu::Error::InvalidOffset),

            o if o + max_payload <= data.len() => Ok((
                pdu::LocalReadBlobResponse::new(&data[o..(o + max_payload)]).into(),
                true,
            )),

            o => Ok((pdu::LocalReadBlobResponse::new(&data[o..]).into(), false)),
        }
    }

    async fn process_prepare_write_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        payload: &[u8],
    ) -> Result<(), ConnectionError<T>>
    where
        T: LogicalLink,
    {
        let request = match pdu::PreparedWriteRequest::try_from_raw(payload) {
            Ok(request) => request,
            Err(e) => {
                return send_error!(channel, 0, ClientPduName::PrepareWriteRequest, e.pdu_err);
            }
        };

        let handle = request.get_handle();

        let check_permissions_result = check_permissions!(self, handle, &super::FULL_WRITE_PERMISSIONS);

        if let Err(e) = check_permissions_result {
            return send_error!(channel, handle, ClientPduName::PrepareWriteRequest, e);
        }

        let prepare_result = self.queued_writer.process_prepared(&request);

        if let Err(e) = prepare_result {
            return send_error!(channel, handle, ClientPduName::PrepareWriteRequest, e);
        }

        let response = pdu::PreparedWriteResponse::pdu_from_request(&request);

        send_pdu!(channel, response)
    }

    async fn process_execute_write_request<T>(
        &mut self,
        channel: &mut BasicFrameChannel<T>,
        request_flag: pdu::ExecuteWriteFlag,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        log::info!("(ATT) processing ATT_EXECUTE_WRITE_REQ {{ flag: {:?} }}", request_flag);

        match match self.queued_writer.process_execute(request_flag) {
            Ok(Some(iter)) => {
                for queued_data in iter.into_iter() {
                    let permission_check = check_permissions!(self, queued_data.0, &super::FULL_WRITE_PERMISSIONS);

                    if permission_check.is_ok() {
                        match self.write_att(queued_data.0, &queued_data.1).await {
                            Ok(_) => (),
                            Err(e) => send_error!(channel, 0, ClientPduName::ExecuteWriteRequest, e)?,
                        };
                    }
                }

                Ok(())
            }

            Ok(None) => Ok(()),

            Err(e) => Err(e),
        } {
            Err(e) => send_error!(channel, 0, ClientPduName::ExecuteWriteRequest, e),

            Ok(_) => send_pdu!(channel, pdu::execute_write_response()),
        }
    }

    /// Get an iterator over the attribute informational data
    ///
    /// This will return an iterator to get the type, permissions, and handle for each attribute
    pub fn iter_attr_info(&self) -> impl Iterator<Item = AttributeInfo<'_>> {
        self.attributes.iter_info()
    }
}

/// Server status
///
/// Returned by the methods [`process_acl_data`] and [`processed_parsed_acl_data`] to give the
/// status of the Server
#[derive(Clone, Debug)]
pub enum Status {
    /// Returned when there is no status to report
    None,
    /// Returned whenever the server process a *handle value confirm* message from the client in
    /// response to a indication.
    IndicationConfirmed,
    /// Returned when the Server has sent the last byte of an attribute's value in a read blob
    /// response
    ReadBlobComplete,
}

/// Attributes of a [`Server`]
///
/// This contains the attributes that are within the server.
pub struct ServerAttributes {
    attributes: Vec<super::Attribute<Box<dyn ServerAttributeValue>>>,
}

impl ServerAttributes {
    /// Create a new `ServiceAttributes`
    pub fn new() -> Self {
        Self {
            attributes: alloc::vec![ReservedHandle.into()],
        }
    }

    /// Push an attribute
    ///
    /// This will push the attribute onto the list of server attributes and return the handle for
    /// the attribute.
    ///
    /// ```
    /// use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
    /// use bo_tie_att::server::ServerAttributes;
    /// use bo_tie_host_util::Uuid;
    ///
    /// let mut attributes = ServerAttributes::new();
    ///
    /// let device_name = Attribute::new(
    ///     Uuid::from_u16(0x2A00),
    ///     vec![AttributePermissions::Read(AttributeRestriction::None)],
    ///     String::from("My Device"),
    /// );
    ///
    /// attributes.push(device_name);
    /// ```
    /// # Panic
    /// If you manage to push `core::u16::MAX - 1` attributes, the push will panic.
    pub fn push<V>(&mut self, attribute: super::Attribute<V>) -> u16
    where
        V: TransferFormatInto + TransferFormatTryFrom + PartialEq + Unpin + Send + Sync + 'static,
    {
        let trivial = super::Attribute {
            ty: attribute.ty,
            handle: attribute.handle,
            permissions: attribute.permissions,
            value: access_value::TrivialAccessor(attribute.value),
        };

        self.push_accessor(trivial)
    }

    /// Push an attribute with a borrowed value
    ///
    /// This will push the attribute onto the list of server attributes and return the handle for
    /// the attribute.
    ///
    /// The main usage of `push_borrowed` is to use a reference to a dynamically sized type when the
    /// attribute is read and use an 'owned' type when the attribute is written. The generic
    /// parameter `D` must be able to be converted from the owned type.
    ///
    /// ```
    /// use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
    /// use bo_tie_att::server::ServerAttributes;
    /// use bo_tie_host_util::Uuid;
    /// use std::borrow::Cow;
    ///
    /// let mut attributes = ServerAttributes::new();
    ///
    /// let device_name = Attribute::new(
    ///     Uuid::from_u16(0x2A00),
    ///     vec![
    ///         AttributePermissions::Read(AttributeRestriction::None),
    ///         AttributePermissions::Write(AttributeRestriction::None)
    ///     ],
    ///     Cow::from("My Device"),
    /// );
    ///
    /// attributes.push_borrowed(device_name);
    /// ```
    pub fn push_borrowed<D>(&mut self, attribute: super::Attribute<D>) -> u16
    where
        D: core::ops::Deref + From<<D::Target as ToOwned>::Owned> + Unpin + Send + 'static,
        D::Target: TransferFormatInto + ToOwned + Comparable + Send + Sync,
        <D::Target as ToOwned>::Owned: TransferFormatTryFrom + Unpin + Send,
    {
        let cow = super::Attribute {
            ty: attribute.ty,
            handle: attribute.handle,
            permissions: attribute.permissions,
            value: access_value::CowAccess(attribute.value),
        };

        self.push_accessor(cow)
    }

    /// Push an attribute whose value is wrapped by an accessor
    ///
    /// An accessor is a type that wraps the value to guard access to it. The most common case is
    /// to wrap the value in a mutex to allow for multiple connections to write to the same
    /// attribute. It is recommended that whatever process is used to access the value be `async`.
    ///
    #[cfg_attr(
        feature = "tokio",
        doc = r##"
```
use std::sync::Arc;
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
use bo_tie_att::server::ServerAttributes;
use bo_tie_host_util::Uuid;
use tokio::sync::Mutex;

let mut attributes = ServerAttributes::new();

// tokio's mutex's implementation of AccessValue
// is gated by the feature `tokio`.
let device_name = Attribute::new(
    Uuid::from_u16(0x2A00),
    vec![
        AttributePermissions::Read(AttributeRestriction::None),
        AttributePermissions::Write(AttributeRestriction::Authorization)
    ],
    Arc::new(Mutex::new(String::from("My Device")))
);

attributes.push_accessor(device_name);
```
    "##
    )]
    ///
    /// # Panic
    /// If you manage to push `core::u16::MAX - 1` attributes, the push will panic.
    pub fn push_accessor<C>(&mut self, attribute: super::Attribute<C>) -> u16
    where
        C: AccessValue + 'static,
        C::ReadValue: TransferFormatInto + Comparable,
        C::WriteValue: TransferFormatTryFrom,
    {
        let handle = self
            .attributes
            .len()
            .try_into()
            .expect("Exceeded attribute handle limit");

        let pushed_att = super::Attribute {
            ty: attribute.ty,
            handle: Some(handle),
            permissions: attribute.permissions,
            value: Box::from(AccessibleValue(attribute.value)) as Box<dyn ServerAttributeValue>,
        };

        self.attributes.push(pushed_att);

        handle
    }

    /// Push a read only attribute
    ///
    /// This will push the attribute onto the list of server attributes and return the handle of
    /// the pushed attribute. This attribute is read only, the client cannot write to the value of
    /// this attribute. Since the client cannot write the value type only needs to implement
    /// [`TransferFormatInto`] and not [`TransferFormatTryFrom`]. However, the consequence of this
    /// is that a Client also cannot search by value for this attribute.
    ///
    /// The main usage of a read only attribute is to allow for dynamically sized types to be the
    /// `Value` of the accessor.
    ///
    #[cfg_attr(
        feature = "tokio",
        doc = r##"
```
use std::sync::Arc;
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
use bo_tie_att::server::ServerAttributes;
use bo_tie_host_util::Uuid;
use tokio::sync::Mutex;

let mut attributes = ServerAttributes::new();

// tokio's mutex's implementation of AccessValue
// is gated by the feature `tokio`.
let device_name = Attribute::new(
    Uuid::from_u16(0x2A00),
    [ AttributePermissions::Read(AttributeRestriction::None) ],
    Arc::new(Mutex::new("My Device"))
);

attributes.push_read_only(device_name);
```
        "##
    )]
    /// # Note
    /// Any write attribute permissions are stripped from the attribute.
    ///
    /// # Panic
    /// If you manage to push `core::u16::MAX - 1` attributes, the push will panic.
    pub fn push_read_only<C>(&mut self, mut attribute: super::Attribute<C>) -> u16
    where
        C: AccessReadOnly + 'static,
        C::Value: TransferFormatInto + Comparable,
    {
        let handle = self
            .attributes
            .len()
            .try_into()
            .expect("Exceeded attribute handle limit");

        let mut cnt = 0;

        // Removing all write permissions
        while cnt != attribute.permissions.len() {
            if let AttributePermissions::Write(_) = attribute.permissions[cnt] {
                attribute.permissions.try_remove(cnt).unwrap();
            }

            cnt += 1;
        }

        let pushed_att = super::Attribute {
            ty: attribute.ty,
            handle: Some(handle),
            permissions: attribute.permissions,
            value: Box::from(ReadOnly(attribute.value)) as Box<dyn ServerAttributeValue>,
        };

        self.attributes.push(pushed_att);

        handle
    }

    /// Get the handle assigned to the attribute to be added next.
    ///
    /// ```
    /// # use bo_tie_att::server::ServerAttributes;
    /// # let attribute = bo_tie_att::Attribute::new( bo_tie_att::Uuid::default(), Vec::new(), () );
    ///
    /// let mut server_attributes = ServerAttributes::new();
    ///
    /// let first_handle = server_attributes.next_handle();
    ///
    /// let pushed_handle = server_attributes.push(attribute);
    ///
    /// assert_eq!( first_handle, pushed_handle );
    /// ```
    pub fn next_handle(&self) -> u16 {
        self.attributes.len() as u16
    }

    /// Get an iterator over the attribute informational data
    ///
    /// This will return an iterator to get the type, permissions, and handle for each attribute
    pub fn iter_info(&self) -> impl Iterator<Item = AttributeInfo<'_>> {
        self.attributes[1..].iter().map(|att| AttributeInfo::from_att(att))
    }

    /// Get an iterator within a range of attribute informational data
    ///
    /// This will return an iterator to get the type, permissions, and handle for each attribute
    /// within the specified range.
    ///
    /// # Panics
    /// The range must be within the valid range of attribute handles. This method will panic if the
    /// range includes 0 or is larger than the number of attributes.
    pub fn iter_info_ranged<R, I>(&self, range: R) -> impl Iterator<Item = AttributeInfo<'_>>
    where
        R: core::ops::RangeBounds<I>,
        I: Into<usize> + Copy,
    {
        let start = match range.start_bound() {
            core::ops::Bound::Unbounded => 1,
            core::ops::Bound::Excluded(v) => (*v).into() + 1,
            core::ops::Bound::Included(v) => {
                let v = (*v).into();

                assert_ne!(v, 0, "The start bound cannot be 0");

                v
            }
        };

        let end = match range.end_bound() {
            core::ops::Bound::Unbounded => self.attributes.len(),
            core::ops::Bound::Excluded(v) => (*v).into(),
            core::ops::Bound::Included(v) => (*v).into() + 1,
        };

        self.attributes[start..end]
            .iter()
            .map(|att| AttributeInfo::from_att(att))
    }

    /// Get the attribute info for a specific handle
    pub fn get_info<I>(&self, handle: I) -> Option<AttributeInfo<'_>>
    where
        I: Into<usize>,
    {
        let index = handle.into();

        self.attributes.get(index).map(|a| AttributeInfo::from_att(a))
    }

    /// Get the number of Attributes
    pub fn count(&self) -> usize {
        // the attribute at `self.attributes[0]` is the
        // reserved attribute
        self.attributes.len() - 1
    }

    /// Get the attribute at the provided handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get(&self, handle: u16) -> Option<&super::Attribute<Box<dyn ServerAttributeValue>>> {
        match handle {
            0 => None,
            h => self.attributes.get(<usize>::from(h)),
        }
    }

    /// Get a mutable reference to the attribute at the provided handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get_mut(&mut self, handle: u16) -> Option<&mut super::Attribute<Box<dyn ServerAttributeValue>>> {
        match handle {
            0 => None,
            h => self.attributes.get_mut(<usize>::from(h)),
        }
    }

    /// Get a reference to the value of an attribute at the given handle
    ///
    /// A reference is returned if there is an attribute at `handle` within this `ServerAttributes`
    /// and `T` is the correct type for the attribute value.
    /// # Note
    /// The list of attributes starts at one, a handle of 0 will always return `None`.
    pub fn get_value<T: core::any::Any>(&self, handle: u16) -> Option<&T> {
        self.attributes
            .get(<usize>::from(handle))
            .and_then(|attribute| attribute.get_value().as_any().downcast_ref())
    }

    /// Get a mutable reference to the value of an attribute at the given handle
    ///
    /// A mutable reference is returned if there is an attribute at `handle` within this
    /// `ServerAttributes` and `T` is the correct type for the attribute value.
    ///
    /// # Note
    /// The list of attributes starts at one, a handle of 0 will always return `None`.
    pub fn get_mut_value<T: core::any::Any>(&mut self, handle: u16) -> Option<&mut T> {
        self.attributes
            .get_mut(<usize>::from(handle))
            .and_then(|attribute| attribute.get_mut_value().as_mut_any().downcast_mut())
    }
}

impl Default for ServerAttributes {
    fn default() -> Self {
        Self::new()
    }
}

pub type PinnedFuture<'a, O> = Pin<Box<dyn Future<Output = O> + Send + 'a>>;

/// An attribute value of a `Server`
///
trait ServerAttributeValue: ServerAttribute + Send {}

impl<T> ServerAttributeValue for T where T: ServerAttribute + Send {}

/// A server attribute
///
/// A `ServerAttribute` is an attribute that has been added to the `ServerAttributes`. These
/// functions are designed to abstract away from the type of the attribute value so a
/// `ServerAttributes` can have a list of boxed `dyn ServerAttribute`.
trait ServerAttribute: core::any::Any {
    /// Read the data
    ///
    /// The returned data is in its transfer format
    fn read(&mut self) -> PinnedFuture<Result<Vec<u8>, pdu::Error>>;

    /// Generate a 'Read Response'
    ///
    /// This will create a read response PDU in its transfer bytes format.
    fn read_response(&mut self) -> PinnedFuture<'_, Result<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>, pdu::Error>>;

    /// Try to convert raw data from the interface and write to the attribute value
    fn try_set_value_from_transfer_format<'a>(
        &'a mut self,
        tf_data: &'a [u8],
    ) -> PinnedFuture<'a, Result<(), pdu::Error>>;

    fn read_type_response(
        &mut self,
        handle: u16,
        size: usize,
    ) -> PinnedFuture<'_, Result<Option<pdu::ReadTypeResponse<Vec<u8>>>, pdu::Error>>;

    /// Compare the value with the data received from the interface
    ///
    /// # Read Only
    /// This is only used when processing read and find operations. The returned boolean must be the
    /// the `raw` compared to the transfer format of the read value.
    ///
    /// # Read Errors
    /// If the value would produce an error on a read, `false` is output by the returned future.   
    fn cmp_value_to_raw_transfer_format<'a>(&'a mut self, raw: &'a [u8]) -> PinnedFuture<'a, bool>;

    /// Get an reference to self as a `dyn Any`
    fn as_any(&self) -> &dyn core::any::Any;

    /// Get a mutable reference to self as a `dyn Any`
    fn as_mut_any(&mut self) -> &mut dyn core::any::Any;
}

/// A trait for comparing a type to transfer formatted data
pub trait Comparable {
    fn cmp_tf_data(&self, tf_data: &[u8]) -> bool;
}

impl<T: TransferFormatTryFrom + PartialEq> Comparable for T {
    fn cmp_tf_data(&self, tf_data: &[u8]) -> bool {
        match <Self as TransferFormatTryFrom>::try_from(tf_data) {
            Err(_) => false,
            Ok(cmp_val) => self.eq(&cmp_val),
        }
    }
}

impl Comparable for str {
    fn cmp_tf_data(&self, tf_data: &[u8]) -> bool {
        core::str::from_utf8(tf_data)
            .map(|tf_str| self.eq(tf_str))
            .unwrap_or_default()
    }
}

impl Comparable for &'_ str {
    fn cmp_tf_data(&self, tf_data: &[u8]) -> bool {
        core::str::from_utf8(tf_data)
            .map(|tf_str| (*self).eq(tf_str))
            .unwrap_or_default()
    }
}

macro_rules! impl_ro_cmp_for_int_slices {
    ($($ints:ty),+ $(,)?) => {
        $(
            impl Comparable for [$ints] {
                fn cmp_tf_data(&self, tf_data: &[u8]) -> bool {
                    let chunks = tf_data.chunks_exact(core::mem::size_of::<$ints>());

                    chunks.remainder().len() == 0 && chunks
                        .map(|v| <$ints>::from_le_bytes(TryFrom::try_from(v).unwrap()))
                        .eq(self.iter().copied())
                }
            }
        )+
    }
}

impl_ro_cmp_for_int_slices!(f32, f64, i8, i16, i32, i64, i128, isize, u8, u16, u32, u64, u128, usize);

/// The Reserved Handle
///
/// The first handle (value of '0') is reserved for future use. This is used to represent that
/// handle when creating a new Attribute Bearer
struct ReservedHandle;

impl From<ReservedHandle> for super::Attribute<Box<dyn ServerAttributeValue>> {
    fn from(_: ReservedHandle) -> Self {
        super::Attribute::new(crate::Uuid::from_u128(0u128), [], Box::new(ReservedHandle))
    }
}

impl ServerAttribute for ReservedHandle {
    fn read(&mut self) -> PinnedFuture<Result<Vec<u8>, pdu::Error>> {
        Box::pin(async move {
            log::error!("(ATT) client tried to read the reserved handle");

            Err(pdu::Error::InvalidHandle)
        })
    }

    fn read_response(&mut self) -> PinnedFuture<'_, Result<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>, pdu::Error>> {
        Box::pin(async {
            log::error!("(ATT) client tried to read the reserved handle for a read response");

            Err(pdu::Error::InvalidHandle)
        })
    }

    fn read_type_response(
        &mut self,
        _: u16,
        _: usize,
    ) -> PinnedFuture<'_, Result<Option<pdu::ReadTypeResponse<Vec<u8>>>, pdu::Error>> {
        Box::pin(async {
            log::error!("(ATT) client tried to read the reserved handle for a read by type request data");

            Err(pdu::Error::InvalidHandle)
        })
    }

    fn try_set_value_from_transfer_format(&mut self, _: &[u8]) -> PinnedFuture<'_, Result<(), pdu::Error>> {
        Box::pin(async {
            log::error!("(ATT) client tried to write to reserved attribute handle");

            Err(pdu::Error::WriteNotPermitted)
        })
    }

    fn cmp_value_to_raw_transfer_format(&mut self, _: &[u8]) -> PinnedFuture<'_, bool> {
        Box::pin(async { false })
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttributeInfo<'a> {
    ty: &'a crate::Uuid,
    handle: u16,
    permissions: &'a [AttributePermissions],
}

impl<'a> AttributeInfo<'a> {
    fn from_att<T>(att: &'a super::Attribute<T>) -> Self {
        AttributeInfo {
            ty: att.get_uuid(),
            handle: att.get_handle().expect("Failed to get the attribute handle"),
            permissions: att.get_permissions(),
        }
    }

    /// Get the attribute's UUID
    ///
    /// This is the UUID that is assigned for this
    pub fn get_uuid(&self) -> &crate::Uuid {
        self.ty
    }

    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    pub fn get_permissions(&self) -> &[super::AttributePermissions] {
        self.permissions
    }
}

/// Trait for queued writing to the server
///
/// A [`Server`](Server) uses this trait for managing queued writes from the client.
///
/// # Note
/// All permission checks for prepare and execute write requests are not dealt with by the
/// implementor of this trait.
pub trait QueuedWriter {
    /// An iterator over attribute handles with transfer formatted data
    type Iter: core::iter::IntoIterator<Item = (u16, Vec<u8>)>;

    /// Process a prepared write request
    fn process_prepared(&mut self, request: &pdu::PreparedWriteRequest<'_>) -> Result<(), pdu::Error>;

    /// Process an execute request request
    ///
    /// This needs to return an iterator over the prepared writes. Each item of the iterator is
    /// an attribute handle with the data to be written to the attribute value. This data needs to
    /// still be in the transfer formatted form, the server will convert it from the transfer format
    /// to the appropriate data type.
    ///
    /// If the request contains the `Cancel all prepared writes` flag, then this function must
    /// return `Ok(None)` and all queued writes must be dropped.
    fn process_execute(&mut self, request_flag: pdu::ExecuteWriteFlag) -> Result<Option<Self::Iter>, pdu::Error>;
}

/// The state of a `BasicQueuedWriter`
///
/// This contains the 'ok' states for when there are no queued writes or there are queued writes,
/// and the error state for an incorrect handle received.
#[derive(Copy, Clone)]
enum BasicQueuedWriterState {
    NoQueuedWrites,
    QueuedWrites(u16),
    InvalidOffset,
}

/// A *very* basic queued writer
///
/// This queued writer supports queuing of in-order prepared write requests for a single attribute.
///
/// This is a basic queued writer as it only contains a buffer for a single attribute value blob.
/// The allocation for the buffer will persists for the lifetime of the BasicQueuedWriter unless
/// the buffer needs to resize to contain a blob larger than the current allocation.
///
/// Once a client sends a prepared write request to the server this queue writer will only accept
/// prepare write requests with the same attribute. Furthermore the offset value in the prepare
/// write request must match the count of all the attribute value bytes received so far. Lastly
/// this queue is initialized with a buffer and the total amount of bytes received cannot exceed
/// the size of the buffer. If any of these conditions are failed the appropriate error is returned.
/// A new prepare queue is started only when an execute write request is received. Then the server
/// can start queueing up writes for a different or the same attribute value.
pub struct BasicQueuedWriter {
    data: Vec<u8>,
    state: BasicQueuedWriterState,
}

impl BasicQueuedWriter {
    /// Create a new `BasicQueuedWriter`
    ///
    /// This creates a `BasicQueuedWriter` with the maximum capacity for a long attribute value (512
    /// bytes).
    pub fn new() -> Self {
        Self {
            data: Vec::with_capacity(512),
            state: BasicQueuedWriterState::NoQueuedWrites,
        }
    }

    /// Create a new `BasicQueuedWriter` with a custom capacity
    ///
    /// This creates a `BasicQueuedWriter` with a custom capacity, but there is no limit check on
    /// this `capacity`. It can be larger than the Bluetooth Specification defined maximum of 512
    /// bytes for a long attribute value, or smaller than the maximum transfer size for the current
    /// ATT bearer. However, to ensure server usability and maintain compliance, a reasonable size
    /// in-between those two values should be used for the `capacity`.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            state: BasicQueuedWriterState::NoQueuedWrites,
        }
    }

    fn prepared_nothing_queued(&mut self, request: &pdu::PreparedWriteRequest<'_>) -> Result<(), pdu::Error> {
        if request.get_prepared_offset() == 0 {
            if request.get_prepared_data().len() <= self.data.capacity() {
                self.state = BasicQueuedWriterState::QueuedWrites(request.get_handle());

                // Data must be already cleared
                self.data.extend_from_slice(request.get_prepared_data());

                Ok(())
            } else {
                Err(pdu::Error::PrepareQueueFull)
            }
        } else {
            self.state = BasicQueuedWriterState::InvalidOffset;

            Ok(())
        }
    }

    fn prepared_queued(&mut self, request: &pdu::PreparedWriteRequest<'_>, self_handle: u16) -> Result<(), pdu::Error> {
        if self.data.len() != request.get_prepared_offset().into() {
            self.state = BasicQueuedWriterState::InvalidOffset;

            Ok(())
        } else if self_handle != request.get_handle() {
            Err(pdu::Error::InvalidHandle)
        } else if self.data.len() + request.get_prepared_data().len() > self.data.capacity() {
            Err(pdu::Error::PrepareQueueFull)
        } else {
            self.data.extend_from_slice(request.get_prepared_data());

            Ok(())
        }
    }

    /// Cancel the queued write
    fn cancel_queued_writes(&mut self) -> Result<Option<<Self as QueuedWriter>::Iter>, pdu::Error> {
        self.data.clear();
        self.state = BasicQueuedWriterState::NoQueuedWrites;
        Ok(None)
    }

    /// Write the queued prepared write to the attribute
    fn exec_queued_writes(&mut self) -> Result<Option<<Self as QueuedWriter>::Iter>, pdu::Error> {
        match core::mem::replace(&mut self.state, BasicQueuedWriterState::NoQueuedWrites) {
            BasicQueuedWriterState::NoQueuedWrites => Ok(self.empty_iter().into()),

            BasicQueuedWriterState::QueuedWrites(h) => Ok(self.create_once_iter(h).into()),

            BasicQueuedWriterState::InvalidOffset => Err(pdu::Error::InvalidOffset),
        }
    }

    /// Creates a once with the value already iterated out
    fn empty_iter(&mut self) -> <Self as QueuedWriter>::Iter {
        let mut once = core::iter::once((0, Vec::new()));

        once.next();

        once
    }

    /// Create the once iterator
    ///
    /// This should only be called when the current state is `QueuedWrites` as this resets both the
    /// state and data
    fn create_once_iter(&mut self, handle: u16) -> <Self as QueuedWriter>::Iter {
        core::iter::once((handle, core::mem::replace(&mut self.data, Vec::new()))).into()
    }
}

impl QueuedWriter for BasicQueuedWriter {
    type Iter = core::iter::Once<(u16, Vec<u8>)>;

    fn process_prepared(&mut self, request: &pdu::PreparedWriteRequest<'_>) -> Result<(), pdu::Error> {
        match self.state {
            BasicQueuedWriterState::NoQueuedWrites => self.prepared_nothing_queued(request),

            BasicQueuedWriterState::QueuedWrites(handle) => self.prepared_queued(request, handle),

            // Error states, client needs to send execute
            BasicQueuedWriterState::InvalidOffset => Ok(()),
        }
    }

    fn process_execute(&mut self, flag: pdu::ExecuteWriteFlag) -> Result<Option<Self::Iter>, pdu::Error> {
        match flag {
            pdu::ExecuteWriteFlag::CancelAllPreparedWrites => self.cancel_queued_writes(),
            pdu::ExecuteWriteFlag::WriteAllPreparedWrites => self.exec_queued_writes(),
        }
    }
}

/// A queued writer where queued writes are unsupported
///
/// A call to any of the functions of the implemented trait [`QueuedWriter`](QueuedWriter) will
/// return the attribute PDU error *request not supported*.
///
/// This is a
/// [Unit Struct](https://doc.rust-lang.org/book/ch05-01-defining-structs.html#unit-like-structs-without-any-fields),
/// there are no fields to be initialized.
pub struct NoQueuedWrites;

impl QueuedWriter for NoQueuedWrites {
    type Iter = Vec<(u16, Vec<u8>)>;

    fn process_prepared(&mut self, _: &pdu::PreparedWriteRequest<'_>) -> Result<(), pdu::Error> {
        Err(pdu::Error::RequestNotSupported)
    }

    fn process_execute(&mut self, _: pdu::ExecuteWriteFlag) -> Result<Option<Self::Iter>, pdu::Error> {
        Err(pdu::Error::RequestNotSupported)
    }
}

/// Error for notifications or indication methods of [`Server`]
pub enum ServerInitiatedError<T: LogicalLink> {
    InvalidHandle(u16),
    ConnectionError(ConnectionError<T>),
    FailedToRead(pdu::Error),
}

impl<T> core::fmt::Debug for ServerInitiatedError<T>
where
    T: LogicalLink,
    <T::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
    <T::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ServerInitiatedError::InvalidHandle(handle) => write!(f, "InvalidHandle({})", handle),
            ServerInitiatedError::ConnectionError(c) => core::fmt::Debug::fmt(&c, f),
            ServerInitiatedError::FailedToRead(e) => write!(f, "FailedToRead({e:?}"),
        }
    }
}

impl<T> core::fmt::Display for ServerInitiatedError<T>
where
    T: LogicalLink,
    <T::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
    <T::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ServerInitiatedError::InvalidHandle(handle) => write!(f, "no attribute for handle {}", handle),
            ServerInitiatedError::ConnectionError(c) => core::fmt::Display::fmt(c, f),
            ServerInitiatedError::FailedToRead(e) => write!(f, "failed to read attribute value: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<T> std::error::Error for ServerInitiatedError<T>
where
    T: LogicalLink,
    <T::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error,
    <T::PhysicalLink as PhysicalLink>::SendErr: std::error::Error,
{
}
