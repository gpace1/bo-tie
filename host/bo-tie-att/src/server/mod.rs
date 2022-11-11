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

pub mod access_value;
#[cfg(test)]
mod tests;

use crate::{
    client::ClientPduName, pdu, AttributePermissions, AttributeRestriction, ConnectionError, TransferFormatError,
    TransferFormatInto, TransferFormatTryFrom,
};
use alloc::{boxed::Box, vec::Vec};
use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::ConnectionChannel;
use core::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

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
            ServerPduName::WriteResponse => write!(f, "Write Response"),
            ServerPduName::PrepareWriteResponse => write!(f, "Prepare Write Response"),
            ServerPduName::ExecuteWriteResponse => write!(f, "Execute Write Response"),
            ServerPduName::HandleValueNotification => write!(f, "Handle Value Notification"),
            ServerPduName::HandleValueIndication => write!(f, "Handle Value Indication"),
        }
    }
}

impl ServerPduName {
    /// Check that the given raw pdu is this response pdu
    ///
    /// This will loosly check that the size of the pdu is correct and that the opcode value
    /// matches this response. The size of the packet will only be checked for the minimum possible
    /// size and not the maximum allowable size by the connection's ATT_MTU.
    pub(super) fn is_convertible_from(&self, raw_pdu: &[u8]) -> bool {
        // Each of these check that the size of the packet is correct and the opcode matches
        match self {
            ServerPduName::ErrorResponse => (raw_pdu.len() == 5) && (raw_pdu[0] == ServerPduName::ErrorResponse.into()),
            ServerPduName::ExchangeMTUResponse => {
                (raw_pdu.len() == 3) && (raw_pdu[0] == ServerPduName::ExchangeMTUResponse.into())
            }
            ServerPduName::FindInformationResponse => {
                (raw_pdu.len() >= 6) && (raw_pdu[0] == ServerPduName::FindInformationResponse.into())
            }
            ServerPduName::FindByTypeValueResponse => {
                (raw_pdu.len() >= 5) && (raw_pdu[0] == ServerPduName::FindByTypeValueResponse.into())
            }
            ServerPduName::ReadByTypeResponse => {
                (raw_pdu.len() >= 4) && (raw_pdu[0] == ServerPduName::ReadByTypeResponse.into())
            }
            ServerPduName::ReadResponse => (raw_pdu.len() >= 1) && (raw_pdu[0] == ServerPduName::ReadResponse.into()),
            ServerPduName::ReadBlobResponse => {
                (raw_pdu.len() >= 1) && (raw_pdu[0] == ServerPduName::ReadBlobResponse.into())
            }
            ServerPduName::ReadMultipleResponse => {
                (raw_pdu.len() >= 1) && (raw_pdu[0] == ServerPduName::ReadMultipleResponse.into())
            }
            ServerPduName::ReadByGroupTypeResponse => {
                (raw_pdu.len() >= 6) && (raw_pdu[0] == ServerPduName::ReadByGroupTypeResponse.into())
            }
            ServerPduName::WriteResponse => (raw_pdu.len() == 1) && (raw_pdu[0] == ServerPduName::WriteResponse.into()),
            ServerPduName::PrepareWriteResponse => {
                (raw_pdu.len() >= 5) && (raw_pdu[0] == ServerPduName::PrepareWriteResponse.into())
            }
            ServerPduName::ExecuteWriteResponse => {
                (raw_pdu.len() == 1) && (raw_pdu[0] == ServerPduName::ExecuteWriteResponse.into())
            }
            ServerPduName::HandleValueNotification => {
                (raw_pdu.len() >= 3) && (raw_pdu[0] == ServerPduName::HandleValueNotification.into())
            }
            ServerPduName::HandleValueIndication => {
                (raw_pdu.len() >= 3) && (raw_pdu[0] == ServerPduName::HandleValueIndication.into())
            }
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
}

/// An Attribute server
///
/// This is an implementation of the server role for the Attribute protocol. A server is made up of
/// attributes, which consist of a handle, a UUID, and a value.
///
/// A handle is much like an index of an array and is used to address the attribute. Per the
/// specification an handle is a u16 value with zero being reserved (attributes will start at handle
/// one). This server forcibly put all attributes in sequential order, as a vector is used for the
/// attributes collection.
///
/// Each server is unique for the connection to the client. Making the server this way allows for a
/// unique state for each connection, allowing the commands being processed independent of other
/// connections. Things like the maximum transfer unit (MTU) and client permissions might be
/// different per connection. Most importantly, because servers are independent, they can be used
/// within separate threads.
///
/// Having a unique server per connection does not mean that the attribute values will need to be
/// wrapped within synchronization containers if they're shared between servers. This is where the
/// somewhat awkward
/// [`AccessValue`](crate::server::AccessValue)
/// can be implemented on the container to perform concurrency safe reading or writing on the
/// contained value.
pub struct Server<Q> {
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

impl<Q> Server<Q>
where
    Q: QueuedWriter,
{
    /// Create a new Server
    ///
    /// Creates an attribute server for a client connected with the logical link `connection`, the
    /// attributes of the server are optionally initialized with input `server_attributes`, and the
    /// `queued_writer` is the manager for queued writes. If `server_attributes` is set to `None`
    /// then a server with no attributes is created.
    pub fn new<A>(server_attributes: A, queued_writer: Q) -> Self
    where
        A: Into<Option<ServerAttributes>>,
    {
        let attributes = server_attributes.into().unwrap_or(ServerAttributes::new());

        Self {
            attributes,
            given_permissions: Vec::new(),
            blob_data: None,
            queued_writer,
        }
    }

    /// Get the Attributes of the server
    pub fn get_attributes(&self) -> &ServerAttributes {
        &self.attributes
    }

    /// Push an attribute
    ///
    /// The attribute is added to the end of the list of attributes on the server.
    ///
    /// This is equivalent to the method [`ServerAttributes::push`]
    pub fn push<V>(&mut self, attribute: super::Attribute<V>) -> u16
    where
        V: TransferFormatTryFrom + TransferFormatInto + PartialEq + Unpin + Send + Sync + 'static,
    {
        self.attributes.push(attribute)
    }

    /// Push an attribute with a borrowed value
    ///
    /// The attribute is added to the end of the list of attributes on the server.
    ///
    /// This is equivalent to the method [`ServerAttributes::push_borrowed`]
    pub fn push_borrowed<D>(&mut self, attribute: super::Attribute<D>) -> u16
    where
        D: core::ops::Deref + From<<D::Target as ToOwned>::Owned> + Unpin + Send + Sync + 'static,
        D::Target: TransferFormatInto + ToOwned + Comparable + Send + Sync,
        <D::Target as ToOwned>::Owned: TransferFormatTryFrom + Unpin + Send + Sync,
    {
        self.attributes.push_borrowed(attribute)
    }

    /// Push an attribute whose value is wrapped by an accessor
    ///
    /// The attribute is added to the end of the list of attributes on the server.
    ///
    /// This is equivalent to the method [`ServerAttributes::push_accessor`]
    pub fn push_accessor<A>(&mut self, attribute: super::Attribute<A>) -> u16
    where
        A: AccessValue + 'static,
        A::ReadValue: TransferFormatInto + Comparable,
        A::WriteValue: TransferFormatTryFrom,
    {
        self.attributes.push_accessor(attribute)
    }

    /// Return the next unused handle
    pub fn next_handle(&self) -> u16 {
        self.attributes.count() as u16
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
            .clone()
            .into_iter()
            .filter(|p| !permissions.borrow().contains(p))
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
        operation_permissions: &[super::AttributePermissions],
    ) -> Result<(), pdu::Error> {
        let att = self.attributes.get(handle).ok_or(super::pdu::Error::InvalidHandle)?;

        match self.validate_permissions(att.get_permissions(), operation_permissions) {
            None => Ok(()),
            Some(e) => Err(e),
        }
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
    fn validate_permissions(
        &self,
        attribute_permissions: &[super::AttributePermissions],
        operation_permissions: &[super::AttributePermissions],
    ) -> Option<pdu::Error> {
        match self
            .given_permissions
            .iter()
            .skip_while(|&p| !attribute_permissions.contains(p) || !operation_permissions.contains(p))
            .nth(0)
        {
            Some(_) => None,
            None => operation_permissions
                .iter()
                .find(|&p| attribute_permissions.contains(p))
                .map(|&p| // Map the invalid permission to it's corresponding error
                    match p {
                        AttributePermissions::Read(AttributeRestriction::None) =>
                            pdu::Error::ReadNotPermitted,

                        AttributePermissions::Write(AttributeRestriction::None) =>
                            pdu::Error::WriteNotPermitted,

                        AttributePermissions::Read(AttributeRestriction::Encryption(_)) =>
                            self.given_permissions.iter().find(|&&x| {
                                match x {
                                    AttributePermissions::Read(AttributeRestriction::Encryption(_)) => true,
                                    _ => false
                                }
                            })
                                .and_then(|_| Some(pdu::Error::InsufficientEncryptionKeySize))
                                .or_else(|| Some(pdu::Error::InsufficientEncryption))
                                .unwrap(),

                        AttributePermissions::Write(AttributeRestriction::Encryption(_)) =>
                            self.given_permissions.iter().find(|&&x| {
                                match x {
                                    AttributePermissions::Write(AttributeRestriction::Encryption(_)) => true,
                                    _ => false
                                }
                            })
                                .and_then(|_| Some(pdu::Error::InsufficientEncryptionKeySize))
                                .or_else(|| Some(pdu::Error::InsufficientEncryption))
                                .unwrap(),

                        AttributePermissions::Read(AttributeRestriction::Authorization) |
                        AttributePermissions::Write(AttributeRestriction::Authorization) =>
                            pdu::Error::InsufficientAuthorization,

                        AttributePermissions::Read(AttributeRestriction::Authentication) |
                        AttributePermissions::Write(AttributeRestriction::Authentication) =>
                            pdu::Error::InsufficientAuthentication,
                    })
                .or(Some(pdu::Error::InsufficientAuthorization)),
        }
    }

    /// Check if a client can read the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_read_attribute<V>(&self, att: &super::Attribute<V>) -> Option<pdu::Error> {
        self.validate_permissions(att.get_permissions(), &super::FULL_READ_PERMISSIONS)
    }

    /// Check if a client can write the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_write_attribute<V>(&self, att: &super::Attribute<V>) -> Option<pdu::Error> {
        self.validate_permissions(att.get_permissions(), &super::FULL_WRITE_PERMISSIONS)
    }

    /// Process a received ACL Data packet form the Bluetooth Controller
    ///
    /// The packet is assumed to be in the form of an Attribute protocol request packet. This
    /// function will then process the request and send to the client the appropriate response
    /// packet.
    ///
    /// This function is a combination of the methods
    /// [`parse_acl_packet`](crate::server::Server::parse_acl_packet) and
    /// [`process_parsed_acl_data`](crate::server::Server::process_parsed_acl_data). It is
    /// recommended to use this function over those two functions when this `Server` is at the top
    /// of your server stack (you're not using GATT or some other custom higher layer protocol).
    pub async fn process_acl_data<C>(
        &mut self,
        connection_channel: &mut C,
        acl_packet: &l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        let (pdu_type, payload) = self.parse_acl_packet(acl_packet)?;

        self.process_parsed_acl_data(connection_channel, pdu_type, payload)
            .await
    }

    /// Parse an ACL Packet
    ///
    /// This checks the following things
    /// * The ACL packet has the correct channel identifier for the Attribute Protocol
    /// * The payload of the packet is not empty
    /// * The pdu type is a [`ClientPduName`](super::client::ClientPduName) enum
    ///
    /// # Note
    /// This is meant to be used by implementations of higher layer protocols for interfacing with
    /// the attribute protocol. Use
    /// [`process_acl_data`](crate::server::Server::process_acl_data) when directly using this
    /// server for communication with a client device.
    pub fn parse_acl_packet<'a>(
        &self,
        acl_packet: &'a l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<(ClientPduName, &'a [u8]), super::Error> {
        use l2cap::{ChannelIdentifier, LeUserChannelIdentifier};

        match acl_packet.get_channel_id() {
            ChannelIdentifier::Le(LeUserChannelIdentifier::AttributeProtocol) => {
                let (att_type, payload) = acl_packet.get_payload().split_at(1);

                if att_type.len() > 0 {
                    let pdu_type = super::client::ClientPduName::try_from(att_type[0])
                        .or(Err(super::Error::UnknownOpcode(att_type[0])))?;

                    Ok((pdu_type, payload))
                } else {
                    Err(super::Error::Empty)
                }
            }
            _ => Err(super::Error::IncorrectChannelId),
        }
    }

    /// Process a parsed ACL Packet
    ///
    /// This will take the data from the Ok result of [`parse_acl_packet`](Server::parse_acl_packet).
    /// This is otherwise equivalent to the function [`process_acl_data`](Server::parse_acl_packet)
    /// (really `process_acl_data` is just `parse_acl_packet` followed by this function) and is
    /// useful for higher layer protocols that need to parse an ACL packet before performing their
    /// own calculations on the data and *then* have the Attribute server processing the data.
    ///
    /// # Note
    /// This is meant to be used by implementations of higher layer protocols for interfacing with
    /// the attribute protocol. Use
    /// [`process_acl_data`](crate::server::Server::process_acl_data) when directly using this
    /// server for communication with a client device.
    pub async fn process_parsed_acl_data<C>(
        &mut self,
        connection_channel: &mut C,
        pdu_type: ClientPduName,
        payload: &[u8],
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        match pdu_type {
            ClientPduName::ExchangeMtuRequest => {
                self.process_exchange_mtu_request(connection_channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            ClientPduName::WriteRequest => self.process_write_request(connection_channel, &payload).await,

            ClientPduName::ReadRequest => {
                self.process_read_request(connection_channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            ClientPduName::FindInformationRequest => {
                self.process_find_information_request(connection_channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            ClientPduName::FindByTypeValueRequest => {
                self.process_find_by_type_value_request(connection_channel, &payload)
                    .await
            }

            ClientPduName::ReadByTypeRequest => {
                self.process_read_by_type_request(connection_channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            ClientPduName::ReadBlobRequest => {
                self.process_read_blob_request(connection_channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            ClientPduName::PrepareWriteRequest => {
                self.process_prepare_write_request(connection_channel, &payload).await
            }

            ClientPduName::ExecuteWriteRequest => {
                self.process_execute_write_request(connection_channel, TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            pdu @ ClientPduName::ReadMultipleRequest
            | pdu @ ClientPduName::WriteCommand
            | pdu @ ClientPduName::HandleValueConfirmation
            | pdu @ ClientPduName::SignedWriteCommand
            | pdu @ ClientPduName::ReadByGroupTypeRequest => {
                self.send_error(connection_channel, 0, pdu.into(), pdu::Error::RequestNotSupported)
                    .await
            }
        }
    }

    /// Send out a notification
    ///
    /// The attribute at the given handle will be sent out in the notification.
    ///
    /// If the handle doesn't exist, then the notification isn't sent and false is returned
    pub async fn send_notification(&self, handle: u16) -> bool {
        match self
            .attributes
            .get(handle)
            .map(|att| att.get_value().notification(handle))
        {
            Some(f) => {
                f.await;
                true
            }
            None => false,
        }
    }

    /// Send the raw transfer format data
    ///
    /// This takes a complete Attribute PDU in its transfer byte form. This will package it into
    /// a L2CAP PDU and send it using the `ConnectionChannel`.
    async fn send_raw_tf<C>(&self, connection_channel: &C, intf_data: Vec<u8>) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        let acl_data = l2cap::BasicInfoFrame::new(intf_data, super::L2CAP_CHANNEL_ID);

        connection_channel.send(acl_data).await.map_err(|e| e.into())
    }

    async fn send<C, D>(&self, connection_channel: &C, data: D) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatInto,
    {
        self.send_raw_tf(connection_channel, TransferFormatInto::into(&data))
            .await
    }

    /// Send an attribute PDU to the client
    pub async fn send_pdu<C, D>(
        &self,
        connection_channel: &C,
        pdu: pdu::Pdu<D>,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatInto,
    {
        log::trace!("Sending {}", pdu.get_opcode());

        self.send(connection_channel, pdu).await
    }

    /// Send an error the the client
    pub async fn send_error<C>(
        &self,
        connection_channel: &C,
        handle: u16,
        received_opcode: ClientPduName,
        pdu_error: pdu::Error,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!(
            "Sending error response. Received Op Code: '{:#x}', Handle: '{:?}', error: '{}'",
            Into::<u8>::into(received_opcode),
            handle,
            pdu_error
        );

        self.send_pdu(
            connection_channel,
            pdu::error_response(received_opcode.into(), handle, pdu_error),
        )
        .await
    }

    /// Get an arc clone to an attribute value
    fn get_att(&self, handle: u16) -> Result<&super::Attribute<Box<dyn ServerAttribute + Send + Sync>>, pdu::Error> {
        if pdu::is_valid_handle(handle) {
            self.attributes.get(handle).ok_or(pdu::Error::InvalidHandle)
        } else {
            Err(pdu::Error::InvalidHandle)
        }
    }

    /// Get a arc to an attribute value
    fn get_att_mut(
        &mut self,
        handle: u16,
    ) -> Result<&mut super::Attribute<Box<dyn ServerAttribute + Send + Sync>>, pdu::Error> {
        if pdu::is_valid_handle(handle) {
            self.attributes.get_mut(handle).ok_or(pdu::Error::InvalidHandle)
        } else {
            Err(pdu::Error::InvalidHandle)
        }
    }

    /// Set the blob data
    ///
    /// Input data must be the full data, in transfer format, of the read item.
    fn set_blob_data(&mut self, blob: Vec<u8>, handle: u16) {
        self.blob_data = MultiReqData { tf_data: blob, handle }.into();
    }

    /// Read an attribute and perform a conversion function on it.
    ///
    /// `read_att_and` is intended as a wrapper for checking if the client has permissions to
    /// perform the provided
    /// It is intended for `job` to convert the given ServerAttribute into a byte vector of the
    /// transfer format.
    ///
    /// Returns an error if the client doesn't have the adequate permissions or the handle is
    /// invalid.
    async fn read_att_and<'s, F, A, O>(&'s self, handle: u16, job: F) -> Result<O, pdu::Error>
    where
        F: FnOnce(&'s (dyn ServerAttribute + Send + Sync)) -> A + 's,
        A: Future<Output = O> + 's,
    {
        let attribute = self.get_att(handle)?;

        if let Some(err) = self.client_can_read_attribute(attribute) {
            Err(err)
        } else {
            Ok(job(attribute.get_value().as_ref()).await)
        }
    }

    /// Write the interface data to the attribute
    ///
    /// Returns an error if the client doesn't have the adequate permissions or the handle is
    /// invalid.
    async fn write_att(&mut self, handle: u16, intf_data: &[u8]) -> Result<(), pdu::Error> {
        if let Some(err) = self.client_can_write_attribute(self.get_att(handle)?) {
            Err(err.into())
        } else {
            match self.get_att_mut(handle) {
                Ok(att) => match att.get_mut_value().try_set_value_from_transfer_format(intf_data).await {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.pdu_err),
                },
                Err(_) => Err(pdu::Error::InvalidPDU.into()),
            }
        }
    }

    /// Process a exchange MTU request from the client
    async fn process_exchange_mtu_request<C>(
        &mut self,
        connection_channel: &mut C,
        client_mtu: u16,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!("Processing PDU ATT_EXCHANGE_MTU_REQ {{ mtu: {} }}", client_mtu);

        connection_channel.set_mtu(client_mtu);

        self.send_pdu(
            connection_channel,
            pdu::exchange_mtu_response(connection_channel.get_mtu() as u16),
        )
        .await
    }

    /// Process a Read Request from the client
    async fn process_read_request<C>(
        &mut self,
        connection_channel: &C,
        handle: u16,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!("Processing PDU ATT_READ_REQ {{ handle: {:#X} }}", handle);

        match self.read_att_and(handle, |att_tf| att_tf.read_response()).await {
            Ok(mut tf) => {
                // Amount of data that can be sent is the MTU minus the read response header size
                if tf.get_parameters().0.len() > (connection_channel.get_mtu() - 1) {
                    use core::mem::replace;

                    let sent = tf.get_parameters().0[..(connection_channel.get_mtu() - 1)].to_vec();

                    self.set_blob_data(replace(&mut tf.get_mut_parameters().0, sent), handle);
                }

                self.send_pdu(connection_channel, tf).await
            }
            Err(e) => {
                self.send_error(connection_channel, handle, ClientPduName::ReadRequest, e)
                    .await
            }
        }
    }

    /// Process a Write Request from the client
    async fn process_write_request<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        // Need to split the handle from the raw data as the data type is not known
        let handle = TransferFormatTryFrom::try_from(&payload[..2]).unwrap();

        log::info!("Processing PDU ATT_WRITE_REQ {{ handle: {:#X} }}", handle);

        match self.write_att(handle, &payload[2..]).await {
            Ok(_) => self.send_pdu(connection_channel, pdu::write_response()).await,
            Err(e) => {
                self.send_error(connection_channel, handle, ClientPduName::WriteRequest, e)
                    .await
            }
        }
    }

    /// Process a Find Information Request form the client
    async fn process_find_information_request<C>(
        &mut self,
        connection_channel: &C,
        handle_range: pdu::HandleRange,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!(
            "Processing PDU ATT_FIND_INFORMATION_REQ {{ start handle: {}, end handle: {} }}",
            handle_range.starting_handle,
            handle_range.ending_handle
        );

        /// Handle with UUID iterator
        ///
        /// The boolean is used to indicate whether or not the iterator is over short or long UUIDs.
        struct HandleUuidItr<I: Iterator<Item = (u16, crate::Uuid)> + Clone>(bool, I);

        impl<I: Iterator<Item = (u16, crate::Uuid)> + Clone> TransferFormatInto for HandleUuidItr<I> {
            fn len_of_into(&self) -> usize {
                1 + self
                    .1
                    .clone()
                    .fold(0usize, |acc, (h, u)| acc + h.len_of_into() + u.len_of_into())
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                const SHORT_FORMAT: u8 = 1;
                const LONG_FORMAT: u8 = 2;

                let mut offset = 1;

                into_ret[0] = if self.0 { SHORT_FORMAT } else { LONG_FORMAT };

                self.1.clone().for_each(|(h, u)| {
                    let h_len = h.len_of_into();
                    let u_len = u.len_of_into();

                    h.build_into_ret(&mut into_ret[offset..(offset + h_len)]);

                    offset += h_len;

                    u.build_into_ret(&mut into_ret[offset..(offset + u_len)]);

                    offset += u_len;
                })
            }
        }

        if handle_range.is_valid() {
            use core::cmp::min;

            // Both the start and ending handles cannot be past the actual length of the attributes
            let start = min(handle_range.starting_handle as usize, self.attributes.count());
            let stop = min(handle_range.ending_handle as usize, self.attributes.count());

            let payload_max = connection_channel.get_mtu() - 2;

            // Size of each handle + 16-bit-uuid responded pair
            let item_size_16 = 4;

            // Try to build response_payload full of 16 bit attribute types. This will stop at the
            // first attribute type that cannot be converted into a shortened 16 bit UUID or where
            // the client does not have permissions to access the attribute.
            let mut handle_uuids_16_bit_itr = HandleUuidItr(
                false,
                self.attributes.attributes[start..stop]
                    .iter()
                    .filter(|att| att.get_uuid().can_be_16_bit())
                    .take_while(|att| self.client_can_write_attribute(att).is_none())
                    .enumerate()
                    .take_while(|(cnt, _)| (cnt + 1) * item_size_16 < payload_max)
                    .map(|(_, att)| (att.get_handle().unwrap(), *att.get_uuid()))
                    .peekable(),
            );

            if let None = handle_uuids_16_bit_itr.1.peek() {
                // If there is no 16 bit UUIDs then the UUIDs must be sent in the full 128 bit form.

                // Size of each handle + 128-bit uuid responded pair
                let item_size_128 = 18;

                // Collect all UUIDs until the PDU is full or the first unreadable attribute is
                // found.
                let mut handle_uuids_128_bit_itr = HandleUuidItr(
                    true,
                    self.attributes.attributes[start..start]
                        .iter()
                        .take_while(|att| self.client_can_read_attribute(att).is_none())
                        .enumerate()
                        .take_while(|(cnt, _)| (cnt + 1) * item_size_128 < payload_max)
                        .map(|(_, att)| (att.get_handle().unwrap(), *att.get_uuid()))
                        .peekable(),
                );

                if let None = handle_uuids_128_bit_itr.1.peek() {
                    // If there are still no UUIDs then there are no UUIDs within the given range
                    // or none had the required read permissions for this operation.

                    self.send_error(
                        connection_channel,
                        start as u16,
                        ClientPduName::FindInformationRequest,
                        pdu::Error::AttributeNotFound,
                    )
                    .await
                } else {
                    let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), handle_uuids_128_bit_itr);

                    self.send_pdu(connection_channel, pdu).await
                }
            } else {
                // Send the 16 bit UUIDs

                let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), handle_uuids_16_bit_itr);

                self.send_pdu(connection_channel, pdu).await
            }
        } else {
            self.send_error(
                connection_channel,
                handle_range.starting_handle,
                ClientPduName::FindInformationRequest,
                pdu::Error::InvalidHandle,
            )
            .await
        }
    }

    /// Process find by type value request
    ///
    /// # Note
    ///
    /// Because the Attribute Protocol doesn't define what a 'group' is this returns the group
    /// end handle with the same found attribute handle.
    async fn process_find_by_type_value_request<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        if payload.len() >= 6 {
            let handle_range: pdu::HandleRange = TransferFormatTryFrom::try_from(&payload[..4]).unwrap();

            let att_type: crate::Uuid = TransferFormatTryFrom::try_from(&payload[4..6]).unwrap();

            log::info!(
                "Processing PDU ATT_FIND_BY_TYPE_VALUE_REQ {{ start handle: {:#X}, end \
                handle: {:#X}, type: {:?}}}",
                handle_range.starting_handle,
                handle_range.ending_handle,
                att_type
            );

            let raw_value = &payload[6..];

            if handle_range.is_valid() {
                use core::cmp::min;

                let start = min(handle_range.starting_handle as usize, self.attributes.count());
                let end = min(handle_range.ending_handle as usize, self.attributes.count());

                let payload_max = connection_channel.get_mtu() - 1;

                let mut cnt = 0;

                let mut transfer = Vec::new();

                for att in self.attributes.attributes[start..end].iter() {
                    if att.get_uuid().can_be_16_bit()
                        && att.get_uuid() == &att_type
                        && att.get_value().cmp_value_to_raw_transfer_format(raw_value).await
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
                    self.send_error(
                        connection_channel,
                        handle_range.starting_handle,
                        ClientPduName::FindByTypeValueRequest,
                        pdu::Error::AttributeNotFound,
                    )
                    .await
                } else {
                    self.send_pdu(
                        connection_channel,
                        pdu::Pdu::new(ServerPduName::FindByTypeValueResponse.into(), transfer),
                    )
                    .await
                }
            } else {
                self.send_error(
                    connection_channel,
                    handle_range.starting_handle,
                    ClientPduName::FindByTypeValueRequest,
                    pdu::Error::AttributeNotFound,
                )
                .await
            }
        } else {
            self.send_error(
                connection_channel,
                0,
                ClientPduName::FindInformationRequest,
                pdu::Error::InvalidPDU,
            )
            .await
        }
    }

    /// Process Read By Type Request
    async fn process_read_by_type_request<C>(
        &mut self,
        connection_channel: &C,
        type_request: pdu::TypeRequest,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!(
            "Processing PDU ATT_READ_BY_TYPE_REQ {{ start handle: {:#X}, end handle: {:#X}, \
            type: {:?} }}",
            type_request.handle_range.starting_handle,
            type_request.handle_range.ending_handle,
            type_request.attr_type
        );

        use core::cmp::min;

        let handle_range = type_request.handle_range;

        let desired_att_type = type_request.attr_type;

        if handle_range.is_valid() {
            let start = min(handle_range.starting_handle as usize, self.attributes.count());
            let end = min(handle_range.ending_handle as usize, self.attributes.count());

            let payload_max = connection_channel.get_mtu() - 2;

            let single_payload_size = |cnt, size| (cnt + 1) * (size + 2) < payload_max;

            let mut init_iter = self.attributes.attributes[start..end]
                .iter()
                .filter(|att| att.get_uuid() == &desired_att_type);

            match init_iter.by_ref().next() {
                None => {
                    self.send_error(
                        connection_channel,
                        handle_range.starting_handle,
                        ClientPduName::ReadByTypeRequest,
                        pdu::Error::AttributeNotFound,
                    )
                    .await
                }

                Some(first_match) => {
                    if let Some(e) = self.client_can_read_attribute(first_match) {
                        self.send_error(
                            connection_channel,
                            handle_range.starting_handle,
                            ClientPduName::ReadByTypeRequest,
                            e,
                        )
                        .await
                    } else {
                        let first_val = first_match.get_value();

                        let first_handle = first_match.get_handle().unwrap();

                        let first_size = first_val.value_transfer_format_size().await;

                        let mut responses = Vec::new();

                        if !single_payload_size(0, first_size) {
                            use core::mem::replace;

                            // This is where the data to be transferred of the first found attribute
                            // is too large or equal to the connection MTU. Here, a read by type
                            // response is generated with as much of the value transfer format that
                            // can fit into the payload. A read blob request from the client is then
                            // required to complete the full read.

                            // Read type response includes a 2 byte handle, so the maximum byte
                            // size for the data is the payload - 2
                            let max_size = payload_max - 2;

                            let mut rsp = first_val.single_read_by_type_response(first_handle).await;

                            let sent = rsp[0..max_size].to_vec();

                            // Move the complete data to a blob data while replacing it with the
                            // sent amount
                            self.set_blob_data(replace(&mut *rsp, sent), rsp.get_handle());

                            responses.push(rsp);
                        } else {
                            let fst_rsp = first_val.single_read_by_type_response(first_handle).await;

                            responses.push(fst_rsp);

                            for (cnt, att) in init_iter.enumerate() {
                                let val = att.get_value();
                                let handle = att.get_handle().unwrap();

                                // Break if att doesn't have the same transfer size as the
                                // first value or if adding the value would exceed the MTU for
                                // the attribute payload
                                if !single_payload_size(cnt + 1, first_size)
                                    || first_size != val.value_transfer_format_size().await
                                {
                                    break;
                                }

                                let response = val.single_read_by_type_response(handle).await;

                                responses.push(response);
                            }
                        }

                        self.send_pdu(connection_channel, pdu::read_by_type_response(responses))
                            .await
                    }
                }
            }
        } else {
            self.send_error(
                connection_channel,
                handle_range.starting_handle,
                ClientPduName::ReadByTypeRequest,
                pdu::Error::InvalidHandle,
            )
            .await
        }
    }

    /// Process read blob request
    async fn process_read_blob_request<C>(
        &mut self,
        connection_channel: &C,
        blob_request: pdu::ReadBlobRequest,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!(
            "Processing PDU ATT_READ_BLOB_REQ {{ handle: {:#X}, offset {:#X} }}",
            blob_request.handle,
            blob_request.offset
        );

        // Check the permissions (`check_permission` also validates the handle)
        match match self.check_permissions(blob_request.handle, &super::FULL_READ_PERMISSIONS) {
            Ok(_) => {
                // Make a new blob if blob data doesn't exist or the blob handle does not match the
                // requested for handle
                let use_old_blob = self
                    .blob_data
                    .as_ref()
                    .map(|bd| bd.handle == blob_request.handle)
                    .unwrap_or_default();

                match (use_old_blob, blob_request.offset) {
                    // No prior blob or start of new blob
                    (false, _) | (_, 0) => self.create_blob_send_response(connection_channel, &blob_request).await,

                    // Continuing reading prior blob
                    (true, offset) => self.use_blob_send_response(connection_channel, offset).await,
                }
            }

            Err(e) => Err(e.into()),
        } {
            Err(e) => match e {
                ConnectionError::AttError(super::Error::PduError(e)) => {
                    self.send_error(
                        connection_channel,
                        blob_request.handle,
                        ClientPduName::ReadBlobRequest,
                        e,
                    )
                    .await
                }

                _ => Err(e),
            },

            _ => Ok(()),
        }
    }

    /// Create a new blob and send the blob response
    ///
    /// This function is a helper function for process read blob request
    ///
    /// # Note
    /// If the entire data payload can be contained within one response then no blob is created.
    ///
    /// # Warning
    /// This does not check permissions for accessibility of the attribute by the client and assumes
    /// the handle requested is valid
    #[inline]
    async fn create_blob_send_response<C>(
        &mut self,
        connection_channel: &C,
        br: &pdu::ReadBlobRequest,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        let data = self.attributes.get(br.handle).unwrap().get_value().read().await;

        let rsp = match self.new_read_blob_response(connection_channel, &data, br.offset)? {
            // when true is returned the data is blobbed
            (rsp, true) => {
                self.blob_data = MultiReqData {
                    handle: br.handle,
                    tf_data: data.clone(),
                }
                .into();

                rsp
            }

            (rsp, false) => rsp,
        };

        self.send_pdu(connection_channel, rsp).await
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
    async fn use_blob_send_response<C>(
        &mut self,
        connection_channel: &C,
        offset: u16,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        let data = self.blob_data.as_ref().unwrap();

        match self.new_read_blob_response(connection_channel, &data.tf_data, offset)? {
            (rsp, false) => {
                self.send_pdu(connection_channel, rsp).await?;

                // This is the final piece of the blob
                self.blob_data = None;

                Ok(())
            }

            (rsp, true) => self.send_pdu(connection_channel, rsp).await,
        }
    }

    /// Create a Read Blob Response
    ///
    /// This return is the Read Blob Response with a boolean to indicate if the response payload was
    /// completely filled with data bytes.
    #[inline]
    fn new_read_blob_response<'a, C>(
        &self,
        connection_channel: &C,
        data: &'a [u8],
        offset: u16,
    ) -> Result<(pdu::Pdu<pdu::LocalReadBlobResponse<'a>>, bool), pdu::Error>
    where
        C: ConnectionChannel,
    {
        let max_payload = connection_channel.get_mtu() - 1;

        match offset as usize {
            o if o > data.len() => Err(pdu::Error::InvalidOffset),

            o if o + max_payload <= data.len() => Ok((
                pdu::LocalReadBlobResponse::new(&data[o..(o + max_payload)]).into(),
                true,
            )),

            o => Ok((pdu::LocalReadBlobResponse::new(&data[o..]).into(), false)),
        }
    }

    async fn process_prepare_write_request<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        if let Err((h, e)) = match pdu::PreparedWriteRequest::try_from_raw(payload) {
            Ok(request) => {
                log::info!(
                    "Processing ATT_PREPARE_WRITE_REQ {{ handle: {:#X}, offset {} }}",
                    request.get_handle(),
                    request.get_prepared_offset()
                );

                match self.check_permissions(request.get_handle(), &super::FULL_WRITE_PERMISSIONS) {
                    Ok(_) => match self.queued_writer.process_prepared(&request) {
                        Err(e) => Err((request.get_handle(), e)),

                        Ok(_) => {
                            let response = pdu::PreparedWriteResponse::pdu_from_request(&request);

                            self.send_pdu(connection_channel, response).await?;

                            Ok(())
                        }
                    },

                    Err(e) => Err((request.get_handle(), e)),
                }
            }

            Err(e) => Err((0, e.pdu_err)),
        } {
            self.send_error(connection_channel, h, ClientPduName::PrepareWriteRequest, e)
                .await
        } else {
            Ok(())
        }
    }

    async fn process_execute_write_request<C>(
        &mut self,
        connection_channel: &C,
        request_flag: pdu::ExecuteWriteFlag,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        log::info!("Processing ATT_EXECUTE_WRITE_REQ {{ flag: {:?} }}", request_flag);

        match match self.queued_writer.process_execute(request_flag) {
            Ok(Some(iter)) => {
                for queued_data in iter.into_iter() {
                    self.check_permissions(queued_data.0, &super::FULL_WRITE_PERMISSIONS)?;

                    self.write_att(queued_data.0, &queued_data.1).await?;
                }

                Ok(())
            }

            Ok(None) => Ok(()),

            Err(e) => Err(e),
        } {
            Err(e) => {
                self.send_error(connection_channel, 0, ClientPduName::ExecuteWriteRequest, e)
                    .await
            }

            Ok(_) => self.send_pdu(connection_channel, pdu::execute_write_response()).await,
        }
    }

    /// Get an iterator over the attribute informational data
    ///
    /// This will return an iterator to get the type, permissions, and handle for each attribute
    pub fn iter_attr_info(&self) -> impl Iterator<Item = AttributeInfo<'_>> {
        self.attributes.iter_info()
    }
}

pub struct ServerAttributes {
    attributes: Vec<super::Attribute<Box<dyn ServerAttribute + Send + Sync>>>,
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
            value: access_value::Trivial(attribute.value),
        };

        self.push_accessor(trivial)
    }

    /// Push an attribute with a borrowed value
    ///
    /// This will push the attribute onto the list of server attributes and return the handle for
    /// the attribute.
    ///
    /// The main usage of `push_borrowed` is to use a dynamically sized type when the attribute is
    /// read and use an 'owned' type when the attribute is written. The generic parameter `D` must
    /// be able to be converted from the owned type.
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
        D: core::ops::Deref + From<<D::Target as ToOwned>::Owned> + Unpin + Send + Sync + 'static,
        D::Target: TransferFormatInto + ToOwned + Comparable + Send + Sync,
        <D::Target as ToOwned>::Owned: TransferFormatTryFrom + Unpin + Send + Sync,
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
            value: Box::from(AccessibleValue(attribute.value)) as Box<dyn ServerAttribute + Send + Sync + 'static>,
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
            value: Box::from(ReadOnly(attribute.value)) as Box<dyn ServerAttribute + Send + Sync + 'static>,
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
        self.attributes.len()
    }

    /// Get attribute with the given handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get(&self, handle: u16) -> Option<&super::Attribute<Box<dyn ServerAttribute + Send + Sync>>> {
        match handle {
            0 => None,
            h => self.attributes.get(<usize>::from(h)),
        }
    }

    /// Get a mutable reference to the attribute with the given handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get_mut(&mut self, handle: u16) -> Option<&mut super::Attribute<Box<dyn ServerAttribute + Send + Sync>>> {
        match handle {
            0 => None,
            h => self.attributes.get_mut(<usize>::from(h)),
        }
    }
}

impl Default for ServerAttributes {
    fn default() -> Self {
        Self::new()
    }
}

pub type PinnedFuture<'a, O> = Pin<Box<dyn Future<Output = O> + Send + Sync + 'a>>;

/// A value accessor
///
/// In order to share a value between connections, the value must be behind an accessor. An accessor
/// ensures that reads and writes are atomic to all clients that have access to the value.
///
/// The intention of this trait is to be implemented for async mutex-like synchronization
/// primitives. Although the implementations must be enabled by features, `AccessValue` is
/// implemented for the mutex types of the crates [async-std], [futures], and [tokio].
///
/// [async-std]: https://docs.rs/async-std/latest/async_std/index.html
/// [futures]: https://docs.rs/futures/latest/futures/index.html
/// [tokio]: https://docs.rs/tokio/latest/tokio/index.html
pub trait AccessValue: Send + Sync {
    type ReadValue: ?Sized + Send + Sync;

    type ReadGuard<'a>: core::ops::Deref<Target = Self::ReadValue>
    where
        Self: 'a;

    type Read<'a>: Future<Output = Self::ReadGuard<'a>> + Send + Sync
    where
        Self: 'a;

    type WriteValue: Unpin + Send + Sync;

    type Write<'a>: Future + Send + Sync
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_>;

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_>;
}

/// Extension method for `ServerAttributeValue`
trait ServerAttributeValueExt: AccessValue {
    /// Read the value and call `f` with a reference to it.
    fn read_and<F, T>(&self, f: F) -> ReadAnd<Self::Read<'_>, F>
    where
        F: FnOnce(&Self::ReadValue) -> T + Unpin + Send + Sync,
    {
        let read = self.read();

        ReadAnd {
            reader: read,
            job: Some(f),
        }
    }
}

impl<S: AccessValue> ServerAttributeValueExt for S {}

/// Future for reading the value and performing an operation
struct ReadAnd<R, F> {
    reader: R,
    job: Option<F>,
}

impl<R, G, V, F, T> Future for ReadAnd<R, F>
where
    R: Future<Output = G>,
    G: core::ops::Deref<Target = V>,
    F: FnOnce(&V) -> T + Unpin,
    V: ?Sized,
{
    type Output = T;

    fn poll(self: Pin<&mut Self>, cx: &mut Context) -> Poll<Self::Output> {
        unsafe {
            let this = self.get_unchecked_mut();

            Pin::new_unchecked(&mut this.reader)
                .poll(cx)
                .map(|val| (this.job.take().unwrap())(&*val))
        }
    }
}

/// Read only access
///
/// This is the same as [`AccessValue`] except this cannot be written to and the associated type
/// `Value` may be a dynamically sized type. The value types only need to implement
/// [`TransferFormatInto`] and not [`TransferFormatTryFrom`]. However, not only can the client not
/// be able to write to this value, it also *cannot search by value for the attribute containing
/// this*. This is because in order to compare
///
/// [`TransferFormatTryFrom`]: crate::TransferFormatTryFrom
pub trait AccessReadOnly: Send + Sync {
    type Value: ?Sized + Send + Sync;

    type ReadGuard<'a>: core::ops::Deref<Target = Self::Value>
    where
        Self: 'a;

    type Read<'a>: Future<Output = Self::ReadGuard<'a>> + Send + Sync
    where
        Self: 'a;

    fn read(&self) -> Self::Read<'_>;
}

trait AccessReadOnlyExt: AccessReadOnly {
    /// Read the value and call `f` with a reference to it.
    fn read_and<F, T>(&self, f: F) -> ReadAnd<Self::Read<'_>, F>
    where
        F: FnOnce(&Self::Value) -> T + Unpin + Send + Sync,
    {
        let read = self.read();

        ReadAnd {
            reader: read,
            job: Some(f),
        }
    }
}

impl<T: AccessReadOnly> AccessReadOnlyExt for T {}

/// A server attribute
///
/// A `ServerAttribute` is an attribute that has been added to the `ServerAttributes`. These
/// functions are designed to abstract away from the type of the attribute value so a
/// `ServerAttributes` can have a list of boxed `dyn ServerAttribute`.
trait ServerAttribute {
    /// Read the data
    ///
    /// The returned data is in its transfer format
    fn read(&self) -> PinnedFuture<Vec<u8>>;

    /// Generate a 'Read Response'
    ///
    /// This will create a read response PDU in its transfer bytes format.
    fn read_response(&self) -> PinnedFuture<'_, pdu::Pdu<pdu::ReadResponse<Vec<u8>>>>;

    /// Generate a 'Notification'
    ///
    /// This creates a notification PDU in its transfer bytes format.
    ///
    /// # Panic
    /// This should panic if the attribute has not been assigned a handle
    fn notification(&self, handle: u16) -> PinnedFuture<'_, pdu::Pdu<pdu::HandleValueNotification<Vec<u8>>>>;

    /// Generate a 'Read by Type Response'
    ///
    /// This creates a
    /// [`ReadByTypeResponse`](crate::pdu::ReadByTypeResponse)
    /// with the data of the response already in the transfer format. If the first found type cannot
    /// fit within the attribute MTU for the att payload, then max_size can be used to truncate the
    /// raw transfer format data of self to max_size. If max_size is None, then truncating is not
    /// performed.
    ///
    /// # Panic
    /// This should panic if the attribute has not been assigned a handle
    fn single_read_by_type_response(&self, handle: u16) -> PinnedFuture<'_, pdu::ReadTypeResponse<Vec<u8>>>;

    /// Try to convert raw data from the interface and write to the attribute value
    fn try_set_value_from_transfer_format<'a>(
        &'a mut self,
        tf_data: &'a [u8],
    ) -> PinnedFuture<'a, Result<(), super::TransferFormatError>>;

    /// The number of bytes in the interface format
    fn value_transfer_format_size(&self) -> PinnedFuture<'_, usize>;

    /// Compare the value with the data received from the interface
    fn cmp_value_to_raw_transfer_format<'a>(&'a self, raw: &'a [u8]) -> PinnedFuture<'a, bool>;
}

/// Wrapper type for an type that implements [`AccessValue`]
struct AccessibleValue<A: AccessValue>(A);

impl<A> ServerAttribute for AccessibleValue<A>
where
    A: AccessValue + 'static,
    A::ReadValue: TransferFormatInto + Comparable,
    A::WriteValue: TransferFormatTryFrom,
{
    fn read(&self) -> PinnedFuture<Vec<u8>> {
        Box::pin(self.0.read_and(|v| TransferFormatInto::into(v)))
    }

    fn read_response(&self) -> PinnedFuture<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>> {
        Box::pin(self.0.read_and(|v| pdu::read_response(TransferFormatInto::into(v))))
    }

    fn notification(&self, handle: u16) -> PinnedFuture<pdu::Pdu<pdu::HandleValueNotification<Vec<u8>>>> {
        Box::pin(
            self.0
                .read_and(move |v| pdu::handle_value_notification(handle, TransferFormatInto::into(v))),
        )
    }

    fn single_read_by_type_response(&self, handle: u16) -> PinnedFuture<pdu::ReadTypeResponse<Vec<u8>>> {
        Box::pin(self.0.read_and(move |v| {
            let tf = TransferFormatInto::into(v);

            pdu::ReadTypeResponse::new(handle, tf)
        }))
    }

    fn try_set_value_from_transfer_format<'a>(
        &'a mut self,
        raw: &'a [u8],
    ) -> PinnedFuture<'a, Result<(), TransferFormatError>> {
        Box::pin(async move {
            self.0.write(TransferFormatTryFrom::try_from(raw)?).await;

            Ok(())
        })
    }

    fn value_transfer_format_size(&self) -> PinnedFuture<usize> {
        Box::pin(async move { self.0.read_and(|v: &A::ReadValue| v.len_of_into()).await })
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a self, raw: &'a [u8]) -> PinnedFuture<'_, bool> {
        Box::pin(async move { self.read().await.cmp_tf_data(raw) })
    }
}

/// Wrapper around a type that implements `AccessReadOnly`
///
/// # Note
/// This type must only be used with read only attribute permissions.
struct ReadOnly<R: AccessReadOnly>(R);

impl<R> ServerAttribute for ReadOnly<R>
where
    R: AccessReadOnly + 'static,
    R::Value: TransferFormatInto + Comparable,
{
    fn read(&self) -> PinnedFuture<Vec<u8>> {
        Box::pin(self.0.read_and(|v| TransferFormatInto::into(v)))
    }

    fn read_response(&self) -> PinnedFuture<pdu::Pdu<pdu::ReadResponse<Vec<u8>>>> {
        Box::pin(self.0.read_and(|v| pdu::read_response(TransferFormatInto::into(v))))
    }

    fn notification(&self, handle: u16) -> PinnedFuture<pdu::Pdu<pdu::HandleValueNotification<Vec<u8>>>> {
        Box::pin(
            self.0
                .read_and(move |v| pdu::handle_value_notification(handle, TransferFormatInto::into(v))),
        )
    }

    fn single_read_by_type_response(&self, handle: u16) -> PinnedFuture<pdu::ReadTypeResponse<Vec<u8>>> {
        Box::pin(self.0.read_and(move |v| {
            let tf = TransferFormatInto::into(v);

            pdu::ReadTypeResponse::new(handle, tf)
        }))
    }

    fn try_set_value_from_transfer_format<'a>(
        &'a mut self,
        _: &'a [u8],
    ) -> PinnedFuture<'a, Result<(), TransferFormatError>> {
        unreachable!()
    }

    fn value_transfer_format_size(&self) -> PinnedFuture<usize> {
        Box::pin(async move { self.0.read_and(|v: &R::Value| v.len_of_into()).await })
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a self, raw: &'a [u8]) -> PinnedFuture<'a, bool> {
        Box::pin(async move { self.read().await.cmp_tf_data(raw) })
    }
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

impl From<ReservedHandle> for super::Attribute<Box<dyn ServerAttribute + Send + Sync>> {
    fn from(_: ReservedHandle) -> Self {
        super::Attribute::new(crate::Uuid::from_u128(0u128), Vec::new(), Box::new(ReservedHandle))
    }
}

impl ServerAttribute for ReservedHandle {
    fn read(&self) -> PinnedFuture<Vec<u8>> {
        log::error!("Tried to read the reserved handle");

        Box::pin(async { Vec::new() })
    }

    fn read_response(&self) -> PinnedFuture<'_, pdu::Pdu<pdu::ReadResponse<Vec<u8>>>> {
        Box::pin(async {
            log::error!("Tried to read the reserved handle for a read response");

            pdu::read_response(Vec::new())
        })
    }

    fn notification(&self, _: u16) -> PinnedFuture<'_, pdu::Pdu<pdu::HandleValueNotification<Vec<u8>>>> {
        Box::pin(async {
            log::error!("Tried to used the reserved handle as a notification");

            pdu::handle_value_notification(0, Vec::new())
        })
    }

    fn single_read_by_type_response(&self, _: u16) -> PinnedFuture<'_, pdu::ReadTypeResponse<Vec<u8>>> {
        Box::pin(async {
            log::error!("Tried to read the reserved handle for a read by type response");

            pdu::ReadTypeResponse::new(0, Vec::new())
        })
    }

    fn try_set_value_from_transfer_format(
        &mut self,
        _: &[u8],
    ) -> PinnedFuture<'_, Result<(), super::TransferFormatError>> {
        Box::pin(async {
            log::error!("Tried to write to reserved attribute handle");

            Err(TransferFormatError::from("ReservedHandle cannot be set from raw data"))
        })
    }

    fn value_transfer_format_size(&self) -> PinnedFuture<'_, usize> {
        Box::pin(async { 0 })
    }

    fn cmp_value_to_raw_transfer_format(&self, _: &[u8]) -> PinnedFuture<'_, bool> {
        Box::pin(async { false })
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttributeInfo<'a> {
    ty: &'a crate::Uuid,
    handle: u16,
    permissions: &'a [super::AttributePermissions],
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
/// Once a client as sent a prepared write request to the server this queue writer will only accept
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
    /// Create a new BasicQueuedWriter
    ///
    /// The input `buffer_cap` is the capacity of the data buffer used for queuing writes.
    pub fn new(buffer_cap: usize) -> Self {
        Self {
            data: Vec::with_capacity(buffer_cap),
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
