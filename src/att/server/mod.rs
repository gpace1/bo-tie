//! Attribute Server
//!
//! The attribute server for this library is dynamic. It utilizes trait objects for the attribute
//! data with the only requirements that the data implement
//! [`TransferFormatInto`](crate::att:TransferFormatInto), and
//! [`TransferFormatTryFrom`](crate::att::TransferFormatTryFrom). The server organizes the data as
//! a vectored list, all attributes are forced into a consecutive order. The client can query the
//! server using the requests specified within the specification (V 5.0, vol 3 part F section 3.4)
//! except for 'Read By Group Type Request' as groups are not specified by the attribute server.
//!
//! Creating a `Server` requires two things, a L2CAP
//! [`ConnectionChannel`](crate::l2cap::ConnectionChannel) and a
//! [`ServerAttributes`](crate::att::server::ServerAttributes). A `ConnectionChannel` comes from
//! something that implements a data link layer, in this library you can create them in the Host
//! Controller Interface from a
//! [`HostInterface`](crate::hci::HostInterface). `ServerAttributes` is the actual list of
//! attributes in the server. Its implemented so that any type of data is accepted so long as the
//! data type implements `TransferFormatInto` and `TransferFormatTryFrom` and is wrapped within the
//! type
//! [`ServerAttributeValue`](crate::att::server::ServerAttributeValue).
//!
//! A `Server` does not implement the marker trait `Sync`, meaning it cannot be shared between
//! threads. There is too many states within a server for a `Server` to be designed to be `Sync`.
//! Instead of one `Server` being used for all connections, there is instead a `Server` for each
//! connection (although there is nothing stopping you from using multiple servers for a connection,
//! its undefined behaviour if you do it). Data can be shared between multiple `Servers` but it
//! needs to be `Send` + `Sync`, which generally requires some synchronization primitives. The
//! point of `ServerAttributeValue` is to provide a synchronization container around a data so that
//! it can be used between multiple servers.
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

#[cfg(test)]
mod tests;

use super::{
    client::ClientPduName, pdu, AttributePermissions, AttributeRestriction, TransferFormatError, TransferFormatInto,
    TransferFormatTryFrom,
};
use crate::l2cap;
use alloc::{boxed::Box, vec::Vec};
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

impl core::convert::TryFrom<super::pdu::PduOpcode> for ServerPduName {
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

impl core::convert::TryFrom<u8> for ServerPduName {
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
/// [`ServerAttributeValue`](crate::att::server::ServerAttributeValue)
/// can be implemented on the container to perform concurrency safe reading or writing on the
/// contained value.
pub struct Server<'c, C, Q> {
    /// The connection channel for sending and receiving data from the Bluetooth controller
    connection_channel: &'c C,
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

impl<'c, C, Q> Server<'c, C, Q>
where
    C: l2cap::ConnectionChannel,
    Q: QueuedWriter,
{
    /// Create a new Server
    ///
    /// Creates an attribute server for a client connected with the logical link `connection`, the
    /// attributes of the server are optionally initialized with input `server_attributes`, and the
    /// `queued_writer` is the manager for queued writes. If `server_attributes` is set to `None`
    /// then a server with no attributes is created.
    pub fn new<A>(connection: &'c C, server_attributes: A, queued_writer: Q) -> Self
    where
        A: Into<Option<ServerAttributes>>,
    {
        let attributes = server_attributes.into().unwrap_or(ServerAttributes::new());

        Self {
            connection_channel: connection,
            attributes,
            given_permissions: Vec::new(),
            blob_data: None,
            queued_writer,
        }
    }

    /// Get the maximum transfer unit of the connection
    ///
    /// The is the current mtu as agreed upon by the client and server
    pub fn get_mtu(&self) -> usize {
        self.connection_channel.get_mtu()
    }

    /// Push an attribute onto the handle stack
    ///
    /// This function will return the handle to the attribute.
    ///
    /// # Panic
    /// If you manage to push 65535 attributes onto this server, the next pushed attribute will
    /// cause this function to panic.
    pub fn push<X, V>(&mut self, attribute: super::Attribute<X>) -> u16
    where
        X: ServerAttributeValue<Value = V> + Send + Sized + 'static,
        V: TransferFormatTryFrom + TransferFormatInto + 'static,
    {
        use core::convert::TryInto;

        let ret = self
            .attributes
            .len()
            .try_into()
            .expect("Exceeded attribute handle limit");

        self.attributes.push(attribute);

        ret
    }

    /// Return the next unused handle
    pub fn next_handle(&self) -> u16 {
        self.attributes.len() as u16
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
    /// does not have permission to perform the operation, an error containing the permission
    /// failure reason is returned. There are to inputs for permission lists. `required` is the list
    /// of permissions that the operation requires that both the attribute and the client have
    /// permission for, and `restricted` are the permissions the client must have if the attribute
    /// requires them.
    ///
    /// The `required` input is the permissions that are needed to perform an operation, and the
    /// operation cannot be done without both the attribute and client having these permissions. If
    /// the operation is a read operation, it could have
    /// [`Read`](crate::att::AttributePermissions::Read) as part of its list of 'required'
    /// permissions. If either the attribute or client does not the `Read` permission then the
    /// operation should fail with the error `ReadNotPermitted`.
    ///
    /// The `restricted` input is the permissions that are required by the client if the attribute
    /// has them. These can be thought of as extra permissions required by the attribute to perform
    /// the operation.
    ///
    /// # Errors
    /// If a permission is not satisfied, this function will return a corresponding error to the
    /// permission
    /// - [`Read`](super::AttributePermissions::Read) ->
    /// [`ReadNotPermitted`](super::pdu::Error::ReadNotPermitted)
    /// - [`Write`](super::AttributePermissions::Write) ->
    /// [`WriteNotPermitted`](super::pdu::Error::WriteNotPermitted)
    /// - [`Encryption`](super::AttributePermissions::Encryption)(`restriction`, _) where
    /// `restriction` isn't matched -> [`InsufficientEncryption`](pdu::Error::InsufficientEncryption)
    /// - [`Encryption`](super::AttributePermissions::Encryption)(`restriction`, `key`) where
    /// `restriction` is matched but `key` is not matched ->
    /// [`InsufficientEncryptionKeySize`](pdu::Error::InsufficientEncryptionKeySize)
    /// - [`Authentication`](super::AttributePermissions::Authentication) ->
    /// [`InsufficientAuthentication`](pdu::Error::InsufficientAuthentication)
    /// - [`Authorization`](super::AttributePermissions::Authorization) ->
    /// [`InsufficientAuthorization`](pdu::Error::InsufficientAuthorization)
    ///
    /// If there is no attribute with the handle `handle`, then the error
    /// [`InvalidHandle`](super::pdu::Error::InvalidHandle) is returned.
    pub fn check_permissions(
        &self,
        handle: u16,
        permissions: &[super::AttributePermissions],
    ) -> Result<(), pdu::Error> {
        let att = self.attributes.get(handle).ok_or(super::pdu::Error::InvalidHandle)?;

        match self.validate_permissions(att.get_permissions(), permissions) {
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
        self.validate_permissions(att.get_permissions(), super::FULL_READ_PERMISSIONS)
    }

    /// Check if a client can write the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_write_attribute<V>(&self, att: &super::Attribute<V>) -> Option<pdu::Error> {
        self.validate_permissions(att.get_permissions(), super::FULL_WRITE_PERMISSIONS)
    }

    /// Process a received Acl Data packet form the Bluetooth Controller
    ///
    /// The packet is assumed to be in the form of an Attribute protocol request packet. This
    /// function will then process the request and send to the client the appropriate response
    /// packet.
    ///
    /// This function is a combination of the methods
    /// [`parse_acl_packet`](crate::att::server::Server::parse_acl_packet) and
    /// [`process_parsed_acl_data`](crate::att::server::Server::process_parsed_acl_data). It is
    /// recommended to use this function over those two functions when this `Server` is at the top
    /// of your server stack (you're not using GATT or some other custom higher layer protocol).
    pub async fn process_acl_data(&mut self, acl_packet: &crate::l2cap::AclData) -> Result<(), super::Error> {
        let (pdu_type, payload) = self.parse_acl_packet(acl_packet)?;

        self.process_parsed_acl_data(pdu_type, payload).await
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
    /// [`process_acl_data`](crate::att::server::Server::process_acl_data) when directly using this
    /// server for communication with a client device.
    pub fn parse_acl_packet<'a>(
        &self,
        acl_packet: &'a crate::l2cap::AclData,
    ) -> Result<(super::client::ClientPduName, &'a [u8]), super::Error> {
        use crate::l2cap::{ChannelIdentifier, LeUserChannelIdentifier};
        use core::convert::TryFrom;

        match acl_packet.get_channel_id() {
            ChannelIdentifier::LE(LeUserChannelIdentifier::AttributeProtocol) => {
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
    /// [`process_acl_data`](crate::att::server::Server::process_acl_data) when directly using this
    /// server for communication with a client device.
    pub async fn process_parsed_acl_data(
        &mut self,
        pdu_type: super::client::ClientPduName,
        payload: &[u8],
    ) -> Result<(), super::Error> {
        match pdu_type {
            super::client::ClientPduName::ExchangeMtuRequest => {
                self.process_exchange_mtu_request(TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            super::client::ClientPduName::WriteRequest => self.process_write_request(&payload).await,

            super::client::ClientPduName::ReadRequest => {
                self.process_read_request(TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            super::client::ClientPduName::FindInformationRequest => {
                self.process_find_information_request(TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            super::client::ClientPduName::FindByTypeValueRequest => {
                self.process_find_by_type_value_request(&payload).await
            }

            super::client::ClientPduName::ReadByTypeRequest => {
                self.process_read_by_type_request(TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            super::client::ClientPduName::ReadBlobRequest => {
                self.process_read_blob_request(TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            super::client::ClientPduName::PrepareWriteRequest => self.process_prepare_write_request(&payload).await,

            super::client::ClientPduName::ExecuteWriteRequest => {
                self.process_execute_write_request(TransferFormatTryFrom::try_from(&payload)?)
                    .await
            }

            pdu @ super::client::ClientPduName::ReadMultipleRequest
            | pdu @ super::client::ClientPduName::WriteCommand
            | pdu @ super::client::ClientPduName::HandleValueConfirmation
            | pdu @ super::client::ClientPduName::SignedWriteCommand
            | pdu @ super::client::ClientPduName::ReadByGroupTypeRequest => {
                self.send_error(0, pdu.into(), pdu::Error::RequestNotSupported).await
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
    async fn send_raw_tf(&self, intf_data: Vec<u8>) -> Result<(), super::Error> {
        let acl_data = l2cap::AclData::new(intf_data, super::L2CAP_CHANNEL_ID);

        self.connection_channel
            .send(acl_data)
            .await
            .map_err(|e| super::Error::send_error::<C>(e))
    }

    async fn send<D>(&self, data: D) -> Result<(), super::Error>
    where
        D: TransferFormatInto,
    {
        self.send_raw_tf(TransferFormatInto::into(&data)).await
    }

    /// Send an attribute PDU to the client
    pub async fn send_pdu<D>(&self, pdu: pdu::Pdu<D>) -> Result<(), super::Error>
    where
        D: TransferFormatInto,
    {
        log::trace!("Sending {}", pdu.get_opcode());

        self.send(pdu).await
    }

    /// Send an error the the client
    pub async fn send_error(
        &self,
        handle: u16,
        received_opcode: ClientPduName,
        pdu_error: pdu::Error,
    ) -> Result<(), super::Error> {
        log::info!(
            "Sending error response. Received Op Code: '{:#x}', Handle: '{:?}', error: '{}'",
            Into::<u8>::into(received_opcode),
            handle,
            pdu_error
        );

        self.send_pdu(pdu::error_response(received_opcode.into(), handle, pdu_error))
            .await
    }

    /// Get an arc clone to an attribute value
    fn get_att(&self, handle: u16) -> Result<&super::Attribute<Box<dyn ServerAttribute + Send>>, pdu::Error> {
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
    ) -> Result<&mut super::Attribute<Box<dyn ServerAttribute + Send>>, pdu::Error> {
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
        F: FnOnce(&'s (dyn ServerAttribute + Send)) -> A + 's,
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
    async fn process_exchange_mtu_request(&mut self, client_mtu: u16) -> Result<(), super::Error> {
        log::info!("Processing PDU ATT_EXCHANGE_MTU_REQ {{ mtu: {} }}", client_mtu);

        self.connection_channel.set_mtu(client_mtu);

        self.send_pdu(pdu::exchange_mtu_response(self.connection_channel.get_mtu() as u16))
            .await
    }

    /// Process a Read Request from the client
    async fn process_read_request(&mut self, handle: u16) -> Result<(), super::Error> {
        log::info!("Processing PDU ATT_READ_REQ {{ handle: {:#X} }}", handle);

        match self.read_att_and(handle, |att_tf| att_tf.read_response()).await {
            Ok(mut tf) => {
                // Amount of data that can be sent is the MTU minus the read response header size
                if tf.get_parameters().0.len() > (self.get_mtu() - 1) {
                    use core::mem::replace;

                    let sent = tf.get_parameters().0[..(self.get_mtu() - 1)].to_vec();

                    self.set_blob_data(replace(&mut tf.get_mut_parameters().0, sent), handle);
                }

                self.send_pdu(tf).await
            }
            Err(e) => self.send_error(handle, ClientPduName::ReadRequest, e).await,
        }
    }

    /// Process a Write Request from the client
    async fn process_write_request(&mut self, payload: &[u8]) -> Result<(), super::Error> {
        // Need to split the handle from the raw data as the data type is not known
        let handle = TransferFormatTryFrom::try_from(&payload[..2]).unwrap();

        log::info!("Processing PDU ATT_WRITE_REQ {{ handle: {:#X} }}", handle);

        match self.write_att(handle, &payload[2..]).await {
            Ok(_) => self.send_pdu(pdu::write_response()).await,
            Err(e) => self.send_error(handle, ClientPduName::WriteRequest, e).await,
        }
    }

    /// Process a Find Information Request form the client
    async fn process_find_information_request(&mut self, handle_range: pdu::HandleRange) -> Result<(), super::Error> {
        log::info!(
            "Processing PDU ATT_FIND_INFORMATION_REQ {{ start handle: {}, end handle: {} }}",
            handle_range.starting_handle,
            handle_range.ending_handle
        );

        /// Handle with UUID iterator
        ///
        /// The boolean is used to indicate whether or not the iterator is over short or long UUIDs.
        struct HandleUuidItr<I: Iterator<Item = (u16, crate::UUID)> + Clone>(bool, I);

        impl<I: Iterator<Item = (u16, crate::UUID)> + Clone> TransferFormatInto for HandleUuidItr<I> {
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
            let start = min(handle_range.starting_handle as usize, self.attributes.len());
            let stop = min(handle_range.ending_handle as usize, self.attributes.len());

            let payload_max = self.get_mtu() - 2;

            // Size of each handle + 16-bit-uuid responded pair
            let item_size_16 = 4;

            // Try to build response_payload full of 16 bit attribute types. This will stop at the
            // first attribute type that cannot be converted into a shortened 16 bit UUID or where
            // the client does not have permissions to access the attribute.
            let mut handle_uuids_16_bit_itr = HandleUuidItr(
                false,
                self.attributes.attributes[start..stop]
                    .iter()
                    .filter(|att| att.get_uuid().is_16_bit())
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
                        start as u16,
                        ClientPduName::FindInformationRequest,
                        pdu::Error::AttributeNotFound,
                    )
                    .await
                } else {
                    let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), handle_uuids_128_bit_itr);

                    self.send_pdu(pdu).await
                }
            } else {
                // Send the 16 bit UUIDs

                let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), handle_uuids_16_bit_itr);

                self.send_pdu(pdu).await
            }
        } else {
            self.send_error(
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
    async fn process_find_by_type_value_request(&mut self, payload: &[u8]) -> Result<(), super::Error> {
        if payload.len() >= 6 {
            let handle_range: pdu::HandleRange = TransferFormatTryFrom::try_from(&payload[..4]).unwrap();

            let att_type: crate::UUID = TransferFormatTryFrom::try_from(&payload[4..6]).unwrap();

            log::info!("Processing PDU ATT_FIND_BY_TYPE_VALUE_REQ {{ start handle: {:#X}, end \
                handle: {:#X}, type: {:?}}}",
                handle_range.starting_handle,
                handle_range.ending_handle,
                att_type
            );

            let raw_value = &payload[6..];

            if handle_range.is_valid() {
                use core::cmp::min;

                let start = min(handle_range.starting_handle as usize, self.attributes.len());
                let end = min(handle_range.ending_handle as usize, self.attributes.len());

                let payload_max = self.get_mtu() - 1;

                let mut cnt = 0;

                let mut transfer = Vec::new();

                for att in self.attributes.attributes[start..end].iter() {
                    if att.get_uuid().is_16_bit()
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
                        handle_range.starting_handle,
                        ClientPduName::FindByTypeValueRequest,
                        pdu::Error::AttributeNotFound,
                    )
                    .await
                } else {
                    self.send_pdu(pdu::Pdu::new(ServerPduName::FindByTypeValueResponse.into(), transfer))
                        .await
                }
            } else {
                self.send_error(
                    handle_range.starting_handle,
                    ClientPduName::FindByTypeValueRequest,
                    pdu::Error::AttributeNotFound,
                )
                .await
            }
        } else {
            self.send_error(0, ClientPduName::FindInformationRequest, pdu::Error::InvalidPDU)
                .await
        }
    }

    /// Process Read By Type Request
    async fn process_read_by_type_request(&mut self, type_request: pdu::TypeRequest) -> Result<(), super::Error> {
        log::info!("Processing PDU ATT_READ_BY_TYPE_REQ {{ start handle: {:#X}, end handle: {:#X}, \
            type: {:?} }}",
            type_request.handle_range.starting_handle,
            type_request.handle_range.ending_handle,
            type_request.attr_type
        );

        use core::cmp::min;

        let handle_range = type_request.handle_range;

        let desired_att_type = type_request.attr_type;

        if handle_range.is_valid() {
            let start = min(handle_range.starting_handle as usize, self.attributes.len());
            let end = min(handle_range.ending_handle as usize, self.attributes.len());

            let payload_max = self.get_mtu() - 2;

            let single_payload_size = |cnt, size| (cnt + 1) * (size + 2) < payload_max;

            let mut init_iter = self.attributes.attributes[start..end]
                .iter()
                .filter(|att| att.get_uuid() == &desired_att_type);

            match init_iter.by_ref().next() {
                None => {
                    self.send_error(
                        handle_range.starting_handle,
                        ClientPduName::ReadByTypeRequest,
                        pdu::Error::AttributeNotFound,
                    )
                    .await
                }

                Some(first_match) => {
                    if let Some(e) = self.client_can_read_attribute(first_match) {
                        self.send_error(handle_range.starting_handle, ClientPduName::ReadByTypeRequest, e)
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

                        self.send_pdu(pdu::read_by_type_response(responses)).await
                    }
                }
            }
        } else {
            self.send_error(
                handle_range.starting_handle,
                ClientPduName::ReadByTypeRequest,
                pdu::Error::InvalidHandle,
            )
            .await
        }
    }

    /// Process read blob request
    async fn process_read_blob_request(&mut self, blob_request: pdu::ReadBlobRequest) -> Result<(), super::Error> {
        log::info!("Processing PDU ATT_READ_BLOB_REQ {{ handle: {:#X}, offset {:#X} }}",
            blob_request.handle,
            blob_request.offset
        );

        // Check the permissions (`check_permission` also validates the handle)
        match match self.check_permissions(blob_request.handle, super::FULL_READ_PERMISSIONS) {
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
                    (false, _) | (_, 0) => self.create_blob_send_response(&blob_request).await,

                    // Continuing reading prior blob
                    (true, offset) => self.use_blob_send_response(offset).await,
                }
            }

            Err(e) => Err(e.into()),
        } {
            Err(e) => match e {
                super::Error::PduError(e) => {
                    self.send_error(blob_request.handle, ClientPduName::ReadBlobRequest, e)
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
    async fn create_blob_send_response(&mut self, br: &pdu::ReadBlobRequest) -> Result<(), super::Error> {
        let data = self.attributes.get(br.handle).unwrap().get_value().read().await;

        let rsp = match self.new_read_blob_response(&data, br.offset)? {
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

        self.send_pdu(rsp).await
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
    async fn use_blob_send_response(&mut self, offset: u16) -> Result<(), super::Error> {
        let data = self.blob_data.as_ref().unwrap();

        match self.new_read_blob_response(&data.tf_data, offset)? {
            (rsp, false) => {
                self.send_pdu(rsp).await?;

                // This is the final piece of the blob
                self.blob_data = None;

                Ok(())
            }

            (rsp, true) => self.send_pdu(rsp).await,
        }
    }

    /// Create a Read Blob Response
    ///
    /// This return is the Read Blob Response with a boolean to indicate if the response payload was
    /// completely filled with data bytes.
    #[inline]
    fn new_read_blob_response<'a>(
        &self,
        data: &'a [u8],
        offset: u16,
    ) -> Result<(pdu::Pdu<pdu::LocalReadBlobResponse<'a>>, bool), pdu::Error> {
        let max_payload = self.get_mtu() - 1;

        match offset as usize {
            o if o > data.len() => Err(pdu::Error::InvalidOffset),

            o if o + max_payload <= data.len() => Ok((
                pdu::LocalReadBlobResponse::new(&data[o..(o + max_payload)]).into(),
                true,
            )),

            o => Ok((pdu::LocalReadBlobResponse::new(&data[o..]).into(), false)),
        }
    }

    async fn process_prepare_write_request(&mut self, payload: &[u8]) -> Result<(), super::Error> {
        if let Err((h, e)) = match pdu::PreparedWriteRequest::try_from_raw(payload) {
            Ok(request) => {
                log::info!("Processing ATT_PREPARE_WRITE_REQ {{ handle: {:#X}, offset {} }}",
                    request.get_handle(),
                    request.get_prepared_offset()
                );

                match self.check_permissions(request.get_handle(), super::FULL_WRITE_PERMISSIONS) {
                    Ok(_) => match self.queued_writer.process_prepared(&request) {
                        Err(e) => Err((request.get_handle(), e)),

                        Ok(_) => {
                            let response = pdu::PreparedWriteResponse::pdu_from_request(&request);

                            self.send_pdu(response).await?;

                            Ok(())
                        }
                    },

                    Err(e) => Err((request.get_handle(), e)),
                }
            },

            Err(e) => Err((0, e.pdu_err)),
        } {
            self.send_error(h, ClientPduName::PrepareWriteRequest, e).await
        } else {
            Ok(())
        }
    }

    async fn process_execute_write_request(&mut self, request_flag: pdu::ExecuteWriteFlag) -> Result<(), super::Error> {
        log::info!("Processing ATT_EXECUTE_WRITE_REQ {{ flag: {:?} }}", request_flag);

        match match self.queued_writer.process_execute(request_flag) {
            Ok(Some(iter)) => {
                for queued_data in iter.into_iter() {
                    self.check_permissions(queued_data.0, super::FULL_WRITE_PERMISSIONS)?;

                    self.write_att(queued_data.0, &queued_data.1).await?;
                }

                Ok(())
            }

            Ok(None) => Ok(()),

            Err(e) => Err(e),
        } {
            Err(e) => self.send_error(0, ClientPduName::ExecuteWriteRequest, e).await,

            Ok(_) => self.send_pdu(pdu::execute_write_response()).await,
        }
    }

    /// Get an iterator over the attribute informational data
    ///
    /// This will return an iterator to get the type, permissions, and handle for each attribute
    pub fn iter_attr_info(&self) -> impl Iterator<Item = AttributeInfo<'_>> {
        self.attributes.iter_info()
    }
}

impl<C, Q> AsRef<C> for Server<'_, C, Q>
where
    C: l2cap::ConnectionChannel,
{
    fn as_ref(&self) -> &C {
        &self.connection_channel
    }
}

pub struct ServerAttributes {
    attributes: Vec<super::Attribute<Box<dyn ServerAttribute + Send>>>,
}

impl ServerAttributes {
    /// Create a new `ServiceAttributes`
    pub fn new() -> Self {
        Self {
            attributes: alloc::vec![ReservedHandle.into()],
        }
    }

    /// Push an attribute to `ServiceAttributes`
    ///
    /// This will push the attribute onto the list of server attributes and return the handle of
    /// the pushed attribute.
    ///
    /// # Panic
    /// If you manage to push `core::u16::MAX - 1` attributes, the push will panic.
    pub fn push<C, V>(&mut self, attribute: super::Attribute<C>) -> u16
    where
        C: ServerAttributeValue<Value = V> + Send + Sized + 'static,
        V: TransferFormatTryFrom + TransferFormatInto + 'static,
    {
        use core::convert::TryInto;

        let handle = self
            .attributes
            .len()
            .try_into()
            .expect("Exceeded attribute handle limit");

        let pushed_att = super::Attribute {
            ty: attribute.ty,
            handle: Some(handle),
            permissions: attribute.permissions,
            value: Box::from(attribute.value) as Box<dyn ServerAttribute + Send + 'static>,
        };

        self.attributes.push(pushed_att);

        handle
    }

    /// Get the next available handle
    ///
    /// This is the handle that is assigned to the next attribute to be
    /// [`push`](#method.push)ed to the `ServerAttributes`. This is generally used to get the
    /// handle of the attribute that is about to be pushed to `ServerAttributes`
    ///
    /// ```
    /// # use bo_tie::att::server::ServerAttributes;
    /// # let attribute = bo_tie::att::Attribute::new( bo_tie::UUID::default(), Vec::new(), () );
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

    /// Attributes length
    pub fn len(&self) -> usize {
        self.attributes.len()
    }

    /// Get attribute with the given handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get(&self, handle: u16) -> Option<&super::Attribute<Box<dyn ServerAttribute + Send>>> {
        match handle {
            0 => None,
            h => self.attributes.get(<usize>::from(h)),
        }
    }

    /// Get a mutable reference to the attribute with the given handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get_mut(&mut self, handle: u16) -> Option<&mut super::Attribute<Box<dyn ServerAttribute + Send>>> {
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

pub type PinnedFuture<'a, O> = Pin<Box<dyn Future<Output = O> + 'a>>;

/// Server Attributes
///
/// Attributes on the server must be implemented with `ServerAttribute` so that the server can
/// facilitate both concurrent and non-concurrent access of an attribute.
///
/// All operations to an attribute by the server revolve around either reading or writing to the
/// value. `read_and` will be called for a read operation, and `write_val` will be used for a write.
/// It is recommended that reading and writing only modify the value of the attribute, but you're
/// the boss of your own implementations.
///
/// Trait [`ServerAttributeValue`](ServerAttributeValue)
/// is implemented for any type that also implements
/// [`TransferFormatTryFrom`](crate::att::TransferFormatTryFrom) and
/// ['TransferFormatInto`](crate::att:TransferFormatInto). However if you want to implement
/// locking or reference counting of the value, you will need to implmenent `ServerAttributeValue`.
/// ```
/// use std::sync::{Arc};
/// use std::borrow::Borrow;
/// use bo_tie::att::{Attribute, server::ServerAttributeValue};
/// use bo_tie::att::server::{ServerAttributes, PinnedFuture};
/// use futures::lock::Mutex;
///
/// #[derive(Default)]
/// struct SyncAttVal<V> {
///     value: Arc<Mutex<V>>
/// };
///
/// impl<V: PartialEq> ServerAttributeValue for SyncAttVal<V> {
///
///     type Value = V;
///
///     fn read_and<'a,F,T>(&'a self, f: F ) -> PinnedFuture<'a,T>
///     where F: FnOnce(&Self::Value) -> T + Unpin + 'a
///     {
///         Box::pin( async move { f( &*self.value.lock().await ) } )
///     }
///
///     fn write_val(&mut self, val: Self::Value) -> PinnedFuture<'_,()> {
///         Box::pin( async move { *self.value.lock().await = val } )
///     }
///
///     fn eq<'a>(&'a self, other: &'a Self::Value) -> PinnedFuture<'a,bool> {
///         Box::pin( async move { &*self.value.lock().await == other } )
///     }
/// }
///
/// // Create a couple of SyncAttVal
/// let val_usize = SyncAttVal::<usize>::default();
/// let val_msg   = SyncAttVal { value: Arc::new(Mutex::new(String::from("Hello World"))) };
///
/// # let uuid_usize = bo_tie::UUID::from_u128(0);
/// # let uuid_msg   = bo_tie::UUID::from_u128(0);
///
/// # let permissions_usize = Vec::new();
/// # let permissions_msg   = Vec::new();
///
/// // Create attributes from them
/// let att_usize = Attribute::new( uuid_usize, permissions_usize, val_usize);
/// let att_msg   = Attribute::new( uuid_msg  , permissions_msg  , val_msg  );
///
/// // Add them to a server attributes to generate a server from
/// let mut server_attributes = ServerAttributes::new();
/// server_attributes.push(att_usize);
/// server_attributes.push(att_msg);
/// ```
pub trait ServerAttributeValue {
    type Value;

    /// Read the value and call `f` with a reference to it.
    fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
    where
        F: FnOnce(&Self::Value) -> T + Unpin + 'a;

    /// Write to the value
    fn write_val(&mut self, val: Self::Value) -> PinnedFuture<'_, ()>;

    /// Compare the value to 'other'
    fn eq<'a>(&'a self, other: &'a Self::Value) -> PinnedFuture<'a, bool>;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AttributeInfo<'a> {
    ty: &'a crate::UUID,
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
    pub fn get_uuid(&self) -> &crate::UUID {
        self.ty
    }

    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    pub fn get_permissions(&self) -> &[super::AttributePermissions] {
        self.permissions
    }
}

/// A future that never pends
///
/// This future will never pend and always returns ready with the result of `FnOnce` used to create
/// it. However, since this future is implemented for a `FnOnce` it will panic if it is polled
/// multiple times.
struct NoPend<T>(Option<T>);

impl<T> NoPend<T> {
    fn new(f: T) -> Self {
        NoPend(Some(f))
    }
}

impl<T, O> Future for NoPend<T>
where
    T: FnOnce() -> O + Unpin,
{
    type Output = O;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(self.get_mut().0.take().expect("NoPend polled multiple times")())
    }
}

/// The trivial implementation for ServerAttributeValue
impl<V> ServerAttributeValue for V
where
    V: PartialEq + Unpin,
{
    type Value = V;

    fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
    where
        F: FnOnce(&V) -> T + Unpin + 'a,
    {
        Box::pin(NoPend::new(move || f(self)))
    }

    fn write_val(&mut self, val: V) -> PinnedFuture<'_, ()> {
        Box::pin(NoPend::new(move || *self = val))
    }

    fn eq<'a>(&'a self, other: &'a V) -> PinnedFuture<'a, bool> {
        let cmp = <Self as PartialEq>::eq(self, other);

        Box::pin(NoPend::new(move || cmp))
    }
}

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
    /// [`ReadByTypeResponse`](crate::att::pdu::ReadByTypeResponse)
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

impl<C, V> ServerAttribute for C
where
    C: ServerAttributeValue<Value = V>,
    V: TransferFormatTryFrom + TransferFormatInto,
{
    fn read(&self) -> PinnedFuture<Vec<u8>> {
        self.read_and(|v| TransferFormatInto::into(v))
    }

    fn read_response(&self) -> PinnedFuture<'_, pdu::Pdu<pdu::ReadResponse<Vec<u8>>>> {
        self.read_and(|v| pdu::read_response(TransferFormatInto::into(v)))
    }

    fn notification(&self, handle: u16) -> PinnedFuture<'_, pdu::Pdu<pdu::HandleValueNotification<Vec<u8>>>> {
        self.read_and(move |v| pdu::handle_value_notification(handle, TransferFormatInto::into(v)))
    }

    fn single_read_by_type_response(&self, handle: u16) -> PinnedFuture<'_, pdu::ReadTypeResponse<Vec<u8>>> {
        self.read_and(move |v| {
            let tf = TransferFormatInto::into(v);

            pdu::ReadTypeResponse::new(handle, tf)
        })
    }

    fn try_set_value_from_transfer_format<'a>(
        &'a mut self,
        raw: &'a [u8],
    ) -> PinnedFuture<'a, Result<(), super::TransferFormatError>> {
        Box::pin(async move {
            self.write_val(TransferFormatTryFrom::try_from(raw)?).await;

            Ok(())
        })
    }

    fn value_transfer_format_size(&self) -> PinnedFuture<'_, usize> {
        Box::pin(async move { self.read_and(|v: &V| v.len_of_into()).await })
    }

    fn cmp_value_to_raw_transfer_format<'a>(&'a self, raw: &'a [u8]) -> PinnedFuture<'_, bool> {
        Box::pin(async move {
            match <V as TransferFormatTryFrom>::try_from(raw) {
                Err(_) => false,
                Ok(cmp_val) => self.eq(&cmp_val).await,
            }
        })
    }
}

/// The Reserved Handle
///
/// The first handle (value of '0') is reserved for future use. This is used to represent that
/// handle when creating a new Attribute Bearer
struct ReservedHandle;

impl From<ReservedHandle> for super::Attribute<Box<dyn ServerAttribute + Send>> {
    fn from(_: ReservedHandle) -> Self {
        super::Attribute::new(crate::UUID::from_u128(0u128), Vec::new(), Box::new(ReservedHandle))
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
