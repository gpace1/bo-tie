use alloc::{
    vec::Vec,
    boxed::Box,
};
use super::{
    pdu,
    TransferFormatError,
    client::ClientPduName
};
use crate::l2cap;
use crate::att::{TransferFormatTryFrom, TransferFormatInto};

macro_rules! log_debug {
    ( $arg1:expr $(, $args:expr)* ) => { log::debug!(concat!("(ATT) ", $arg1) $(, $args)*) }
}

#[derive(Debug,Clone,Copy,PartialEq,PartialOrd,Eq)]
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

impl core::convert::TryFrom<super::pdu::PduOpCode> for ServerPduName {
    type Error = ();

    fn try_from(opcode: super::pdu::PduOpCode) -> Result<Self, Self::Error> {
        Self::try_from(opcode.as_raw())
    }
}

impl From<ServerPduName> for pdu::PduOpCode {
    fn from(pdu_name: ServerPduName) -> pdu::PduOpCode {
        let raw: u8 = From::from(pdu_name);

        From::from(raw)
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
            0x1  => Ok(ServerPduName::ErrorResponse),
            0x3  => Ok(ServerPduName::ExchangeMTUResponse),
            0x5  => Ok(ServerPduName::FindInformationResponse),
            0x7  => Ok(ServerPduName::FindByTypeValueResponse),
            0x9  => Ok(ServerPduName::ReadByTypeResponse),
            0xB  => Ok(ServerPduName::ReadResponse),
            0xD  => Ok(ServerPduName::ReadBlobResponse),
            0xF  => Ok(ServerPduName::ReadMultipleResponse),
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
    pub(super) fn is_convertible_from(&self, raw_pdu: &[u8] ) -> bool {

        // Each of these check that the size of the packet is correct and the opcode matches
        match self {
            ServerPduName::ErrorResponse => {
                ( raw_pdu.len() == 5 ) && ( raw_pdu[0] == ServerPduName::ErrorResponse.into() )
            },
            ServerPduName::ExchangeMTUResponse => {
                ( raw_pdu.len() == 3 ) && ( raw_pdu[0] == ServerPduName::ExchangeMTUResponse.into() )
            },
            ServerPduName::FindInformationResponse => {
                ( raw_pdu.len() >= 6 ) && ( raw_pdu[0] == ServerPduName::FindInformationResponse.into() )
            },
            ServerPduName::FindByTypeValueResponse => {
                ( raw_pdu.len() >= 5 ) && ( raw_pdu[0] == ServerPduName::FindByTypeValueResponse.into() )
            },
            ServerPduName::ReadByTypeResponse => {
                ( raw_pdu.len() >= 4 ) && ( raw_pdu[0] == ServerPduName::ReadByTypeResponse.into() )
            },
            ServerPduName::ReadResponse => {
                ( raw_pdu.len() >= 1 ) && ( raw_pdu[0] == ServerPduName::ReadResponse.into() )
            },
            ServerPduName::ReadBlobResponse => {
                ( raw_pdu.len() >= 1 ) && ( raw_pdu[0] == ServerPduName::ReadBlobResponse.into() )
            },
            ServerPduName::ReadMultipleResponse => {
                ( raw_pdu.len() >= 1 ) && ( raw_pdu[0] == ServerPduName::ReadMultipleResponse.into() )
            },
            ServerPduName::ReadByGroupTypeResponse => {
                ( raw_pdu.len() >= 6 ) && ( raw_pdu[0] == ServerPduName::ReadByGroupTypeResponse.into() )
            },
            ServerPduName::WriteResponse => {
                ( raw_pdu.len() == 1 ) && ( raw_pdu[0] == ServerPduName::WriteResponse.into() )
            },
            ServerPduName::PrepareWriteResponse => {
                ( raw_pdu.len() >= 5 ) && ( raw_pdu[0] == ServerPduName::PrepareWriteResponse.into() )
            },
            ServerPduName::ExecuteWriteResponse => {
                ( raw_pdu.len() == 1 ) && ( raw_pdu[0] == ServerPduName::ExecuteWriteResponse.into() )
            },
            ServerPduName::HandleValueNotification => {
                ( raw_pdu.len() >= 3 ) && ( raw_pdu[0] == ServerPduName::HandleValueNotification.into() )
            },
            ServerPduName::HandleValueIndication => {
                ( raw_pdu.len() >= 3 ) && ( raw_pdu[0] == ServerPduName::HandleValueIndication.into() )
            },
        }
    }
}

/// An Attribute server
///
/// For now a server can only handle one client. It will be updated to handle multiple clients
/// as soon as possible.
pub struct Server<'c, C>
{
    /// The maximum mtu that this server can handle. This is also the mtu sent in a MTU response
    /// PDU. This is not the mtu that is decided as the maximum transmit size between the server
    /// and client, that is `set_mtu`.
    max_mtu: u16,
    /// The set mtu between the client and server. If this value is ever None, then the default
    /// value as defined in the connection channel will be used.
    set_mtu: Option<u16>,
    connection: &'c C,
    attributes: Vec<Box<dyn ServerAttribute + Send + Sync >>,
    /// The permissions the client currently has
    given_permissions: Vec<super::AttributePermissions>,
}

impl<'c, C> Server<'c, C>
where C: l2cap::ConnectionChannel
{

    /// Create a new Server
    ///
    /// The maximum transfer unit is set here, it cannot be smaller then the minimum MTU as
    /// specified by the DEFAULT_ATT_MTU constant in trait `l2cap::ConnectionChannel`. If the provided MTU
    /// value is smaller than DEFAULT_ATT_MTU or none is passed, then the MTU will be set to
    /// DEFAULT_ATT_MTU.
    pub fn new<Mtu, A>( connection: &'c C, max_mtu: Mtu, server_attributes: A) -> Self
    where Mtu: Into<Option<u16>>,
          A: Into<Option<ServerAttributes>>
    {
        let actual_max_mtu = if let Some(val) = max_mtu.into() {
            if val >= super::MIN_ATT_MTU_LE {
                val
            } else {
                super::MIN_ATT_MTU_LE
            }
        } else {
            super::MIN_ATT_MTU_LE
        };

        let attributes = match server_attributes.into()
        {
            Some(a) => a.attributes,
            None => ServerAttributes::new().attributes,
        };

        Self {
            max_mtu: actual_max_mtu,
            set_mtu: None,
            connection,
            attributes,
            given_permissions: Vec::new(),
        }
    }

    /// Get the maximum transfer unit of the connection
    ///
    /// The is the current mtu as agreed upon by the client and server
    pub fn get_mtu(&self) -> usize {
        ( match self.set_mtu { Some(mtu) => mtu, None => super::MIN_ATT_MTU_LE } ) as usize
    }

    /// Push an attribute onto the handle stack
    ///
    /// This function will return the handle to the attribute.
    ///
    /// # Panic
    /// If you manage to push 65535 attributes onto this server, the next pushed attribute will
    /// cause this function to panic.
    pub fn push<X,V>(&mut self, attribute: super::Attribute<X>) -> u16
    where X: ServerAttributeValue<V> + Sized + Send + Sync + 'static,
          V: TransferFormatTryFrom + TransferFormatInto + Send + Sync + PartialEq + 'static,
    {
        use core::convert::TryInto;

        let ret = self.attributes.len().try_into().expect("Exceeded attribute handle limit");

        self.attributes.push( Box::new( ServerAttEntry::from(attribute) ) );

        ret
    }

    /// Return the next unused handle
    pub fn next_handle(&self) -> u16 { self.attributes.len() as u16 }

    /// Give a permission to the client
    ///
    /// This doesn't check that the client is qualified to receive the permission, it just adds an
    /// indication on the server that the client has it.
    pub fn give_permission_to_client(&mut self, permission: super::AttributePermissions) {
        if !self.given_permissions.contains(&permission) {
            self.given_permissions.push(permission);
        }
    }

    /// Remove one or more permission given to the client
    ///
    /// This will remove every permission in `permissions` from the client.
    pub fn revoke_permissions_of_client(&mut self, permissions: &[super::AttributePermissions]) {
        self.given_permissions = self.given_permissions.clone().into_iter()
            .filter(|p| !permissions.contains(p) )
            .collect();
    }

    /// Check if the client has acceptable permissions for the attribute with the provided handle
    ///
    /// This function checks two sets of premissions against the both the client and the attribute
    /// at `handle`. The `required` input is used to check that both the client and attribute have
    /// all permissions in `required`. The `restricted` input is a list of permissions that the
    /// client must have if (but only it) the attribute has them.
    ///
    /// To better explain with an example, say we are going to create a read attribute request and
    /// response procedure. The responder (the server) would use this function by setting the `required`
    /// input to contain the permission
    /// [`Read`](super::AttributePermissions::Read)
    /// and the `restricted` to contain
    /// [`Encryption`](super::AttributePermissions::Encryption)([`Read`](super::AttributePermissions::Read),[`Bits128`](super::EncryptionKeySize::Bits128)),
    /// [`Encryption`](super::AttributePermissions::Encryption)([`Read`](super::AttributePermissions::Read),[`Bits192`](super::EncryptionKeySize::Bits192)),
    /// [`Encryption`](super::AttributePermissions::Encryption)([`Read`](super::AttributePermissions::Read),[`Bits256`](super::EncryptionKeySize::Bits256)),
    /// [`Authentication`](super::AttributePermissions::Authentication)([`Read`](super::AttributePermissions::Read)),
    /// and
    /// [`Authorization`](super::AttributePermissions::Authorization)([`Read`](super::AttributePermissions::Read))
    /// to see if the requester (the client) has the adequate rights to read the requested attribute.
    /// If the attribute with handle `handle` doesn't have the read permission, then
    /// `check_permission` will always return an error. However, to continue the example, lets say
    /// that the permissions of the attribute are `Read`, `Encryption`(`Read`,`Bits128`), and
    /// `Authentication`(`Read`), and `Write`. Now the attribue satisfies all the required permissions,
    /// but the client also needs to have the required permission as well as
    /// `Encryption`(`Read`,`Bits128`) and `Authentication`(`Read`) because they are in both the
    /// restricted permissions and the attribute permissions. The client doesn't need the other
    /// permissions in the restricted input because they are not part of the permissions set of the
    /// attribute (also the client doesn't need the `write` permission because it is not part of
    /// either the `required` or `restricted` lists)
    ///
    /// # Inputs
    /// - `required` -> The list of permissions that the attribute and client must have for the
    /// operation
    /// - `restricted` -> The list of all possible permissions that the client would be required to
    /// have if the attribute had them. These permissions do not need to be part of the list of
    /// permissions assigned to the attribute, they are just a list of permissions that the
    /// attribute *could* have one or more of.
    ///
    /// # Note
    /// There is no hierarcy of permissions, one permission doesn't supersede another. Also
    /// the variant values further differentiate each permission, as such the variant
    /// `Encryption`(`Read`, `Bits128`) is a different permission to
    /// `Encryption`(`Read`, `Bits256`).
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
    pub fn check_permission(
        &self,
        handle: u16,
        required: &[super::AttributePermissions],
        restricted: &[super::AttributePermissions])
    -> Result<(), pdu::Error>
    {
        let any_attribute = self.attributes.get(handle as usize)
            .ok_or(super::pdu::Error::InvalidHandle)?;

        match self.validate_permissions(any_attribute.as_ref(), required, restricted) {
            None => Ok(()),
            Some(e) => Err(e),
        }
    }

    /// Validate the permissions of the attribute
    ///
    /// There are two types of permissions that are checked for
    /// * `required` - permissions that *both* the attribute and client must have
    /// * `restricted` - permissions that the client must have if the the attribute has it.
    ///
    /// If there is an offending permission, that permission is returned. If 'None' is returned the
    /// client has the required permissions to proceed with the operation.
    fn validate_permissions(&self,
        att: &dyn ServerAttribute,
        required: &[super::AttributePermissions],
        restricted: &[super::AttributePermissions])
    -> Option<pdu::Error>
    {
        let attribute_permissions = att.get_permissions();

        // Both closures for the `filter` functions return true when a permission is not valid. The
        // the closure provided to `map` is only invoked when a permission check fails.
        required.iter()
        .filter(|&&p| {
            attribute_permissions.iter().find(|&&x| x == p).is_none() ||
            self.given_permissions.iter().find(|&&x| x == p).is_none()
        })
        .chain(
            restricted.iter()
            .filter(|&&p| {
                attribute_permissions.iter().find(|&&x| x == p).is_some() &&
                self.given_permissions.iter().find(|&&x| x == p).is_none()
            })
        )
        .map(|p| {
            // Map the invalid permission to it's corresponding error
            match p {
                super::AttributePermissions::Read => pdu::Error::ReadNotPermitted,
                super::AttributePermissions::Write => pdu::Error::WriteNotPermitted,
                super::AttributePermissions::Encryption(rest, _) => {
                    attribute_permissions.iter().find(|&&x| {
                        match x {
                            super::AttributePermissions::Encryption(x_rest, _) => *rest == x_rest,
                            _ => false
                        }
                    })
                    .and_then(|_| Some(pdu::Error::InsufficientEncryptionKeySize) )
                    .or_else( || Some(pdu::Error::InsufficientEncryption) )
                    .unwrap()
                }
                super::AttributePermissions::Authentication(_) => pdu::Error::InsufficientAuthentication,
                super::AttributePermissions::Authorization(_) => pdu::Error::InsufficientAuthorization,
            }
        })
        .nth(0) // return the first offending permission, if any.
    }

    /// Check if a client can read the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_read_attribute(&self, att: &dyn ServerAttribute ) -> Option<pdu::Error> {
        const REQUIRED: &'static [super::AttributePermissions] = &[
            super::AttributePermissions::Read
        ];

        const RESTRICTED: &'static [super::AttributePermissions] = &[
            super::AttributePermissions::Encryption(super::AttributeRestriction::Read, super::EncryptionKeySize::Bits128),
            super::AttributePermissions::Encryption(super::AttributeRestriction::Read, super::EncryptionKeySize::Bits192),
            super::AttributePermissions::Encryption(super::AttributeRestriction::Read, super::EncryptionKeySize::Bits256),
            super::AttributePermissions::Authentication(super::AttributeRestriction::Read),
            super::AttributePermissions::Authorization(super::AttributeRestriction::Read),
        ];

        self.validate_permissions(att, REQUIRED, RESTRICTED)
    }

    /// Check if a client can write the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_write_attribute(&self, att: &dyn ServerAttribute ) -> Option<pdu::Error>
    {
        const REQUIRED: &'static [super::AttributePermissions] = &[
            super::AttributePermissions::Write
        ];

        const RESTRICTED: &'static [super::AttributePermissions] = &[
            super::AttributePermissions::Encryption(super::AttributeRestriction::Write, super::EncryptionKeySize::Bits128),
            super::AttributePermissions::Encryption(super::AttributeRestriction::Write, super::EncryptionKeySize::Bits192),
            super::AttributePermissions::Encryption(super::AttributeRestriction::Write, super::EncryptionKeySize::Bits256),
            super::AttributePermissions::Authentication(super::AttributeRestriction::Write),
            super::AttributePermissions::Authorization(super::AttributeRestriction::Write),
        ];

        self.validate_permissions(att, REQUIRED, RESTRICTED)
    }

    /// Process a received Acl Data packet form the Bluetooth Controller
    ///
    /// The packet is assumed to be in the form of an Attribute protocol request packet. This
    /// function will then process the request and send to the client the appropriate response
    /// packet.
    ///
    /// An error will be returned based on the following:
    /// * The input acl_packet did not contain
    pub fn process_acl_data(&mut self, acl_packet: &crate::l2cap::AclData ) -> Result<(), super::Error>
    {
        let (pdu_type, payload) = self.parse_acl_packet(acl_packet)?;

        self.process_parsed_acl_data(pdu_type, payload)
    }

    /// Parse an ACL Packet
    ///
    /// This checks the following things
    /// * The ACL packet has the correct channel identifier for the Attribute Protocol
    /// * The payload of the packet is not empty
    /// * The pdu type is a [`ClientPduName`](super::client::ClientPduName) enum
    pub fn parse_acl_packet<'a>(&self, acl_packet: &'a crate::l2cap::AclData)
    -> Result<(super::client::ClientPduName, &'a [u8]), super::Error>
    {
        use crate::l2cap::{ChannelIdentifier, LeUserChannelIdentifier};
        use core::convert::TryFrom;

        match acl_packet.get_channel_id() {
            ChannelIdentifier::LE( LeUserChannelIdentifier::AttributeProtocol ) => {

                let (att_type, payload) = acl_packet.get_payload().split_at(1);

                if att_type.len() > 0 {
                    let pdu_type = super::client::ClientPduName::try_from(att_type[0])
                        .or( Err(super::Error::UnknownOpcode(att_type[0])) )?;

                    Ok( (pdu_type, payload) )
                } else {
                    Err( super::Error::Empty )
                }
            }
            _ => Err( super::Error::IncorrectChannelId )
        }
    }

    /// Process a parsed ACL Packet
    ///
    /// This will take the data from the Ok result of [`parse_acl_packet`](Server::parse_acl_packet).
    /// This is otherwise equivalent to the function [`process_acl_data`](Server::parse_acl_packet)
    /// (really `process_acl_data` is just `parse_acl_packet` followed by this function) and is
    /// useful for higher layer protocols that need to parse an ACL packet before performing their
    /// own calculations on the data and *then* have the Attribute server processing the data.
    pub fn process_parsed_acl_data(&mut self, pdu_type: super::client::ClientPduName, payload: &[u8])
    -> Result<(), super::Error>
    {
        log::info!("(ATT) processing '{:?}'", pdu_type);

        match pdu_type {
            super::client::ClientPduName::ExchangeMtuRequest =>
                self.process_exchange_mtu_request( TransferFormatTryFrom::try_from( &payload)? ),

            super::client::ClientPduName::WriteRequest =>
                self.process_write_request( &payload ),

            super::client::ClientPduName::ReadRequest =>
                self.process_read_request( TransferFormatTryFrom::try_from(&payload)? ),

            super::client::ClientPduName::FindInformationRequest =>
                self.process_find_information_request( TransferFormatTryFrom::try_from(&payload)? ),

            super::client::ClientPduName::FindByTypeValueRequest =>
                self.process_find_by_type_value_request( &payload ),

            super::client::ClientPduName::ReadByTypeRequest =>
                self.process_read_by_type_request( TransferFormatTryFrom::try_from(&payload)? ),

            pdu @ super::client::ClientPduName::ReadBlobRequest |
            pdu @ super::client::ClientPduName::ReadMultipleRequest |
            pdu @ super::client::ClientPduName::WriteCommand |
            pdu @ super::client::ClientPduName::PrepareWriteRequest |
            pdu @ super::client::ClientPduName::ExecuteWriteRequest |
            pdu @ super::client::ClientPduName::HandleValueConfirmation |
            pdu @ super::client::ClientPduName::SignedWriteCommand |
            pdu @ super::client::ClientPduName::ReadByGroupTypeRequest =>
                self.send_error(0, pdu.into(), pdu::Error::RequestNotSupported),
        };

        Ok(())
    }

    /// Send out a notification
    ///
    /// The attribute at the given handle will be sent out in the notification.
    ///
    /// If the handle doesn't exist, then the notification isn't sent and false is returned
    pub fn send_notification(&self, handle: u16) -> bool {
        self.attributes.get(handle as usize).map( | attribute | {
            self.send( pdu::handle_value_notification( handle, attribute.as_ref() ) );
        } )
        .is_some()
    }

    fn send_raw(&self, intf_data: Vec<u8>) {
        let acl_data = l2cap::AclData::new( intf_data, super::L2CAP_CHANNEL_ID );

        self.connection.send(acl_data);
    }

    fn send<D>(&self, data: D) where D: TransferFormatInto {
        self.send_raw( TransferFormatInto::into(&data) );
    }

    /// Send an attribute PDU to the client
    pub fn send_pdu<D>(&self, pdu: pdu::Pdu<D> ) where D: TransferFormatInto {
        self.send(pdu);
    }

    /// Send an error the the client
    pub fn send_error(&self, handle: u16, received_opcode: ClientPduName, pdu_error: pdu::Error) {

        log_debug!("Sending error response. Received Op Code: '{:#x}', Handle: '{:?}', error: '{}'",
            Into::<u8>::into(received_opcode), handle, pdu_error);

        self.send( pdu::error_response(received_opcode.into(),handle,pdu_error) );
    }

    /// Get a reference to an attribute
    fn get_att(&self, handle: u16) -> Result<& (dyn ServerAttribute + Send + Sync), pdu::Error> {
        if pdu::is_valid_handle(handle) {
            Err(pdu::Error::InvalidHandle)
        }
        else {
            self.attributes.get(handle as usize)
                .ok_or(pdu::Error::InvalidHandle)
                .map(|a| a.as_ref() )
        }
    }

    /// Get a reference to a mutable attribute
    fn get_att_mut(&mut self, handle: u16) -> Result<&mut (dyn ServerAttribute + Send + Sync + 'static), pdu::Error> {
        if pdu::is_valid_handle(handle) {
            Err(pdu::Error::InvalidHandle)
        }
        else {
            self.attributes.get_mut(handle as usize)
                .ok_or(pdu::Error::InvalidHandle)
                .map(|a| a.as_mut() )
        }
    }

    /// Get a readable reference to the attribute value
    ///
    /// Returns an error if the client doesn't have the adequate permissions or the handle is
    /// invalid.
    fn read_att_and<F>(&self, handle: u16, transform: F) -> Result<(), pdu::Error>
    where F: Fn(&dyn TransferFormatInto) -> ()
    {
        let attribute = self.get_att(handle)?;

        if let Some(err) = self.client_can_read_attribute(attribute) {
            Err(err)
        } else {
            attribute.value_to_transfer_format(&mut |a| transform(a) );

            Ok(())
        }
    }

    /// Write the interface data to the attribute
    ///
    /// Returns an error if the client doesn't have the adequate permissions or the handle is
    /// invalid.
    fn write_att(&mut self, handle: u16, intf_data: &[u8]) -> Result<(), pdu::Error> {

        let attribute = self.get_att(handle)?;

        if let Some(err) = self.client_can_write_attribute(attribute) {
            Err(err)
        } else {
            match self.get_att_mut(handle).map(|att| att.value_from_transfer_format(intf_data) ){
                Ok(_) => Ok(()),
                Err(_) => Err(pdu::Error::InvalidPDU)
            }
        }
    }

    fn process_exchange_mtu_request(&mut self, client_mtu: u16) {

        if (super::MIN_ATT_MTU_LE..=self.max_mtu).contains(&client_mtu)  {
            self.set_mtu = Some(client_mtu.into());
        }

        log_debug!("Sending exchange mtu response");

        self.send(pdu::exchange_mtu_response(self.get_mtu() as u16));
    }

    /// Process a Read Request from the client
    fn process_read_request(&mut self, handle: u16) {
        log::trace!("Read Request");

        self.read_att_and(handle, |att_tf| self.send( pdu::read_response(att_tf) ) )
            .unwrap_or_else(|e| self.send_error(handle, ClientPduName::ReadRequest, e) );
    }

    /// Process a Write Request from the client
    fn process_write_request(&mut self, payload: &[u8]) {
        log::trace!("Write Request");

        let handle = TransferFormatTryFrom::try_from( &payload[..2] ).expect("Failed to convert 2 bytes to u16");

        self.write_att( handle, &payload[2..])
            .unwrap_or_else(|e| self.send_error(handle, ClientPduName::WriteRequest, e) );
    }

    /// Process a Find Information Request form the client
    fn process_find_information_request(&mut self, handle_range: pdu::HandleRange) {

        log::trace!("Find Information Request");

        /// Handle with UUID iterator
        ///
        /// The boolean is used to indicate whether or not the iterator is over short or long UUIDs.
        struct HandleUuidItr<I: Iterator<Item=(u16,crate::UUID)> + Clone>(bool, I);

        impl<I: Iterator<Item=(u16,crate::UUID)> + Clone> TransferFormatInto for HandleUuidItr<I>
        {
            fn len_of_into(&self) -> usize {
                1 + self.1.clone().fold(0usize, |acc, (h,u)| acc + h.len_of_into() + u.len_of_into() )
            }

            fn build_into_ret(&self, into_ret: &mut [u8] ) {

                const SHORT_FORMAT: u8 = 1;
                const LONG_FORMAT: u8 = 2;

                let mut offset = 1;

                into_ret[0] = if self.0 {SHORT_FORMAT} else {LONG_FORMAT};

                self.1.clone().for_each( |(h,u)| {
                    let h_len = h.len_of_into();
                    let u_len = u.len_of_into();

                    h.build_into_ret(&mut into_ret[offset..(offset + h_len)] );

                    offset += h_len;

                    u.build_into_ret(&mut into_ret[offset..(offset + u_len)] );

                    offset += u_len;
                })
            }
        }

        if handle_range.is_valid() {
            use core::cmp::min;

            // Both the start and ending handles cannot be past the actual length of the attributes
            let start = min( handle_range.starting_handle as usize, self.attributes.len() );
            let stop  = min( handle_range.ending_handle   as usize, self.attributes.len() );

            let payload_max = self.get_mtu() - 2;

            // Try to build response_payload full of 16 bit attribute types. This will stop at the first
            // attribute type cannot be converted into a shortened 16 bit UUID.
            let mut handle_uuids_16_bit_itr = HandleUuidItr(false, self.attributes[start..stop]
                .iter()
                .filter(|att| att.get_type().is_16_bit() )
                .take_while(|att| self.client_can_write_attribute(att.as_ref()).is_none() )
                .enumerate()
                .take_while(|(cnt, att)| (cnt * 4 < payload_max) && att.get_type().is_16_bit() )
                .map(|(_,att)| (att.get_handle(), att.get_type()) )
                .peekable()
            );

            if let None = handle_uuids_16_bit_itr.1.peek() {

                // If there is no 16 bit UUIDs then the UUIDs must be sent in the full 128 bit form.

                // Collect all UUIDs until the PDU is full or the first unreadable attribute is
                // found.
                let mut handle_uuids_128_bit_itr = HandleUuidItr(true, self.attributes[start..start]
                    .iter()
                    .take_while(|att| self.client_can_read_attribute(att.as_ref()).is_none() )
                    .enumerate()
                    .take_while(|(cnt, _)| cnt * 18 < payload_max )
                    .map(|(_,att)| (att.get_handle(), att.get_type()) )
                    .peekable()
                );

                if let None = handle_uuids_128_bit_itr.1.peek() {

                    // If there are still no UUIDs then there are no UUIDs within the given range (or
                    // permissions were not granted)

                    self.send_error(start as u16, ClientPduName::FindInformationRequest, pdu::Error::AttributeNotFound)
                } else {
                    let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), handle_uuids_128_bit_itr, None);

                    self.send( pdu );
                }
            } else {

                // Send the 16 bit UUIDs

                let pdu = pdu::Pdu::new(ServerPduName::FindInformationResponse.into(), handle_uuids_16_bit_itr, None);

                self.send( pdu );
            }
        } else {
            self.send_error(handle_range.starting_handle, ClientPduName::FindInformationRequest, pdu::Error::InvalidHandle);
        }
    }

    /// Process find by type value request
    fn process_find_by_type_value_request(&mut self, payload: &[u8] ) {

        /// Handles iterator
        struct HandleGroupItr<I: Iterator<Item=(u16,u16)> + Clone >(I);

        impl<I: Iterator<Item=(u16,u16)> + Clone> TransferFormatInto for HandleGroupItr<I>
        {
            fn len_of_into(&self) -> usize { self.0.clone().fold(0usize, |acc,_| acc + 4) }

            fn build_into_ret(&self, into_ret: &mut [u8] ) {

                self.0.clone().enumerate().for_each( |(cnt, (h,g))| {
                    into_ret[      (cnt * 2)..((cnt + 1) * 2)].copy_from_slice(&h.to_le_bytes());
                    into_ret[((cnt + 1) * 2)..((cnt + 2) * 2)].copy_from_slice(&g.to_le_bytes());
                })
            }
        }

        if payload.len() >= 6 {

            let handle_range: pdu::HandleRange = TransferFormatTryFrom::try_from( &payload[..4] ).unwrap();

            let att_type: crate::UUID = TransferFormatTryFrom::try_from( &payload[4..6] ).unwrap();

            let raw_value = &payload[6..];

            if handle_range.is_valid() {
                use core::cmp::min;

                let start = min( handle_range.starting_handle as usize, self.attributes.len() );
                let end   = min( handle_range.ending_handle   as usize, self.attributes.len() );

                let payload_max = self.get_mtu() - 1;

                let mut handles = HandleGroupItr( self.attributes[start..end].iter()
                    .filter(|att| att.get_type().is_16_bit() )
                    .filter(|att| att.get_type() == att_type)
                    .filter(|att| att.cmp_value_to_raw_transfer_format(raw_value) )
                    .enumerate()
                    .take_while(|(cnt, _)| cnt * 4 < payload_max )
                    .map(|(_,att)| (att.get_handle(), att.get_handle()) )
                );

                if let None = handles.0.by_ref().peekable().peek() {

                    self.send_error(
                        handle_range.starting_handle,
                        ClientPduName::FindByTypeValueRequest,
                        pdu::Error::AttributeNotFound
                    );

                } else {
                    self.send(pdu::Pdu::new(ServerPduName::FindByTypeValueResponse.into(), handles, None));
                }
            } else {
                self.send_error(
                    handle_range.starting_handle,
                    ClientPduName::FindByTypeValueRequest,
                    pdu::Error::AttributeNotFound
                );
            }
        } else {
            self.send_error(0, ClientPduName::FindInformationRequest, pdu::Error::InvalidPDU);
        }
    }

    /// Process Read By Type Request
    fn process_read_by_type_request(&self, type_request: pdu::TypeRequest ) {
        use core::cmp::min;

        let handle_range = type_request.handle_range;

        let desired_att_type = type_request.attr_type;

        /// Handles iterator
        struct HandleValItr<I>(usize,I);

        impl<'a, I> TransferFormatInto for HandleValItr<I>
        where I: Iterator<Item=&'a (dyn ServerAttribute + Send + Sync)> + Clone
        {
            fn len_of_into(&self) -> usize {
                self.0 * self.1.clone().fold(0usize, |acc,att| acc + att.value_transfer_format_size() )
            }

            fn build_into_ret(&self, into_ret: &mut [u8] ) {

                into_ret[0] = (self.0 & (core::u8::MAX as usize)) as u8;

                self.1.clone().enumerate().for_each( |(cnt, att)| {
                    let offset = &mut into_ret[cnt * (2 + self.0)..(cnt + 1) * (2 + self.0)];

                    att.get_type().build_into_ret(&mut offset[..2]);

                    att.value_to_transfer_format(&mut |v| v.build_into_ret(&mut offset[2..]) );
                })
            }
        }

        if handle_range.is_valid() {
            let start = min( handle_range.starting_handle as usize, self.attributes.len() );
            let end   = min( handle_range.ending_handle   as usize, self.attributes.len() );

            let payload_max = self.get_mtu() - 2;

            let mut init_iter = self.attributes[start..end].iter()
                .filter(|att| att.get_type() == desired_att_type)
                .peekable();

            match init_iter.peek() {
                None =>
                    self.send_error(handle_range.starting_handle, ClientPduName::ReadByTypeRequest, pdu::Error::InvalidHandle),

                Some(first_match) => {
                    if let Some(e) = self.client_can_read_attribute(first_match.as_ref()) {
                        self.send_error(handle_range.starting_handle, ClientPduName::ReadByTypeRequest, e)
                    } else {
                        let first_size = first_match.value_transfer_format_size();

                        let iterator = init_iter
                            .filter(|att| att.value_transfer_format_size() == first_size )
                            .enumerate()
                            .take_while(|(cnt, _)| cnt * first_size < payload_max )
                            .map(|(_,att)| att.as_ref());

                        let parameter = HandleValItr(first_size, iterator);

                        let pdu = pdu::Pdu::new(ServerPduName::ReadByTypeResponse.into(), parameter, None);

                        self.send(pdu);
                    }
                }
            }
        } else {
            self.send_error(handle_range.starting_handle, ClientPduName::ReadByTypeRequest, pdu::Error::InvalidHandle);
        }
    }
}

impl<'c, C> AsRef<C> for Server<'c, C> where C: l2cap::ConnectionChannel {
    fn as_ref(&self) -> &C {
        &self.connection
    }
}

pub struct ServerAttributes {
    attributes: Vec<Box<dyn ServerAttribute + Send + Sync>>
}

impl ServerAttributes {

    /// Create a new `ServiceAttributes`
    pub fn new() -> Self {

        Self { attributes: alloc::vec![ Box::new( ReservedHandle ) ] }
    }

    /// Push an attribute to `ServiceAttributes`
    ///
    /// This will push the attribute onto the list of server attributes and return the handle of
    /// the pushed attribute.
    ///
    /// # Panic
    /// If you manage to push `core::u16::MAX - 1` attributes, the push will panic.
    pub fn push<C,V>(&mut self, mut attribute: super::Attribute<C>) -> u16
        where C: ServerAttributeValue<V> + Sized + Send + Sync + 'static,
              V: TransferFormatTryFrom + TransferFormatInto + Send + Sync + PartialEq + 'static,
    {
        use core::convert::TryInto;

        let ret = self.attributes.len().try_into().expect("Exceeded attribute handle limit");

        // Set the handle now that the attribute is part of a list
        attribute.handle = Some(ret);

        self.attributes.push( Box::new( ServerAttEntry::from(attribute) ) );

        ret
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
    pub fn iter(&self) -> impl Iterator<Item = &dyn AttributeInfo > {
        ServerAttributesIter(self.attributes.iter())
    }
}

impl Default for ServerAttributes {
    fn default() -> Self {
        Self::new()
    }
}

struct ServerAttributesIter<'a>(core::slice::Iter<'a, Box<dyn ServerAttribute + Send + Sync >>);

impl<'a> Iterator for ServerAttributesIter<'a> {
    type Item = &'a dyn AttributeInfo;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|b| b.as_att_info() )
    }
}

pub trait AttributeInfo {
    /// Get the attribute type
    fn get_type(&self) -> crate::UUID;

    /// Get the attribute permissions
    fn get_permissions(&self) -> &[super::AttributePermissions];

    /// Get the attribute handle
    fn get_handle(&self) -> u16;
}

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
/// use std::sync::{Arc, Mutex};
/// use std::borrow::Borrow;
/// use bo_tie::att::{Attribute, server::ServerAttributeValue};
/// use bo_tie::att::server::ServerAttributes;
///
/// #[derive(Default)]
/// struct SyncAttVal<V> {
///     value: Arc<Mutex<V>>
/// };
///
/// impl<V> ServerAttributeValue<V> for SyncAttVal<V> {
///
///     fn read_and<F,T>(&self, f: F ) -> T where F: FnMut(&V) -> T {
///         f( self.value.lock.unwrap() )
///     }
///
///     fn write_val(&mut self, val: V) {
///         *self.value.lock().unwrap() = val
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
pub trait ServerAttributeValue<V> {

    fn read_and<F,T>(&self, f: F ) -> T where F: FnMut(&V) -> T;

    fn write_val(&mut self, val: V);
}

/// The trivial implementation for ServerAttributeValue
impl<V> ServerAttributeValue<V> for V {
    fn read_and<F,T>(&self, mut f: F ) -> T where F: FnMut(&V) -> T { f( self ) }

    fn write_val(&mut self, val: V) { *self = val }
}

/// A server attribute
///
/// A `ServerAttribute` is an attribute that has been added to the `ServerAttributes`. These
/// functions are designed to abstract away from the type of the attribute value so a
/// `ServerAttributes` can have a list of boxed `dyn ServerAttribute`.
trait ServerAttribute: AttributeInfo {

    fn as_att_info(&self) -> &dyn AttributeInfo;

    /// Read the attribute value and convert the data into the raw interface form
    ///
    /// The `transform` input is used to convert the attribute value into the full PDU sent to the
    /// interface, usually by just wrapping the data in a PDU. The input to `transform` is the value
    /// of the attribute as a [`TransferFormatInto`](crate::att::TransferFormatInto) trait object.
    fn value_to_transfer_format(&self, transform: &mut dyn FnMut(&dyn TransferFormatInto) );

    /// Try to convert raw data from the interface and write to the attribute value
    fn value_from_transfer_format(&mut self, tf_data: &[u8]) -> Result<(), super::TransferFormatError>;

    /// The number of bytes in the interface format
    fn value_transfer_format_size(&self) -> usize;

    /// Compare the value with the data received from the interface
    fn cmp_value_to_raw_transfer_format(&self, raw: &[u8] ) -> bool;
}

/// An entry in an attribute server
///
/// This is required so that generic argument `V` is not an unbound lifetime in the implementation
/// for `ServerAttribute` for this. Otherwise it would just be implemented for
/// `super::Attribute<C>`.
struct ServerAttEntry<C,V> {
    attribute: super::Attribute<C>,
    p: core::marker::PhantomData<V>,
}

impl<C,V> From<super::Attribute<C>> for ServerAttEntry<C,V> {
    fn from(attribute: super::Attribute<C> ) -> Self {
        Self { attribute, p: core::marker::PhantomData }
    }
}

impl<C,V> AttributeInfo for ServerAttEntry<C,V> {
    fn get_type(&self) -> crate::UUID {
        self.attribute.ty
    }

    fn get_permissions(&self) -> &[super::AttributePermissions] {
        &self.attribute.permissions
    }

    fn get_handle(&self) -> u16 {
        self.attribute.get_handle().expect("Handle does not exist for server attribute")
    }
}

impl<C, V> ServerAttribute for ServerAttEntry<C,V>
where C: ServerAttributeValue<V> + Send + Sync,
      V: TransferFormatTryFrom + TransferFormatInto + Send + Sync + PartialEq,
{
    fn as_att_info(&self) -> &dyn AttributeInfo { self }

    fn value_to_transfer_format(&self, transform: &mut dyn FnMut(&dyn TransferFormatInto) )
    {
        self.attribute.value.read_and(|v| transform(v) )
    }

    fn value_from_transfer_format(&mut self, raw: &[u8] ) -> Result<(), super::TransferFormatError>
    {
        self.attribute.value.write_val( TransferFormatTryFrom::try_from(raw)? );
        Ok(())
    }

    fn value_transfer_format_size(&self) -> usize {
        let mut size = 0;

        self.attribute.value.read_and(|v: &V| size = v.len_of_into() );

        size
    }

    fn cmp_value_to_raw_transfer_format(&self, raw: &[u8] ) -> bool {
        <V as TransferFormatTryFrom>::try_from(raw)
            .map( |ref cmp_val| self.attribute.value.read_and( |v| v == cmp_val ) )
            .unwrap_or_default()
    }
}

impl TransferFormatInto for &(dyn ServerAttribute + Send + Sync) {
    fn len_of_into(&self) -> usize { self.value_transfer_format_size() }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.value_to_transfer_format(  &mut |a| a.build_into_ret(into_ret) )
    }
}

/// The Reserved Handle
///
/// The first handle (value of '0') is reserved for future use. This is used to represent that
/// handle when creating a new Attribute Bearer
struct ReservedHandle;

impl AttributeInfo for ReservedHandle {
    fn get_type(&self) -> crate::UUID { crate::UUID::from_u128(0u128) }

    fn get_permissions(&self) -> &[super::AttributePermissions] {
        &[ super::AttributePermissions::Read ]
    }

    fn get_handle(&self) -> u16 { 0 }
}

impl ServerAttribute for ReservedHandle
{
    fn as_att_info(&self) -> &dyn AttributeInfo { self }

    fn value_to_transfer_format(&self, _: &mut dyn FnMut(&dyn TransferFormatInto) )
    {
        log::error!("Tried to read from reserved attribute handle");
    }

    fn value_from_transfer_format(&mut self, _: &[u8] )
    -> Result<(), super::TransferFormatError>
    {
        log::error!("Tried to write to reserved attribute handle");

        Err( TransferFormatError::from("ReservedHandle cannot be set from raw data") )
    }

    fn value_transfer_format_size(&self) -> usize { 0 }

    fn cmp_value_to_raw_transfer_format(&self, _: &[u8] ) -> bool { false }
}