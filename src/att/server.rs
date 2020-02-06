use alloc::{
    vec::Vec,
    boxed::Box,
};
use super::{
    pdu,
    TransferFormat,
    TransferFormatError
};
use crate::l2cap;

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
        Self::try_from(opcode.into_raw())
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
    attributes: Vec<Box<dyn super::AnyAttribute + Send + Sync >>,
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

        let attributes: Vec<Box<dyn super::AnyAttribute + Send + Sync>> = match server_attributes.into()
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
    pub fn get_mtu(&self) -> u16 {
        match self.set_mtu { Some(mtu) => mtu, None => super::MIN_ATT_MTU_LE }
    }

    /// Push an attribute onto the handle stack
    ///
    /// This function will return the handle to the attribute.
    ///
    /// # Panic
    /// If you manage to push 65535 attributes onto this server, the next pushed attribute will
    /// cause this function to panic.
    pub fn push<V>(&mut self, attribute: super::Attribute<V>) -> u16
    where V: TransferFormat + Sized + Send + Sync + 'static
    {
        use core::convert::TryInto;

        let ret = self.attributes.len().try_into().expect("Exceeded attribute handle limit");

        self.attributes.push( Box::new(attribute) );

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
    /// If a permisson is not satisfied, this function will return a corresponding error to the
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
    /// * `restricted` - each permission that the client must have if *and only if* the the
    ///   attribute has it.
    ///
    /// If there is an offending permision, that permission is returned, otherwise 'None' is
    /// returned by this function.
    fn validate_permissions(&self,
        att: &dyn super::AnyAttribute,
        required: &[super::AttributePermissions],
        restricted: &[super::AttributePermissions])
    -> Option<pdu::Error>
    {
        let attribute_permissions = att.get_permissions();

        // Both filter closures return true when a permission is not valid
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
                self.process_exchange_mtu_request( TransferFormat::try_from( &payload)? ),

            super::client::ClientPduName::WriteRequest =>
                self.process_write_request( &payload ),

            super::client::ClientPduName::ReadRequest =>
                self.process_read_request( TransferFormat::try_from(&payload)? ),

            super::client::ClientPduName::FindInformationRequest =>
                self.process_find_information_request( TransferFormat::try_from(&payload)? ),

            super::client::ClientPduName::FindByTypeValueRequest =>
                self.process_find_by_type_value_request( &payload ),

            super::client::ClientPduName::ReadByTypeRequest =>
                self.process_read_by_type_request( TransferFormat::try_from(&payload)? ),

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

    /// Send out notification
    ///
    /// The attribute at the given handle will be sent out in the notification.
    ///
    /// If the handle doesn't exist, then the notification isn't sent and false is returned
    pub fn send_notification(&self, handle: u16) -> bool {
        self.attributes.get(handle as usize).and_then( | attribute | {

            let val = attribute.get_val_as_transfer_format().into();

            let pdu = pdu::handle_value_notification( handle, val );

            let data = TransferFormat::into(&pdu);

            self.connection.send( l2cap::AclData::new(data.into(), super::L2CAP_CHANNEL_ID) );

            Some(())
        } )
        .is_some()
    }

    /// Deref the handle, and if the handle is valid, do F, otherwise return an error.
    ///
    /// If the handle is invalid, then this function sends the error PDU with the error InvalidHandle
    #[inline]
    pub fn send_invalid_handle_error(&self, handle: u16, received_opcode: u8) {
        log_debug!("Sending error response. Received Op Code: '{:#x}', Handle: '{:#x}', error: '{}'",
            received_opcode, handle, pdu::Error::InvalidHandle);

        self.send_error(handle, received_opcode, pdu::Error::InvalidHandle);
    }

    #[inline]
    pub fn send_error(&self, handle: u16, received_opcode: u8, pdu_error: pdu::Error) {

        let err_pdu = pdu::error_response(
            received_opcode,
            handle,
            pdu_error
        );

        let data = TransferFormat::into(&err_pdu);

        log_debug!("Sending error response. Received Op Code: '{:#x}', Handle: '{:#x}', error: '{}'",
            received_opcode, handle, pdu_error);

        self.connection.send( l2cap::AclData::new(data.into(), super::L2CAP_CHANNEL_ID) );
    }

    fn process_exchange_mtu_request(&mut self, client_mtu: u16) {

        if (super::MIN_ATT_MTU_LE..=self.max_mtu).contains(&client_mtu)  {
            self.set_mtu = Some(client_mtu.into());
        }

        let response_pdu = pdu::exchange_mtu_response(self.get_mtu());

        let data = TransferFormat::into(&response_pdu);

        log_debug!("Sending exchange mtu response");

        self.connection.send( l2cap::AclData::new( data.into(), super::L2CAP_CHANNEL_ID) );
    }

    fn process_read_request(&mut self, handle: u16) {

        if let Some(attribute) = self.attributes.get( handle as usize) {

            let mut data = alloc::vec!( super::server::ServerPduName::ReadResponse.into() );

            data.extend_from_slice( &attribute.get_val_as_transfer_format().into() );

            let acl_data = l2cap::AclData::new( data, super::L2CAP_CHANNEL_ID );

            log_debug!("Sending read response");

            self.connection.send( acl_data );
        } else {
            self.send_invalid_handle_error(handle, super::client::ClientPduName::ReadRequest.into());
        }
    }

    /// # Note
    /// This cannot accept a PDU because the data size isn't know at compile time, thus the method
    /// determines the data type based on the handle.
    fn process_write_request(&mut self, payload: &[u8]) {
        let received_opcode = super::client::ClientPduName::WriteRequest.into();

        if payload.len() >= 2 {
            let raw_handle = &payload[..2];
            let raw_data = &payload[2..];

            let handle = TransferFormat::try_from( &raw_handle ).unwrap();

            if let Some(data) = self.attributes.get_mut( handle as usize ) {
                match data.set_val_from_raw( raw_data ) {
                    Ok(_) => {
                        let data = TransferFormat::into(&pdu::write_response());

                        log_debug!("Sending write response");

                        self.connection.send( l2cap::AclData::new( data.into(), super::L2CAP_CHANNEL_ID ) );
                    },
                    Err(pdu_err) =>
                        self.send_error(handle, received_opcode, pdu_err.pdu_err),
                };
            } else {
                self.send_invalid_handle_error(handle, received_opcode);
            }
        } else {
            self.send_error(0, received_opcode, pdu::Error::InvalidPDU);
        }
    }

    fn process_find_information_request(&mut self, handle_range: pdu::HandleRange) {
        use pdu::HandleRange;

        log::debug!("HandleRange: starting_handle: {}, ending_handle: {}",
            handle_range.starting_handle, handle_range.ending_handle );

        match handle_range{
            HandleRange { starting_handle: 0, .. } => {
                let oc = super::client::ClientPduName::FindInformationRequest.into();

                log::error!("Received 'find information request' with a handle range starting \
                    at 0");

                self.send_invalid_handle_error(0, oc);
            },
            HandleRange { starting_handle: sh @ _, ending_handle: eh @ _ } if sh <= eh => {
                use core::cmp::min;
                use core::convert::TryInto;
                use core::mem::size_of;

                enum Format {
                    Uuid16Bit,
                    Uuid128Bit,
                }

                let start = min( sh as usize, self.attributes.len() );
                let stop  = min( eh as usize, self.attributes.len() );

                let attributes = &self.attributes[start..stop];

                attributes
                .first()
                .and_then(|first| {

                    // See if the first attribute's type can be made into a 16 bit UUID
                    TryInto::<u16>::try_into(first.get_type()).and_then( | uuid | {

                        let handle = first.get_handle();

                        Ok( (handle, uuid) )
                    })
                    .and_then( | (first_handle, first_uuid) | {

                        // The type of the starting attribute is convertable to a 16 bit UUID.
                        //
                        // The find information response PDU will contain the the attributes after
                        // the starting attribute until:
                        // * an attribute's type cannot be converted to a 16 bit uuid
                        // * the end of `attributes`
                        // * the packet MTU was reached

                        let mtu = self.get_mtu() as usize;

                        let vec_cap = min( (stop - start) * (2 + size_of::<u16>()), mtu - 2 );

                        let mut v = Vec::with_capacity( vec_cap );

                        v.extend_from_slice( &TransferFormat::into(&first_handle) );
                        v.extend_from_slice( &TransferFormat::into(&first_uuid) );

                        for attribute in attributes[1..].iter() {
                            if (v.len() + 2 + size_of::<u16>()) < v.capacity() {
                                if let Ok(uuid_16) = TryInto::<u16>::try_into(attribute.get_type()) {
                                    let handle =  attribute.get_handle();

                                    v.extend_from_slice( &TransferFormat::into(&handle) );
                                    v.extend_from_slice( &TransferFormat::into(&uuid_16) );

                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }

                        log_debug!("Sending a 'find information response' with 16 bit UUIDs");

                        Ok( (Format::Uuid16Bit, v) )
                    })
                    .or_else( |_| -> Result<(Format,Vec<u8>), ()> {

                        // The type of the first attribute cannot be made into a 16 bit UUID.
                        //
                        // The find information response PDU will contain the the attributes after
                        // the starting attribute until:
                        // * the end of `attributes`
                        // * the packet MTU was reached
                        //
                        // This is greedy, attributes that have a type that can be converted into a
                        // 16 bit UUID are included.

                        let mtu = self.get_mtu() as usize;

                        let vec_cap = min( (stop - start) * (2 + size_of::<u128>()), mtu - 2 );

                        let mut v = Vec::with_capacity( vec_cap );

                        for attribute in attributes[1..].iter() {
                            if (v.len() + 2 + size_of::<u128>()) < v.capacity() {
                                if let Ok(uuid_128) = TryInto::<u128>::try_into(attribute.get_type()) {
                                    let handle =  attribute.get_handle();

                                    v.extend_from_slice( &TransferFormat::into(&handle) );
                                    v.extend_from_slice( &TransferFormat::into(&uuid_128) );

                                } else {
                                    break;
                                }
                            } else {
                                break;
                            }
                        }

                        log_debug!("Sending a 'find information response' with 128 bit UUIDs");

                        Ok( (Format::Uuid128Bit, v) )
                    })
                    .and_then( | (format, information_data) | {

                        let mut vec = Vec::new();

                        vec.push( ServerPduName::FindInformationResponse.into() );

                        vec.push( match format { Format::Uuid16Bit => 0x1, Format::Uuid128Bit => 0x2 } );

                        vec.extend_from_slice(&information_data);

                        let data = vec.into_boxed_slice();

                        self.connection.send( l2cap::AclData::new( data.into(), super::L2CAP_CHANNEL_ID ));

                        Ok(())
                    })
                    .ok()
                })
                .or_else( || {

                    // When there is no first attribute, that means there is no attributes
                    // within the specified range

                    let starting_handle = sh;

                    let oc = super::client::ClientPduName::FindInformationRequest.into();

                    self.send_error(starting_handle, oc, pdu::Error::AttributeNotFound);

                    None
                });
            },
            HandleRange { starting_handle: h @ _, ..} => {

                let oc = super::client::ClientPduName::FindInformationRequest.into();

                log::error!("Received invalid handle range in 'find information request'");

                self.send_invalid_handle_error(h, oc);
            }
        }


    }

    fn process_find_by_type_value_request(&mut self, payload: &[u8] ) {

        if payload.len() >= 6 {

            let starting_handle: u16 = TransferFormat::try_from( &payload[..2] ).unwrap();

            let ending_handle: u16 = TransferFormat::try_from( &payload[2..4] ).unwrap();

            let att_type: crate::UUID = TransferFormat::try_from( &payload[4..6] ).unwrap();

            let raw_value = &payload[6..];

            if starting_handle == 0u16 {
                let oc = super::client::ClientPduName::FindByTypeValueRequest.into();

                log::error!("Received 'find type by value request' with a handle range starting \
                    at 0");

                self.send_invalid_handle_error(0, oc);

            } else if starting_handle <= ending_handle {
                use core::cmp::min;
                use core::mem::size_of;

                let start = min( starting_handle as usize, self.attributes.len() );
                let end   = min( ending_handle   as usize, self.attributes.len() );

                let mtu = self.get_mtu() as usize;

                let attributes = &self.attributes[start..end];

                let vec_cap = min( (end - start) * (2 + size_of::<u16>()), mtu - 1 );

                let mut size_counter = 0;

                let mut handles_information_list = Vec::with_capacity(vec_cap + 1);

                handles_information_list.push( ServerPduName::FindByTypeValueResponse.into() );

                attributes
                .iter()
                .filter(|attribute| {
                    (attribute.get_type() == att_type) &&
                    (attribute.get_val_as_transfer_format().into() == raw_value)
                })
                .try_for_each(|a| {

                    handles_information_list.extend_from_slice( &TransferFormat::into( &a.get_handle() ));
                    handles_information_list.extend_from_slice( &TransferFormat::into( &a.get_type() ));

                    size_counter += 2 + size_of::<u16>();

                    if size_counter < vec_cap { Ok(()) } else { Err(()) }
                })
                .ok();

                if handles_information_list.len() > 1 {

                    log_debug!("Sending 'find by type value response'");

                    self.connection.send(
                        l2cap::AclData::new(
                            handles_information_list,
                            super::L2CAP_CHANNEL_ID
                        )
                    );

                } else {
                    let oc = super::client::ClientPduName::FindByTypeValueRequest.into();

                    self.send_error(starting_handle, oc, pdu::Error::AttributeNotFound);
                }

            } else {
                let oc = super::client::ClientPduName::FindByTypeValueRequest.into();

                log::error!("Sending Error response to 'find by type value request', invalid
                    handles receive");

                self.send_invalid_handle_error(starting_handle, oc);
            }
        } else {

            log::error!("Invalid 'find by type value request' received");

            self.send_error(0, 0, pdu::Error::InvalidPDU);
        }
    }

    fn process_read_by_type_request(&self, type_request: pdu::TypeRequest ) {

        use pdu::HandleRange;

        let handle_range = type_request.handle_range;

        let desired_att_type = type_request.attr_type;

        // required permissions
        let required = &[
            super::AttributePermissions::Read
        ];

        let restricted = &[
            super::AttributePermissions::Encryption(super::AttributeRestriction::Read, super::EncryptionKeySize::Bits128),
            super::AttributePermissions::Encryption(super::AttributeRestriction::Read, super::EncryptionKeySize::Bits192),
            super::AttributePermissions::Encryption(super::AttributeRestriction::Read, super::EncryptionKeySize::Bits256),
            super::AttributePermissions::Authentication(super::AttributeRestriction::Read),
            super::AttributePermissions::Authorization(super::AttributeRestriction::Read),
        ];

        match handle_range {
            HandleRange{ starting_handle: 0, .. } => {
                let oc = super::client::ClientPduName::ReadByTypeRequest.into();

                log::error!("Received 'read by type request' with a handle range starting with 0");

                self.send_invalid_handle_error(0, oc);
            },
            HandleRange{ starting_handle: sh @ _, ending_handle: eh @ _ } if eh >= sh => {
                use core::cmp::min;

                let start = min( sh as usize, self.attributes.len() );
                let end   = min( eh as usize, self.attributes.len() );

                let vec_cap = min(self.get_mtu() as usize, 256);

                let mut read_by_type_response = Vec::with_capacity(vec_cap);

                read_by_type_response.push( ServerPduName::ReadByTypeResponse.into() );

                log::trace!("(ATT) searching for attributes with type {:#x}", desired_att_type);

                let first_match = self.attributes[start..end].iter()
                    .enumerate()
                    .filter( |(_,att)| att.get_type() == desired_att_type )
                    .next();

                first_match.and_then( |(cnt, att)| {

                    if let Some(permission) = self.validate_permissions(att.as_ref(), required, restricted) {

                        let oc = super::client::ClientPduName::ReadByTypeRequest.into();

                        self.send_error(sh, oc, permission.into());

                        None

                    } else {

                        let transfer_value = att.get_val_as_transfer_format().into();

                        let handle = att.get_handle();

                        let length = min(transfer_value.len() + 2, vec_cap - 2);

                        // Add the length of each handle value pair
                        read_by_type_response.push( length as u8 );

                        // Add the first handle
                        read_by_type_response.extend_from_slice( &TransferFormat::into(&handle) );

                        // Add the first value
                        read_by_type_response.extend_from_slice( &transfer_value );

                        // Return the next attribute to be check and the length of the matched
                        // attribute
                        Some( (start + cnt + 1, length) )
                    }
                })
                .and_then( | (next_attr, handle_value_len) | {

                    let mut remaining = vec_cap - (2 + handle_value_len);

                    let attr_iter = self.attributes[next_attr..end].iter()
                        .filter(|att| att.get_type() == desired_att_type);

                    // Scour the rest of the attributes for any more values that can be added
                    for attribute in attr_iter {
                        let transfer_value = attribute.get_val_as_transfer_format().into();

                        if (2 + transfer_value.len()) <= remaining &&
                           None == self.validate_permissions(attribute.as_ref(), required, restricted)
                        {
                            remaining -= transfer_value.len();

                            let handle = attribute.get_handle();

                            read_by_type_response.extend_from_slice( &TransferFormat::into(&handle) );

                            read_by_type_response.extend_from_slice( &transfer_value );

                        } else {
                            break;
                        }
                    }

                    Some(())
                });

                // Check that at least one handle-value was added to the response otherwise return
                // the error that no attributes were found.
                if read_by_type_response.len() > 1 {

                    log_debug!("Sending 'read by type response'");

                    self.connection.send( l2cap::AclData::new(
                        read_by_type_response,
                        super::L2CAP_CHANNEL_ID
                    ));

                } else {
                    let oc = super::client::ClientPduName::ReadByTypeRequest.into();

                    self.send_error(sh, oc, super::pdu::Error::AttributeNotFound);
                }
            },
            HandleRange{ starting_handle: sh @ _, .. } => {
                let oc = super::client::ClientPduName::ReadByTypeRequest.into();

                self.send_invalid_handle_error(sh, oc);
            }
        }
    }
}

impl<'c, C> AsRef<C> for Server<'c, C> where C: l2cap::ConnectionChannel {
    fn as_ref(&self) -> &C {
        &self.connection
    }
}

/// The Reserved Handle
///
/// The first handle (value of '0') is reserved for future use. This is used to represent that
/// handle when creating a new Attribute Bearer
struct ReservedHandle;

impl super::AnyAttribute for ReservedHandle {
    fn get_type(&self) -> crate::UUID { Into::<crate::UUID>::into(0u128) }

    fn get_permissions(&self) -> Vec<super::AttributePermissions> {
        alloc::vec!(super::AttributePermissions::Read)
    }

    fn get_handle(&self) -> u16 { 0 }

    fn set_val_from_raw(&mut self, _: &[u8]) -> Result<(), TransferFormatError> {
        Err(TransferFormatError::from("ReservedHandle cannot be set from raw data"))
    }

    fn get_val_as_transfer_format(&self) -> &dyn TransferFormat { &() }
}

/// The constructor of attributes on an Attribute Server
///
/// `ServerAttributes` construsts a list of attributes.
#[derive(Default)]
pub struct ServerAttributes {
    attributes: Vec<Box<dyn super::AnyAttribute + Send + Sync>>
}

impl ServerAttributes {

    /// Create a new `ServiceAttributes`
    pub fn new() -> Self {

        Self { attributes: alloc::vec![ Box::new(ReservedHandle) ] }
    }

    /// Push an attribute to `ServiceAttributes`
    ///
    /// This will push the attribute onto the list of server attributes and return the handle of
    /// the pushed attribute.
    pub fn push<V>(&mut self, mut attribute: super::Attribute<V>) -> u16
    where V: TransferFormat + Sized + Send + Sync + 'static
    {
        use core::convert::TryInto;

        let ret = self.attributes.len().try_into().expect("Exceeded attribute handle limit");

        // Set the handle now that the attribute is part of the list
        attribute.handle = Some(ret);

        log::trace!("Adding attribute with type '{:#x}' to server attributes", attribute.ty );

        self.attributes.push( Box::new(attribute) );

        ret
    }

    /// Get the next available handle
    ///
    /// This is the handle that is assigned to the next attribute to be
    /// [`push`](#method.push)ed to the `ServerAttributes`. This is generally used to get the
    /// handle of the attribute that is about to be pushed to `ServerAttributes`
    ///
    /// ```rust
    /// # use bo_tie::att::server::ServerAttributes;
    /// # let attribute = bo_tie::att::Attribute::new( bo_tie::UUID::default(), Box::new(), () );
    ///
    /// let server_attributes = ServerAttributes::new();
    ///
    /// let first_handle = server_attributes.next_handle();
    ///
    /// let pushed_handle = server_attributes.push(attribute);
    ///
    /// assert_eq!( first_handle, pushed_handle );
    pub fn next_handle(&self) -> u16 {
        self.attributes.len() as u16
    }
}
