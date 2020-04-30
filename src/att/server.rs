use alloc::{
    vec::Vec,
    boxed::Box,
};
use super::{
    AttributePermissions,
    AttributeRestriction,
    client::ClientPduName,
    pdu,
    TransferFormatError,
    TransferFormatInto,
    TransferFormatTryFrom,
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
    attributes: ServerAttributes,
    /// The permissions the client currently has
    ///
    /// This is sorted and de-duplicated, to make things marginally faster for linear search. Most
    /// permission checks will be for permissions sorted towards the front (Unencrypted Read/Write,
    /// Encrypted Read/Write,
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

        let attributes = server_attributes.into().unwrap_or(ServerAttributes::new());

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

        self.attributes.push( attribute );

        ret
    }

    /// Return the next unused handle
    pub fn next_handle(&self) -> u16 { self.attributes.len() as u16 }

    /// Give a permission to the client
    ///
    /// This doesn't check that the client is qualified to receive the permission, it just adds an
    /// indication on the server that the client has it.
    pub fn give_permissions_to_client<P>(&mut self, permissions: P )
    where P: core::borrow::Borrow<[AttributePermissions]>,
    {
        permissions.borrow().iter()
            .for_each(|p| if let Err(pos) = self.given_permissions.binary_search(&p) {
                    self.given_permissions.insert(pos, *p);
                }
            )
    }

    /// Remove one or more permission given to the client
    ///
    /// This will remove every permission in `permissions` from the client.
    pub fn revoke_permissions_of_client<P>(&mut self, permissions: P)
    where P: core::borrow::Borrow<[AttributePermissions]>
    {
        self.given_permissions = self.given_permissions.clone().into_iter()
            .filter(|p| !permissions.borrow().contains(p) )
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
        permissions: &[super::AttributePermissions])
    -> Result<(), pdu::Error>
    {
        let att = self.attributes.get(handle).ok_or(super::pdu::Error::InvalidHandle)?;

        match self.validate_permissions(att, permissions) {
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
        att: &dyn ServerAttribute,
        operation_permissions: &[super::AttributePermissions]
    ) -> Option<pdu::Error>
    {
        match self.given_permissions.iter()
            .skip_while(|&p| {
                !att.get_permissions().contains(p) || !operation_permissions.contains(p)
            })
            .nth(0)
        {
            Some(_) => None,
            None => operation_permissions.iter()
                .find(|&p| att.get_permissions().contains(p) )
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
                    }
                )
                .or( Some(pdu::Error::InsufficientAuthorization) )
        }
    }

    /// Check if a client can read the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_read_attribute(&self, att: &dyn ServerAttribute ) -> Option<pdu::Error> {
        self.validate_permissions(att, super::FULL_READ_PERMISSIONS)
    }

    /// Check if a client can write the given attribute
    ///
    /// Returns the error as to why the client couldn't read the attribute
    fn client_can_write_attribute(&self, att: &dyn ServerAttribute ) -> Option<pdu::Error> {
        self.validate_permissions(att, super::FULL_WRITE_PERMISSIONS)
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
        self.attributes.get(handle).map( | attribute | {
            self.send( pdu::handle_value_notification( handle, attribute ) );
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
    fn get_att(&self, handle: u16) -> Result<&(dyn ServerAttribute + Send + Sync), pdu::Error> {
        if pdu::is_valid_handle(handle) {
            self.attributes.get(handle).ok_or(pdu::Error::InvalidHandle)
        }
        else {
            Err(pdu::Error::InvalidHandle)
        }
    }

    /// Get a reference to a mutable attribute
    fn get_att_mut(&mut self, handle: u16) -> Result<&mut (dyn ServerAttribute + Send + Sync + 'static), pdu::Error> {
        if pdu::is_valid_handle(handle) {
            self.attributes.get_mut(handle).ok_or(pdu::Error::InvalidHandle)
        }
        else {
            Err(pdu::Error::InvalidHandle)
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

        match self.read_att_and(handle, |att_tf| self.send( pdu::read_response(att_tf) ) ) {
            Err(e) => self.send_error(handle, ClientPduName::ReadRequest, e),
            Ok(_) => (),
        }
    }

    /// Process a Write Request from the client
    fn process_write_request(&mut self, payload: &[u8]) {
        log::trace!("Write Request");

        let handle = TransferFormatTryFrom::try_from( &payload[..2] ).expect("Failed to convert 2 bytes to u16");

        match self.write_att( handle, &payload[2..]) {
            Ok(_) => self.send_pdu(pdu::write_response()),
            Err(e) => self.send_error(handle, ClientPduName::WriteRequest, e),
        }
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
            let mut handle_uuids_16_bit_itr = HandleUuidItr(false, self.attributes.attributes[start..stop]
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
                let mut handle_uuids_128_bit_itr = HandleUuidItr(true, self.attributes.attributes[start..start]
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

                let mut handles = HandleGroupItr( self.attributes.attributes[start..end].iter()
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

            let mut init_iter = self.attributes.attributes[start..end].iter()
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

    /// Get an iterator over the attribute informational data
    ///
    /// This will return an iterator to get the type, permissions, and handle for each attribute
    pub fn iter_attr_info(&self) -> impl Iterator<Item = &dyn AttributeInfo > {
        self.attributes.iter_info()
    }
}

impl<C> AsRef<C> for Server<'_, C> where C: l2cap::ConnectionChannel {
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
    pub fn iter_info(&self) -> impl Iterator<Item = &dyn AttributeInfo > {
        ServerAttributesIter(self.attributes[1..].iter())
    }

    /// Attributes length
    pub fn len(&self) -> usize { self.attributes.len() }

    /// Get attribute with the given handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get(&self, handle: u16) -> Option<&(dyn ServerAttribute + Send + Sync)> {
        match handle {
            0 => None,
            h => self.attributes.get(h as usize).map(|h| h.as_ref() )
        }
    }

    /// Get a mutable reference to the attribute with the given handle
    ///
    /// This returns `None` if the handle is 0 or not in attributes
    fn get_mut(&mut self, handle: u16) -> Option<&mut (dyn ServerAttribute + Send + Sync + 'static)> {
        match handle {
            0 => None,
            h => self.attributes.get_mut(h as usize).map(|h| h.as_mut() )
        }
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

    fn get_permissions(&self) -> &[super::AttributePermissions] { &[] }

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

#[cfg(test)]
mod tests {
    mod permission_tests {
        use crate::{
            att::{
                *,
                server::*
            },
            l2cap::{L2capPdu, AclDataFragment},
            UUID,
        };
        use tinymt::TinyMT64;
        use std::{
            mem::MaybeUninit,
            ops::{Deref, DerefMut},
            sync::{
                Arc,
                Mutex,
                atomic::{AtomicUsize, Ordering},
            },
            task::Waker,
        };

        const ALL_ATT_PERM_SIZE: usize = 12;

        const MAX_VEC_SIZE: usize = 10_000;

        type AllAttributePermissions = [AttributePermissions; ALL_ATT_PERM_SIZE];

        #[derive(Debug)]
        struct PermVec {
            len: usize,
            permissions: MaybeUninit<AllAttributePermissions>,
        }

        impl PermVec {
            fn new() -> Self { Self { len: 0, permissions: MaybeUninit::uninit() } }

            /// Push an item, panics if `self.len > size_of<AllAttributePermissions>()`
            fn push(&mut self, p: AttributePermissions) {
                unsafe { (*self.permissions.as_mut_ptr())[self.len] = p };
                self.len += 1;
            }
        }

        impl From<&'_ [AttributePermissions]> for PermVec {
            fn from(ap: &[AttributePermissions]) -> Self {
                let mut permissions: MaybeUninit<AllAttributePermissions> = MaybeUninit::uninit();

                let perm_ref = unsafe { &mut *permissions.as_mut_ptr() };

                perm_ref[..ap.len()].copy_from_slice(ap);

                Self { len: ap.len(), permissions }
            }
        }

        impl Deref for PermVec {
            type Target = [AttributePermissions];

            fn deref(&self) -> &Self::Target {
                unsafe { &(*self.permissions.as_ptr())[..self.len] }
            }
        }

        impl DerefMut for PermVec {
            fn deref_mut(&mut self) -> &mut Self::Target {
                unsafe { &mut (*self.permissions.as_mut_ptr())[..self.len] }
            }
        }

        /// Calculate factorial, panics on overflow
        fn factorial(v: usize) -> usize { (2..=v).fold(1, |c, v| c * v) }

        fn permutations(n: usize, r: usize) -> usize { factorial(n) / factorial(n - r) }

        fn all_sized_permutations_cnt(list_size: usize) -> usize {
            (0..=list_size).fold(0, |c, k| c + permutations(list_size, k))
        }

        /// This returns a boolean indicating if the permission should be added to the set of
        /// permissions to be tested.
        ///
        /// This generates a random integer between 0 up to `chance_max`. If the randomly generated
        /// number is 0 then this function returns true.
        ///
        /// This function is a helper function for `permutation_step`.
        ///
        /// An implementation of the Mersenne Twister is used to generate the 'random' chance.
        fn add_permission_set(rng: Arc<Mutex<tinymt::TinyMT64>>, chance_max: usize) -> bool {
            use rand::Rng;

            if chance_max != 0 {
                0 == rng.lock().unwrap().gen_range(0, chance_max)
            } else {
                true
            }
        }

        /// This is used to calculate if an entire recursion branch should be skipped.
        ///
        /// This calculates the odds where every generated set of permissions by a recursion branch
        /// would not be included as part of a returned set. The point of this is to speed up the
        /// function `permutation_step` by reducing the number of recursion calls made.
        ///
        /// The input `do_not_add_chance_max` is the upward bound when generating a random number in
        ///  a range between zero and it. When zero is the randomly generated number, then it would
        /// indicate that the permission set would not be added to the list of generated
        /// permissions.
        fn do_recursion_branch(
            rng: Arc<Mutex<tinymt::TinyMT64>>,
            do_not_add_chance_max: f64,
            perms_size: usize,
            step_size: usize,
        ) -> bool {
            use rand::Rng;

            // the exponent for calculating the odds that no members of a branch are added to the
            // eventual test list.
            let exponent =
                (1..=(perms_size-step_size))
                .fold(0usize, |exp, s_size| exp + permutations(perms_size, s_size) );

            let v = match std::convert::TryFrom::try_from(exponent) {
                Ok(exp) => do_not_add_chance_max.powi(exp),
                Err(_)  => do_not_add_chance_max.powf(exponent as f64),
            };

            if v <= 1000f64 {
                // boost numbers by 100_000 for resolution in the random number generation
                let max = (v * 100_000f64) as usize;

                100_000 < rng.lock().unwrap().gen_range(0, max)
            } else if v >= (u64::MAX as f64) {
                true
            } else {
                0 != rng.lock().unwrap().gen_range(0, v as u64)
            }
        }

        fn permutation_step(
            permutations: Arc<Mutex<Vec<PermVec>>>,
            perms: &[AttributePermissions],
            step: &[AttributePermissions],
            rand_generator: Arc<Mutex<tinymt::TinyMT64>>,
            add_chance_max: usize,
            do_not_add_chance_max: f64,
            added_cnt: Arc<AtomicUsize>,
        ) {
            use rayon::prelude::*;

            perms.par_iter().enumerate().for_each(|(cnt, permission)| {

                if added_cnt.load(Ordering::Acquire) >= MAX_VEC_SIZE { return }

                let step_permutation = {
                    let mut s = PermVec::from(step);
                    s.push(*permission);
                    s
                };

                if do_recursion_branch(
                    rand_generator.clone(),
                    do_not_add_chance_max,
                    ALL_ATT_PERM_SIZE,
                    step_permutation.len())
                {
                    let rotated_perms = {
                        let mut v = PermVec::from(perms);
                        v.rotate_left(cnt);
                        v
                    };

                    permutation_step(
                        permutations.clone(),
                        &rotated_perms[1..],
                        &step_permutation,
                        rand_generator.clone(),
                        add_chance_max,
                        do_not_add_chance_max,
                        added_cnt.clone(),
                    );
                }

                if add_permission_set(rand_generator.clone(), add_chance_max) &&
                    added_cnt.fetch_add(1, Ordering::Release) < MAX_VEC_SIZE
                {
                    permutations.lock().unwrap().push(step_permutation);
                }
            });
        }

        fn permissions_permutations(all_permissions: &AllAttributePermissions) -> Vec<PermVec> {
            use rand::SeedableRng;

            let all_permutations = all_sized_permutations_cnt(all_permissions.len());


            let add_chance_max = all_permutations / MAX_VEC_SIZE;

            let do_not_add_chance_max =
                all_permutations as f64 / (all_permutations - MAX_VEC_SIZE) as f64;

            let output = Arc::new(Mutex::new(Vec::with_capacity(MAX_VEC_SIZE)));

            let tiny_mt_64 = Arc::new(Mutex::new(TinyMT64::from_entropy()));

            // Determine whether to add the empty set or not.
            let cnt = if add_permission_set(tiny_mt_64.clone(), add_chance_max) {
                output.lock().unwrap().push(PermVec::new());

                Arc::new(AtomicUsize::new(1))
            } else {
                Arc::new(AtomicUsize::default())
            };

            permutation_step(
                output.clone(),
                all_permissions,
                &[],
                tiny_mt_64,
                add_chance_max,
                do_not_add_chance_max,
                cnt.clone(),
            );

            Arc::try_unwrap(output).unwrap().into_inner().unwrap()
        }

        fn expected_permissions_result(
            operation_permissions: &[AttributePermissions],
            attribute_permissions: &[AttributePermissions],
            client_permissions: &[AttributePermissions],
        ) -> Result<(), pdu::Error>
        {
            use AttributePermissions::*;
            use AttributeRestriction::{Encryption, Authorization, Authentication};
            use EncryptionKeySize::*;

            match operation_permissions.iter().find(|&&op|
                attribute_permissions.iter().find(|&&ap| ap == op).is_some() &&
                    client_permissions.iter().find(|&&cp| cp == op).is_some()
            ) {
                Some(_) => Ok(()),
                None =>
                    Err(match operation_permissions.iter()
                        .find(|&p| attribute_permissions.contains(p))
                    {
                        Some(Read(AttributeRestriction::None)) => pdu::Error::ReadNotPermitted,

                        Some(Write(AttributeRestriction::None)) => pdu::Error::WriteNotPermitted,

                        Some(Read(Encryption(_))) =>
                            if client_permissions.contains(&Read(Encryption(Bits128))) ||
                                client_permissions.contains(&Read(Encryption(Bits192))) ||
                                client_permissions.contains(&Read(Encryption(Bits256)))
                            {
                                pdu::Error::InsufficientEncryptionKeySize
                            } else {
                                pdu::Error::InsufficientEncryption
                            },

                        Some(Write(Encryption(_))) =>
                            if client_permissions.contains(&Write(Encryption(Bits128))) ||
                                client_permissions.contains(&Write(Encryption(Bits192))) ||
                                client_permissions.contains(&Write(Encryption(Bits256)))
                            {
                                pdu::Error::InsufficientEncryptionKeySize
                            } else {
                                pdu::Error::InsufficientEncryption
                            },

                        Some(Read(Authentication)) |
                        Some(Write(Authentication)) =>
                            pdu::Error::InsufficientAuthentication,

                        Some(Read(Authorization)) |
                        Some(Write(Authorization)) |
                        None =>
                            pdu::Error::InsufficientAuthorization,
                    }
                ),
            }
        }

        #[test]
        #[cfg(target_pointer_width = "64")]
        /// This is an 'entropy' test as it doesn't test every permission combination between
        /// server operations, client granted permissions, and the permissions of the attributes
        /// themselves. It selects a random number of permissions (up to 10k, but probably 10k) and
        /// tests only those. Every time this test is run it is highly, highly, highly likely that
        /// the sets of tested permissions are different. Re-running the test will probably produce
        /// different results.
        fn check_permissions_entropy_test() {
            use AttributePermissions::*;
            use AttributeRestriction::*;
            use EncryptionKeySize::*;
            use rayon::prelude::*;

            let all_permissions: AllAttributePermissions = [
                Read(None),
                Read(Encryption(Bits128)),
                Read(Encryption(Bits192)),
                Read(Encryption(Bits256)),
                Read(Authentication),
                Read(Authorization),
                Write(None),
                Write(Encryption(Bits128)),
                Write(Encryption(Bits192)),
                Write(Encryption(Bits256)),
                Write(Authentication),
                Write(Authorization),
            ];

            struct DummyConnection;

            impl crate::l2cap::ConnectionChannel for DummyConnection {
                fn send<Pdu>(&self, _: Pdu) where Pdu: Into<L2capPdu> {}

                fn receive(&self, _: &Waker) -> Option<Vec<AclDataFragment>> { Some(Vec::new()) }
            }

            let all_tested_permission_permutations = &permissions_permutations(&all_permissions);

            let mut server_attributes = ServerAttributes::default();

             all_tested_permission_permutations.iter().for_each(|permissions| {
                let attribute = Attribute::new(UUID::from(1u16), permissions.to_vec(), ());

                server_attributes.push(attribute);
            });

            let mut server = Server::new(&DummyConnection, 100, server_attributes);

            all_tested_permission_permutations.iter().for_each(|perm_client| {

                server.revoke_permissions_of_client(all_permissions.as_ref());

                server.give_permissions_to_client(perm_client.as_ref());

                all_tested_permission_permutations.par_iter().for_each(|perm_op| {
                    all_tested_permission_permutations.iter().enumerate().for_each(|(cnt, perm_att)| {

                        // 'cnt + 1' because attributes start at handle 1
                        let calculated = server.check_permissions((cnt + 1) as u16, perm_op);

                        let expected = expected_permissions_result(&perm_op, &perm_att, &perm_client);

                        assert_eq!(
                            expected,
                            calculated,
                            "Permissions check failed, mismatch in return\n\
                            (Please note: this test is a comparison between two algorithms, and the \
                            expected result may be incorrect)\n\n\
                            Operation permissions {:#?}\nAttribute permissions {:#?}\n\
                            Client permissions {:#?}",
                            perm_op.to_vec(),
                            perm_att.to_vec(),
                            perm_client.to_vec()
                        );
                    });
                });
            })
        }
    }
}