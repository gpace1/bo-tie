use crate::{pdu, server::ServerPduName, TransferFormatError, TransferFormatInto, TransferFormatTryFrom};
use alloc::{format, vec::Vec};
use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::{ConnectionChannel, ConnectionChannelExt};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq)]
pub enum ClientPduName {
    ExchangeMtuRequest,
    FindInformationRequest,
    FindByTypeValueRequest,
    ReadByTypeRequest,
    ReadRequest,
    ReadBlobRequest,
    ReadMultipleRequest,
    ReadByGroupTypeRequest,
    WriteRequest,
    WriteCommand,
    PrepareWriteRequest,
    ExecuteWriteRequest,
    HandleValueConfirmation,
    SignedWriteCommand,
}

impl TryFrom<u8> for ClientPduName {
    type Error = ();

    fn try_from(val: u8) -> Result<Self, ()> {
        match val {
            0x02 => Ok(ClientPduName::ExchangeMtuRequest),
            0x04 => Ok(ClientPduName::FindInformationRequest),
            0x06 => Ok(ClientPduName::FindByTypeValueRequest),
            0x08 => Ok(ClientPduName::ReadByTypeRequest),
            0x0A => Ok(ClientPduName::ReadRequest),
            0x0C => Ok(ClientPduName::ReadBlobRequest),
            0x0E => Ok(ClientPduName::ReadMultipleRequest),
            0x10 => Ok(ClientPduName::ReadByGroupTypeRequest),
            0x12 => Ok(ClientPduName::WriteRequest),
            0x52 => Ok(ClientPduName::WriteCommand),
            0x16 => Ok(ClientPduName::PrepareWriteRequest),
            0x18 => Ok(ClientPduName::ExecuteWriteRequest),
            0x1E => Ok(ClientPduName::HandleValueConfirmation),
            0xD2 => Ok(ClientPduName::SignedWriteCommand),
            _ => Err(()),
        }
    }
}

impl From<ClientPduName> for pdu::PduOpcode {
    fn from(pdu_name: ClientPduName) -> pdu::PduOpcode {
        pdu::PduOpcode::Client(pdu_name)
    }
}

impl From<ClientPduName> for u8 {
    fn from(pdu_name: ClientPduName) -> u8 {
        match pdu_name {
            ClientPduName::ExchangeMtuRequest => 0x02,
            ClientPduName::FindInformationRequest => 0x04,
            ClientPduName::FindByTypeValueRequest => 0x06,
            ClientPduName::ReadByTypeRequest => 0x08,
            ClientPduName::ReadRequest => 0x0A,
            ClientPduName::ReadBlobRequest => 0x0C,
            ClientPduName::ReadMultipleRequest => 0x0E,
            ClientPduName::ReadByGroupTypeRequest => 0x10,
            ClientPduName::WriteRequest => 0x12,
            ClientPduName::WriteCommand => 0x52,
            ClientPduName::PrepareWriteRequest => 0x16,
            ClientPduName::ExecuteWriteRequest => 0x18,
            ClientPduName::HandleValueConfirmation => 0x1E,
            ClientPduName::SignedWriteCommand => 0xD2,
        }
    }
}

impl core::fmt::Display for ClientPduName {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ClientPduName::ExchangeMtuRequest => write!(f, "Exchange Mtu Request"),
            ClientPduName::FindInformationRequest => write!(f, "Find Information Request"),
            ClientPduName::FindByTypeValueRequest => write!(f, "Find By Type Value Request"),
            ClientPduName::ReadByTypeRequest => write!(f, "Read By Type Request"),
            ClientPduName::ReadRequest => write!(f, "Read Request"),
            ClientPduName::ReadBlobRequest => write!(f, "Read Blob Request"),
            ClientPduName::ReadMultipleRequest => write!(f, "Read Multiple Request"),
            ClientPduName::ReadByGroupTypeRequest => write!(f, "Read By Group Type Request"),
            ClientPduName::WriteRequest => write!(f, "Write Request"),
            ClientPduName::WriteCommand => write!(f, "Write Command"),
            ClientPduName::PrepareWriteRequest => write!(f, "Prepare Write Request"),
            ClientPduName::ExecuteWriteRequest => write!(f, "Execute Write Request"),
            ClientPduName::HandleValueConfirmation => write!(f, "Handle Value Confirmation"),
            ClientPduName::SignedWriteCommand => write!(f, "Signed Write Command"),
        }
    }
}

pub trait ResponseProcessor {
    type Response;

    fn process_response(self, b_frame: &l2cap::pdu::BasicFrame<Vec<u8>>) -> Result<Self::Response, super::Error>;
}

/// Process a server response of a client request
struct ResponseProcessorCheck<F, R>(F)
where
    F: FnOnce(&[u8]) -> Result<R, super::Error>;

impl<F, R> ResponseProcessor for ResponseProcessorCheck<F, R>
where
    F: FnOnce(&[u8]) -> Result<R, super::Error>,
{
    type Response = R;

    /// Process the response
    ///
    /// The input `acl_data` should be the response from the server to the request that generated
    /// this `ResponseProcessor`.
    fn process_response(self, acl_data: &l2cap::pdu::BasicFrame<Vec<u8>>) -> Result<Self::Response, super::Error> {
        if acl_data.get_channel_id() == super::L2CAP_CHANNEL_ID {
            self.0(acl_data.get_payload())
        } else {
            Err(super::Error::IncorrectChannelId(acl_data.get_channel_id()))
        }
    }
}

/// Connect this device to an Attribute Server
///
/// `ConnectClient` is used for initiating and connecting to an attribute server. Unlike a physical
/// link there is not an extensive process to setup an ATT connection beyond configuring a Maximum
/// Transmission Unit (MTU). In fact if the default MTU is to be used for the connection (the value
/// of which is defined at a higher layer) then there is not exchange with the server and the client
/// automatically "connects".
/// ```
pub struct ConnectClient {
    default_mtu: usize,
    requested_mtu: usize,
    skipped_mtu_request: bool,
}

impl ConnectClient {
    /// Connect to the Attribute server of the peer device
    ///
    /// `connect` is a shortcut of calling methods `initiate` and then `create_client`. This is a
    /// simpler, but it doesn't allow for other Bluetooth protocols to transmit PDU's on the same
    /// physical link until it is complete.
    ///
    /// # MTU
    /// The `default_mtu` is the initial MTU set for this instance of the ATT protocol. This value
    /// is defined by a higher layer protocol or profile and it is the assumed value of the MTU when
    /// the client and server initially connect.
    ///
    /// The `requested_mtu` is the value that will be sent as part of an *exchange MTU request* that
    /// is sent after the client and server connect. It may become the `requested_mtu` if it is an
    /// accepted size by the server. If it isn't then the whatever is the smaller of the MTU's
    /// during the MTU exchange will be set as the new MTU.
    pub async fn connect<C, M>(
        connection_channel: &mut C,
        default_mtu: u16,
        requested_mtu: M,
    ) -> Result<Client, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        M: Into<Option<u16>>,
    {
        let connect_client = Self::initiate(connection_channel, default_mtu, requested_mtu).await?;

        let response = connection_channel
            .receive_b_frame()
            .await
            .map_err(|e| super::ConnectionError::RecvError(e))?;

        connect_client.create_client(&response).await.map_err(|e| e.into())
    }

    /// Initiate a connection to an ATT server
    ///
    /// # MTU
    /// The `default_mtu` is the initial MTU set for this instance of the ATT protocol. This value
    /// is defined by a higher layer protocol or profile and it is the assumed value of the MTU when
    /// the client and server initially connect.
    ///
    /// The `requested_mtu` is the value that will be sent as part of an *exchange MTU request* that
    /// is sent after the client and server connect. It may become the `requested_mtu` if it is an
    /// accepted size by the server. If it isn't then the whatever is the smaller of the MTU's
    /// during the MTU exchange will be set as the new MTU.
    pub async fn initiate<C, M>(
        connection_channel: &C,
        default_mtu: u16,
        requested_mtu: M,
    ) -> Result<ConnectClient, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        M: Into<Option<u16>>,
    {
        let default_mtu = default_mtu.into();

        if let Some(requested_mtu) = requested_mtu.into() {
            let mtu_req = pdu::exchange_mtu_request(requested_mtu as u16);

            let requested_mtu = requested_mtu.into();

            let acl_data = l2cap::pdu::BasicFrame::new(TransferFormatInto::into(&mtu_req), super::L2CAP_CHANNEL_ID);

            connection_channel
                .send(acl_data)
                .await
                .map_err(|e| super::ConnectionError::SendError(e))?;

            Ok(ConnectClient {
                default_mtu,
                requested_mtu,
                skipped_mtu_request: false,
            })
        } else {
            let requested_mtu = default_mtu;

            Ok(ConnectClient {
                default_mtu,
                requested_mtu,
                skipped_mtu_request: true,
            })
        }
    }

    /// Finish connecting a client to a attribute server
    ///
    /// This takes the response from the MTU from the server and creates a `Client`. An error will
    /// occur if the response doesn't contain the correct channel identifier or an unexpected ATT
    /// PDU was received. The server is expected to respond with either a mtu response PDU or an
    /// error PDU with request not supported.
    pub async fn create_client(self, response: &l2cap::pdu::BasicFrame<Vec<u8>>) -> Result<Client, super::Error> {
        if self.skipped_mtu_request {
            Ok(Client::new(self.requested_mtu))
        } else if response.get_channel_id() != super::L2CAP_CHANNEL_ID {
            Err(super::Error::IncorrectChannelId(response.get_channel_id()).into())
        } else if ServerPduName::ExchangeMTUResponse.is_convertible_from(response.get_payload()) {
            self.process_mtu_response(response.get_payload())
        } else if ServerPduName::ErrorResponse.is_convertible_from(response.get_payload()) {
            self.process_err_response(response.get_payload())
        } else {
            self.process_incorrect_response(response.get_payload().get(0).cloned())
                .map_err(|e| e.into())
        }
    }

    fn process_mtu_response(self, payload: &[u8]) -> Result<Client, crate::Error> {
        let pdu: Result<pdu::Pdu<pdu::MtuResponse>, _> = TransferFormatTryFrom::try_from(payload);

        match pdu {
            Ok(received_mtu) => {
                let mtu: usize = self.requested_mtu.min(received_mtu.get_parameters().0.into());

                Ok(Client::new(mtu))
            }
            Err(e) => Err(TransferFormatError::from(format!("Bad exchange MTU response: {}", e)).into()),
        }
    }

    fn process_err_response(self, payload: &[u8]) -> Result<Client, super::Error> {
        match pdu::Error::from_raw(payload[4]) {
            // Per the Spec (Core v5.0, Vol 3, part F, 3.4.9), this should be the only
            // error type received
            pdu::Error::RequestNotSupported => {
                // Log that exchange MTU is not supported by the server, and return a
                // client with the default MTU

                log::info!("(ATT) server doesn't support 'MTU exchange'; default MTU is used",);

                Ok(Client::new(self.default_mtu))
            }

            e @ _ => Err(super::Error::from(TransferFormatError {
                pdu_err: e,
                message: format!("{}", e),
            })),
        }
    }

    fn process_incorrect_response(self, opcode: Option<u8>) -> Result<Client, super::Error> {
        // Convert the first byte into the
        match opcode.and_then(|b| Some(ServerPduName::try_from(b))) {
            Some(Ok(pdu)) => Err(TransferFormatError::from(format!(
                "Client received \
                invalid pdu in response to 'exchange MTU request'. Received '{}'",
                pdu
            ))),

            Some(Err(_)) => Err(TransferFormatError::from(format!(
                "Received unknown \
                invalid PDU for response to 'exchange MTU request'; raw value is {:#x}",
                opcode.unwrap()
            ))),

            None => Err(TransferFormatError::from(
                "Received empty packet for
                response to 'exchange MTU request'",
            )),
        }
        .map_err(|e| e.into())
    }
}

/// The `Client` of the Attribute Protocol
///
/// A `Client` is created by connection to a ATT server, which can be done with
/// [`LeConnectClient`](crate::client::LeConnectClient).
/// After connecting, the `Client` used for performing everything required to interact with the
/// server.
///
/// The MTU between the Client and Server is already established when a 'Client' is created, however
/// a new MTU can be requested at any time.
pub struct Client {
    mtu: usize,
}

impl Client {
    fn new(mtu: usize) -> Self {
        Self { mtu }
    }

    fn process_raw_data<P>(expected_response: ServerPduName, bytes: &[u8]) -> Result<P, super::Error>
    where
        P: TransferFormatTryFrom + pdu::ExpectedOpcode,
    {
        if bytes.len() == 0 {
            Err(super::Error::Empty)
        } else if expected_response.is_convertible_from(bytes) {
            let pdu: pdu::Pdu<P> = TransferFormatTryFrom::try_from(&bytes)?;

            Ok(pdu.into_parameters())
        } else if ServerPduName::ErrorResponse.is_convertible_from(bytes) {
            let err_pdu: pdu::Pdu<pdu::ErrorResponse> = TransferFormatTryFrom::try_from(&bytes)?;

            Err(err_pdu.into())
        } else {
            match ServerPduName::try_from(bytes[0]) {
                Ok(_) => Err(super::Error::UnexpectedPdu(bytes[0])),
                Err(_) => Err(TransferFormatError::from(format!(
                    "Received Unknown PDU '{:#x}', \
                            expected '{} ({:#x})'",
                    bytes[0],
                    expected_response,
                    Into::<u8>::into(expected_response)
                ))
                .into()),
            }
        }
    }

    async fn send<C, P>(&self, connection_channel: &C, pdu: &pdu::Pdu<P>) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        P: TransferFormatInto,
    {
        let payload = TransferFormatInto::into(pdu);

        if payload.len() > self.mtu {
            Err(super::Error::MtuExceeded.into())
        } else {
            let data = l2cap::pdu::BasicFrame::new(payload.to_vec(), super::L2CAP_CHANNEL_ID);

            connection_channel
                .send(data)
                .await
                .map_err(|e| super::ConnectionError::SendError(e))
        }
    }

    /// Send the mtu request
    ///
    /// The maximum transfer size is part of connecting the client to the server, but if you want
    /// to try to change the mtu, then this will resend the exchange mtu request PDU to the server.
    ///
    /// The new MTU is returned by the future
    pub async fn exchange_mtu_request<C>(
        &mut self,
        connection_channel: &mut C,
        mtu: u16,
    ) -> Result<impl ResponseProcessor<Response = ()> + '_, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        if self.mtu > mtu.into() {
            Err(super::Error::TooSmallMtu.into())
        } else {
            self.send(connection_channel, &pdu::exchange_mtu_request(mtu)).await?;

            Ok(ResponseProcessorCheck(move |data| {
                let response: pdu::MtuResponse = Self::process_raw_data(ServerPduName::ExchangeMTUResponse, data)?;

                self.mtu = core::cmp::min(mtu, response.0).into();

                Ok(())
            }))
        }
    }

    /// Find information request
    ///
    /// # Panic
    /// A range cannot be the reserved handle 0x0000 and the ending handle must be larger than or
    /// equal to the starting handle
    pub async fn find_information_request<C, R>(
        &self,
        connection_channel: &C,
        handle_range: R,
    ) -> Result<impl ResponseProcessor<Response = pdu::FormattedHandlesWithType>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        R: Into<pdu::HandleRange> + core::ops::RangeBounds<u16>,
    {
        if !pdu::is_valid_handle_range(&handle_range) {
            panic!("Invalid handle range")
        }

        self.send(connection_channel, &pdu::find_information_request(handle_range))
            .await?;

        Ok(ResponseProcessorCheck(|data| {
            Self::process_raw_data(ServerPduName::FindInformationResponse, data)
        }))
    }

    /// Find by type and value request
    ///
    /// The attribute type, labeled as the input `uuid`, is a 16 bit assigned number type. If the
    /// type cannot be converted into a 16 bit UUID, then this function will return an error
    /// containing the incorrect type.
    ///
    /// # Panic
    /// A range cannot be the reserved handle 0x0000 and the start handle must be larger then the
    /// ending handle
    pub async fn find_by_type_value_request<C, R, D>(
        &self,
        connection_channel: &C,
        handle_range: R,
        uuid: crate::Uuid,
        value: D,
    ) -> Result<impl ResponseProcessor<Response = pdu::TypeValueResponse>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        R: Into<pdu::HandleRange> + core::ops::RangeBounds<u16>,
        D: TransferFormatTryFrom + TransferFormatInto,
    {
        if !pdu::is_valid_handle_range(&handle_range) {
            panic!("Invalid handle range")
        }

        let pdu_rslt = pdu::find_by_type_value_request(handle_range, uuid, value);

        match pdu_rslt {
            Ok(pdu) => {
                self.send(connection_channel, &pdu).await?;

                Ok(ResponseProcessorCheck(|d| {
                    Self::process_raw_data(ServerPduName::FindByTypeValueResponse, d)
                }))
            }
            Err(_) => Err(super::Error::Other("Cannot convert UUID to a 16 bit short version").into()),
        }
    }

    /// Read by type request
    ///
    /// # Panic
    /// A range cannot contain be the reserved handle 0x0000 and the start handle must be larger
    /// then the ending handle
    pub async fn read_by_type_request<C, R, D>(
        &self,
        connection_channel: &C,
        handle_range: R,
        attr_type: crate::Uuid,
    ) -> Result<impl ResponseProcessor<Response = Vec<pdu::ReadTypeResponse<D>>>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        R: Into<pdu::HandleRange>,
        D: TransferFormatTryFrom + TransferFormatInto,
    {
        let handle_range = handle_range.into();

        if !pdu::is_valid_handle_range(&handle_range.to_range_bounds()) {
            panic!("Invalid handle range")
        }

        self.send(connection_channel, &pdu::read_by_type_request(handle_range, attr_type))
            .await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::ReadByTypeResponse, d).map(|rsp: pdu::ReadByTypeResponse<D>| rsp.0)
        }))
    }

    /// Read request
    ///
    /// # Panic
    /// A handle cannot be the reserved handle 0x0000
    pub async fn read_request<C, D>(
        &self,
        connection_channel: &C,
        handle: u16,
    ) -> Result<impl ResponseProcessor<Response = D>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatTryFrom,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::read_request(handle)).await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::ReadResponse, d).map(|rsp: pdu::ReadResponse<D>| rsp.0)
        }))
    }

    /// Read blob request
    ///
    /// Reading data that must be blobbed is a multi-request process. Once all data is received will
    ///
    /// # Panic
    /// A handle cannot be the reserved handle 0x0000
    pub async fn read_blob_request<C, D>(
        &self,
        connection_channel: &C,
        handle: u16,
        offset: u16,
    ) -> Result<impl ResponseProcessor<Response = ReadBlob>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatTryFrom,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::read_blob_request(handle, offset))
            .await?;

        Ok(ResponseProcessorCheck(move |d| {
            let rsp: pdu::ReadBlobResponse = Self::process_raw_data(ServerPduName::ReadBlobResponse, d)?;

            Ok(ReadBlob {
                handle,
                offset: offset.into(),
                blob: rsp.into_inner(),
            })
        }))
    }

    /// Read multiple handles
    ///
    /// If handles has length of 0 an error is returned
    ///
    /// # Panic
    /// A handle cannot be the reserved handle 0x0000
    pub async fn read_multiple_request<C, D, I>(
        &self,
        connection_channel: &C,
        handles: I,
    ) -> Result<impl ResponseProcessor<Response = Vec<D>>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        I: IntoIterator<Item = u16> + Clone,
        Vec<D>: TransferFormatTryFrom + TransferFormatInto,
    {
        handles.clone().into_iter().for_each(|h| {
            if !pdu::is_valid_handle(h) {
                panic!("Handle 0 is reserved for future use by the spec.")
            }
        });

        self.send(
            connection_channel,
            &pdu::read_multiple_request(handles.into_iter().collect())?,
        )
        .await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::ReadMultipleResponse, d)
                .map(|rsp: pdu::ReadMultipleResponse<D>| rsp.0)
        }))
    }

    /// Read by group type
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn read_by_group_type_request<C, R, D>(
        &self,
        connection_channel: &C,
        handle_range: R,
        group_type: crate::Uuid,
    ) -> Result<impl ResponseProcessor<Response = pdu::ReadByGroupTypeResponse<D>>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        R: Into<pdu::HandleRange> + core::ops::RangeBounds<u16>,
        D: TransferFormatTryFrom,
    {
        if !pdu::is_valid_handle_range(&handle_range) {
            panic!("Invalid handle range")
        }

        self.send(
            connection_channel,
            &pdu::read_by_group_type_request(handle_range, group_type),
        )
        .await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::ReadByGroupTypeResponse, d)
        }))
    }

    /// Request to write data to a handle on the server
    ///
    /// The clint will send a response to the write request if the write was made on the server,
    /// otherwise the client will send an error PDU if the write couldn't be made.
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn write_request<C, D>(
        &self,
        connection_channel: &C,
        handle: u16,
        data: D,
    ) -> Result<impl ResponseProcessor<Response = ()>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatTryFrom + TransferFormatInto,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::write_request(handle, data)).await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::WriteResponse, d).map(|_: pdu::WriteResponse| ())
        }))
    }

    /// Command the server to write data to a handle
    ///
    /// No response or error is sent by the server for this command. This client will not know if
    /// write was successful on the server.
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn write_command<C, D>(
        &self,
        connection_channel: &C,
        handle: u16,
        data: D,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatInto,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::write_command(handle, data)).await
    }

    /// Prepare Write Request
    ///
    /// An iterator of `PreparedWriteRequest` can be created from an
    /// [`PreparedWriteRequests`](crate::pdu::PreparedWriteRequests) with the `iter` method.
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn prepare_write_request<C, D>(
        &self,
        connection_channel: &C,
        pwr: pdu::Pdu<pdu::PreparedWriteRequest<'_>>,
    ) -> Result<impl ResponseProcessor<Response = pdu::PreparedWriteResponse>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatTryFrom + TransferFormatInto,
    {
        self.send(connection_channel, &pwr).await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::PrepareWriteResponse, d)
        }))
    }

    pub async fn execute_write_request<C>(
        &self,
        connection_channel: &C,
        execute: pdu::ExecuteWriteFlag,
    ) -> Result<impl ResponseProcessor<Response = ()>, super::ConnectionError<C>>
    where
        C: ConnectionChannel,
    {
        self.send(connection_channel, &pdu::execute_write_request(execute))
            .await?;

        Ok(ResponseProcessorCheck(|d| {
            Self::process_raw_data(ServerPduName::ExecuteWriteResponse, d).map(|_: pdu::ExecuteWriteResponse| ())
        }))
    }

    /// Send a custom command to the server
    ///
    /// This can be used by higher layer protocols to send a command to the server that is not
    /// implemented at the ATT protocol level. However, if the provided pdu contains an opcode
    /// already used by the ATT protocol, then an error is returned.
    pub async fn custom_command<C, D>(
        &self,
        connection_channel: &C,
        pdu: pdu::Pdu<D>,
    ) -> Result<(), super::ConnectionError<C>>
    where
        C: ConnectionChannel,
        D: TransferFormatInto,
    {
        let op: u8 = pdu.get_opcode().as_raw();

        if ClientPduName::try_from(op).is_err() && ServerPduName::try_from(op).is_err() {
            if self.mtu >= pdu.len_of_into() {
                self.send(connection_channel, &pdu).await?;

                Ok(())
            } else {
                Err(super::Error::MtuExceeded.into())
            }
        } else {
            Err(super::Error::AttUsedOpcode(op).into())
        }
    }
}

/// A blob of data read from the server
///
/// This is a blob of data that was received from the server in response to a read blob request.
/// Once all blobs are received the client can try to assemble the data into its data type. Each
/// blob is a pseudo linked list, as they are received then can be combined together until the
/// combination function determines that all blobs were received.
///
/// Blobs can attempt to combine together with the
/// [`Add`](https://doc.rust-lang.org/std/ops/trait.Add.html), but the offsets and handles need to
/// be correct. A `ReadBlob` can be combined with another `ReadBlob` when they both have the same
/// attribute handle, the the offset of the later blob is in the correct position. The offset must
/// be equal to the offset plus the length of the stored data within the first `ReadBlob`.
pub struct ReadBlob {
    handle: u16,
    offset: usize,
    blob: Vec<u8>,
}

impl ReadBlob {
    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Get the offset a `ReadBlob` must have to combine with this `ReadBlob`
    fn combine_offset(&self) -> usize {
        self.offset + self.blob.len()
    }

    fn try_append_blob(mut self, other: Self) -> Result<Self, ReadBlobError> {
        if self.handle != other.handle {
            return Err(ReadBlobError::IncorrectHandle);
        }

        if self.combine_offset() != other.offset {
            Err(ReadBlobError::IncorrectOffset)
        } else {
            self.blob.extend(other.blob);

            Ok(ReadBlob {
                handle: self.handle,
                offset: self.offset,
                blob: self.blob,
            })
        }
    }
}

impl core::ops::Add for ReadBlob {
    type Output = Result<Self, ReadBlobError>;

    fn add(self, rhs: Self) -> Self::Output {
        self.try_append_blob(rhs)
    }
}

impl core::ops::Add<ReadBlob> for Result<ReadBlob, ReadBlobError> {
    type Output = Self;

    fn add(self, rhs: ReadBlob) -> Self::Output {
        self.and_then(|rb| rb.try_append_blob(rhs))
    }
}

#[derive(Debug)]
pub enum ReadBlobError {
    IncorrectHandle,
    IncorrectOffset,
}
