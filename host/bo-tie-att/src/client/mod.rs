//! Attribute Client Implementation

pub mod response_processor;

use crate::client::response_processor::{
    ExchangeMtuResponseProcessor, ExecuteWriteResponseProcessor, FindByTypeValueResponseProcessor,
    FindInformationResponseProcessor, PrepareWriteResponseProcessor, ReadBlobResponseProcessor,
    ReadByGroupTypeResponseProcessor, ReadByTypeResponseProcessor, ReadMultipleResponseProcessor,
    ReadResponseProcessor, WriteResponseProcessor,
};
use crate::{pdu, server::ServerPduName, TransferFormatError, TransferFormatInto, TransferFormatTryFrom};
use alloc::{format, vec::Vec};
use bo_tie_l2cap as l2cap;
use bo_tie_l2cap::cid::ChannelIdentifier;
use bo_tie_l2cap::{BasicFrameChannel, LogicalLink};
pub use response_processor::ResponseProcessor;

/// Attribute PDUs sent by the client
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
    ReadMultipleVariable,
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
            0x20 => Ok(ClientPduName::ReadMultipleVariable),
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
            ClientPduName::ReadMultipleVariable => 0x20,
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
            ClientPduName::ReadMultipleVariable => write!(f, "Read Multiple Variable Request"),
            ClientPduName::WriteRequest => write!(f, "Write Request"),
            ClientPduName::WriteCommand => write!(f, "Write Command"),
            ClientPduName::PrepareWriteRequest => write!(f, "Prepare Write Request"),
            ClientPduName::ExecuteWriteRequest => write!(f, "Execute Write Request"),
            ClientPduName::HandleValueConfirmation => write!(f, "Handle Value Confirmation"),
            ClientPduName::SignedWriteCommand => write!(f, "Signed Write Command"),
        }
    }
}

/// Connect this device to an Attribute Server
///
/// This is used for connecting a client on an ATT bearer using a fixed L2CAP channel ID. ATT
/// bearers on fixed channels need to perform an MTU exchange unless there is a default ATT MTU
/// specified at by a higher layer protocol.
///
// /// (todo) A ATT bearer (or enhanced ATT bearer) using a L2CAP channel with a dynamically allocated channel
// /// ID does use `ConnectFixedClient` to create a [`Client`]. The MTU of this ATT bearer is defined
// /// by the Bluetooth Specification to be the same as the MTU of the channel (dynamically allocated
// /// channel IDs are for either credit based or enhanced credit based channels). To create a `Client`
// /// for this kind of ATT bearer use the implementation of `From<`[`CreditBasedChannel`]`>` for
// /// `Client`.
// ///
/// ## MTU exchange
/// The *MTU exchange* is the process of determining the MTU of an ATT bearer with a fixed channel
/// ID using the ATT protocol. This process is not needed for an ATT bearer that uses a dynamically
/// allocated channel ID as the MTU is determined by the L2CAP channel creation process.
///
/// When creating a fixed client, there can either be a default MTU, a requested MTU, or both (
/// having neither will produce an error). If just a default MTU is set, then there will be no *MTU
/// exchange* initiated by this server. If just a requested MTU is set, then the *MTU exchange*
/// process will occur, but an error is produced if this process fails. If there is a default MTU
/// and a requested MTU then the *MTU exchange* occurs with the default MTU being used if the
/// exchange fails.
///
// /// [`CreditBasedChannel`]: bo_tie_l2cap::channel::CreditBasedChannel
pub struct ConnectFixedClient {
    default_mtu: usize,
    request_mtu: usize,
    skipped_mtu_request: bool,
    channel_id: ChannelIdentifier,
}

impl ConnectFixedClient {
    /// Initiate a connection to an ATT server
    ///
    /// # MTU
    /// The `default_mtu` is the initial MTU set for this instance of the ATT protocol. This value
    /// is defined by a higher layer protocol or profile, and it is the assumed value of the MTU
    /// when the client and server initially connect.
    ///
    /// The `requested_mtu` is the value that will be sent as part of an *exchange MTU request* that
    /// is sent after the client and server connect. It may become the `requested_mtu` if it is an
    /// accepted size by the server. If it isn't then the whatever is the smallest of the MTU values
    /// during the MTU exchange will be set as the new MTU.
    ///
    /// # Panic
    /// Input `default_mtu` cannot be greater than `request_mtu`.
    pub async fn initiate<T, I, R>(
        att_bearer: &mut BasicFrameChannel<T>,
        default_mtu: I,
        request_mtu: R,
    ) -> Result<ConnectFixedClient, super::ConnectionError<T>>
    where
        T: LogicalLink,
        I: Into<Option<u16>>,
        R: Into<Option<u16>>,
    {
        let (default_mtu, request_mtu) = match (default_mtu.into(), request_mtu.into()) {
            (None, None) => return Err(super::ConnectionError::InvalidMtuInputs),
            (Some(v), None) => {
                return Ok(ConnectFixedClient {
                    default_mtu: v.into(),
                    request_mtu: 0,
                    skipped_mtu_request: true,
                    channel_id: att_bearer.get_cid(),
                })
            }
            (None, Some(v)) => (0, v),
            (Some(d), Some(r)) => {
                assert!(d <= r, "input default_mtu cannot be greater than request_mtu");

                (d, r)
            }
        };

        let request = pdu::exchange_mtu_request(request_mtu);

        let acl_data = TransferFormatInto::into(&request);

        att_bearer
            .send(acl_data)
            .await
            .map_err(|e| super::ConnectionError::SendError(e))?;

        Ok(ConnectFixedClient {
            default_mtu: default_mtu.into(),
            request_mtu: request_mtu.into(),
            skipped_mtu_request: false,
            channel_id: att_bearer.get_cid(),
        })
    }

    /// Finish connecting a client to an Attribute server
    ///
    /// This takes the response from the MTU from the server and creates a `Client`. An error will
    /// occur if the response doesn't contain the correct channel identifier or an ATT PDU was received. The server is expected to respond with either a mtu response PDU or an
    /// error PDU with request not supported.
    pub fn create_client(self, response: &l2cap::pdu::BasicFrame<Vec<u8>>) -> Result<Client, super::Error> {
        if self.skipped_mtu_request {
            Ok(Client::new(self.default_mtu))
        } else if response.get_channel_id() != self.channel_id {
            Err(super::Error::IncorrectChannelId(response.get_channel_id()).into())
        } else if ServerPduName::ExchangeMTUResponse.is(response.get_payload()) {
            self.process_mtu_response(response.get_payload())
        } else if ServerPduName::ErrorResponse.is(response.get_payload()) {
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
                let mtu: usize = self.request_mtu.min(received_mtu.get_parameters().0.into());

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

    /// Get the maximum transfer unit (MTU) for this ATT connection
    ///
    /// This is the MTU *set for* the ATT protocol. The return is either the default MTU (as
    /// specified by a higher protocol layer) or the MTU set as part of the MTU exchange.
    ///
    /// ## ATT bearers using a dynamic L2CAP channel ID
    /// This method will return `None` for ATT bearers that use a dynamic channel ID. For those
    /// channels the ATT protocol uses the L2CAP MTU that was determined as part of establishing the
    /// L2CAP channel. The MTU for these connections can be acquired from the instance of the L2CAP
    /// channel.
    pub fn get_mtu(&self) -> Option<u16> {
        Some(self.mtu as u16)
    }

    async fn send<T, P>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        pdu: &pdu::Pdu<P>,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
        P: TransferFormatInto,
    {
        let payload = TransferFormatInto::into(pdu);

        if payload.len() > self.mtu {
            Err(super::Error::MtuExceeded.into())
        } else {
            let data = payload;

            connection_channel
                .send(data)
                .await
                .map_err(|e| super::ConnectionError::SendError(e))
        }
    }

    /// Send the mtu request
    ///
    /// The maximum transfer size is *normally* part of connecting the client to the server. Per the
    /// specification the exchange MTU request shall only be sent once per connection by the
    /// client. To comply with the specification, *this method shall only be called for an ATT
    /// bearer with a fixed L2CAP channel ID **and** only the default MTU was used for the
    /// `ConnectFixedClient` that created this `Client`.
    ///
    /// The new MTU is output by the returned `ResponseProcessor`, but it can also .
    pub async fn exchange_mtu_request<'a, T>(
        &'a mut self,
        connection_channel: &mut BasicFrameChannel<T>,
        mtu: u16,
    ) -> Result<ExchangeMtuResponseProcessor<'a>, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        if self.mtu > mtu.into() {
            Err(super::Error::TooSmallMtu.into())
        } else {
            self.send(connection_channel, &pdu::exchange_mtu_request(mtu)).await?;

            Ok(ExchangeMtuResponseProcessor::new(self, mtu))
        }
    }

    /// Find information request
    ///
    /// # Panic
    /// A range cannot be the reserved handle 0x0000 and the ending handle must be larger than or
    /// equal to the starting handle
    pub async fn find_information_request<T, R>(
        &self,
        channel: &mut BasicFrameChannel<T>,
        handle_range: R,
    ) -> Result<FindInformationResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
        R: Into<pdu::HandleRange> + core::ops::RangeBounds<u16>,
    {
        if !pdu::is_valid_handle_range(&handle_range) {
            panic!("Invalid handle range")
        }

        self.send(channel, &pdu::find_information_request(handle_range)).await?;

        Ok(FindInformationResponseProcessor)
    }

    /// Find by type and value request
    ///
    /// The attribute type, labeled as the input `uuid`, is a 16-bit assigned number type. If the
    /// type cannot be converted into a 16 bit UUID, then this function will return an error
    /// containing the incorrect type.
    ///
    /// # Panic
    /// A range cannot be the reserved handle 0x0000 and the start handle must be larger than the
    /// ending handle
    pub async fn find_by_type_value_request<T, R, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle_range: R,
        uuid: crate::Uuid,
        value: D,
    ) -> Result<FindByTypeValueResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
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

                Ok(FindByTypeValueResponseProcessor)
            }
            Err(_) => Err(super::Error::Other("Cannot convert UUID to a 16 bit short version").into()),
        }
    }

    /// Read by type request
    ///
    /// # Panic
    /// A range cannot contain be the reserved handle 0x0000 and the start handle must be larger
    /// then the ending handle
    pub async fn read_by_type_request<T, R, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle_range: R,
        attr_type: crate::Uuid,
    ) -> Result<ReadByTypeResponseProcessor<D>, super::ConnectionError<T>>
    where
        T: LogicalLink,
        R: Into<pdu::HandleRange>,
        D: TransferFormatTryFrom + TransferFormatInto,
    {
        let handle_range = handle_range.into();

        if !pdu::is_valid_handle_range(&handle_range.to_range_bounds()) {
            panic!("Invalid handle range")
        }

        self.send(connection_channel, &pdu::read_by_type_request(handle_range, attr_type))
            .await?;

        Ok(ReadByTypeResponseProcessor::new())
    }

    /// Send a read request
    ///
    /// # Panic
    /// The input `handle` cannot be the reserved handle 0x0000
    pub async fn read_request<T, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle: u16,
    ) -> Result<ReadResponseProcessor<D>, super::ConnectionError<T>>
    where
        T: LogicalLink,
        D: TransferFormatTryFrom,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::read_request(handle)).await?;

        Ok(ReadResponseProcessor::new())
    }

    /// Read blob request
    ///
    /// This is used for reading a blob of data from the server. The most common usage of this is
    /// to do a basic fragmentation of an Attributes value so that it can be sent over multiple ATT
    /// PDUs.
    ///
    /// ```
    /// # use std::error::Error;
    /// # use bo_tie_att::Client;
    /// # use bo_tie_att::client::ResponseProcessor;
    /// # use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink, LeUNext};
    /// # async fn example<P, B, S>(mut le_link: LeULogicalLink<P,B,S>, client: Client) -> Result<(), Box<dyn Error>> {
    /// # let handle = 1;
    /// let mut offset = 0;
    /// let mut full_blob = None;
    ///
    /// loop {
    ///     let channel = &mut le_link.get_att_channel().unwrap();
    ///
    ///     let response_processor = client.read_blob_request(channel, handle, offset)
    ///         .await
    ///         .expect("failed to send request");
    ///
    ///     let LeUNext::AttributeChannel { pdu, .. } = le_link.next().await? else {
    ///         return Err("unexpected LE data".into())
    ///     };
    ///
    ///     match response_processor.process_response(&pdu)?
    ///     {
    ///         // You can add a `Option<ReadBlob>` to a `ReadBlob`,
    ///         // but it must be on the right side of the `+` and
    ///         // the operation outputs a `Result<ReadBlob, _>`.
    ///         Some(blob) => {
    ///             full_blob = (blob + full_blob).expect("bad blob").into();
    ///             
    ///             offset = blob.get_end_offset() as u16;
    ///         }
    ///
    ///         // If the transfer size of the attribute data is
    ///         // unknown, then `read_blob_request` needs to be
    ///         // called until `None` is returned.
    ///         None => break,
    ///     }
    /// }
    ///
    /// // In this example this value is a String, but it can be
    /// // whatever type that is associated with the Attribute value
    /// let value: String = full_blob.unwrap().try_into_value()?;
    ///
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// ## Large Attribute Values
    /// As per the specification for *long Attribute values*, the maximum size of a blob can be 512
    /// bytes. However, this is only true for the currently read value, there is no requirement for
    /// the value to be static for the lifetime of the Attribute (hey... this is a rust library,
    /// rust like explanations *should* be used :). A higher layer protocol could implement the
    /// Attribute value to change on every read operation, or after the current value is fully read.
    /// This could permit multiple read operations to create a service data much larger than 512
    /// bytes.
    ///
    /// # Panic
    /// The `handle` cannot be the reserved handle 0
    pub async fn read_blob_request<T>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle: u16,
        offset: u16,
    ) -> Result<ReadBlobResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::read_blob_request(handle, offset))
            .await?;

        Ok(ReadBlobResponseProcessor::new(handle, offset))
    }

    /// Read multiple handles
    ///
    /// # Errors
    /// An error is returned if handles is an empty iterator.
    ///
    /// # Panic
    /// A handle within `handles` cannot be the reserved handle 0x0000.
    pub async fn read_multiple_request<T, I>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handles: I,
    ) -> Result<ReadMultipleResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
        I: IntoIterator<Item = u16> + Clone,
    {
        let mut att_count = 0;

        let handles = handles
            .into_iter()
            .inspect(|h| {
                att_count += 1;

                if !pdu::is_valid_handle(*h) {
                    panic!("Handle 0 is reserved for future use by the spec.")
                }
            })
            .collect();

        self.send(connection_channel, &pdu::read_multiple_request(handles)?)
            .await?;

        Ok(ReadMultipleResponseProcessor::new(att_count))
    }

    /// Read by group type
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn read_by_group_type_request<T, R, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle_range: R,
        group_type: crate::Uuid,
    ) -> Result<ReadByGroupTypeResponseProcessor<D>, super::ConnectionError<T>>
    where
        T: LogicalLink,
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

        Ok(ReadByGroupTypeResponseProcessor::new())
    }

    /// Request to write data to a handle on the server
    ///
    /// The clint will send a response to the write request if the *write* was made on the server,
    /// otherwise the client will send an error PDU if the *write* couldn't be made.
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn write_request<T, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle: u16,
        data: D,
    ) -> Result<WriteResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
        D: TransferFormatTryFrom + TransferFormatInto,
    {
        if !pdu::is_valid_handle(handle) {
            panic!("Handle 0 is reserved for future use by the spec.")
        }

        self.send(connection_channel, &pdu::write_request(handle, data)).await?;

        Ok(WriteResponseProcessor)
    }

    /// Command the server to write data to a handle
    ///
    /// No response or error is sent by the server for this command. This client will not know if
    /// write was successful on the server.
    ///
    /// # Panic
    /// The handle cannot be the reserved handle 0x0000
    pub async fn write_command<T, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        handle: u16,
        data: D,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
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
    pub async fn prepare_write_request<T>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        pwr: pdu::Pdu<pdu::PreparedWriteRequest<'_>>,
    ) -> Result<PrepareWriteResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        self.send(connection_channel, &pwr).await?;

        Ok(PrepareWriteResponseProcessor)
    }

    pub async fn execute_write_request<T>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        execute: pdu::ExecuteWriteFlag,
    ) -> Result<ExecuteWriteResponseProcessor, super::ConnectionError<T>>
    where
        T: LogicalLink,
    {
        self.send(connection_channel, &pdu::execute_write_request(execute))
            .await?;

        Ok(ExecuteWriteResponseProcessor)
    }

    /// Send a custom command to the server
    ///
    /// This can be used by higher layer protocols to send a command to the server that is not
    /// implemented at the ATT protocol level. However, if the provided pdu contains an opcode
    /// already used by the ATT protocol, then an error is returned.
    ///
    /// # Note
    /// This is not supported by the Specification, and should generally only be used by
    /// applications deliberately out of spec (tooling, debugging, ect.).
    pub async fn custom_command<T, D>(
        &self,
        connection_channel: &mut BasicFrameChannel<T>,
        pdu: pdu::Pdu<D>,
    ) -> Result<(), super::ConnectionError<T>>
    where
        T: LogicalLink,
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
/// See method [`Client::read_blob_request`] for usage.
pub struct ReadBlob {
    handle: u16,
    offset: usize,
    blob: Vec<u8>,
}

impl ReadBlob {
    /// Get the handle of the data of the blob
    pub fn get_handle(&self) -> u16 {
        self.handle
    }

    /// Get the offset
    ///
    /// This returns the offset to the first byte in the blob
    pub fn get_offset(&self) -> usize {
        self.offset
    }

    /// Get the offset of the end
    ///
    /// This returns the offset to the end of the blob. This can be used as the offset to the the
    /// next blob of data
    pub fn get_end_offset(&self) -> usize {
        self.blob.len()
    }

    fn try_append_blob(mut self, other: Self) -> Result<Self, ReadBlobError> {
        self.try_append_blob_ref(other)?;

        Ok(self)
    }

    #[inline]
    fn try_append_blob_ref(&mut self, mut other: Self) -> Result<(), ReadBlobError> {
        if self.handle != other.handle {
            return Err(ReadBlobError::IncorrectHandle);
        }

        if self.get_end_offset() == other.offset {
            if self
                .offset
                .checked_add(other.blob.len())
                .map(|val| val > 512)
                .unwrap_or_default()
            {
                return Err(ReadBlobError::MaximumSizeExceeded);
            }

            self.offset = other.get_offset();

            self.blob.extend(other.blob);

            Ok(())
        } else if other.get_end_offset() == self.offset {
            if other
                .offset
                .checked_add(self.blob.len())
                .map(|val| val > 512)
                .unwrap_or_default()
            {
                return Err(ReadBlobError::MaximumSizeExceeded);
            }

            other.blob.extend(core::mem::take(&mut self.blob));

            self.blob = other.blob;

            Ok(())
        } else {
            return Err(ReadBlobError::IncorrectOffset);
        }
    }

    /// Try to convert this blob into an Attributes value
    pub fn try_into_value<T>(&self) -> Result<T, TransferFormatError>
    where
        T: TransferFormatTryFrom,
    {
        TransferFormatTryFrom::try_from(&self.blob)
    }
}

impl core::ops::Add for ReadBlob {
    type Output = Result<Self, ReadBlobError>;

    fn add(self, rhs: Self) -> Self::Output {
        self.try_append_blob(rhs)
    }
}

impl core::ops::Add<Option<ReadBlob>> for ReadBlob {
    type Output = Result<Self, ReadBlobError>;

    fn add(self, rhs: Option<ReadBlob>) -> Self::Output {
        match rhs {
            Some(blob) => self + blob,
            None => Ok(self),
        }
    }
}

impl bo_tie_core::buffer::TryExtend<ReadBlob> for ReadBlob {
    type Error = ReadBlobError;

    fn try_extend<T>(&mut self, read_blob_iter: T) -> Result<(), Self::Error>
    where
        T: IntoIterator<Item = ReadBlob>,
    {
        for blob in read_blob_iter {
            self.try_append_blob_ref(blob)?;
        }

        Ok(())
    }
}

/// Error for [`read_blob_request`]
///
/// [`read_blob_request`]: Client::read_blob_request
#[derive(Debug)]
pub enum ReadBlobError {
    IncorrectHandle,
    IncorrectOffset,
    MaximumSizeExceeded,
}

impl core::fmt::Display for ReadBlobError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ReadBlobError::IncorrectHandle => f.write_str("blob handles do not match"),
            ReadBlobError::IncorrectOffset => {
                f.write_str("expected the end offset of the left blob to be equal to the other blob's starting offset")
            }
            ReadBlobError::MaximumSizeExceeded => {
                f.write_str("combined blob would exceed the maximum size of a long Attribute value")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReadBlobError {}

/// Read Multiple
///
/// This is response from the server to the `read_multiple_request` command. See the method
/// [`read_multiple_request`] for details.
///
/// [`read_multiple_request`]: Client::read_multiple_request
pub struct ReadMultiple {
    att_count: usize,
    offset: core::cell::Cell<usize>,
    val_count: core::cell::Cell<usize>,
    data: Vec<u8>,
}

impl ReadMultiple {
    /// Create a new `ReadMultiple`
    fn new(att_count: usize, response_data: Vec<u8>) -> Self {
        let offset = core::cell::Cell::new(0);
        let val_count = core::cell::Cell::new(0);
        let data = response_data;

        Self {
            att_count,
            offset,
            val_count,
            data,
        }
    }

    /// Get the read multiple data
    ///
    /// This is useful when trying to parse the data with a higher layer protocol.
    pub fn get_data(&self) -> &[u8] {
        &self.data
    }

    /// Iterate through the multiple values
    ///
    /// This returns an iterator through the values returned in the read multiple response. There is
    /// no indication on the transfer format size nor the number of values
    pub fn iter(&mut self) -> impl Iterator<Item = ReadMultipleValue<'_>> + '_ {
        struct Iter<'a>(&'a ReadMultiple);

        impl<'a> Iterator for Iter<'a> {
            type Item = ReadMultipleValue<'a>;

            fn next(&mut self) -> Option<Self::Item> {
                if self.0.offset.get() < self.0.data.len() {
                    Some(ReadMultipleValue::new(self.0))
                } else if self.0.offset.get() > self.0.data.len() {
                    None
                } else {
                    // offset == self.data.len()
                    if self.0.val_count.get() == self.0.att_count {
                        self.0.offset.set(self.0.offset.get() + 1);
                        None
                    } else {
                        Some(ReadMultipleValue::new_invalid_count())
                    }
                }
            }
        }

        self.offset.set(0);

        self.val_count.set(0);

        Iter(self)
    }

    /// Iterate through the same kind of values
    ///
    /// This is used to iterate over a `ReadMultiple` that only contains the same *sized* value.
    /// The returned iterator effectively just divides the read multiple response by the number of
    /// attributes to be read.
    ///
    /// This method cannot be called if the response has the possibility to overflow. An overflow
    /// occurs when the total transfer size of the values is larger than the `MTU - 1`. If the
    /// response were to overflow, then the correct transfer size for `V` would not be correctly
    /// calculated.
    ///
    /// # Error
    /// If a value fails to be converted from the response data, the iterator will output an error
    /// on the current iteration and then return `None` on the next.
    ///
    /// # Panic
    /// The returned response must be cleanly divisible by the
    pub fn iter_same<V>(&mut self) -> impl Iterator<Item = Result<V, ReadMultipleValueError>> + '_
    where
        V: TransferFormatTryFrom,
    {
        let size = self.data.len() / self.att_count;

        self.iter().map(move |v| v.try_into_value(size))
    }
}

/// A read multiple value
///
/// This is output by the iterator returned by the method `into_iter` of `ReadMultiple`. This is
/// used for converting the transfer format of a value in the read multiple request into the value.
/// See the method [`into_iter`] for more details.
pub struct ReadMultipleValue<'a> {
    inner: ReadMultipleValueInner<'a>,
}

impl<'a> ReadMultipleValue<'a> {
    /// Create a normal, new `ReadMultipleValue`
    fn new(read_multiple: &'a ReadMultiple) -> Self {
        let inner = ReadMultipleValueInner::Value(read_multiple);

        Self { inner }
    }

    /// Create an invalid count `ReadMultipleValue`
    fn new_invalid_count() -> Self {
        let inner = ReadMultipleValueInner::InvalidCount;

        Self { inner }
    }

    /// Try to convert this `ReadMultipleValue` into a real value
    ///
    /// This tries to convert this into a value. The size of the transfer format for the value must
    /// be provided as in input as the read multiple response has no size markers for any of the
    /// Attribute values within the `set of values`.
    pub fn try_into_value<V>(self, value_size: usize) -> Result<V, ReadMultipleValueError>
    where
        V: TransferFormatTryFrom,
    {
        match self.inner {
            ReadMultipleValueInner::InvalidCount => Err(ReadMultipleValueError::InvalidCount),
            ReadMultipleValueInner::Value(read_multiple) => {
                let old_offset = read_multiple.offset.get();

                read_multiple.offset.set(old_offset + value_size);

                if read_multiple.offset.get() > read_multiple.data.len() {
                    return Err(ReadMultipleValueError::InvalidValueSize);
                }

                read_multiple.val_count.set(read_multiple.val_count.get() + 1);

                let end = old_offset + value_size;

                TransferFormatTryFrom::try_from(&read_multiple.data[old_offset..end]).map_err(|e| {
                    read_multiple.offset.set(read_multiple.data.len() + 1);

                    ReadMultipleValueError::TransferFormatError(e)
                })
            }
        }
    }
}

/// Inner value of `ReadMultipleValue`
enum ReadMultipleValueInner<'a> {
    Value(&'a ReadMultiple),
    InvalidCount,
}

#[derive(Debug, PartialEq)]
pub enum ReadMultipleValueError {
    InvalidCount,
    InvalidValueSize,
    TransferFormatError(TransferFormatError),
}

impl core::fmt::Display for ReadMultipleValueError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            ReadMultipleValueError::InvalidCount => {
                f.write_str("the amount of values does not match the number of Attributes in the request")
            }
            ReadMultipleValueError::InvalidValueSize => {
                f.write_str("size of value exceeds end of read multiple response")
            }
            ReadMultipleValueError::TransferFormatError(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ReadMultipleValueError {}
