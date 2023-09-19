//! Response Processing
//!
//! When a `Client` sends an Attribute request PDU, it needs to await for the response from the
//! other device and then process the response. These response processors are used to take the
//! transfer formatted data response received and try to convert it into a meaningful response.
//!
//! Per the specification, every request has a corresponding response PDU sent from the other
//! device's ATT server. A response from the other device is received as a [`BasicFrame`]. Every
//! response processor implements the trait [`ResponseProcessor`] to convert a received `BasicFrame`
//! into some meaningful value. This can either be an expected response value, an error sent as a
//! response, or just a validation that no error was sent.

use crate::client::{Client, ReadBlob, ReadMultiple};
use crate::server::ServerPduName;
use crate::{pdu, Error, TransferFormatError, TransferFormatTryFrom};
use bo_tie_l2cap::pdu::BasicFrame;

#[must_use = "ATT requests require processing of the server's response"]
pub trait ResponseProcessor {
    type Response;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error>;
}

/// Common processing for response data
fn process_raw_data<T>(expected_response: ServerPduName, bytes: &[u8]) -> Result<T, Error>
where
    T: TransferFormatTryFrom + pdu::ExpectedOpcode,
{
    if bytes.len() == 0 {
        Err(Error::Empty)
    } else if expected_response.is(bytes) {
        let pdu: pdu::Pdu<T> = TransferFormatTryFrom::try_from(&bytes)?;

        Ok(pdu.into_parameters())
    } else if ServerPduName::ErrorResponse.is(bytes) {
        let err_pdu: pdu::Pdu<pdu::ErrorResponse> = TransferFormatTryFrom::try_from(&bytes)?;

        Err(err_pdu.into())
    } else {
        match ServerPduName::try_from(bytes[0]) {
            Ok(val) => Err(Error::UnexpectedServerPdu(val)),
            Err(_) => Err(TransferFormatError::from(format!(
                "Received Unknown PDU '{:#x}', expected '{} ({:#x})'",
                bytes[0],
                expected_response,
                Into::<u8>::into(expected_response)
            ))
            .into()),
        }
    }
}

fn response_check<F, R>(b_frame: &BasicFrame<Vec<u8>>, f: F) -> Result<R, Error>
where
    F: FnOnce(&[u8]) -> Result<R, Error>,
{
    if b_frame.get_channel_id() == crate::L2CAP_FIXED_CHANNEL_ID {
        f(b_frame.get_payload())
    } else {
        Err(Error::IncorrectChannelId(b_frame.get_channel_id()))
    }
}

fn implicit<T>(b_frame: &BasicFrame<Vec<u8>>, expected_response: ServerPduName) -> Result<T, Error>
where
    T: TransferFormatTryFrom + pdu::ExpectedOpcode,
{
    response_check(b_frame, |pdu| process_raw_data(expected_response, pdu))
}

/// Response processor for `exchange_mtu_request`
pub struct ExchangeMtuResponseProcessor<'a> {
    client: &'a mut Client,
    request_mtu: u16,
}

impl<'a> ExchangeMtuResponseProcessor<'a> {
    pub(super) fn new(client: &'a mut Client, request_mtu: u16) -> Self {
        ExchangeMtuResponseProcessor { client, request_mtu }
    }
}

impl ResponseProcessor for ExchangeMtuResponseProcessor<'_> {
    type Response = ();

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        response_check(b_frame, |pdu| {
            let response: pdu::MtuResponse = process_raw_data(ServerPduName::ExchangeMTUResponse, pdu)?;

            self.client.mtu = core::cmp::min(self.request_mtu, response.0).into();

            Ok(())
        })
    }
}

/// Response processor for `find_information_request`
pub struct FindInformationResponseProcessor;

impl ResponseProcessor for FindInformationResponseProcessor {
    type Response = pdu::FormattedHandlesWithType;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::FindInformationResponse)
    }
}

/// Response process for `find_by_type_value_request`
pub struct FindByTypeValueResponseProcessor;

impl ResponseProcessor for FindByTypeValueResponseProcessor {
    type Response = Vec<pdu::TypeValueResponse>;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::FindByTypeValueResponse)
    }
}

/// Response processor for `read_by_type_request`
pub struct ReadByTypeResponseProcessor<D>(core::marker::PhantomData<D>);

impl<D> ReadByTypeResponseProcessor<D> {
    pub(super) fn new() -> Self {
        Self(core::marker::PhantomData)
    }
}

impl<D> ResponseProcessor for ReadByTypeResponseProcessor<D>
where
    D: TransferFormatTryFrom,
{
    type Response = Vec<pdu::ReadTypeResponse<D>>;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::ReadByTypeResponse).map(|rsp: pdu::ReadByTypeResponse<D>| rsp.0)
    }
}

/// Response processor for `read_request`
pub struct ReadResponseProcessor<D>(core::marker::PhantomData<D>);

impl<D> ReadResponseProcessor<D> {
    pub(super) fn new() -> ReadResponseProcessor<D> {
        ReadResponseProcessor(core::marker::PhantomData)
    }
}

impl<D> ResponseProcessor for ReadResponseProcessor<D>
where
    D: TransferFormatTryFrom,
{
    type Response = D;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::ReadResponse).map(|rsp: pdu::ReadResponse<D>| rsp.0)
    }
}

/// Response processor for `read_blob_request`
pub struct ReadBlobResponseProcessor {
    handle: u16,
    offset: u16,
}

impl ReadBlobResponseProcessor {
    pub(super) fn new(handle: u16, offset: u16) -> ReadBlobResponseProcessor {
        ReadBlobResponseProcessor { handle, offset }
    }
}

impl ResponseProcessor for ReadBlobResponseProcessor {
    type Response = Option<ReadBlob>;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        response_check(b_frame, |pdu| {
            let expected_response = ServerPduName::ReadBlobResponse;

            if pdu.len() == 0 {
                Err(Error::Empty)
            } else if expected_response.is(pdu) {
                let pdu: pdu::Pdu<pdu::ReadBlobResponse> = TransferFormatTryFrom::try_from(&pdu)?;

                let parameters = pdu.into_parameters();

                let blob = parameters.into_inner();

                Ok(Some(ReadBlob {
                    handle: self.handle,
                    offset: self.offset.into(),
                    blob,
                }))
            } else if ServerPduName::ErrorResponse.is(pdu) {
                let err_pdu: pdu::Pdu<pdu::ErrorResponse> = TransferFormatTryFrom::try_from(&pdu)?;

                if let pdu::Error::InvalidOffset = err_pdu.get_parameters().error {
                    Ok(None)
                } else {
                    Err(err_pdu.into())
                }
            } else {
                match ServerPduName::try_from(pdu[0]) {
                    Ok(val) => Err(Error::UnexpectedServerPdu(val)),
                    Err(_) => Err(TransferFormatError::from(format!(
                        "Received Unknown PDU '{:#x}', \
                            expected '{} ({:#x})'",
                        pdu[0],
                        expected_response,
                        Into::<u8>::into(expected_response)
                    ))
                    .into()),
                }
            }
        })
    }
}

/// Response processor for `read_multiple_request`
pub struct ReadMultipleResponseProcessor {
    count: usize,
}

impl ReadMultipleResponseProcessor {
    pub(super) fn new(count: usize) -> ReadMultipleResponseProcessor {
        ReadMultipleResponseProcessor { count }
    }
}

impl ResponseProcessor for ReadMultipleResponseProcessor {
    type Response = ReadMultiple;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        response_check(b_frame, |pdu| {
            let read_multiple_response: pdu::ReadMultipleResponse =
                process_raw_data(ServerPduName::ReadMultipleResponse, pdu)?;

            let read_multiple = ReadMultiple::new(self.count, read_multiple_response.0);

            Ok(read_multiple)
        })
    }
}

/// Response processor for `read_by_group_type_requst`
pub struct ReadByGroupTypeResponseProcessor<D>(core::marker::PhantomData<D>);

impl<D> ReadByGroupTypeResponseProcessor<D> {
    pub(super) fn new() -> Self {
        ReadByGroupTypeResponseProcessor(core::marker::PhantomData)
    }
}

impl<D> ResponseProcessor for ReadByGroupTypeResponseProcessor<D>
where
    D: TransferFormatTryFrom,
{
    type Response = pdu::ReadByGroupTypeResponse<D>;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::ReadByGroupTypeResponse)
    }
}

/// Response processor for `write_request`
pub struct WriteResponseProcessor;

impl ResponseProcessor for WriteResponseProcessor {
    type Response = ();

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::WriteResponse).map(|_: pdu::WriteResponse| ())
    }
}

/// Response processor for `prepare_write_request`
pub struct PrepareWriteResponseProcessor;

impl ResponseProcessor for PrepareWriteResponseProcessor {
    type Response = pdu::PreparedWriteResponse;

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::PrepareWriteResponse)
    }
}

/// Response processor for `execute_write_request`
pub struct ExecuteWriteResponseProcessor;

impl ResponseProcessor for ExecuteWriteResponseProcessor {
    type Response = ();

    fn process_response(self, b_frame: &BasicFrame<Vec<u8>>) -> Result<Self::Response, Error> {
        implicit(b_frame, ServerPduName::ExecuteWriteResponse).map(|_: pdu::ExecuteWriteResponse| ())
    }
}
