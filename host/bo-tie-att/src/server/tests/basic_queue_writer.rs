//! Tests for the [`BasicQueuedWriter`](crate::server::BasicQueuedWriter)

use super::{pdu_into_acl_data, PayloadConnection};
use crate::{
    pdu,
    server::{BasicQueuedWriter, Server, ServerAttributes},
    TransferFormatTryFrom,
};
use bo_tie_l2cap::{BasicInfoFrame, ConnectionChannel};
use std::sync::Arc;
use tokio::sync::Mutex;

#[tokio::test]
#[cfg(feature = "tokio")]
async fn prepare_write_with_exec_test() {
    use pdu::ExecuteWriteFlag::WriteAllPreparedWrites;

    use crate::{Attribute, FULL_WRITE_PERMISSIONS};

    let mut cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queued_writer = BasicQueuedWriter::new(2048);

    let mut server = Server::new(sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val: Arc<Mutex<String>> = Arc::default();

    let att = Attribute::new(1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push_accessor(att);

    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce a nisi in t\
            urpis interdum pharetra. Vestibulum lorem turpis, sodales sit amet facilisis sed, hendr\
            erit in massa. Sed a tempor dui. Proin tristique nisi a ligula ultrices, eget pharetra \
            ligula posuere. Duis nec elit a libero maximus euismod. Morbi bibendum dignissim elit q\
            ellentesque luctus iaculis neque sed mollis. Duis faucibus leo quis justo pulvinar vari\
            us.Aenean diam elit, varius ultricies sollicitudin sed, blandit sed quam. Integer aliqu\
            et dictum justo. Donec iaculis consequat sem, sed laoreet nulla. Cras sed nunc et \
            augue auctor laoreet vitae quis quam. Praesent condimentum fringilla finibus.";

    let prepared_write_requests = pdu::PreparedWriteRequests::new(att_handle, &test_data, cc.get_mtu());

    for request in prepared_write_requests.iter() {
        let request_handle = request.get_parameters().get_handle();

        let request_offset = request.get_parameters().get_prepared_offset() as usize;

        let request_data = request.get_parameters().get_prepared_data();

        let acl_data = pdu_into_acl_data(request);

        server.process_acl_data(&mut cc, &acl_data).await.unwrap();

        let server_sent_response: pdu::Pdu<pdu::PreparedWriteResponse> =
            TransferFormatTryFrom::try_from(&cc.sent.take()).unwrap();

        assert_eq!(request_handle, server_sent_response.get_parameters().handle);
        assert_eq!(request_offset, server_sent_response.get_parameters().offset);
        assert_eq!(request_data, server_sent_response.get_parameters().data);
    }

    let exec_write_request = pdu::execute_write_request(WriteAllPreparedWrites);

    server
        .process_acl_data(&mut cc, &pdu_into_acl_data(exec_write_request))
        .await
        .unwrap();

    <pdu::Pdu<pdu::ExecuteWriteResponse> as TransferFormatTryFrom>::try_from(&cc.sent.take()).unwrap();

    assert_eq!(&*att_val.lock().await, test_data);
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn prepare_write_with_cancel_test() {
    use pdu::ExecuteWriteFlag::CancelAllPreparedWrites;

    use crate::{Attribute, FULL_WRITE_PERMISSIONS};

    let mut cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queued_writer = BasicQueuedWriter::new(2048);

    let mut server = Server::new(sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val: Arc<Mutex<String>> = Arc::default();

    let att = Attribute::new(1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push_accessor(att);

    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce a nisi in t\
            urpis interdum pharetra. Vestibulum lorem turpis, sodales sit amet facilisis sed, hendr\
            erit in massa. Sed a tempor dui. Proin tristique nisi a ligula ultrices, eget pharetra \
            ligula posuere. Duis nec elit a libero maximus euismod. Morbi bibendum dignissim elit q\
            ellentesque luctus iaculis neque sed mollis. Duis faucibus leo quis justo pulvinar vari\
            us.Aenean diam elit, varius ultricies sollicitudin sed, blandit sed quam. Integer aliqu\
            et dictum justo. Donec iaculis consequat sem, sed laoreet nulla. Cras sed nunc et \
            augue auctor laoreet vitae quis quam. Praesent condimentum fringilla finibus.";

    let prepared_write_requests = pdu::PreparedWriteRequests::new(att_handle, &test_data, cc.get_mtu());

    for request in prepared_write_requests.iter() {
        server
            .process_acl_data(&mut cc, &pdu_into_acl_data(request))
            .await
            .unwrap()
    }

    let cancel_write_request = pdu::execute_write_request(CancelAllPreparedWrites);

    server
        .process_acl_data(&mut cc, &pdu_into_acl_data(cancel_write_request))
        .await
        .unwrap();

    <pdu::Pdu<pdu::ExecuteWriteResponse> as TransferFormatTryFrom>::try_from(&cc.sent.take()).unwrap();

    assert_ne!(&*att_val.lock().await, test_data);
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn prepare_write_over_flow() {
    use crate::{Attribute, FULL_WRITE_PERMISSIONS};

    let mut cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queue_size = 50;

    // The max size of the data bytes sent in a request payload
    let prepared_request_max_payload_size = cc.get_mtu() - 5;

    let queued_writer = BasicQueuedWriter::new(queue_size);

    let mut server = Server::new(sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val: Arc<Mutex<String>> = Arc::default();

    let att = Attribute::new(1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push_accessor(att);

    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce a nisi in t\
            urpis interdum pharetra. Vestibulum lorem turpis, sodales sit amet facilisis sed, hendr\
            erit in massa. Sed a tempor dui. Proin tristique nisi a ligula ultrices, eget pharetra \
            ligula posuere. Duis nec elit a libero maximus euismod. Morbi bibendum dignissim elit q\
            ellentesque luctus iaculis neque sed mollis. Duis faucibus leo quis justo pulvinar vari\
            us.Aenean diam elit, varius ultricies sollicitudin sed, blandit sed quam. Integer aliqu\
            et dictum justo. Donec iaculis consequat sem, sed laoreet nulla. Cras sed nunc et \
            augue auctor laoreet vitae quis quam. Praesent condimentum fringilla finibus.";

    let prepared_write_requests = pdu::PreparedWriteRequests::new(att_handle, &test_data, cc.get_mtu());

    for (cnt, request) in prepared_write_requests.iter().enumerate() {
        server
            .process_acl_data(&mut cc, &pdu_into_acl_data(request))
            .await
            .unwrap();

        if (cnt + 1) * prepared_request_max_payload_size > queue_size {
            let pdu: pdu::Pdu<pdu::ErrorResponse> = TransferFormatTryFrom::try_from(&cc.sent.take()).unwrap();

            assert_eq!(att_handle, pdu.get_parameters().requested_handle);
            assert_eq!(pdu::Error::PrepareQueueFull, pdu.get_parameters().error);

            return;
        }
    }

    panic!("write request did not complete")
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn prepare_write_bad_offset() {
    use crate::{Attribute, FULL_WRITE_PERMISSIONS};

    let mut cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queue_size = 50;

    let queued_writer = BasicQueuedWriter::new(queue_size);

    let mut server = Server::new(sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val: Arc<Mutex<String>> = Arc::default();

    let att = Attribute::new(1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push_accessor(att);

    // A request with a bad offset (last 2 bytes should indicate an offset of 0)
    let raw_request = [0x16, att_handle as u8, 0, 33, 33].to_vec();

    let acl_data = BasicInfoFrame::new(raw_request, crate::L2CAP_CHANNEL_ID);

    server.process_acl_data(&mut cc, &acl_data).await.unwrap();

    let exec_req = pdu::execute_write_request(pdu::ExecuteWriteFlag::WriteAllPreparedWrites);

    <pdu::Pdu<pdu::PreparedWriteResponse> as TransferFormatTryFrom>::try_from(&cc.sent.take()).unwrap();

    server
        .process_acl_data(&mut cc, &pdu_into_acl_data(exec_req))
        .await
        .unwrap();

    let rsp: pdu::Pdu<pdu::ErrorResponse> = TransferFormatTryFrom::try_from(&cc.sent.take()).unwrap();

    assert_eq!(pdu::Error::InvalidOffset, rsp.get_parameters().error);
}
