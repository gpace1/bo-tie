//! Tests for the [`BasicQueuedWriter`](crate::att::server::BasicQueuedWriter)

use crate::att::{
    pdu,
    server::{BasicQueuedWriter, ServerAttributes, Server},
    TransferFormatTryFrom,
};
use crate::l2cap::{ConnectionChannel, AclData};
use super::{AMutex, PayloadConnection, pdu_into_acl_data};

#[test]
fn prepare_write_with_exec_test() {

    use pdu::ExecuteWriteFlag::WriteAllPreparedWrites;

    use crate::att::{Attribute, FULL_WRITE_PERMISSIONS};
    use futures::executor::block_on;

    let cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queued_writer = BasicQueuedWriter::new(2048);

    let mut server = Server::new(&cc, sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val = AMutex::from(String::new());

    let att = Attribute::new( 1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push(att);

    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce a nisi in t\
            urpis interdum pharetra. Vestibulum lorem turpis, sodales sit amet facilisis sed, hendr\
            erit in massa. Sed a tempor dui. Proin tristique nisi a ligula ultrices, eget pharetra \
            ligula posuere. Duis nec elit a libero maximus euismod. Morbi bibendum dignissim elit q\
            ellentesque luctus iaculis neque sed mollis. Duis faucibus leo quis justo pulvinar vari\
            us.Aenean diam elit, varius ultricies sollicitudin sed, blandit sed quam. Integer aliqu\
            et dictum justo. Donec iaculis consequat sem, sed laoreet nulla. Cras sed nunc et \
            augue auctor laoreet vitae quis quam. Praesent condimentum fringilla finibus.";

    let prepared_write_requests = pdu::PreparedWriteRequests::new(
        att_handle,
        &test_data,
        cc.get_mtu()
    );

    prepared_write_requests.iter().for_each( |request| {

        let request_handle = request.get_parameters().get_handle();

        let request_offset = request.get_parameters().get_prepared_offset() as usize;

        let request_data = request.get_parameters().get_prepared_data();

        let acl_data = pdu_into_acl_data(request);

        block_on( server.process_acl_data(&acl_data) ).unwrap();

        let server_sent_response: pdu::Pdu<pdu::PreparedWriteResponse> =
            TransferFormatTryFrom::try_from(&cc.sent.take()).unwrap();

        assert_eq!(request_handle, server_sent_response.get_parameters().handle );
        assert_eq!(request_offset, server_sent_response.get_parameters().offset );
        assert_eq!(request_data, server_sent_response.get_parameters().data );
    });

    let exec_write_request = pdu::execute_write_request(WriteAllPreparedWrites);

    block_on( server.process_acl_data(&pdu_into_acl_data(exec_write_request)) ).unwrap();

    <pdu::Pdu<pdu::ExecuteWriteResponse> as TransferFormatTryFrom>::try_from(&cc.sent.take())
        .unwrap();

    assert_eq!( &*block_on( att_val.0.lock() ), test_data );
}

#[test]
fn prepare_write_with_cancel_test() {

    use pdu::ExecuteWriteFlag::CancelAllPreparedWrites;

    use crate::att::{Attribute, FULL_WRITE_PERMISSIONS};
    use futures::executor::block_on;

    let cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queued_writer = BasicQueuedWriter::new(2048);

    let mut server = Server::new(&cc, sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val = AMutex::from(String::new());

    let att = Attribute::new( 1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push(att);

    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce a nisi in t\
            urpis interdum pharetra. Vestibulum lorem turpis, sodales sit amet facilisis sed, hendr\
            erit in massa. Sed a tempor dui. Proin tristique nisi a ligula ultrices, eget pharetra \
            ligula posuere. Duis nec elit a libero maximus euismod. Morbi bibendum dignissim elit q\
            ellentesque luctus iaculis neque sed mollis. Duis faucibus leo quis justo pulvinar vari\
            us.Aenean diam elit, varius ultricies sollicitudin sed, blandit sed quam. Integer aliqu\
            et dictum justo. Donec iaculis consequat sem, sed laoreet nulla. Cras sed nunc et \
            augue auctor laoreet vitae quis quam. Praesent condimentum fringilla finibus.";

    let prepared_write_requests = pdu::PreparedWriteRequests::new(
        att_handle,
        &test_data,
        cc.get_mtu()
    );

    prepared_write_requests.iter().for_each( |request|
        block_on( server.process_acl_data(&pdu_into_acl_data(request)) ).unwrap()
    );

    let cancel_write_request = pdu::execute_write_request(CancelAllPreparedWrites);

    block_on( server.process_acl_data(&pdu_into_acl_data(cancel_write_request)) ).unwrap();

    <pdu::Pdu<pdu::ExecuteWriteResponse> as TransferFormatTryFrom>::try_from(&cc.sent.take())
        .unwrap();

    assert_ne!( &*block_on( att_val.0.lock() ), test_data );
}

#[test]
fn prepare_write_over_flow() {

    use crate::att::{Attribute, FULL_WRITE_PERMISSIONS};
    use futures::executor::block_on;

    let cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queue_size = 50;

    // The max size of the data bytes sent in a request payload
    let prepared_request_max_payload_size = cc.get_mtu() - 5;

    let queued_writer = BasicQueuedWriter::new(queue_size);

    let mut server = Server::new(&cc, sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val = AMutex::from(String::new());

    let att = Attribute::new( 1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push(att);

    let test_data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Fusce a nisi in t\
            urpis interdum pharetra. Vestibulum lorem turpis, sodales sit amet facilisis sed, hendr\
            erit in massa. Sed a tempor dui. Proin tristique nisi a ligula ultrices, eget pharetra \
            ligula posuere. Duis nec elit a libero maximus euismod. Morbi bibendum dignissim elit q\
            ellentesque luctus iaculis neque sed mollis. Duis faucibus leo quis justo pulvinar vari\
            us.Aenean diam elit, varius ultricies sollicitudin sed, blandit sed quam. Integer aliqu\
            et dictum justo. Donec iaculis consequat sem, sed laoreet nulla. Cras sed nunc et \
            augue auctor laoreet vitae quis quam. Praesent condimentum fringilla finibus.";

    let prepared_write_requests = pdu::PreparedWriteRequests::new(
        att_handle,
        &test_data,
        cc.get_mtu()
    );

    let rslt = prepared_write_requests.iter().enumerate().try_for_each( |(cnt,request)| {

        block_on(server.process_acl_data(&pdu_into_acl_data(request))).unwrap();

        if (cnt + 1) * prepared_request_max_payload_size > queue_size {

            let pdu: pdu::Pdu<pdu::ErrorResponse> =
                TransferFormatTryFrom::try_from(&cc.sent.take()).unwrap();

            assert_eq!(att_handle, pdu.get_parameters().requested_handle);
            assert_eq!(pdu::Error::PrepareQueueFull, pdu.get_parameters().error);

            None
        } else {
            Some(())
        }
    });

    assert!( rslt.is_none() )
}

#[test]
fn prepare_write_bad_offset() {
    use crate::att::{Attribute, FULL_WRITE_PERMISSIONS};
    use futures::executor::block_on;

    let cc = PayloadConnection::default();

    let sa = ServerAttributes::default();

    let queue_size = 50;

    let queued_writer = BasicQueuedWriter::new(queue_size);

    let mut server = Server::new(&cc, sa, queued_writer);

    server.give_permissions_to_client(FULL_WRITE_PERMISSIONS);

    let att_val = AMutex::from(String::new());

    let att = Attribute::new(1u16.into(), FULL_WRITE_PERMISSIONS.into(), att_val.clone());

    let att_handle = server.push(att);

    // A request with a bad offset (last 2 bytes should indicate an offset of 0)
    let raw_request = [0x16, att_handle as u8, 0, 33, 33].to_vec();

    let acl_data = AclData::new(raw_request, crate::att::L2CAP_CHANNEL_ID);

    block_on(server.process_acl_data(&acl_data)).unwrap();

    let exec_req = pdu::execute_write_request(pdu::ExecuteWriteFlag::WriteAllPreparedWrites);

    <pdu::Pdu<pdu::PreparedWriteResponse> as TransferFormatTryFrom>::try_from(&cc.sent.take())
        .unwrap();

    block_on(server.process_acl_data(&pdu_into_acl_data(exec_req))).unwrap();

    let rsp: pdu::Pdu<pdu::ErrorResponse> = TransferFormatTryFrom::try_from(&cc.sent.take())
        .unwrap();

    assert_eq!(pdu::Error::InvalidOffset, rsp.get_parameters().error);
}