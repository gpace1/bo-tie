use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction, Server};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::{LeULogicalLink, LeUNext, PhysicalLink};

/// Tests for server notifications

#[tokio::test]
async fn simple_notification() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let attribute: Attribute<u64> = Attribute::new(
                Uuid::from_u16(0x1234),
                [AttributePermissions::Read(AttributeRestriction::None)].to_vec(),
                23,
            );

            let mut server_attributes = ServerAttributes::new();

            let handle = server_attributes.push(attribute);

            let mut server = Server::new_fixed(
                LeULink::SUPPORTED_MTU,
                LeULink::SUPPORTED_MTU,
                server_attributes,
                NoQueuedWrites,
            );

            let channel = &mut link.get_att_channel().unwrap();

            assert!(server.send_notification(channel, handle).await.unwrap());
        })
        .set_verify(|mut end| async move {
            let fragment = end.recv().await.unwrap().unwrap();

            let data: Vec<u8> = fragment.into_inner().collect();

            assert_eq!(&data[..2], &[11, 0]);

            assert_eq!(&data[2..4], &[4, 0]);

            assert_eq!(&data[4..], &[0x1b, 1, 0, 23, 0, 0, 0, 0, 0, 0, 0])
        })
        .run()
        .await;
}

#[tokio::test]
async fn long_notification() {
    let test_data = "
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
        labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco 
        laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in 
        voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat 
        cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    ";

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let attribute: Attribute<&str> = Attribute::new(
                Uuid::from_u16(0x1234),
                [AttributePermissions::Read(AttributeRestriction::None)].to_vec(),
                test_data,
            );

            let mut server_attributes = ServerAttributes::new();

            let handle = server_attributes.push_read_only(attribute);

            let mut server = Server::new_fixed(
                LeULink::SUPPORTED_MTU,
                LeULink::SUPPORTED_MTU,
                server_attributes,
                NoQueuedWrites,
            );

            let channel = &mut link.get_att_channel().unwrap();

            assert!(!server.send_notification(channel, handle).await.unwrap());

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, channel } => {
                        server.process_att_pdu(channel, pdu).await.expect("att server error");
                    }
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .set_verify(|mut end| async move {
            let fragment = end.recv().await.unwrap().unwrap();

            let notify_data: Vec<u8> = fragment.into_inner().collect();

            assert_eq!(&notify_data[..2], &[23, 0]);

            let handle = <u16>::from_le_bytes([notify_data[5], notify_data[6]]);

            assert_eq!(handle, 1);

            let mut offset = 20;

            let mut recv_data = notify_data[7..].to_vec();

            loop {
                let read_blob_req = bo_tie_att::pdu::read_blob_request(handle, offset);

                let request = bo_tie_att::TransferFormatInto::into(&read_blob_req);

                let mut header = vec![request.len() as u8, 0, 4, 0];

                header.extend(request);

                let fragment = L2capFragment::new(true, header);

                end.send(fragment).await.unwrap();

                let blob_response = end.recv().await.unwrap().unwrap();

                let blob_data: Vec<u8> = blob_response.into_inner().collect();

                if test_data.len() - 22 >= offset as usize {
                    assert_eq!(&blob_data[..2], &[23, 0]);
                }

                assert_eq!(&blob_data[2..4], &[4, 0]);

                assert_eq!(0xd, blob_data[4]);

                let blob_len = blob_data[5..].len();

                offset += blob_len as u16;

                recv_data.extend(blob_data[5..].iter().copied());

                // maximum blob returned is 22 bytes
                if blob_len != 22 {
                    break;
                }
            }

            assert_eq!(test_data.len(), offset.into());

            let str_data = ::std::str::from_utf8(&recv_data).unwrap();

            assert_eq!(str_data, test_data);
        })
        .run()
        .await;
}

#[tokio::test]
async fn long_notification_temp_readable() {
    let test_data = "
        Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut
        labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco 
        laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in 
        voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat 
        cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
    ";

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let attribute: Attribute<&str> = Attribute::new(Uuid::from_u16(0x1234), [].to_vec(), "");

            let mut server_attributes = ServerAttributes::new();

            let handle = server_attributes.push_read_only(attribute);

            let mut server = Server::new_fixed(
                LeULink::SUPPORTED_MTU,
                LeULink::SUPPORTED_MTU,
                server_attributes,
                NoQueuedWrites,
            );

            let channel = &mut link.get_att_channel().unwrap();

            assert!(!server
                .send_notification_with(channel, handle, test_data, [AttributeRestriction::None])
                .await
                .unwrap());

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, channel } => {
                        server.process_att_pdu(channel, pdu).await.expect("att server error");
                    }
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .set_verify(|mut end| async move {
            let fragment = end.recv().await.unwrap().unwrap();

            let notify_data: Vec<u8> = fragment.into_inner().collect();

            assert_eq!(&notify_data[..2], &[23, 0]);

            let handle = <u16>::from_le_bytes([notify_data[5], notify_data[6]]);

            assert_eq!(handle, 1);

            let mut offset = 20;

            let mut recv_data = notify_data[7..].to_vec();

            loop {
                let read_blob_req = bo_tie_att::pdu::read_blob_request(handle, offset);

                let request = bo_tie_att::TransferFormatInto::into(&read_blob_req);

                let mut header = vec![request.len() as u8, 0, 4, 0];

                header.extend(request);

                let fragment = L2capFragment::new(true, header);

                end.send(fragment).await.unwrap();

                let blob_response = end.recv().await.unwrap().unwrap();

                let blob_data: Vec<u8> = blob_response.into_inner().collect();

                if test_data.len() - 22 >= offset as usize {
                    assert_eq!(&blob_data[..2], &[23, 0], "{:?}", blob_data);
                }

                assert_eq!(&blob_data[2..4], &[4, 0]);

                assert_eq!(0xd, blob_data[4]);

                let blob_len = blob_data[5..].len();

                offset += blob_len as u16;

                recv_data.extend(blob_data[5..].iter().copied());

                // maximum blob returned is 22 bytes
                if blob_len != 22 {
                    break;
                }
            }

            assert_eq!(test_data.len(), offset.into());

            let str_data = ::std::str::from_utf8(&recv_data).unwrap();

            assert_eq!(str_data, test_data);
        })
        .run()
        .await;
}
