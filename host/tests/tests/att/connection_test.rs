//! Test `test_connection`
//!
//! This test is for a client and server successfully communicating with each other. This is a test
//! for a general operation of the Attribute protocol.

use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction, ConnectFixedClient, Server};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};

macro_rules! read_att_type {
    ($link:expr, $client:expr, $uuid:expr, $data_type:ty) => {{
        let channel = &mut $link.get_att_channel().unwrap();

        let response_processor = $client
            .read_by_type_request::<_, _, $data_type>(channel, 1..0xFFFF, $uuid)
            .await
            .expect(format!("failed to read type ({:x})", $uuid).as_str());

        let b_frame = match $link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        let read_type_response = bo_tie_att::client::ResponseProcessor::process_response(response_processor, &b_frame)
            .expect("failed to process response");

        let first = read_type_response.into_iter().next().expect("no items in response");

        (first.get_handle(), first.into_inner())
    }};
}

macro_rules! get_handle {
    ($link:expr, $client:expr, $uuid:expr) => {
        read_att_type!($link, $client, $uuid, Vec<u8>).0
    };
}

macro_rules! write_request {
    ($link:expr, $client:expr, $handle:expr, $data:expr) => {{
        let mut channel = $link.get_att_channel().unwrap();

        let response_processor = $client
            .write_request(&mut channel, $handle, $data)
            .await
            .expect("failed to write test val 1");

        let b_frame = match $link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        bo_tie_att::client::ResponseProcessor::process_response(response_processor, &b_frame)
            .expect("failed to process response");
    }};
}

const UUID_1: Uuid = Uuid::from_u16(1);
const UUID_2: Uuid = Uuid::from_u16(2);
const UUID_3: Uuid = Uuid::from_u16(3);

#[tokio::test]
async fn test_connection() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let attribute_0: Attribute<usize> = Attribute::new(
                UUID_1,
                [
                    AttributePermissions::Read(AttributeRestriction::None),
                    AttributePermissions::Write(AttributeRestriction::None),
                ]
                .to_vec(),
                0usize,
            );

            let attribute_1: Attribute<u64> = Attribute::new(
                UUID_2,
                [
                    AttributePermissions::Read(AttributeRestriction::None),
                    AttributePermissions::Write(AttributeRestriction::None),
                ]
                .to_vec(),
                0u64,
            );

            let attribute_2: Attribute<i8> = Attribute::new(
                UUID_3,
                [
                    AttributePermissions::Read(AttributeRestriction::None),
                    AttributePermissions::Write(AttributeRestriction::None),
                ]
                .to_vec(),
                0i8,
            );

            let mut server_attributes = ServerAttributes::new();

            assert_eq!(server_attributes.push(attribute_0), 1);
            assert_eq!(server_attributes.push(attribute_1), 2);
            assert_eq!(server_attributes.push(attribute_2), 3);

            let mut server = Server::new_fixed(
                LeULink::SUPPORTED_MTU,
                LeULink::SUPPORTED_MTU,
                server_attributes,
                NoQueuedWrites,
            );

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, channel } => {
                        server.process_att_pdu(channel, pdu).await.expect("att server error");
                    }
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let test_val_1: usize = 33;
            let test_val_2: u64 = 64;
            let test_val_3: i8 = -118;

            let mut att_bearer = link.get_att_channel().unwrap();

            let connect_client = ConnectFixedClient::initiate(&mut att_bearer, LeULink::SUPPORTED_MTU, 64)
                .await
                .unwrap();

            let mut client = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => connect_client.create_client(&pdu).unwrap(),
                next => panic!("received unexpected {next:?}"),
            };

            let handle_1: u16 = get_handle!(link, &mut client, UUID_1);

            assert_eq!(handle_1, 1);

            let handle_2 = get_handle!(link, &mut client, UUID_2);

            assert_eq!(handle_2, 2);

            let handle_3 = get_handle!(link, &mut client, UUID_3);

            assert_eq!(handle_3, 3);

            write_request!(link, &mut client, handle_1, test_val_1);

            write_request!(link, &mut client, handle_2, test_val_2);

            write_request!(link, &mut client, handle_3, test_val_3);

            let read_val_1: usize = read_att_type!(link, &mut client, UUID_1, usize).1;

            let read_val_2: u64 = read_att_type!(link, &mut client, UUID_2, u64).1;

            let read_val_3: i8 = read_att_type!(link, &mut client, UUID_3, i8).1;

            assert_eq!(test_val_1, read_val_1, "test and read val 1 do not match");

            assert_eq!(test_val_2, read_val_2, "test and read val 2 do not match");

            assert_eq!(test_val_3, read_val_3, "test and read val 3 do not match");
        })
        .run()
        .await
}
