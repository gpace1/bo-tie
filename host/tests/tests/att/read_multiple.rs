//! Tests for read multiple request/response
//!
//! todo read multiple is not supported by the server at this time

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{Attribute, ConnectFixedClient, Server, FULL_READ_PERMISSIONS};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};

macro_rules! connect_setup {
    (|$link:ident, $client:ident| $action:block ) => {{
        PhysicalLinkLoop::default()
            .test_scaffold()
            .set_tested(|end| async {
                let mut link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let mut server_attributes = ServerAttributes::new();

                server_attributes.push(Attribute::new(Uuid::from(1u16), FULL_READ_PERMISSIONS, 1u8));

                server_attributes.push(Attribute::new(Uuid::from(2u16), FULL_READ_PERMISSIONS, 2u8));

                server_attributes.push(Attribute::new(Uuid::from(3u16), FULL_READ_PERMISSIONS, 3u8));

                server_attributes.push(Attribute::new(Uuid::from(4u16), FULL_READ_PERMISSIONS, 4u8));

                server_attributes.push(Attribute::new(Uuid::from(5u16), FULL_READ_PERMISSIONS, 5u8));

                server_attributes.push(Attribute::new(Uuid::from(6u16), FULL_READ_PERMISSIONS, 6u8));

                server_attributes.push(Attribute::new(Uuid::from(7u16), FULL_READ_PERMISSIONS, 7u8));

                server_attributes.push(Attribute::new(Uuid::from(8u16), FULL_READ_PERMISSIONS, 8u8));

                server_attributes.push(Attribute::new(Uuid::from(9u16), FULL_READ_PERMISSIONS, 9u8));

                let mut server = Server::new_fixed(
                    LeULink::SUPPORTED_MTU,
                    LeULink::SUPPORTED_MTU,
                    server_attributes,
                    NoQueuedWrites,
                );

                loop {
                    match &mut link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, channel } => {
                            server.process_att_pdu(channel, pdu).await.unwrap();
                        }
                        next => panic!("received unexpected {next:?}"),
                    }
                }
            })
            .set_verify(|end| async {
                let mut $link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let channel = &mut $link.get_att_channel().unwrap();

                let connect = ConnectFixedClient::initiate(channel, LeULink::SUPPORTED_MTU, LeULink::SUPPORTED_MTU)
                    .await
                    .unwrap();

                let $client = match $link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => connect.create_client(&pdu).unwrap(),
                    next => panic!("received unexpected {next:?}"),
                };

                $action
            })
            .run()
            .await;
    }};
}

#[tokio::test]
#[ignore] // read multiple isn't implemented in the `Server` yet
async fn read_success() {
    connect_setup!(|link, client| {
        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .read_multiple_request(channel, [1, 3, 5, 7, 9])
            .await
            .expect("failed to read");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        let mut read_multiple = response_processor
            .process_response(&response)
            .expect("failed to process response");

        let mut multiple_iter = read_multiple
            .iter_same::<u8>()
            .map(|maybe_byte| maybe_byte.expect("read multiple error"));

        assert_eq!(multiple_iter.next(), Some(1));
        assert_eq!(multiple_iter.next(), Some(3));
        assert_eq!(multiple_iter.next(), Some(5));
        assert_eq!(multiple_iter.next(), Some(7));
        assert_eq!(multiple_iter.next(), Some(9));
    })
}
