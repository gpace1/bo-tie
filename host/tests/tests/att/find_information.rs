//! Tests for the find information request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::pdu::{FormattedHandlesWithType, HandleWithType};
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{Attribute, Client, ConnectFixedClient, Server, FULL_READ_PERMISSIONS};
use bo_tie_host_tests::{create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;

const UUID_SHORT_1: Uuid = Uuid::from_u16(1);
const UUID_SHORT_2: Uuid = Uuid::from_u16(2);

const UUID_SHORT_3: Uuid = Uuid::from_u16(3);

const UUID_FULL_1: Uuid = Uuid::from_u128(1);

const UUID_FULL_2: Uuid = Uuid::from_u128(2);

const UUID_FULL_3: Uuid = Uuid::from_u128(3);

async fn att_setup<Fun>(test: Fun)
where
    Fun: for<'a> FnOnce(
            &'a mut BasicFrameChannel<LeULogicalLink<PhysicalLink>>,
            &'a mut Client,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send
        + 'static,
{
    let (client_link, server_link) = create_le_link(LeULink::SUPPORTED_MTU.into());

    let (rendezvous_client, rendezvous_server) = directed_rendezvous();

    let client_handle = tokio::spawn(async move {
        let mut att_bearer = client_link.get_att_channel();

        let mut client = ConnectFixedClient::connect(&mut att_bearer, LeULink::SUPPORTED_MTU, LeULink::SUPPORTED_MTU)
            .await
            .expect("exchange MTU failed");

        test(&mut att_bearer, &mut client).await;

        rendezvous_client.rendez().await;
    });

    let server_handle = tokio::spawn(async move {
        let mut att_bearer = server_link.get_att_channel();

        let mut server_attributes = ServerAttributes::new();

        server_attributes.push(Attribute::new(UUID_SHORT_1, FULL_READ_PERMISSIONS, 0u8));

        server_attributes.push(Attribute::new(UUID_SHORT_2, FULL_READ_PERMISSIONS, 0u8));

        server_attributes.push(Attribute::new(UUID_FULL_1, FULL_READ_PERMISSIONS, 0u8));

        server_attributes.push(Attribute::new(UUID_FULL_2, FULL_READ_PERMISSIONS, 0u8));

        server_attributes.push(Attribute::new(UUID_SHORT_3, FULL_READ_PERMISSIONS, 0u8));

        server_attributes.push(Attribute::new(UUID_FULL_3, FULL_READ_PERMISSIONS, 0u8));

        let mut server = Server::new_fixed(
            LeULink::SUPPORTED_MTU,
            LeULink::SUPPORTED_MTU,
            server_attributes,
            NoQueuedWrites,
        );

        let mut rendez = Box::pin(rendezvous_server.rendez());

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive() => {
                    let received = received.expect("receiver closed");

                    server.process_att_pdu(&mut att_bearer, &received).await.expect("failed to process ATT PDU");
                }
            }
        }
    });

    client_handle.await.unwrap();

    server_handle.await.unwrap();
}

#[tokio::test]
async fn find_success() {
    att_setup(|channel, client| {
        macro_rules! test {
            (FULL, $range:expr, |$response:ident| $test:block) => {
                test!(BOTH, $range, |$response| $test, |_unused| {
                    panic!("unexpected short UUIDs")
                })
            };

            (SHORT, $range:expr, |$response:ident| $test:block) => {
                test!(
                    BOTH,
                    $range,
                    |_unused| { panic!("unexpected full UUIDs") },
                    |$response| $test
                )
            };

            (BOTH, $range:expr, |$response_full:ident| $full:block, |$response_short:ident| $short:block) => {{
                let response_processor = client
                    .find_information_request(channel, $range)
                    .await
                    .expect("failed to send request");

                let response = channel.receive().await.expect("failed to receive");

                let handles = response_processor
                    .process_response(&response)
                    .expect("invalid response");

                match handles {
                    FormattedHandlesWithType::HandlesWithFullUuids(response) => {
                        (|$response_full: Vec<HandleWithType>| $full)(response)
                    }
                    FormattedHandlesWithType::HandlesWithShortUuids(response) => {
                        (|$response_short: Vec<HandleWithType>| $short)(response)
                    }
                }
            }};
        }

        Box::pin(async {
            test!(SHORT, 1..0xFFFF, |handles| {
                assert_eq!(handles.len(), 2);

                assert_eq!(handles[0], HandleWithType::new(1, UUID_SHORT_1));

                assert_eq!(handles[1], HandleWithType::new(2, UUID_SHORT_2));
            });

            test!(FULL, 3..0xFFFF, |handles| {
                // the MTU dictates that only one u128 UUID can be transferred
                assert_eq!(handles.len(), 1);

                assert_eq!(handles[0], HandleWithType::new(3, UUID_FULL_1));
            });

            test!(FULL, 4..0xFFFF, |handles| {
                assert_eq!(handles.len(), 1);

                assert_eq!(handles[0], HandleWithType::new(4, UUID_FULL_2));
            });

            test!(SHORT, 5..0xFFFF, |handles| {
                assert_eq!(handles.len(), 1);

                assert_eq!(handles[0], HandleWithType::new(5, UUID_SHORT_3));
            });

            test!(FULL, 6..0xFFFF, |handles| {
                assert_eq!(handles.len(), 1);

                assert_eq!(handles[0], HandleWithType::new(6, UUID_FULL_3));
            })
        })
    })
    .await
}
