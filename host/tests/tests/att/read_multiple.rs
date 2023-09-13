//! Tests for read multiple request/response
//!
//! todo read multiple is not supported by the server at this time

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{Attribute, Client, ConnectFixedClient, Server, FULL_READ_PERMISSIONS};
use bo_tie_host_tests::{create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;

async fn connect_setup<Fun>(test: Fun)
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
#[ignore]
async fn read_success() {
    connect_setup(|channel, client| {
        Box::pin(async {
            let response_processor = client
                .read_multiple_request(channel, [1, 3, 5, 7, 9])
                .await
                .expect("failed to read");

            let response = channel.receive().await.expect("failed to receive");

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
    })
    .await
}
