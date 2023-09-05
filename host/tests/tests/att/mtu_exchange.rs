//! Tests for the MTU exchange

use bo_tie_att::server::NoQueuedWrites;
use bo_tie_att::{ConnectFixedClient, Server};
use bo_tie_host_tests::{create_le_link, directed_rendezvous};
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};

async fn mtu_setup(client_mtu: u16, server_mtu: u16, expected_mtu: u16) {
    let (client, server) = create_le_link(LeULink::SUPPORTED_MTU.into());

    let (rendezvous_client, rendezvous_server) = directed_rendezvous();

    let client_handle = tokio::spawn(async move {
        let mut att_bearer = client.get_att_channel();

        let client = ConnectFixedClient::connect(&mut att_bearer, LeULink::SUPPORTED_MTU, client_mtu)
            .await
            .expect("exchange MTU failed");

        assert_eq!(client.get_mtu(), Some(expected_mtu));

        rendezvous_client.rendez().await;
    });

    let server_handle = tokio::spawn(async move {
        let mut att_bearer = server.get_att_channel();

        let mut server = Server::new_fixed(LeULink::SUPPORTED_MTU, server_mtu, None, NoQueuedWrites);

        let mut rendez = Box::pin(rendezvous_server.rendez());

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive() => {
                    let received = received.expect("receiver closed");

                    server.process_att_pdu(&mut att_bearer, &received).await.expect("failed to process L2CAP data");
                }
            }
        }
    });

    client_handle.await.unwrap();

    server_handle.await.unwrap();
}

#[tokio::test]
async fn mtu_agree_1() {
    mtu_setup(256, 512, 256).await;
}

#[tokio::test]
async fn mtu_agree_2() {
    mtu_setup(265, 128, 128).await;
}

#[tokio::test]
async fn mtu_agree_3() {
    mtu_setup(256, 256, 256).await;
}

#[tokio::test]
#[should_panic]
async fn mtu_client_too_tiny() {
    mtu_setup(10, 48, LeULink::SUPPORTED_MTU).await;
}

#[tokio::test]
#[should_panic]
async fn mtu_server_too_tiny() {
    mtu_setup(64, 8, LeULink::SUPPORTED_MTU).await;
}
