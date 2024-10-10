//! Tests for the MTU exchange

use bo_tie_att::server::NoQueuedWrites;
use bo_tie_att::{ConnectFixedClient, Server};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};

async fn mtu_setup(client_mtu: u16, server_mtu: u16, expected_mtu: u16) {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let mut server = Server::new_fixed(LeULink::SUPPORTED_MTU, server_mtu, None, NoQueuedWrites);

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, channel } => {
                        server
                            .process_att_pdu(channel, pdu)
                            .await
                            .expect("failed to process L2CAP data");
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

            let channel = &mut link.get_att_channel().unwrap();

            let connect = ConnectFixedClient::initiate(channel, LeULink::SUPPORTED_MTU, client_mtu)
                .await
                .unwrap();

            let client = match &link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => connect.create_client(pdu).unwrap(),
                next => panic!("received unexpectd {next:?}"),
            };

            assert_eq!(client.get_mtu(), Some(expected_mtu));
        })
        .run()
        .await;
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
