//! Tests for the write request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_WRITE_PERMISSIONS,
};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};
use std::sync::Arc;
use tokio::sync::Mutex;

const UUID: Uuid = Uuid::from_u16(0x1234);

macro_rules! connect_setup {
    (|$link:ident, $client:ident, $ref_cell_value:ident| $action:block ) => {{
        let $ref_cell_value: Arc<Mutex<usize>> = Default::default();

        let server_value = $ref_cell_value.clone();

        PhysicalLinkLoop::default()
            .test_scaffold()
            .set_tested(|end| async {
                let mut link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let mut server_attributes = ServerAttributes::new();

                server_attributes.push_accessor(Attribute::new(UUID, FULL_WRITE_PERMISSIONS, server_value));

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
async fn write_success() {
    connect_setup!(|link, client, value| {
        let test_val = 10usize;

        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .write_request(channel, 1, test_val)
            .await
            .expect("write request failed");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        response_processor.process_response(&response).expect("write failed");

        assert_eq!(*value.lock().await, test_val)
    })
}

#[tokio::test]
async fn invalid_value() {
    connect_setup!(|link, client, val| {
        let channel = &mut link.get_att_channel().unwrap();

        let test_val = "the wrong word".to_string();

        let response_processor = client
            .write_request(channel, 1, test_val)
            .await
            .expect("write request failed");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        match response_processor.process_response(&response) {
            Err(bo_tie_att::Error::Pdu(pdu)) => {
                assert_eq!(
                    pdu.get_parameters().error,
                    bo_tie_att::pdu::Error::InvalidAttributeValueLength,
                )
            }
            _ => panic!("expected invalid attribute value length "),
        }
    })
}

macro_rules! connect_permission_setup {
    ($client_permission:expr, |$link:ident, $client:ident| $test:expr) => {{
        PhysicalLinkLoop::default()
            .test_scaffold()
            .set_tested(|end| async {
                let mut link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let mut server_attributes = ServerAttributes::new();

                // These attributes are for permission checks
                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Write(AttributeRestriction::None)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Write(AttributeRestriction::Authentication)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Write(AttributeRestriction::Authorization)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Write(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits128,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Write(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits192,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Write(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits256,
                    ))],
                    0u8,
                ));

                let mut server = Server::new_fixed(
                    LeULink::SUPPORTED_MTU,
                    LeULink::SUPPORTED_MTU,
                    server_attributes,
                    NoQueuedWrites,
                );

                server.revoke_permissions_of_client([AttributePermissions::Write(AttributeRestriction::None)]);

                server.give_permissions_to_client($client_permission);

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

                let connector = ConnectFixedClient::initiate(channel, LeULink::SUPPORTED_MTU, LeULink::SUPPORTED_MTU)
                    .await
                    .unwrap();

                let $client = match $link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => connector.create_client(&pdu).unwrap(),
                    next => panic!("received unexpected {next:?}"),
                };

                $test
            })
            .run()
            .await;
    }};
}

macro_rules! permission_tests {
    (
        $permission_name:ident,
        $restriction:ident $( ($encryption:ident) )? ,
        $handle:literal,
        $exp_err:ident
        $(,)?
    ) => {
        ::paste::paste! {
            #[tokio::test]
            async fn [<insufficient_ $permission_name _permissions>] () {
                connect_permission_setup!([], |link, client| {
                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .write_request(channel, $handle, 10u8)
                        .await
                        .expect("failed to send request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(bo_tie_att::Error::Pdu(pdu)) => {
                            assert_eq!(
                                pdu.get_parameters().error,
                                bo_tie_att::pdu::Error::$exp_err
                            )
                        }
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(_) => panic!("unexpected response"),
                    }
                })
            }

            #[tokio::test]
            async fn [<sufficient_ $permission_name _permissions>] () {
                let permissions = [
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup!(permissions, |link, client| {
                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .write_request(channel, $handle, 10u8)
                        .await
                        .expect("failed to send request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(_) => (),
                    }
                })
            }
        }
    };
}

permission_tests!(write, None, 1, WriteNotPermitted);

permission_tests!(authentication, Authentication, 2, InsufficientAuthentication);

permission_tests!(authorization, Authorization, 3, InsufficientAuthorization);

permission_tests!(encryption_bits_128, Encryption(Bits128), 4, InsufficientEncryption);

permission_tests!(encryption_bits_192, Encryption(Bits192), 5, InsufficientEncryption);

permission_tests!(encryption_bits_256, Encryption(Bits256), 6, InsufficientEncryption);
