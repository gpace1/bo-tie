//! Tests for the write request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, Client, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_WRITE_PERMISSIONS,
};
use bo_tie_host_tests::{create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

const UUID: Uuid = Uuid::from_u16(0x1234);

async fn connect_setup<Fun>(test: Fun)
where
    Fun: for<'a> FnOnce(
            &'a mut BasicFrameChannel<LeULogicalLink<PhysicalLink>>,
            &'a mut Client,
            &'a Arc<Mutex<usize>>,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send
        + 'static,
{
    let (client_link, server_link) = create_le_link(LeULink::SUPPORTED_MTU.into());

    let (rendezvous_client, rendezvous_server) = directed_rendezvous();

    let att_value: Arc<Mutex<usize>> = Default::default();

    let servers_att_value = att_value.clone();

    let client_handle = tokio::spawn(async move {
        let mut att_bearer = client_link.get_att_channel();

        let mut client = ConnectFixedClient::connect(&mut att_bearer, LeULink::SUPPORTED_MTU, LeULink::SUPPORTED_MTU)
            .await
            .expect("exchange MTU failed");

        test(&mut att_bearer, &mut client, &att_value).await;

        rendezvous_client.rendez().await;
    });

    let server_handle = tokio::spawn(async move {
        let mut att_bearer = server_link.get_att_channel();

        let mut server_attributes = ServerAttributes::new();

        server_attributes.push_accessor(Attribute::new(UUID, FULL_WRITE_PERMISSIONS, servers_att_value));

        let mut server = Server::new_fixed(
            LeULink::SUPPORTED_MTU,
            LeULink::SUPPORTED_MTU,
            server_attributes,
            NoQueuedWrites,
        );

        let mut rendez = Box::pin(rendezvous_server.rendez());

        let buffer = &mut Vec::new();

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive(buffer) => {
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
async fn write_success() {
    connect_setup(|channel, client, accessor| {
        Box::pin(async {
            let test_val = 10usize;

            let response_processor = client
                .write_request(channel, 1, test_val)
                .await
                .expect("write request failed");

            let response = channel.receive(&mut Vec::new()).await.expect("response failed");

            response_processor.process_response(&response).expect("write failed");

            assert_eq!(*accessor.lock().await, test_val)
        })
    })
    .await
}

#[tokio::test]
async fn invalid_value() {
    connect_setup(|channel, client, _| {
        Box::pin(async {
            let test_val = "the wrong word".to_string();

            let response_processor = client
                .write_request(channel, 1, test_val)
                .await
                .expect("write request failed");

            let response = channel.receive(&mut Vec::new()).await.expect("response failed");

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
    })
    .await
}

async fn connect_permission_setup<Fun>(client_permission: &'static [AttributePermissions], test: Fun)
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

        server.give_permissions_to_client(client_permission);

        let mut rendez = Box::pin(rendezvous_server.rendez());

        let buffer = &mut Vec::new();

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive(buffer) => {
                    let received = received.expect("receiver closed");

                    server.process_att_pdu(&mut att_bearer, &received).await.expect("failed to process ATT PDU");
                }
            }
        }
    });

    client_handle.await.unwrap();

    server_handle.await.unwrap();
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
                connect_permission_setup(&[], |channel, client| {
                    Box::pin(async {
                        let response_processor = client
                            .write_request(channel, $handle, 10u8)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

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
                })
                .await
            }

            #[tokio::test]
            async fn [<sufficient_ $permission_name _permissions>] () {
                let permissions = &[
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup(permissions, |channel, client| {
                    Box::pin(async {
                        let response_processor = client
                            .write_request(channel, $handle, 10u8)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(_) => (),
                        }
                    })
                })
                .await
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
