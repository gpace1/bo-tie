//! Tests for read blob request/response
//!
//! This tests the read blob request/response and any commands whose read can be continued with a
//! read blob request.

use bo_tie_att::client::{ClientPduName, ReadBlob, ResponseProcessor};
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, Client, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_READ_PERMISSIONS,
};
use bo_tie_host_tests::{create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;

const UUID: Uuid = Uuid::from_u16(1);

const TEST_VALUE: &'static str = "this is a value too long for to read in a single ATT pdu";

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

        server_attributes.push(Attribute::new(UUID, FULL_READ_PERMISSIONS, TEST_VALUE.to_string()));

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
async fn read_success() {
    connect_setup(|channel, client| {
        Box::pin(async {
            macro_rules! test {
                ($handle:expr, $value_ty:ty, |$blob:ident| $test:block) => {{
                    let mut blob: Option<ReadBlob> = None;

                    // loop should break before 10 times
                    for _ in 0..10 {
                        let offset = blob
                            .as_ref()
                            .map(|blob| blob.get_end_offset())
                            .unwrap_or_default() as u16;

                        let response_processor = client
                            .read_blob_request(channel, 1, offset)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

                        match response_processor
                            .process_response(&response)
                            .expect("invalid response")
                        {
                            Some(new_blob) => {
                                blob = (new_blob + blob).expect("bad blob").into();
                            }
                            None => break,
                        }
                    }

                    (|$blob: ReadBlob| $test)(blob.unwrap())
                }};
            }

            test!(1, String, |blob| {
                let value: String = blob.try_into_value().expect("invalid blob");

                assert_eq!(TEST_VALUE, value.as_str())
            })
        })
    })
    .await
}

async fn connect_permission_setup<Fun>(
    client_permission: &'static [AttributePermissions],
    revoke_permissions: Option<&'static [AttributePermissions]>,
    test: Fun,
) where
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
            [AttributePermissions::Read(AttributeRestriction::None)],
            TEST_VALUE.to_string(),
        ));

        server_attributes.push(Attribute::new(
            UUID,
            [AttributePermissions::Read(AttributeRestriction::Authentication)],
            TEST_VALUE.to_string(),
        ));

        server_attributes.push(Attribute::new(
            UUID,
            [AttributePermissions::Read(AttributeRestriction::Authorization)],
            TEST_VALUE.to_string(),
        ));

        server_attributes.push(Attribute::new(
            UUID,
            [AttributePermissions::Read(AttributeRestriction::Encryption(
                EncryptionKeySize::Bits128,
            ))],
            TEST_VALUE.to_string(),
        ));

        server_attributes.push(Attribute::new(
            UUID,
            [AttributePermissions::Read(AttributeRestriction::Encryption(
                EncryptionKeySize::Bits192,
            ))],
            TEST_VALUE.to_string(),
        ));

        server_attributes.push(Attribute::new(
            UUID,
            [AttributePermissions::Read(AttributeRestriction::Encryption(
                EncryptionKeySize::Bits256,
            ))],
            TEST_VALUE.to_string(),
        ));

        let mut server = Server::new_fixed(
            LeULink::SUPPORTED_MTU,
            LeULink::SUPPORTED_MTU,
            server_attributes,
            NoQueuedWrites,
        );

        server.revoke_permissions_of_client([AttributePermissions::Read(AttributeRestriction::None)]);

        server.give_permissions_to_client(client_permission);

        let mut rendez = Box::pin(rendezvous_server.rendez());

        let buffer = &mut Vec::new();

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive(buffer) => {
                    let received = received.expect("receiver closed");

                    server.process_att_pdu(&mut att_bearer, &received).await.expect("failed to process ATT PDU");

                    if let Some(revoke_permissions) = revoke_permissions {
                        if let (ClientPduName::ReadBlobRequest, _) = server.parse_att_pdu(&received).expect("failed to parse ATT PDU") {
                            server.revoke_permissions_of_client(revoke_permissions)
                        }
                    }
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
                connect_permission_setup(&[], None, |channel, client| {
                    Box::pin(async {
                        let response_processor = client
                            .read_blob_request(channel, $handle, 0)
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
                            Ok(_) => panic!("unexpected find information response"),
                        }
                    })
                })
                .await
            }

            #[tokio::test]
            async fn [<sufficient_ $permission_name _permissions>] () {
                let permissions = &[
                    ::bo_tie_att::AttributePermissions::Read(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup(permissions, None, |channel, client| {
                    Box::pin(async {
                        let mut blob: Option<ReadBlob> = None;

                        // loop should break before 10 times
                        for _ in 0..10 {
                            let offset = blob
                            .as_ref()
                            .map(|blob| blob.get_end_offset())
                            .unwrap_or_default() as u16;

                            let response_processor = client
                                .read_blob_request(channel, $handle, offset)
                                .await
                                .expect("failed to send request");

                            let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

                            match response_processor.process_response(&response)
                                .expect("invalid response")
                            {
                                Some(new_blob) => {
                                    blob = (new_blob + blob).expect("bad blob").into();
                                }
                                None => break,
                            }
                        }
                    })
                })
                .await
            }

            #[tokio::test]
            async fn [<sufficient_to_insufficient_ $permission_name _permissions>] () {
                let permissions = &[
                    ::bo_tie_att::AttributePermissions::Read(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup(permissions, Some(permissions), |channel, client| {
                    Box::pin(async {
                        let blob: ReadBlob;

                        let response_processor = client
                            .read_blob_request(channel, $handle, 0)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

                        match response_processor.process_response(&response)
                            .expect("invalid response")
                        {
                            Some(new_blob) => blob = new_blob,
                            None => panic!("invalid empty blob"),
                        }

                        let offset = blob.get_end_offset() as u16;

                        let response_processor = client
                            .read_blob_request(channel, $handle, offset)
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
                            Ok(_) => panic!("unexpected find information response"),
                        }
                    })
                })
                .await
            }
        }
    };
}

permission_tests!(read, None, 1, ReadNotPermitted);

permission_tests!(authentication, Authentication, 2, InsufficientAuthentication);

permission_tests!(authorization, Authorization, 3, InsufficientAuthorization);

permission_tests!(encryption_bits_128, Encryption(Bits128), 4, InsufficientEncryption);

permission_tests!(encryption_bits_192, Encryption(Bits192), 5, InsufficientEncryption);

permission_tests!(encryption_bits_256, Encryption(Bits256), 6, InsufficientEncryption);
