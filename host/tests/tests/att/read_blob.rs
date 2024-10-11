//! Tests for read blob request/response
//!
//! This tests-scaffold the read blob request/response and any commands whose read can be continued with a
//! read blob request.

use bo_tie_att::client::{ClientPduName, ReadBlob, ResponseProcessor};
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_READ_PERMISSIONS,
};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};

const UUID: Uuid = Uuid::from_u16(1);

const TEST_VALUE: &'static str = "this is a value too long for to read in a single ATT pdu";

macro_rules! connect_setup {
    (|$link:ident, $client:ident| $action:block ) => {{
        PhysicalLinkLoop::<4>::new()
            .test_scaffold()
            .set_tested(|end| async {
                let mut link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let mut server_attributes = ServerAttributes::new();

                server_attributes.push(Attribute::new(UUID, FULL_READ_PERMISSIONS, TEST_VALUE.to_string()));

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
async fn read_success() {
    connect_setup!(|link, client| {
        macro_rules! test {
            ($handle:expr, $value_ty:ty, |$blob:ident| $test:block) => {{
                let mut blob: Option<ReadBlob> = None;

                // loop should break before long before 10000 times
                for _ in 0..10000 {
                    let offset = blob
                        .as_ref()
                        .map(|blob| blob.get_end_offset())
                        .unwrap_or_default() as u16;

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .read_blob_request(channel, 1, offset)
                        .await
                        .expect("failed to send request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}"),
                    };

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
        });
    })
}

macro_rules! connect_permission_setup {
    ($client_permission:expr $(=> $revoke_permissions:expr )? , |$link:ident, $client:ident| $test:expr) => {{
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
                    [AttributePermissions::Read(AttributeRestriction::None)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Read(AttributeRestriction::Authentication)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Read(AttributeRestriction::Authorization)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits128,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits192,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
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

                server.revoke_permissions_of_client([AttributePermissions::Read(AttributeRestriction::None)]);

                server.give_permissions_to_client($client_permission);

                loop {
                    match &mut link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, channel } => {
                            server.process_att_pdu(channel, pdu).await.unwrap();

                            $(
                                if let (ClientPduName::ReadBlobRequest, _) =
                                    server.parse_att_pdu(pdu).expect("failed to parse ATT PDU")
                                {
                                    server.revoke_permissions_of_client($revoke_permissions)
                                }
                            )?
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
            .await
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
                        .read_blob_request(channel, $handle, 0)
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
                        Ok(_) => panic!("unexpected find information response"),
                    }
                })
            }

            #[tokio::test]
            async fn [<sufficient_ $permission_name _permissions>] () {
                let permissions = [
                    ::bo_tie_att::AttributePermissions::Read(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup!(permissions, |link, client| {
                        let mut blob: Option<ReadBlob> = None;

                        // loop should break before 10 times
                        for _ in 0..10 {
                            let offset = blob
                            .as_ref()
                            .map(|blob| blob.get_end_offset())
                            .unwrap_or_default() as u16;

                            let channel = &mut link.get_att_channel().unwrap();

                            let response_processor = client
                                .read_blob_request(channel, $handle, offset)
                                .await
                                .expect("failed to send request");

                            let response = match link.next().await.unwrap() {
                                LeUNext::AttributeChannel { pdu, .. } => pdu,
                                next => panic!("received unexpected {next:?}")
                            };

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
            }

            #[tokio::test]
            async fn [<sufficient_to_insufficient_ $permission_name _permissions>] () {
                let permissions = [
                    ::bo_tie_att::AttributePermissions::Read(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup!(permissions => permissions, |link, client| {
                    let blob: ReadBlob;

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .read_blob_request(channel, $handle, 0)
                        .await
                        .expect("failed to send request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response)
                        .expect("invalid response")
                    {
                        Some(new_blob) => blob = new_blob,
                        None => panic!("invalid empty blob"),
                    }

                    let offset = blob.get_end_offset() as u16;

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .read_blob_request(channel, $handle, offset)
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
                        Ok(_) => panic!("unexpected find information response"),
                    }
                })
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
