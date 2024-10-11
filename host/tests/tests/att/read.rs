//! Tests for the read request/response

use bo_tie_att::client::{ClientPduName, ResponseProcessor};
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes, ServerPduName};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_READ_PERMISSIONS, LE_U_FIXED_CHANNEL_ID,
};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::{BasicFrame, FragmentIterator, FragmentL2capPdu, L2capFragment};
use bo_tie_l2cap::{LeULogicalLink, LeUNext, PhysicalLink};

const UUID: Uuid = Uuid::from_u16(0x1234);

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

                server_attributes.push(Attribute::new(UUID, FULL_READ_PERMISSIONS, "hello world".to_string()));

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
        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .read_request::<_, String>(channel, 1)
            .await
            .expect("failed to read");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        let data = response_processor
            .process_response(&response)
            .expect("failed to process response");

        assert_eq!("hello world", data.as_str())
    })
}

#[tokio::test]
async fn invalid_handle() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let server_attributes = ServerAttributes::new();

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
        .set_verify(|mut end| async move {
            for data in [
                [ClientPduName::ReadRequest.into(), 0, 0],
                [ClientPduName::ReadRequest.into(), 2, 0],
            ] {
                let basic_frame = BasicFrame::new(data, LE_U_FIXED_CHANNEL_ID);

                let mut fragments = basic_frame.into_fragments(end.max_transmission_size().into()).unwrap();

                let mut first = true;

                while let Some(fragment) = fragments.next() {
                    let l2cap_fragment = L2capFragment::new(first, fragment);

                    first = false;

                    end.send(l2cap_fragment).await.unwrap();

                    let received = end.recv().await.unwrap().unwrap();

                    let mut payload = received.into_inner();

                    assert_eq!(payload.len(), 9);

                    assert_eq!(
                        payload.by_ref().skip(4).next().unwrap(),
                        ServerPduName::ErrorResponse.into()
                    );

                    let invalid_handle_error = 0x1u8;

                    assert_eq!(payload.by_ref().skip(3).next().unwrap(), invalid_handle_error);
                }
            }
        })
        .run()
        .await
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
                        .read_request::<_, u8>(channel, $handle)
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
                    let channel = &mut link.get_att_channel().unwrap();

                        let response_processor = client
                            .read_request::<_, u8>(channel, $handle)
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

permission_tests!(read, None, 1, ReadNotPermitted);

permission_tests!(authentication, Authentication, 2, InsufficientAuthentication);

permission_tests!(authorization, Authorization, 3, InsufficientAuthorization);

permission_tests!(encryption_bits_128, Encryption(Bits128), 4, InsufficientEncryption);

permission_tests!(encryption_bits_192, Encryption(Bits192), 5, InsufficientEncryption);

permission_tests!(encryption_bits_256, Encryption(Bits256), 6, InsufficientEncryption);
