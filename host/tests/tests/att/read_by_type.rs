//! Tests for the read by type request/response

use bo_tie_att::client::{ClientPduName, ResponseProcessor};
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes, ServerPduName};
use bo_tie_att::{
    pdu, Attribute, AttributePermissions, AttributeRestriction, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_READ_PERMISSIONS, LE_U_FIXED_CHANNEL_ID,
};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::{BasicFrame, FragmentIterator, FragmentL2capPdu, L2capFragment};
use bo_tie_l2cap::{LeULogicalLink, LeUNext, PhysicalLink};

const UUID_1: Uuid = Uuid::from_u16(1);

const UUID_2: Uuid = Uuid::from_u16(2);

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

                server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 0u8));

                server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 0u32));

                server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 1u8));

                server_attributes.push(Attribute::new(UUID_2, FULL_READ_PERMISSIONS, 1u32));

                server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 1u32));

                server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 10usize));

                server_attributes.push(Attribute::new(UUID_2, FULL_READ_PERMISSIONS, "hello world".to_string()));

                server_attributes.push(Attribute::new(UUID_2, FULL_READ_PERMISSIONS, "goodbye bob".to_string()));

                server_attributes.push(Attribute::new(
                    UUID_2,
                    FULL_READ_PERMISSIONS,
                    "generic test string".to_string(),
                ));

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
    // Note: all responses will not have a `group end handle`
    // as that is defined by a higher layer specification.
    connect_setup!(|link, client| {
        macro_rules! test {
            ($range:expr, $uuid:expr, $value_ty:ty, |$response:ident| $test:block) => {{
                let channel = &mut link.get_att_channel().unwrap();

                let response_processor = client
                    .read_by_type_request(channel, $range, $uuid)
                    .await
                    .expect("failed to send request");

                let response = match link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => pdu,
                    next => panic!("received unexpected {next:?}"),
                };

                let response = response_processor
                    .process_response(&response)
                    .expect("invalid response");

                (|$response: Vec<bo_tie_att::pdu::ReadTypeResponse<$value_ty>>| $test)(response)
            }};
        }

        test!(1..=0xFFFF, UUID_1, u8, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(1, next.get_handle());

            assert_eq!(0u8, next.into_inner());

            let next = response_iter.next().unwrap();

            assert_eq!(3, next.get_handle());

            assert_eq!(1u8, next.into_inner());

            assert!(response_iter.next().is_none())
        });

        test!(2..=0xFFFF, UUID_1, u32, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(2, next.get_handle());

            assert_eq!(0u32, next.into_inner());

            let next = response_iter.next().unwrap();

            assert_eq!(5, next.get_handle());

            assert_eq!(1u32, next.into_inner());

            assert!(response_iter.next().is_none())
        });

        test!(4..=0xFFFF, UUID_1, u32, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(5, next.get_handle());

            assert_eq!(1u32, next.into_inner());

            assert!(response_iter.next().is_none())
        });

        test!(6..=0xFFFF, UUID_1, usize, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(6, next.get_handle());

            assert_eq!(10, next.into_inner());

            assert!(response_iter.next().is_none())
        });

        test!(1..=0xFFFF, UUID_2, u32, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(4, next.get_handle());

            assert_eq!(1u32, next.into_inner());

            assert!(response_iter.next().is_none())
        });

        test!(7..=0xFFFF, UUID_2, String, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(7, next.get_handle());

            assert_eq!("hello world", next.into_inner().as_str());

            assert!(response_iter.next().is_none());
        });

        test!(8..=0xFFFF, UUID_2, String, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(8, next.get_handle());

            assert_eq!("goodbye bob", next.into_inner().as_str());

            assert!(response_iter.next().is_none())
        });

        test!(9..=0xFFFF, UUID_2, String, |responses| {
            let mut response_iter = responses.into_iter();

            let next = response_iter.next().unwrap();

            assert_eq!(9, next.get_handle());

            assert_eq!("generic test string", next.into_inner().as_str());

            assert!(response_iter.next().is_none())
        });
    })
}

#[tokio::test]
async fn invalid_handles() {
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
            for request_data in [
                [ClientPduName::ReadByTypeRequest.into(), 0, 0, 0xFF, 0xFF, 1, 0],
                [ClientPduName::ReadByTypeRequest.into(), 0, 0, 0, 0, 1, 0],
                [ClientPduName::ReadByTypeRequest.into(), 1, 0, 0, 0, 1, 0],
                [ClientPduName::ReadByTypeRequest.into(), 2, 0, 1, 0, 1, 0],
                [ClientPduName::ReadByTypeRequest.into(), 0xFF, 0xFF, 1, 0, 1, 0],
            ] {
                let basic_frame = BasicFrame::new(request_data, LE_U_FIXED_CHANNEL_ID);

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
        .await;
}

#[tokio::test]
async fn no_attributes() {
    connect_setup!(|link, client| {
        macro_rules! fake_loop {
            (for $range:ident in [$($elem:expr),* $(,)?] $todo:block) => {
                $({
                    let $range = $elem;

                    $todo
                })*
            };
        }

        fake_loop!(for range in [10..=0xFFFF, 10..=10] {
            let channel = &mut link.get_att_channel().unwrap();

            let response_processor = client
                .read_by_type_request::<_, _, u8>(channel, range, UUID_2)
                .await
                .expect("failed to send request");

            let response = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => pdu,
                next => panic!("received unexpected {next:?}"),
            };

            match response_processor.process_response(&response) {
                Err(bo_tie_att::Error::Pdu(pdu)) => {
                    assert_eq!(pdu.get_parameters().error, pdu::Error::AttributeNotFound)
                }
                Err(e) => panic!("unexpected error {:?}", e),
                Ok(_) => panic!("unexpected find information response"),
            }
        });
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
                    UUID_1,
                    [AttributePermissions::Read(AttributeRestriction::None)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_1,
                    [AttributePermissions::Read(AttributeRestriction::Authentication)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_1,
                    [AttributePermissions::Read(AttributeRestriction::Authorization)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_1,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits128,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_1,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits192,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_1,
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
        $uuid:expr,
        $val_ty:ty,
        $exp_err:ident
        $(,)?
    ) => {
        ::paste::paste! {
            #[tokio::test]
            async fn [<insufficient_ $permission_name _permissions>] () {
                connect_permission_setup!([], |link, client| {
                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .find_information_request(channel, $handle..=0xFFFF)
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
                                bo_tie_att::pdu::Error::AttributeNotFound
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
                        .read_by_type_request::<_, _, $val_ty>(channel, $handle..=$handle, $uuid)
                        .await
                        .expect("failed to send request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}"),
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(responses) => assert_eq!(responses.len(), 1),
                    }
                })
            }
        }
    };
}

permission_tests!(read, None, 1, UUID_1, u8, ReadNotPermitted);

permission_tests!(
    authentication,
    Authentication,
    2,
    UUID_1,
    u8,
    InsufficientAuthentication
);

permission_tests!(authorization, Authorization, 3, UUID_1, u8, InsufficientAuthorization);

permission_tests!(
    encryption_bits_128,
    Encryption(Bits128),
    4,
    UUID_1,
    u8,
    InsufficientEncryption
);

permission_tests!(
    encryption_bits_192,
    Encryption(Bits192),
    5,
    UUID_1,
    u8,
    InsufficientEncryption
);

permission_tests!(
    encryption_bits_256,
    Encryption(Bits256),
    6,
    UUID_1,
    u8,
    InsufficientEncryption
);

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn throughput() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let mut server_attributes = ServerAttributes::new();

            // note: `..` is used over `..=` as one less than
            // the maximum is desired (handle 0 is reserved).
            for _ in 0..<u16>::MAX {
                server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 0u8));
            }

            let mut server = Server::new_fixed(<u16>::MAX, <u16>::MAX, server_attributes, NoQueuedWrites);

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
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let channel = &mut link.get_att_channel().unwrap();

            let connect = ConnectFixedClient::initiate(channel, <u16>::MAX, <u16>::MAX)
                .await
                .expect("exchange MTU failed");

            let client = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => connect.create_client(&pdu).unwrap(),
                next => panic!("received unexpected {next:?}"),
            };

            for (start, expected_len) in [(1, 21844), (21845, 21844), (43689, 21844)] {
                let channel = &mut link.get_att_channel().unwrap();

                let response_processor = client
                    .read_by_type_request::<_, _, u8>(channel, start..=0xFFFF, UUID_1)
                    .await
                    .expect("failed to send request");

                let response = match link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => pdu,
                    next => panic!("received unexpected {next:?}"),
                };

                match response_processor.process_response(&response) {
                    Err(e) => panic!("unexpected error {:?}", e),
                    Ok(responses) => assert_eq!(responses.len(), expected_len),
                }
            }
        })
        .run()
        .await
}
