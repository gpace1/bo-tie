//! Tests for the find information request/response

use bo_tie_att::client::{ClientPduName, ResponseProcessor};
use bo_tie_att::pdu::{FormattedHandlesWithType, HandleWithType};
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

const UUID_SHORT_1: Uuid = Uuid::from_u16(1);

const UUID_SHORT_2: Uuid = Uuid::from_u16(2);

const UUID_SHORT_3: Uuid = Uuid::from_u16(3);

const UUID_FULL_1: Uuid = Uuid::from_u128(1);

const UUID_FULL_2: Uuid = Uuid::from_u128(2);

const UUID_FULL_3: Uuid = Uuid::from_u128(3);

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
async fn find_success() {
    connect_setup!(|link, client| {
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
                let channel = &mut link.get_att_channel().unwrap();

                let response_processor = client
                    .find_information_request(channel, $range)
                    .await
                    .expect("failed to send request");

                let response = match link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => pdu,
                    next => panic!("received unexpected {next:?}"),
                };

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

        test!(SHORT, 1..=0xFFFF, |handles| {
            assert_eq!(handles.len(), 2);

            assert_eq!(handles[0], HandleWithType::new(1, UUID_SHORT_1));

            assert_eq!(handles[1], HandleWithType::new(2, UUID_SHORT_2));
        });

        test!(FULL, 3..=0xFFFF, |handles| {
            // the MTU dictates that only one u128 UUID can be transferred
            assert_eq!(handles.len(), 1);

            assert_eq!(handles[0], HandleWithType::new(3, UUID_FULL_1));
        });

        test!(FULL, 4..=0xFFFF, |handles| {
            assert_eq!(handles.len(), 1);

            assert_eq!(handles[0], HandleWithType::new(4, UUID_FULL_2));
        });

        test!(SHORT, 5..=0xFFFF, |handles| {
            assert_eq!(handles.len(), 1);

            assert_eq!(handles[0], HandleWithType::new(5, UUID_SHORT_3));
        });

        test!(FULL, 6..=0xFFFF, |handles| {
            assert_eq!(handles.len(), 1);

            assert_eq!(handles[0], HandleWithType::new(6, UUID_FULL_3));
        });

        test!(SHORT, 2..=2, |handles| {
            assert_eq!(handles.len(), 1);

            assert_eq!(handles[0], HandleWithType::new(2, UUID_SHORT_2));
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
                [ClientPduName::FindInformationRequest.into(), 0, 0, 0xFF, 0xFF],
                [ClientPduName::FindInformationRequest.into(), 0, 0, 0, 0],
                [ClientPduName::FindInformationRequest.into(), 1, 0, 0, 0],
                [ClientPduName::FindInformationRequest.into(), 2, 0, 1, 0],
                [ClientPduName::FindInformationRequest.into(), 0xFF, 0xFF, 1, 0],
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

        fake_loop!(for range in [7..=0xFFFF, 7..=7] {
            let channel = &mut link.get_att_channel().unwrap();

            let response_processor = client
                .find_information_request(channel, range)
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
                    UUID_SHORT_1,
                    [AttributePermissions::Read(AttributeRestriction::None)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_SHORT_1,
                    [AttributePermissions::Read(AttributeRestriction::Authentication)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_SHORT_1,
                    [AttributePermissions::Read(AttributeRestriction::Authorization)],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_SHORT_1,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits128,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_SHORT_1,
                    [AttributePermissions::Read(AttributeRestriction::Encryption(
                        EncryptionKeySize::Bits192,
                    ))],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID_SHORT_1,
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

/// Creates two test per permission check
///
/// The first test is insufficient_{permission} and will test an attribute whereby the client does
/// not have permissions for it, and the second test sufficient_{permission} will test the same
/// attribute with the client given permissions to access it.
macro_rules! permission_tests {
    (
        $permission_name:ident,
        $restriction:ident $( ($encryption:ident) )? ,
        $handle:literal
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
                        .find_information_request(channel, $handle..=0xFFFF)
                        .await
                        .expect("failed to send request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(FormattedHandlesWithType::HandlesWithFullUuids(mut response)) |
                        Ok(FormattedHandlesWithType::HandlesWithShortUuids(mut response)) => {
                            let first = response.pop().expect("unexpected empty response");

                            assert_eq!(first.get_handle(), $handle);
                        },
                    }
                })
            }
        }
    };
}

permission_tests!(read, None, 1);

permission_tests!(authentication, Authentication, 2,);

permission_tests!(authorization, Authorization, 3);

permission_tests!(encryption_bits_128, Encryption(Bits128), 4);

permission_tests!(encryption_bits_192, Encryption(Bits192), 5);

permission_tests!(encryption_bits_256, Encryption(Bits256), 6);

/// This setups the server to be completely filled with the same attribute
///
/// This is for testing the throughput (checking every attribute) of the server with the find
/// information command.
macro_rules! connect_benchmark_setup {
    (|$link:ident, $client:ident| $test:block ) => {{
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
                    server_attributes.push(Attribute::new(UUID_SHORT_1, FULL_READ_PERMISSIONS, 0u8));
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
                let mut $link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let channel = &mut $link.get_att_channel().unwrap();

                let connect = ConnectFixedClient::initiate(channel, <u16>::MAX, <u16>::MAX)
                    .await
                    .expect("exchange MTU failed");

                let $client = match $link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => connect.create_client(&pdu).unwrap(),
                    next => panic!("recieved unexpected {next:?}"),
                };

                $test
            })
            .run()
            .await
    }};
}

#[tokio::test]
#[cfg_attr(miri, ignore)]
async fn throughput() {
    connect_benchmark_setup!(|link, client| {
        for (start, expected_len) in [(1, 16383), (16384, 16383), (32767, 16383), (49150, 16383)] {
            let channel = &mut link.get_att_channel().unwrap();

            let response_processor = client
                .find_information_request(channel, start..=0xFFFF)
                .await
                .expect("failed to send request");

            let response = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => pdu,
                next => panic!("received unexpected {next:?}"),
            };

            match response_processor.process_response(&response) {
                Err(e) => panic!("unexpected error {:?}", e),
                Ok(FormattedHandlesWithType::HandlesWithFullUuids(response))
                | Ok(FormattedHandlesWithType::HandlesWithShortUuids(response)) => {
                    assert_eq!(response.len(), expected_len)
                }
            }
        }
    })
}
