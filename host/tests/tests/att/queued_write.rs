//! Tests for prepare write request and execute write request/response.

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::pdu::{ExecuteWriteFlag, PreparedWriteRequests};
use bo_tie_att::server::{BasicQueuedWriter, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_WRITE_PERMISSIONS,
};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};
use std::cell::RefCell;
use std::sync::Arc;
use tokio::sync::Mutex;

const UUID: Uuid = Uuid::from_u16(0x1234);

macro_rules! connect_setup {
    (|$link:ident, $client:ident, $ref_cell_value:ident, $value_type:ty| $action:block ) => {{
        let $ref_cell_value: Arc<Mutex<$value_type>> = Default::default();

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
                    BasicQueuedWriter::new(),
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
    connect_setup!(|link, client, value, String| {
        let test_data = "this is a very long string, too long for a single write to complete";

        let mtu = client.get_mtu().unwrap().into();

        let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

        let mut expected_offset = 0;

        for request in prepared_requests.iter() {
            let channel = &mut link.get_att_channel().unwrap();

            let response_processor = client
                .prepare_write_request(channel, request)
                .await
                .expect("failed to send prepare write request");

            let response = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => pdu,
                next => panic!("received unexpected {next:?}"),
            };

            let prepared_write_response = response_processor
                .process_response(&response)
                .expect("prepared write failed");

            assert_eq!(1, prepared_write_response.handle);

            assert_eq!(expected_offset, prepared_write_response.offset);

            let start = expected_offset;

            expected_offset += mtu - 5;

            let end = core::cmp::min(expected_offset, test_data.len());

            assert_eq!(
                &test_data[start..end],
                std::str::from_utf8(&prepared_write_response.data).unwrap(),
            );
        }

        assert_eq!("".to_string(), *value.lock().await);

        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .execute_write_request(channel, ExecuteWriteFlag::WriteAllPreparedWrites)
            .await
            .expect("failed to send execute write request");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        response_processor
            .process_response(&response)
            .expect("execute write failed");

        assert_eq!(test_data.to_string(), *value.lock().await);
    })
}

#[tokio::test]
async fn execute_cancel_success() {
    connect_setup!(|link, client, value, String| {
        let test_data = "this is a very long string, too long for a single write to complete";

        let mtu = client.get_mtu().unwrap().into();

        let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

        let mut expected_offset = 0;

        for request in prepared_requests.iter() {
            let channel = &mut link.get_att_channel().unwrap();

            let response_processor = client
                .prepare_write_request(channel, request)
                .await
                .expect("failed to send prepare write request");

            let response = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => pdu,
                next => panic!("received unexpected {next:?}"),
            };

            let prepared_write_response = response_processor
                .process_response(&response)
                .expect("prepared write failed");

            assert_eq!(1, prepared_write_response.handle);

            assert_eq!(expected_offset, prepared_write_response.offset);

            let start = expected_offset;

            expected_offset += mtu - 5;

            let end = core::cmp::min(expected_offset, test_data.len());

            assert_eq!(
                &test_data[start..end],
                std::str::from_utf8(&prepared_write_response.data).unwrap(),
            );
        }

        assert_eq!("".to_string(), *value.lock().await);

        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .execute_write_request(channel, ExecuteWriteFlag::CancelAllPreparedWrites)
            .await
            .expect("failed to send execute write request");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        response_processor
            .process_response(&response)
            .expect("execute write failed");

        assert_ne!(test_data.to_string(), *value.lock().await);

        assert_eq!("".to_string(), *value.lock().await);
    })
}

#[tokio::test]
async fn full_queue() {
    connect_setup!(|link, client, value, u8| {
        let test_data: &[u8] = &[0u8; 512 + 1];

        let mtu = client.get_mtu().unwrap().into();

        let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

        let mut counter = 0;

        for request in prepared_requests.iter() {
            let channel = &mut link.get_att_channel().unwrap();

            let response_processor = client
                .prepare_write_request(channel, request)
                .await
                .expect("failed to send prepare write request");

            let response = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => pdu,
                next => panic!("received unexpected {next:?}"),
            };

            match response_processor.process_response(&response) {
                Ok(_) => counter += 1,
                Err(bo_tie_att::Error::Pdu(pdu)) => {
                    assert_eq!(pdu.get_parameters().error, bo_tie_att::pdu::Error::PrepareQueueFull);

                    break;
                }
                Err(e) => panic!("unexpected error {:?}", e),
            }

            // a check to ensure this test doesn't run forever
            // (which is a problem).
            assert_ne!(counter, 512 + 1);
        }
    })
}

#[tokio::test]
async fn invalid_value_size() {
    connect_setup!(|link, client, value, usize| {
        let test_data: &[u8] = &[0, 1, 2, 3, 4, 5, 6];

        let mtu = client.get_mtu().unwrap().into();

        let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

        let request = prepared_requests.iter().next().unwrap();

        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .prepare_write_request(channel, request)
            .await
            .expect("failed to send prepare write request");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        match response_processor.process_response(&response) {
            Ok(_) => (),
            Err(e) => panic!("unexpected error {:?}", e),
        }

        let channel = &mut link.get_att_channel().unwrap();

        let response_processor = client
            .execute_write_request(channel, ExecuteWriteFlag::WriteAllPreparedWrites)
            .await
            .expect("failed to send execute write request");

        let response = match link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        match response_processor.process_response(&response) {
            Err(bo_tie_att::Error::Pdu(pdu)) => {
                assert_eq!(
                    pdu.get_parameters().error,
                    bo_tie_att::pdu::Error::InvalidAttributeValueLength
                );
            }
            Err(e) => panic!("unexpected error {:?}", e),
            Ok(_) => panic!("unexpected valid response"),
        }
    })
}

macro_rules! connect_permission_setup {
    ($ref_cell_client_permission:expr, |$link:ident, $client:ident| $test:expr) => {{
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
                    [
                        AttributePermissions::Read(AttributeRestriction::None),
                        AttributePermissions::Write(AttributeRestriction::None),
                    ],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [
                        AttributePermissions::Read(AttributeRestriction::None),
                        AttributePermissions::Write(AttributeRestriction::Authentication),
                    ],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [
                        AttributePermissions::Read(AttributeRestriction::None),
                        AttributePermissions::Write(AttributeRestriction::Authorization),
                    ],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [
                        AttributePermissions::Read(AttributeRestriction::None),
                        AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits128)),
                    ],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [
                        AttributePermissions::Read(AttributeRestriction::None),
                        AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits192)),
                    ],
                    0u8,
                ));

                server_attributes.push(Attribute::new(
                    UUID,
                    [
                        AttributePermissions::Read(AttributeRestriction::None),
                        AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
                    ],
                    0u8,
                ));

                let mut server = Server::new_fixed(
                    LeULink::SUPPORTED_MTU,
                    LeULink::SUPPORTED_MTU,
                    server_attributes,
                    BasicQueuedWriter::new(),
                );

                server.revoke_permissions_of_client(FULL_WRITE_PERMISSIONS);

                server.give_permissions_to_client($ref_cell_client_permission.borrow().clone());

                loop {
                    match &mut link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, channel } => {
                            server.process_att_pdu(channel, pdu).await.unwrap();

                            server.revoke_permissions_of_client(FULL_WRITE_PERMISSIONS);

                            server.give_permissions_to_client($ref_cell_client_permission.borrow().clone());
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

macro_rules! prepare_permission_tests {
    (
        $permission_name:ident,
        $restriction:ident $( ($encryption:ident) )? ,
        $handle:literal,
        $exp_err:ident
        $(,)?
    ) => {
        ::paste::paste! {
            #[tokio::test]
            async fn [<insufficient_prepare_ $permission_name _permissions>] () {
                connect_permission_setup!( RefCell::new(Vec::<::bo_tie_att::AttributePermissions>::new()), |link, client| {
                    let mtu = client.get_mtu().unwrap().into();

                    let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                    let first_request = prepared_requests.iter().next().unwrap();

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .prepare_write_request(channel, first_request)
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
            async fn [<sufficient_prepare_ $permission_name _permissions>] () {
                let permissions = RefCell::new(vec![
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ]);

                connect_permission_setup!(permissions, |link, client| {
                    let mtu = client.get_mtu().unwrap().into();

                    let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                    let first_request = prepared_requests.iter().next().unwrap();

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .prepare_write_request(channel, first_request)
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

            #[tokio::test]
            async fn [<sufficient_to_insufficient_prepare_ $permission_name _permissions>] () {
                let permissions = RefCell::new(vec![
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ]);

                connect_permission_setup!(permissions, |link, client| {
                    let mtu = client.get_mtu().unwrap().into();

                    let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                    let first_request = prepared_requests.iter().next().unwrap();

                    let channel = &mut link.get_att_channel().unwrap();

                    // this will change the permissions *after* the next
                    // ATT request PDU
                    *permissions.borrow_mut() = vec![];

                    let response_processor = client
                        .prepare_write_request(channel, first_request)
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

                    let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                    let first_request = prepared_requests.iter().next().unwrap();

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .prepare_write_request(channel, first_request)
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
                        Ok(v) => panic!("unexpected response {v:?}"),
                    }
                })
            }
        }
    };
}

prepare_permission_tests!(write, None, 1, WriteNotPermitted);

prepare_permission_tests!(authentication, Authentication, 2, InsufficientAuthentication);

prepare_permission_tests!(authorization, Authorization, 3, InsufficientAuthorization);

prepare_permission_tests!(encryption_bits_128, Encryption(Bits128), 4, InsufficientEncryption);

prepare_permission_tests!(encryption_bits_192, Encryption(Bits192), 5, InsufficientEncryption);

prepare_permission_tests!(encryption_bits_256, Encryption(Bits256), 6, InsufficientEncryption);

macro_rules! execute_permission_tests {
    (
        $permission_name:ident,
        $restriction:ident $( ($encryption:ident) )? ,
        $handle:literal,
        $exp_err:ident
        $(,)?
    ) => {
        ::paste::paste! {
            #[tokio::test]
            async fn [<insufficient_execute_ $permission_name _permissions>] () {
                let permissions = RefCell::new(vec![
                    ::bo_tie_att::AttributePermissions::Read(
                        ::bo_tie_att::AttributeRestriction::None
                    ),
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ]);

                connect_permission_setup!(permissions, |link, client| {
                    let mtu = client.get_mtu().unwrap().into();

                    let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                    let first_request = prepared_requests.iter().next().unwrap();

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .prepare_write_request(channel, first_request)
                        .await
                        .expect("failed to send prepare request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(_) => (),
                    }

                    *permissions.borrow_mut() = vec![];

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .execute_write_request(channel, ExecuteWriteFlag::CancelAllPreparedWrites)
                        .await
                        .expect("failed to send execute request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(_) => (),
                    }

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .read_request::<_, u8>(channel, $handle)
                        .await
                        .expect("failed read request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error {:?}", e),
                        Ok(val) => assert_eq!(val, 0),
                    }
                })
            }

            #[tokio::test]
            async fn [<sufficient_execute_ $permission_name _permissions>] () {
                let permissions = RefCell::new(vec![
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ]);

                connect_permission_setup!(permissions, |link, client| {
                    let mtu = client.get_mtu().unwrap().into();

                    let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                    let first_request = prepared_requests.iter().next().unwrap();

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .prepare_write_request(channel, first_request)
                        .await
                        .expect("failed to send prepare request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error 1 {:?}", e),
                        Ok(_) => (),
                    }

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .execute_write_request(channel, ExecuteWriteFlag::CancelAllPreparedWrites)
                        .await
                            .expect("failed to send execute request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error 2 {:?}", e),
                        Ok(_) => (),
                    }

                    let channel = &mut link.get_att_channel().unwrap();

                    let response_processor = client
                        .read_request::<_, u8>(channel, $handle)
                        .await
                        .expect("failed read request");

                    let response = match link.next().await.unwrap() {
                        LeUNext::AttributeChannel { pdu, .. } => pdu,
                        next => panic!("received unexpected {next:?}")
                    };

                    match response_processor.process_response(&response) {
                        Err(e) => panic!("unexpected error 3 {:?}", e),
                        Ok(val) => assert_eq!(val, 0),
                    }
                })
            }
        }
    };
}

execute_permission_tests!(write, None, 1, WriteNotPermitted);

execute_permission_tests!(authentication, Authentication, 2, InsufficientAuthentication);

execute_permission_tests!(authorization, Authorization, 3, InsufficientAuthorization);

execute_permission_tests!(encryption_bits_128, Encryption(Bits128), 4, InsufficientEncryption);

execute_permission_tests!(encryption_bits_192, Encryption(Bits192), 5, InsufficientEncryption);

execute_permission_tests!(encryption_bits_256, Encryption(Bits256), 6, InsufficientEncryption);
