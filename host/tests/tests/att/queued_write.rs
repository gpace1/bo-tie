//! Tests for prepare write request and execute write request/response.

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::pdu::{ExecuteWriteFlag, PreparedWriteRequests};
use bo_tie_att::server::{BasicQueuedWriter, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, Client, ConnectFixedClient, EncryptionKeySize, Server,
    TransferFormatInto, TransferFormatTryFrom, FULL_WRITE_PERMISSIONS,
};
use bo_tie_host_tests::{create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;
use std::sync::Arc;
use tokio::sync::Mutex;

const UUID: Uuid = Uuid::from_u16(0x1234);

async fn connect_setup<Fun, D>(test: Fun)
where
    Fun: for<'a> FnOnce(
            &'a mut BasicFrameChannel<LeULogicalLink<PhysicalLink>>,
            &'a mut Client,
            &'a Arc<Mutex<D>>,
        ) -> std::pin::Pin<Box<dyn Future<Output = ()> + Send + 'a>>
        + Send
        + 'static,
    D: Default + TransferFormatTryFrom + TransferFormatInto + PartialEq + Unpin + Send + 'static,
{
    let (client_link, server_link) = create_le_link(LeULink::SUPPORTED_MTU.into());

    let (rendezvous_client, rendezvous_server) = directed_rendezvous();

    let att_value: Arc<Mutex<D>> = Default::default();

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
            BasicQueuedWriter::new(),
        );

        let mut rendez = Box::pin(rendezvous_server.rendez());

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive() => {
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
    connect_setup::<_, String>(|channel, client, value| {
        Box::pin(async {
            let test_data = "this is a very long string, too long for a single write to complete";

            let mtu = client.get_mtu().unwrap().into();

            let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

            let mut expected_offset = 0;

            for request in prepared_requests.iter() {
                let response_processor = client
                    .prepare_write_request(channel, request)
                    .await
                    .expect("failed to send prepare write request");

                let response = channel.receive().await.expect("failed to receive response");

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

            let response_processor = client
                .execute_write_request(channel, ExecuteWriteFlag::WriteAllPreparedWrites)
                .await
                .expect("failed to send execute write request");

            let response = channel
                .receive()
                .await
                .expect("failed to received prepare write response");

            response_processor
                .process_response(&response)
                .expect("execute write failed");

            assert_eq!(test_data.to_string(), *value.lock().await);
        })
    })
    .await
}

#[tokio::test]
async fn execute_cancel_success() {
    connect_setup::<_, String>(|channel, client, value| {
        Box::pin(async {
            let test_data = "this is a very long string, too long for a single write to complete";

            let mtu = client.get_mtu().unwrap().into();

            let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

            let mut expected_offset = 0;

            for request in prepared_requests.iter() {
                let response_processor = client
                    .prepare_write_request(channel, request)
                    .await
                    .expect("failed to send prepare write request");

                let response = channel.receive().await.expect("failed to receive response");

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

            let response_processor = client
                .execute_write_request(channel, ExecuteWriteFlag::CancelAllPreparedWrites)
                .await
                .expect("failed to send execute write request");

            let response = channel
                .receive()
                .await
                .expect("failed to received prepare write response");

            response_processor
                .process_response(&response)
                .expect("execute write failed");

            assert_ne!(test_data.to_string(), *value.lock().await);

            assert_eq!("".to_string(), *value.lock().await);
        })
    })
    .await
}

#[tokio::test]
async fn full_queue() {
    connect_setup::<_, u8>(|channel, client, _| {
        Box::pin(async {
            let test_data: &[u8] = &[0u8; 512 + 1];

            let mtu = client.get_mtu().unwrap().into();

            let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

            let mut counter = 0;

            for request in prepared_requests.iter() {
                let response_processor = client
                    .prepare_write_request(channel, request)
                    .await
                    .expect("failed to send prepare write request");

                let response = channel.receive().await.expect("failed to receive response");

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
    })
    .await
}

#[tokio::test]
async fn invalid_value_size() {
    connect_setup::<_, u64>(|channel, client, _| {
        Box::pin(async {
            let test_data: &[u8] = &[0, 1, 2, 3, 4, 5, 6];

            let mtu = client.get_mtu().unwrap().into();

            let prepared_requests = PreparedWriteRequests::new(1, &test_data, mtu);

            let request = prepared_requests.iter().next().unwrap();

            let response_processor = client
                .prepare_write_request(channel, request)
                .await
                .expect("failed to send prepare write request");

            let response = channel.receive().await.expect("failed to receive response");

            match response_processor.process_response(&response) {
                Ok(_) => (),
                Err(e) => panic!("unexpected error {:?}", e),
            }

            let response_processor = client
                .execute_write_request(channel, ExecuteWriteFlag::WriteAllPreparedWrites)
                .await
                .expect("failed to send execute write request");

            let response = channel.receive().await.expect("failed to receive response");

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
    })
    .await
}

async fn connect_permission_setup<P, Fun>(permissions: P, test: Fun)
where
    P: Fn() -> std::pin::Pin<Box<dyn Future<Output = &'static [AttributePermissions]> + Send>> + Sync + Send + 'static,
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

        server.revoke_permissions_of_client([AttributePermissions::Write(AttributeRestriction::None)]);

        let mut set_permissions = permissions().await;

        server.give_permissions_to_client(set_permissions);

        let mut rendez = Box::pin(rendezvous_server.rendez());

        loop {
            tokio::select! {
                _ = &mut rendez => break,

                received = att_bearer.receive() => {
                    let received = received.expect("receiver closed");

                    server.revoke_permissions_of_client(set_permissions);

                    set_permissions = permissions().await;

                    server.give_permissions_to_client(set_permissions);

                    server.process_att_pdu(&mut att_bearer, &received).await.expect("failed to process ATT PDU");
                }
            }
        }
    });

    client_handle.await.unwrap();

    server_handle.await.unwrap();
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
                connect_permission_setup(|| Box::pin(async {&[] as &[_]}), |channel, client| {
                    Box::pin(async {
                        let mtu = client.get_mtu().unwrap().into();

                        let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                        let first_request = prepared_requests.iter().next().unwrap();

                        let response_processor = client
                            .prepare_write_request(channel, first_request)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive().await.expect("failed to receive");

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
            async fn [<sufficient_prepare_ $permission_name _permissions>] () {
                let permissions: &'static [_] = &[
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup(move || Box::pin(async move {permissions}), |channel, client| {
                    Box::pin(async {
                        let mtu = client.get_mtu().unwrap().into();

                        let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                        let first_request = prepared_requests.iter().next().unwrap();

                        let response_processor = client
                            .prepare_write_request(channel, first_request)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive().await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(_) => (),
                        }
                    })
                })
                .await
            }

            #[tokio::test]
            async fn [<sufficient_to_insufficient_prepare_ $permission_name _permissions>] () {
                let init_permissions: &[_] = &[
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                let permissions = Arc::new(Mutex::new(init_permissions));

                let p_clone = permissions.clone();

                let p_fun = move || {
                    let owned = p_clone.clone();

                    Box::pin(async move {*owned.lock().await})
                        as ::core::pin::Pin<Box<dyn Future<Output = &'static [AttributePermissions]> + Send>>
                };

                connect_permission_setup(p_fun, |channel, client| {
                    Box::pin(async move {
                        let mtu = client.get_mtu().unwrap().into();

                        let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                        let first_request = prepared_requests.iter().next().unwrap();

                        let response_processor = client
                            .prepare_write_request(channel, first_request)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive().await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(_) => (),
                        }

                        *permissions.lock().await = &[];

                        let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                        let first_request = prepared_requests.iter().next().unwrap();

                        let response_processor = client
                            .prepare_write_request(channel, first_request)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive().await.expect("failed to receive");

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
                let init_permissions: &[_] = &[
                    ::bo_tie_att::AttributePermissions::Read(
                        ::bo_tie_att::AttributeRestriction::None
                    ),
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                let permissions = Arc::new(Mutex::new(init_permissions));

                let p_clone = permissions.clone();

                let p_fun = move || {
                    let owned = p_clone.clone();

                    Box::pin(async move {*owned.lock().await})
                        as ::core::pin::Pin<Box<dyn Future<Output = &'static [AttributePermissions]> + Send>>
                };

                connect_permission_setup(p_fun, |channel, client| {
                    Box::pin(async move {
                        let mtu = client.get_mtu().unwrap().into();

                        let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                        let first_request = prepared_requests.iter().next().unwrap();

                        let response_processor = client
                            .prepare_write_request(channel, first_request)
                            .await
                            .expect("failed to send prepare request");

                        let response = channel.receive().await
                            .expect("failed to receive prepare response");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(_) => (),
                        }

                        *permissions.lock().await = &[];

                        let response_processor = client
                            .execute_write_request(channel, ExecuteWriteFlag::CancelAllPreparedWrites)
                            .await
                            .expect("failed to send execute request");

                        let response = channel.receive().await
                            .expect("failed to receive execute response");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(_) => (),
                        }

                        *permissions.lock().await = &[
                            ::bo_tie_att::AttributePermissions::Read(
                                ::bo_tie_att::AttributeRestriction::None
                            )
                        ];

                        let response_processor = client
                            .read_request::<_, u8>(channel, $handle)
                            .await
                            .expect("failed read request");

                        let response = channel.receive().await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(val) => assert_eq!(val, 0),
                        }
                    })
                })
                .await
            }

            #[tokio::test]
            async fn [<sufficient_execute_ $permission_name _permissions>] () {
                let permissions: &'static [_] = &[
                    ::bo_tie_att::AttributePermissions::Write(
                        ::bo_tie_att::AttributeRestriction::$restriction $( (
                            ::bo_tie_att::EncryptionKeySize::$encryption
                        ) )?
                    )
                ];

                connect_permission_setup(move || Box::pin(async move {permissions}), |channel, client| {
                    Box::pin(async {
                        let mtu = client.get_mtu().unwrap().into();

                        let prepared_requests = PreparedWriteRequests::new($handle, &10u8, mtu);

                        let first_request = prepared_requests.iter().next().unwrap();

                        let response_processor = client
                            .prepare_write_request(channel, first_request)
                            .await
                            .expect("failed to send prepare request");

                        let response = channel.receive().await
                            .expect("failed to receive prepare response");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error 1 {:?}", e),
                            Ok(_) => (),
                        }

                        let response_processor = client
                            .execute_write_request(channel, ExecuteWriteFlag::CancelAllPreparedWrites)
                            .await
                            .expect("failed to send execute request");

                        let response = channel.receive().await
                            .expect("failed to receive execute response");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error 2 {:?}", e),
                            Ok(_) => (),
                        }

                        let response_processor = client
                            .read_request::<_, u8>(channel, $handle)
                            .await
                            .expect("failed read request");

                        let response = channel.receive().await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error 3 {:?}", e),
                            Ok(val) => assert_eq!(val, 0),
                        }
                    })
                })
                .await
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
