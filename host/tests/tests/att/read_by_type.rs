//! Tests for the read by type request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    pdu, Attribute, AttributePermissions, AttributeRestriction, Client, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_READ_PERMISSIONS,
};
use bo_tie_host_tests::{create_le_false_link, create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::{BasicFrame, L2capFragment};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;

const UUID_1: Uuid = Uuid::from_u16(1);

const UUID_2: Uuid = Uuid::from_u16(2);

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
async fn read_success() {
    // Note: all responses will not have a `group end handle`
    // as that is defined by a higher layer specification.
    connect_setup(|channel, client| {
        macro_rules! test {
            ($range:expr, $uuid:expr, $value_ty:ty, |$response:ident| $test:block) => {{
                let response_processor = client
                    .read_by_type_request(channel, $range, $uuid)
                    .await
                    .expect("failed to send request");

                let response = channel.receive().await.expect("failed to receive");

                let response = response_processor
                    .process_response(&response)
                    .expect("invalid response");

                (|$response: Vec<bo_tie_att::pdu::ReadTypeResponse<$value_ty>>| $test)(response)
            }};
        }

        Box::pin(async {
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
            })
        })
    })
    .await
}

pub fn raw_client_fragments<I>(
    request: bo_tie_att::client::ClientPduName,
    request_data: I,
) -> impl Iterator<Item = L2capFragment<Vec<u8>>>
where
    I: std::borrow::Borrow<[u8]>,
{
    let mut payload = vec![request.into()];

    payload.extend(request_data.borrow());

    let basic_frame = BasicFrame::new(
        payload,
        bo_tie_l2cap::channel::id::ChannelIdentifier::Le(bo_tie_l2cap::channel::id::LeCid::AttributeProtocol),
    );

    let mut fragments =
        bo_tie_l2cap::pdu::FragmentL2capPdu::into_fragments(basic_frame, LeULink::SUPPORTED_MTU.into()).unwrap();

    let mut first = true;

    std::iter::from_fn(move || {
        bo_tie_l2cap::pdu::FragmentIterator::next(&mut fragments).map(|data| {
            let is_first = first;

            first = false;

            L2capFragment::new(is_first, data.collect())
        })
    })
}

async fn false_server_connection<Fun>(test: Fun)
where
    Fun: for<'a> FnOnce(
        &'a mut (dyn futures::Sink<L2capFragment<Vec<u8>>, Error = futures::channel::mpsc::SendError> + Unpin),
        &'a mut (dyn futures::Stream<Item = L2capFragment<Vec<u8>>> + Unpin),
    ) -> std::pin::Pin<Box<dyn Future<Output = ()> + 'a>>,
{
    let (server_link, mut into, mut out) = create_le_false_link(LeULink::SUPPORTED_MTU.into());

    let (rendezvous_client, rendezvous_server) = directed_rendezvous();

    let server_handle = tokio::spawn(async move {
        let mut att_bearer = server_link.get_att_channel();

        let mut rendez = Box::pin(rendezvous_server.rendez());

        let mut server = Server::new_fixed(LeULink::SUPPORTED_MTU, LeULink::SUPPORTED_MTU, None, NoQueuedWrites);

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

    test(&mut into, &mut out).await;

    rendezvous_client.rendez().await;

    server_handle.await.unwrap();
}

#[tokio::test]
async fn invalid_handles() {
    false_server_connection(|into, out| {
        Box::pin(async {
            for request_data in [
                [0, 0, 0xFF, 0xFF, 1, 0],
                [0, 0, 0, 0, 1, 0],
                [1, 0, 0, 0, 1, 0],
                [2, 0, 1, 0, 1, 0],
                [0xFF, 0xFF, 1, 0, 1, 0],
            ] {
                let fragments =
                    raw_client_fragments(bo_tie_att::client::ClientPduName::ReadByTypeRequest, request_data);

                for fragment in fragments {
                    futures::SinkExt::send(into, fragment)
                        .await
                        .expect("failed to send fragment")
                }

                let response = futures::StreamExt::next(out).await.expect("server stopped");

                let error_pdu: pdu::Pdu<pdu::ErrorResponse> =
                    bo_tie_att::TransferFormatTryFrom::try_from(&response.get_data()[4..]).expect("unexpected pdu");

                assert_eq!(error_pdu.get_parameters().error, pdu::Error::InvalidHandle);
            }
        })
    })
    .await;
}

#[tokio::test]
async fn no_attributes() {
    connect_setup(|channel, client| {
        macro_rules! fake_loop {
            (for $range:ident in [$($elem:expr),* $(,)?] $todo:block) => {
                $({
                    let $range = $elem;

                    $todo
                })*
            };
        }

        Box::pin(async {
            fake_loop!(for range in [10..=0xFFFF, 10..=10] {
                let response_processor = client
                    .read_by_type_request::<_, _, u8>(channel, range, UUID_2)
                    .await
                    .expect("failed to send request");

                let response = channel.receive().await.expect("failed to receive");

                match response_processor.process_response(&response) {
                    Err(bo_tie_att::Error::Pdu(pdu)) => {
                        assert_eq!(pdu.get_parameters().error, pdu::Error::AttributeNotFound)
                    }
                    Err(e) => panic!("unexpected error {:?}", e),
                    Ok(_) => panic!("unexpected find information response"),
                }
            });
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

        server.give_permissions_to_client(client_permission);

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
                connect_permission_setup(&[], |channel, client| {
                    Box::pin(async {
                        let response_processor = client
                            .read_by_type_request::<_, _, $val_ty>(channel, $handle..=$handle, $uuid)
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

                connect_permission_setup(permissions, |channel, client| {
                    Box::pin(async {
                        let response_processor = client
                            .read_by_type_request::<_, _, $val_ty>(channel, $handle..=$handle, $uuid)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive().await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(responses) => assert_eq!(responses.len(), 1),
                        }
                    })
                })
                .await
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

/// This setups the server to be completely filled with the same attribute
///
/// This is for testing the throughput (checking every attribute) of the server with the find
/// information command.
async fn connect_benchmark_setup<Fun>(test: Fun)
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

        let mut client = ConnectFixedClient::connect(&mut att_bearer, <u16>::MAX, <u16>::MAX)
            .await
            .expect("exchange MTU failed");

        test(&mut att_bearer, &mut client).await;

        rendezvous_client.rendez().await;
    });

    let server_handle = tokio::spawn(async move {
        let mut att_bearer = server_link.get_att_channel();

        let mut server_attributes = ServerAttributes::new();

        // note: `..` is used over `..=` as one less than
        // the maximum is desired (handle 0 is reserved).
        for _ in 0..<u16>::MAX {
            server_attributes.push(Attribute::new(UUID_1, FULL_READ_PERMISSIONS, 0u8));
        }

        let mut server = Server::new_fixed(<u16>::MAX, <u16>::MAX, server_attributes, NoQueuedWrites);

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
async fn throughput() {
    connect_benchmark_setup(|channel, client| {
        Box::pin(async {
            for (start, expected_len) in [(1, 21844), (21845, 21844), (43689, 21844)] {
                let response_processor = client
                    .read_by_type_request::<_, _, u8>(channel, start..=0xFFFF, UUID_1)
                    .await
                    .expect("failed to send request");

                let response = channel.receive().await.expect("failed to receive");

                match response_processor.process_response(&response) {
                    Err(e) => panic!("unexpected error {:?}", e),
                    Ok(responses) => assert_eq!(responses.len(), expected_len),
                }
            }
        })
    })
    .await
}
