//! Tests for the find information request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::pdu::{FormattedHandlesWithType, HandleWithType};
use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    pdu, Attribute, AttributePermissions, AttributeRestriction, Client, ConnectFixedClient, EncryptionKeySize, Server,
    FULL_READ_PERMISSIONS,
};
use bo_tie_host_tests::{create_le_false_link, create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::{BasicFrame, FragmentIterator, L2capFragment};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;

const UUID_SHORT_1: Uuid = Uuid::from_u16(1);

const UUID_SHORT_2: Uuid = Uuid::from_u16(2);

const UUID_SHORT_3: Uuid = Uuid::from_u16(3);

const UUID_FULL_1: Uuid = Uuid::from_u128(1);

const UUID_FULL_2: Uuid = Uuid::from_u128(2);

const UUID_FULL_3: Uuid = Uuid::from_u128(3);

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
        fragments.next().map(|data| {
            let is_first = first;

            first = false;

            L2capFragment::new(is_first, data.collect())
        })
    })
}

#[tokio::test]
async fn find_success() {
    connect_setup(|channel, client| {
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
                let response_processor = client
                    .find_information_request(channel, $range)
                    .await
                    .expect("failed to send request");

                let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

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

        Box::pin(async {
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
    })
    .await
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

    test(&mut into, &mut out).await;

    rendezvous_client.rendez().await;

    server_handle.await.unwrap();
}

#[tokio::test]
async fn invalid_handles() {
    false_server_connection(|into, out| {
        Box::pin(async {
            for request_data in [
                [0, 0, 0xFF, 0xFF],
                [0, 0, 0, 0],
                [1, 0, 0, 0],
                [2, 0, 1, 0],
                [0xFF, 0xFF, 1, 0],
            ] {
                let fragments =
                    raw_client_fragments(bo_tie_att::client::ClientPduName::FindInformationRequest, request_data);

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
            fake_loop!(for range in [7..=0xFFFF, 7..=7] {
                let response_processor = client
                    .find_information_request(channel, range)
                    .await
                    .expect("failed to send request");

                let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

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
                connect_permission_setup(&[], |channel, client| {
                    Box::pin(async {
                        let response_processor = client
                            .find_information_request(channel, $handle..=0xFFFF)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

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
                            .find_information_request(channel, $handle..=0xFFFF)
                            .await
                            .expect("failed to send request");

                        let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

                        match response_processor.process_response(&response) {
                            Err(e) => panic!("unexpected error {:?}", e),
                            Ok(FormattedHandlesWithType::HandlesWithFullUuids(mut response)) |
                            Ok(FormattedHandlesWithType::HandlesWithShortUuids(mut response)) => {
                                let first = response.pop().expect("unexpected empty response");

                                assert_eq!(first.get_handle(), $handle);
                            },
                        }
                    })
                })
                .await
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
            server_attributes.push(Attribute::new(UUID_SHORT_1, FULL_READ_PERMISSIONS, 0u8));
        }

        let mut server = Server::new_fixed(<u16>::MAX, <u16>::MAX, server_attributes, NoQueuedWrites);

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
#[cfg_attr(miri, ignore)]
async fn throughput() {
    connect_benchmark_setup(|channel, client| {
        Box::pin(async {
            for (start, expected_len) in [(1, 16383), (16384, 16383), (32767, 16383), (49150, 16383)] {
                let response_processor = client
                    .find_information_request(channel, start..=0xFFFF)
                    .await
                    .expect("failed to send request");

                let response = channel.receive(&mut Vec::new()).await.expect("failed to receive");

                match response_processor.process_response(&response) {
                    Err(e) => panic!("unexpected error {:?}", e),
                    Ok(FormattedHandlesWithType::HandlesWithFullUuids(response))
                    | Ok(FormattedHandlesWithType::HandlesWithShortUuids(response)) => {
                        assert_eq!(response.len(), expected_len)
                    }
                }
            }
        })
    })
    .await
}
