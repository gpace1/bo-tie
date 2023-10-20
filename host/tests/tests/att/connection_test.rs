//! Test `test_connection`
//!
//! This test is for a client and server successfully communicating with each other. This is a test
//! for a general operation of the Attribute protocol.

use bo_tie_att::server::{NoQueuedWrites, ServerAttributes};
use bo_tie_att::{
    Attribute, AttributePermissions, AttributeRestriction, Client, ConnectFixedClient, Server, TransferFormatInto,
    TransferFormatTryFrom,
};
use bo_tie_host_tests::Rendezvous;
use bo_tie_host_tests::{create_le_link, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::time::Duration;

const UUID_1: Uuid = Uuid::from_u16(1);
const UUID_2: Uuid = Uuid::from_u16(2);
const UUID_3: Uuid = Uuid::from_u16(3);

#[tokio::test]
async fn test_connection() {
    let (client, server) = create_le_link(LeULink::SUPPORTED_MTU.into());

    let (rendezvous_client, rendezvous_server) = bo_tie_host_tests::directed_rendezvous();

    let handle_client = tokio::spawn(test_connection_client(client, rendezvous_client));

    let handle_server = tokio::spawn(test_connection_server(server, rendezvous_server));

    handle_client.await.unwrap();

    handle_server.await.unwrap();
}

async fn test_connection_client(link: LeULogicalLink<PhysicalLink>, rendezvous: Rendezvous) {
    let timeout = Duration::from_millis(500);
    let test_val_1: usize = 33;
    let test_val_2: u64 = 64;
    let test_val_3: i8 = -118;

    let mut att_bearer = link.get_att_channel();

    let connect_client = ConnectFixedClient::connect(&mut att_bearer, LeULink::SUPPORTED_MTU, 64);

    let mut client = tokio::time::timeout(timeout, connect_client)
        .await
        .expect("connect timeout")
        .expect("failed to connect client");

    let handle_1 = get_handle(&mut att_bearer, &mut client, UUID_1).await;

    assert_eq!(handle_1, 1);

    let handle_2 = get_handle(&mut att_bearer, &mut client, UUID_2).await;

    assert_eq!(handle_2, 2);

    let handle_3 = get_handle(&mut att_bearer, &mut client, UUID_3).await;

    assert_eq!(handle_3, 3);

    write_request(&mut att_bearer, &mut client, handle_1, test_val_1).await;

    write_request(&mut att_bearer, &mut client, handle_2, test_val_2).await;

    write_request(&mut att_bearer, &mut client, handle_3, test_val_3).await;

    let read_val_1: usize = read_att_type(&mut att_bearer, &mut client, UUID_1).await.1;

    let read_val_2: u64 = read_att_type(&mut att_bearer, &mut client, UUID_2).await.1;

    let read_val_3: i8 = read_att_type(&mut att_bearer, &mut client, UUID_3).await.1;

    assert_eq!(test_val_1, read_val_1, "test and read val 1 do not match");

    assert_eq!(test_val_2, read_val_2, "test and read val 2 do not match");

    assert_eq!(test_val_3, read_val_3, "test and read val 3 do not match");

    rendezvous.rendez().await;
}

async fn test_connection_server(link: LeULogicalLink<PhysicalLink>, rendezvous: Rendezvous) {
    let attribute_0: Attribute<usize> = Attribute::new(
        UUID_1,
        [
            AttributePermissions::Read(AttributeRestriction::None),
            AttributePermissions::Write(AttributeRestriction::None),
        ]
        .to_vec(),
        0usize,
    );

    let attribute_1: Attribute<u64> = Attribute::new(
        UUID_2,
        [
            AttributePermissions::Read(AttributeRestriction::None),
            AttributePermissions::Write(AttributeRestriction::None),
        ]
        .to_vec(),
        0u64,
    );

    let attribute_2: Attribute<i8> = Attribute::new(
        UUID_3,
        [
            AttributePermissions::Read(AttributeRestriction::None),
            AttributePermissions::Write(AttributeRestriction::None),
        ]
        .to_vec(),
        0i8,
    );

    let mut att_channel = link.get_att_channel();

    let mut server_attributes = ServerAttributes::new();

    assert_eq!(server_attributes.push(attribute_0), 1);
    assert_eq!(server_attributes.push(attribute_1), 2);
    assert_eq!(server_attributes.push(attribute_2), 3);

    let mut server = Server::new_fixed(
        LeULink::SUPPORTED_MTU,
        LeULink::SUPPORTED_MTU,
        server_attributes,
        NoQueuedWrites,
    );

    let mut rendez = Box::pin(rendezvous.rendez());

    let buffer = &mut Vec::new();

    loop {
        tokio::select! {
            _ = &mut rendez => break,

            rx = att_channel.receive(buffer) => {
                server.process_att_pdu(&mut att_channel, &rx.expect("channel error")).await.expect("att server error");
            }
        }
    }
}

/*
 * Helper methods for the client to read and write with the server
 */
pub async fn read_att_type<D: TransferFormatTryFrom + TransferFormatInto>(
    channel: &mut BasicFrameChannel<'_, LeULogicalLink<PhysicalLink>>,
    client: &mut Client,
    uuid: Uuid,
) -> (u16, D) {
    use bo_tie_att::client::ResponseProcessor;

    let response_processor = client
        .read_by_type_request::<_, _, D>(channel, 1..0xFFFF, uuid)
        .await
        .expect(format!("failed to read type ({:x})", uuid).as_str());

    let b_frame = channel.receive(&mut Vec::new()).await.expect("failed to get response");

    let read_type_response = response_processor
        .process_response(&b_frame)
        .expect("failed to process response");

    let first = read_type_response.into_iter().next().expect("no items in response");

    (first.get_handle(), first.into_inner())
}

pub async fn get_handle(
    channel: &mut BasicFrameChannel<'_, LeULogicalLink<PhysicalLink>>,
    client: &mut Client,
    uuid: Uuid,
) -> u16 {
    read_att_type::<Vec<u8>>(channel, client, uuid).await.0
}

pub async fn write_request<D: TransferFormatTryFrom + TransferFormatInto>(
    channel: &mut BasicFrameChannel<'_, LeULogicalLink<PhysicalLink>>,
    client: &mut Client,
    handle: u16,
    data: D,
) {
    use bo_tie_att::client::ResponseProcessor;

    let response_processor = client
        .write_request(channel, handle, data)
        .await
        .expect("failed to write test val 1");

    let b_frame = channel.receive(&mut Vec::new()).await.expect("failed to get response");

    response_processor
        .process_response(&b_frame)
        .expect("failed to process response");
}
