//! tests for read by group type request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::NoQueuedWrites;
use bo_tie_att::{ConnectFixedClient, FULL_PERMISSIONS};
use bo_tie_gatt::characteristic::Properties;
use bo_tie_gatt::{Client, GapServiceBuilder, ServerBuilder};
use bo_tie_host_tests::{create_le_link, directed_rendezvous, PhysicalLink};
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{BasicFrameChannel, LeULogicalLink};
use std::future::Future;

const SERVICE_1: Uuid = Uuid::from_u16(10);

const SERVICE_2: Uuid = Uuid::from_u16(20);

const SERVICE_1_CHARACTERISTIC_1: Uuid = Uuid::from_u16(111);
const SERVICE_1_CHARACTERISTIC_2: Uuid = Uuid::from_u16(112);
const SERVICE_1_CHARACTERISTIC_3: Uuid = Uuid::from_u16(113);

const SERVICE_2_CHARACTERISTIC_1: Uuid = Uuid::from_u16(121);
const SERVICE_2_CHARACTERISTIC_2: Uuid = Uuid::from_u16(122);
const SERVICE_2_CHARACTERISTIC_3: Uuid = Uuid::from_u16(123);
const SERVICE_2_CHARACTERISTIC_4: Uuid = Uuid::from_u16(124);

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
            .expect("exchange MTU failed")
            .into();

        test(&mut att_bearer, &mut client).await;

        rendezvous_client.rendez().await;
    });

    let server_handle = tokio::spawn(async move {
        let mut att_bearer = server_link.get_att_channel();

        let gatt_service = GapServiceBuilder::new("test device", 0);

        let mut server_builder: ServerBuilder = gatt_service.into();

        let record = server_builder
            .new_service(SERVICE_1)
            .add_characteristics()
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_1_CHARACTERISTIC_1)
                    })
                    .set_value(|value_builder| value_builder.set_value(0u32).set_permissions(FULL_PERMISSIONS))
            })
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_1_CHARACTERISTIC_2)
                    })
                    .set_value(|value_builder| value_builder.set_value(1u32).set_permissions(FULL_PERMISSIONS))
            })
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_1_CHARACTERISTIC_3)
                    })
                    .set_value(|value_builder| value_builder.set_value(2u32).set_permissions(FULL_PERMISSIONS))
            })
            .finish_service()
            .as_record();

        server_builder
            .new_service(SERVICE_2)
            .into_includes_adder()
            .include_service(record)
            .unwrap()
            .add_characteristics()
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_2_CHARACTERISTIC_1)
                    })
                    .set_value(|value_builder| value_builder.set_value(3u64).set_permissions(FULL_PERMISSIONS))
            })
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_2_CHARACTERISTIC_2)
                    })
                    .set_value(|value_builder| value_builder.set_value(4u64).set_permissions(FULL_PERMISSIONS))
            })
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_2_CHARACTERISTIC_3)
                    })
                    .set_value(|value_builder| value_builder.set_value(5u64).set_permissions(FULL_PERMISSIONS))
            })
            .new_characteristic(|characteristic_builder| {
                characteristic_builder
                    .set_declaration(|declaration_builder| {
                        declaration_builder
                            .set_properties([Properties::Read, Properties::Write])
                            .set_uuid(SERVICE_2_CHARACTERISTIC_4)
                    })
                    .set_value(|value_builder| value_builder.set_value(6u64).set_permissions(FULL_PERMISSIONS))
            })
            .finish_service();

        let mut server = server_builder.make_server(NoQueuedWrites);

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
async fn discovery_success() {
    connect_setup(|channel, client| {
        Box::pin(async {
            loop {
                let query_next = client.partial_discovery(channel).await.expect("failed to send query");

                let response = channel.receive().await.expect("failed to receive response");

                if query_next.process_response(&response).expect("unexpected response") {
                    break;
                }
            }

            let services = client.get_known_services();

            assert_eq!(bo_tie_gatt::uuid::gap::GAP_SERVICE, services[0].get_uuid());
            assert_eq!(SERVICE_1, services[1].get_uuid());
            assert_eq!(SERVICE_2, services[2].get_uuid());
        })
    })
    .await
}
