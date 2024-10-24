//! tests-scaffold for read by group type request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::NoQueuedWrites;
use bo_tie_att::{ConnectFixedClient, FULL_PERMISSIONS};
use bo_tie_gatt::characteristic::Properties;
use bo_tie_gatt::{GapServiceBuilder, ServerBuilder};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext, PhysicalLink};

#[tokio::test]
async fn service_discovery_success() {
    const SERVICE_1: Uuid = Uuid::from_u16(10);

    const SERVICE_2: Uuid = Uuid::from_u16(20);

    const SERVICE_1_CHARACTERISTIC_1: Uuid = Uuid::from_u16(111);
    const SERVICE_1_CHARACTERISTIC_2: Uuid = Uuid::from_u16(112);
    const SERVICE_1_CHARACTERISTIC_3: Uuid = Uuid::from_u16(113);

    const SERVICE_2_CHARACTERISTIC_1: Uuid = Uuid::from_u16(121);
    const SERVICE_2_CHARACTERISTIC_2: Uuid = Uuid::from_u16(122);
    const SERVICE_2_CHARACTERISTIC_3: Uuid = Uuid::from_u16(123);
    const SERVICE_2_CHARACTERISTIC_4: Uuid = Uuid::from_u16(124);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let gap_service = GapServiceBuilder::new("test device", 0);

            let mut server_builder: ServerBuilder = gap_service.into();

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

            let connect = ConnectFixedClient::initiate(channel, LeULink::SUPPORTED_MTU, LeULink::SUPPORTED_MTU)
                .await
                .unwrap();

            let mut client = match link.next().await.unwrap() {
                LeUNext::AttributeChannel { pdu, .. } => {
                    ::bo_tie_gatt::Client::from(connect.create_client(&pdu).unwrap())
                }
                next => panic!("received unexpected {next:?}"),
            };

            loop {
                let channel = &mut link.get_att_channel().unwrap();

                let query_next = client
                    .partial_service_discovery(channel)
                    .await
                    .expect("failed to send query");

                let response = match link.next().await.unwrap() {
                    LeUNext::AttributeChannel { pdu, .. } => pdu,
                    next => panic!("received unexpected {next:?}"),
                };

                if query_next.process_response(&response).expect("unexpected response") {
                    break;
                }
            }

            let services = client.get_known_services();

            assert_eq!(bo_tie_gatt::uuid::gap::GAP_SERVICE, services[0].get_uuid());
            assert_eq!(SERVICE_1, services[1].get_uuid());
            assert_eq!(SERVICE_2, services[2].get_uuid());
        })
        .run()
        .await;
}

macro_rules! pdu_len {
    ($a:tt $(,)?) => {1};
    ($a:tt, $($b:tt),+ $(,)?) => { ( pdu_len!($($b),+) + 1 ) }
}

macro_rules! fragment {
    ($($data:expr),*) => {
        ::bo_tie_l2cap::pdu::L2capFragment::new(
            true,
            [ pdu_len!($($data),*), 0, 4, 0, $($data),* ]
        )
    };
}

macro_rules! test {
    ($end:expr; $($sent_byte:expr),* $(,)? => $($expected_recv_byte:expr),* $(,)?) => {{
        let sent = fragment!($($sent_byte),*);

        $end.send(sent).await.unwrap();

        let response = $end.recv().await
            .unwrap()
            .unwrap()
            .into_inner()
            .collect::<Vec<u8>>();

        assert_eq!(&[$($expected_recv_byte),*], &response[4..])
    }};
}
#[tokio::test]
async fn discover_primary_services_of_server() {
    PhysicalLinkLoop::<256>::new()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let mut server_builder: ServerBuilder = GapServiceBuilder::new("full_discovery_of_server", None).into();

            server_builder
                .new_service(0x1001u16)
                .add_characteristics()
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                        .set_value(|v| v.set_value(11u32).set_permissions(FULL_PERMISSIONS))
                })
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                        .set_value(|v| v.set_value(12u32).set_permissions(FULL_PERMISSIONS))
                })
                .finish_service();

            server_builder
                .new_service(0x1002u16)
                .add_characteristics()
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2021u16))
                        .set_value(|v| v.set_value(21u32).set_permissions(FULL_PERMISSIONS))
                })
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2022u16))
                        .set_value(|v| v.set_value(22u32).set_permissions(FULL_PERMISSIONS))
                })
                .finish_service();

            let mut server = server_builder.make_server(NoQueuedWrites);

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
            // discover primary services
            test!(
                end;
                0x10, 0x1, 0x0, 0xff, 0xff, 0x00, 0x28
                => 0x11, 6,
                    0x1, 0x0, 0x5, 0, 0x00, 0x18, // gap service
                    0x6, 0x0, 0xa, 0x0, 0x1, 0x10, // service 0x1001
                    0xb, 0x0, 0xf, 0x0, 0x2, 0x10, // service 0x1002
                    0x10, 0x0, 0x10, 0x0, 0x1, 0x18, // GattServer tacked on gatt service
            );
        })
        .run()
        .await
}

#[tokio::test]
async fn discover_primary_service_by_uuid_of_server() {
    PhysicalLinkLoop::<256>::new()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let mut server_builder: ServerBuilder = GapServiceBuilder::new("full_discovery_of_server", None).into();

            server_builder
                .new_service(0x1001u16)
                .add_characteristics()
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                        .set_value(|v| v.set_value(11u32).set_permissions(FULL_PERMISSIONS))
                })
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                        .set_value(|v| v.set_value(12u32).set_permissions(FULL_PERMISSIONS))
                })
                .finish_service();

            server_builder
                .new_service(0x1002u16)
                .add_characteristics()
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2021u16))
                        .set_value(|v| v.set_value(21u32).set_permissions(FULL_PERMISSIONS))
                })
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2022u16))
                        .set_value(|v| v.set_value(22u32).set_permissions(FULL_PERMISSIONS))
                })
                .finish_service();

            server_builder
                .new_service(0x1001u16)
                .add_characteristics()
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                        .set_value(|v| v.set_value(31u32).set_permissions(FULL_PERMISSIONS))
                })
                .new_characteristic(|c| {
                    c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                        .set_value(|v| v.set_value(32u32).set_permissions(FULL_PERMISSIONS))
                })
                .finish_service();

            let mut server = server_builder.make_server(NoQueuedWrites);

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
            // GATT service uuid (0x1801u16)
            test!(
                end;
                0x6, 0x1, 0x0, 0xFF, 0xFF, 0x00, 0x28, 0x1, 0x18
                => 0x7, 0x15, 0x0, 0x15, 0x0
            );

            // service with uuid 0x1001
            test!(
                end;
                0x6, 0x1, 0x0, 0xff, 0xff, 0x00, 0x28, 0x01, 0x10
                => 0x7, 0x6, 0x0, 0xa, 0x0, 0x10, 0x0, 0x14, 0x0
            )
        })
        .run()
        .await
}
