//! Tests for the find by type value request/response

use bo_tie_att::client::ResponseProcessor;
use bo_tie_att::server::NoQueuedWrites;
use bo_tie_att::{ConnectFixedClient, FULL_READ_PERMISSIONS};
use bo_tie_gatt::characteristic::Properties;
use bo_tie_gatt::{GapServiceBuilder, ServerBuilder};
use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};

macro_rules! connect_setup {
    (|$link:ident, $client:ident| $action:block ) => {{
        PhysicalLinkLoop::default()
            .test_scaffold()
            .set_tested(|end| async {
                let mut link = LeULogicalLink::builder(end)
                    .enable_attribute_channel()
                    .use_vec_buffer()
                    .build();

                let mut server_builder: ServerBuilder = GapServiceBuilder::new("full_discovery_of_server", None).into();

                let service_data = server_builder
                    .add_service(0x1001u16)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                            .set_value(|v| v.set_value(11u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                            .set_value(|v| v.set_value(12u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                // these and subsequent asserts in `set_tested` are really just for handle info
                assert_eq!(service_data.get_handle(), 6);
                assert_eq!(service_data.get_end_group_handle(), 10);

                let service_data = server_builder
                    .add_service(0x1002u16)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2021u16))
                            .set_value(|v| v.set_value(21u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2022u16))
                            .set_value(|v| v.set_value(22u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                assert_eq!(service_data.get_handle(), 11);
                assert_eq!(service_data.get_end_group_handle(), 15);

                let service_data = server_builder
                    .add_service(0x1001u16)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                            .set_value(|v| v.set_value(31u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                            .set_value(|v| v.set_value(32u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                assert_eq!(service_data.get_handle(), 16);
                assert_eq!(service_data.get_end_group_handle(), 20);

                let service_data = server_builder
                    .add_service(0x675b8edd491f4affaf3f2d2158c1025cu128)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| {
                            d.set_properties([Properties::Read])
                                .set_uuid(0xea2a1a67b13d47599edd02ad70a05fbeu128)
                        })
                        .set_value(|v| v.set_value(41u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| {
                            d.set_properties([Properties::Read])
                                .set_uuid(0x3cb3782235b4401ea1e1add02a8ad344u128)
                        })
                        .set_value(|v| v.set_value(42u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                assert_eq!(service_data.get_handle(), 21);
                assert_eq!(service_data.get_end_group_handle(), 25);

                let service_data = server_builder
                    .add_service(0x1003u16)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                            .set_value(|v| v.set_value(11u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                            .set_value(|v| v.set_value(12u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                assert_eq!(service_data.get_handle(), 26);
                assert_eq!(service_data.get_end_group_handle(), 30);

                let service_data = server_builder
                    .add_service(0x1004u16)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2021u16))
                            .set_value(|v| v.set_value(21u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2022u16))
                            .set_value(|v| v.set_value(22u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                assert_eq!(service_data.get_handle(), 31);
                assert_eq!(service_data.get_end_group_handle(), 35);

                let service_data = server_builder
                    .add_service(0x1001u16)
                    .add_characteristics()
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2011u16))
                            .set_value(|v| v.set_value(31u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .new_characteristic(|c| {
                        c.set_declaration(|d| d.set_properties([Properties::Read]).set_uuid(0x2012u16))
                            .set_value(|v| v.set_value(32u32).set_permissions(FULL_READ_PERMISSIONS))
                    })
                    .finish_service()
                    .as_record();

                assert_eq!(service_data.get_handle(), 36);
                assert_eq!(service_data.get_end_group_handle(), 40);

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
            .await
    }};
}

macro_rules! test {
    ($link:expr, $client:expr, $range:expr, $uuid:expr, $value:expr, |$response:ident| $test:block) => {{
        let channel = &mut $link.get_att_channel().unwrap();

        let response_processor = $client
            .find_by_type_value_request(channel, $range, $uuid, $value)
            .await
            .expect("failed to send request");

        let response = match $link.next().await.unwrap() {
            LeUNext::AttributeChannel { pdu, .. } => pdu,
            next => panic!("received unexpected {next:?}"),
        };

        let response = response_processor
            .process_response(&response)
            .expect("invalid response");

        (|$response: Vec<bo_tie_att::pdu::TypeValueResponse>| $test)(response)
    }};
}

#[tokio::test]
async fn find_primary_services_success() {
    // Note: all responses will not have a `group end handle`
    // as that is defined by a higher layer specification.
    connect_setup!(|link, client| {
        test!(
            link,
            client,
            1..=0xFFFF,
            Uuid::from(0x2800u16),
            Uuid::from(0x1001u16),
            |responses| {
                let response = responses.get(0).unwrap();

                assert_eq!(response.get_handle(), 6);
                assert_eq!(response.get_end_group_handle(), 10);

                let response = responses.get(1).unwrap();

                assert_eq!(response.get_handle(), 16);
                assert_eq!(response.get_end_group_handle(), 20);

                let response = responses.get(2).unwrap();

                assert_eq!(response.get_handle(), 36);
                assert_eq!(response.get_end_group_handle(), 40);

                assert!(responses.get(3).is_none());
            }
        );
    })
}

#[tokio::test]
async fn find_characteristics_success() {
    connect_setup!(|link, client| {
        test!(
            link,
            client,
            1..=0xFFFF,
            Uuid::from(0x2803u16),
            Uuid::from(0x2011u16),
            |responses| {
                let response = responses.get(0).unwrap();

                assert_eq!(response.get_handle(), 7);
                assert_eq!(response.get_end_group_handle(), 8);

                let response = responses.get(1).unwrap();

                assert_eq!(response.get_handle(), 17);
                assert_eq!(response.get_end_group_handle(), 18);

                let response = responses.get(2).unwrap();

                assert_eq!(response.get_handle(), 27);
                assert_eq!(response.get_end_group_handle(), 28);

                let response = responses.get(3).unwrap();

                assert_eq!(response.get_handle(), 37);
                assert_eq!(response.get_end_group_handle(), 38);
            }
        )
    })
}
