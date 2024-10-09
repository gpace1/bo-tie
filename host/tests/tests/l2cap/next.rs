//! Tests for the `next` methods

use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_l2cap::cid::{ChannelIdentifier, LeCid};
use bo_tie_l2cap::signalling::ReceivedLeUSignal;
use bo_tie_l2cap::signals::packets::{
    CommandRejectResponse, LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer,
};
use bo_tie_l2cap::{LeULogicalLink, LeUNext};

#[tokio::test]
async fn le_u_logical_link_next() {
    let mut requested_channel = None;
    let mut received_channel = None;

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut channel = link.get_signalling_channel().unwrap();

            let connection_request = channel
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(34),
                    5,
                )
                .await
                .unwrap();

            requested_channel = connection_request.get_source_cid().into();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let received = link.next().await.unwrap();

            let LeUNext::SignallingChannel { signal, channel } = received else {
                panic!("expected signalling channel")
            };

            assert_eq!(
                ChannelIdentifier::Le(LeCid::LeSignalingChannel),
                channel.get_channel_id()
            );

            let ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) = signal else {
                panic!("expected 'LeCreditBasedConnectionRequest`, received {signal:?}");
            };

            assert_eq!(1, request.identifier.get());

            received_channel = request.get_source_cid().into();
        })
        .run()
        .await;

    assert_eq!(received_channel, requested_channel);
}

#[tokio::test]
async fn le_u_logical_link_unused_channels() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            LeULogicalLink::builder(end)
                .enable_unused_fixed_channel_response()
                .build()
                .next()
                .await
                .unwrap();

            panic!("tested ")
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .enable_signalling_channel()
                .enable_security_manager_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let find_info_request = [0x4, 0x0, 0x0, 0xFF, 0xFF];

            link.get_att_channel().unwrap().send(find_info_request).await.unwrap();

            let next = link.next().await.unwrap();

            let LeUNext::AttributeChannel { pdu: att_pdu, .. } = next else {
                panic!("expected attribute channel data")
            };

            // [error opcode, request opcode, handle_0, handle_1, error code]
            assert_eq!(att_pdu.get_payload(), &[0x1, 0x4, 0x0, 0x0, 0x6]);

            link.get_signalling_channel()
                .unwrap()
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(34),
                    5,
                )
                .await
                .unwrap();

            let next = link.next().await.unwrap();

            let LeUNext::SignallingChannel { signal, .. } = next else {
                panic!("expected signalling channel data")
            };

            let ReceivedLeUSignal::CommandRejectRsp(response) = signal else {
                panic!("expected CommandRejectRsp")
            };

            assert_eq!(
                response.into_inner(),
                CommandRejectResponse::new_command_not_understood(core::num::NonZeroU8::new(1).unwrap())
            );

            let pairing_request = [0x1, 0x0, 0x0, 0xD, 0x10, 0x02, 0x02];

            link.get_security_manager_channel()
                .unwrap()
                .send(pairing_request)
                .await
                .unwrap();

            let next = link.next().await.unwrap();

            let LeUNext::SecurityManagerChannel { pdu: sm_pdu, .. } = next else {
                panic!("expected security manager channel data")
            };

            assert_eq!(sm_pdu.get_payload(), &[0x5, 0x5])
        })
        .run()
        .await;
}
