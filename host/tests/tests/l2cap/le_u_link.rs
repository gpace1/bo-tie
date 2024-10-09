//! Tests for a LE-U Link

use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_l2cap::signalling::ReceivedLeUSignal;
use bo_tie_l2cap::signals::packets::{
    CommandRejectResponse, LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer,
};
use bo_tie_l2cap::{LeULogicalLink, LeUNext, PhysicalLink};

const TEST_DATA: &[u8] = b"Actualis at conscius supponam ac. Vocem si longo mo co veris \
    entis. Similibus essentiae argumenti sum contingit eae praesenti. Spectatum de jactantur \
    veritatis ut. Negans impetu optima nos postea rectum primas una. Actu iste ego lor haec \
    ipsa quia tria meo. Eam unquam vim obstat eamque nia factam manebo. Anima terea ideas tur \
    putem nec nolim aliae imo. Securum cum ultimum eam nul creatum suppono diversi. Vox pluribus \
    jam chimerae acceptis eos utrimque impellit nihilque.";

#[tokio::test]
async fn minimal_fragments() {
    PhysicalLinkLoop::<1>::new()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .use_vec_buffer()
                .build();

            let mut channel = link.get_att_channel().unwrap();

            channel
                .send(TEST_DATA.iter().copied())
                .await
                .expect("failed to send gibberish")
        })
        .set_verify(|mut end| async move {
            let mut bytes = Vec::new();

            while bytes.len() < TEST_DATA.len() {
                let l2cap_fragment = end.recv().await.unwrap().unwrap();

                assert_eq!(l2cap_fragment.get_data().len(), 1);

                let byte: u8 = l2cap_fragment.into_inner().next().unwrap();

                bytes.push(byte)
            }
        })
        .run()
        .await;
}

#[tokio::test]
#[should_panic]
async fn zero_sized_fragments() {
    PhysicalLinkLoop::<0>::new()
        .test_scaffold()
        .set_tested(|_| async {})
        .set_verify(|end| async {
            LeULogicalLink::builder(end).build();
        })
        .run()
        .await
}

#[tokio::test]
async fn le_u_logical_link_unused_channels() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_unused_fixed_channel_response()
                .build();

            let next = link.next().await.unwrap();

            panic!("unexpectedly received {next:?}");
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
