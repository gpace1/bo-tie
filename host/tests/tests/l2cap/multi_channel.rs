//! Tests for multiple channels sending/receiving at the same time

use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_l2cap::cid::{ChannelIdentifier, LeCid};
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::{
    BasicFrame, ControlFrame, CreditBasedSdu, FragmentIterator, FragmentL2capPdu, FragmentL2capSdu, L2capFragment,
    SduPacketsIterator,
};
use bo_tie_l2cap::signalling::ReceivedLeUSignal;
use bo_tie_l2cap::signals::packets::CommandRejectReason;
use bo_tie_l2cap::{CreditBasedChannelNext, LeULogicalLink, LeUNext, PhysicalLink};
use std::cmp::{max, min};
use std::pin::pin;

const TEST_MESSAGE_ATT: &[u8] = b"this is a test message sent to the ATT channel";

const TEST_MESSAGE_CREDIT_CHANNEL_1: &[u8] = b"
this is a test message sent to the first credit based channel. It is purposely long as to 
force the credit based channel to send this SDU over multiple credit based frames. This allows for
mixing and matching of frames between different channels to properly test this .... bla bla bla ...

Curant id qualem humana et nequit facile. Volo vul sit sap esto quid. Credo cujus vobis nasci ad ii.
Ut parentibus ad permiscent affirmarem cucurbitas attigerint si religionis. Ope immortalem 
quaerantur mei contrariae. Lucis terra ac entis du varia lucem situm. Quoties usu tes nutriri 
numquam vim viribus. To veri ne ex duce deus nego rari.

Infixa ac de mellis at habeam humana in. Momentis sequitur eas sua ulterius probatur cum. Quaeque 
poterit vim cognitu via possunt qua. Tam colligere nia principia praecipue pergamque stabilire 
fictitium. Lucem ii operi edita leone porro novum ab. Hae quavis hic tam essent quidam altius multis
tum. 
";

const TEST_MESSAGE_CREDIT_CHANNEL_2: &[u8] = b"
this is a test message sent to the second credit based channel. It is purposely long as to 
force the credit based channel to send this SDU over multiple credit based frames. This allows for
mixing and matching of frames between different channels to properly test this .... bla bla bla ...

Omnis vapor gi ipsos at eo aucta at minus illud. Sed humanam prudens sciamus res ineunte sum sopitum
hic. Habentur sed periculi per tum tenebras seu incipere. Varietates dissolvant agnoscerem ei
praecipuas durationem at. Supersunt recurrunt affirmans occasione mo ad is in infinitam. Quibusnam
lor alligatus sub dei tollentur sed. Vox iis age pretium fuerunt formali hominem. Is haec quos et
illa quam ut utor loco me. Si liberius et gi admoneri importat. Aliunde du indutum et gallico im
angelos ii timenda dormiam.

Curant id qualem humana et nequit facile. Volo vul sit sap esto quid. Credo cujus vobis nasci ad ii.
Ut parentibus ad permiscent affirmarem cucurbitas attigerint si religionis. Ope immortalem
quaerantur mei contrariae. Lucis terra ac entis du varia lucem situm. Quoties usu tes nutriri
numquam vim viribus. To veri ne ex duce deus nego rari.

Infixa ac de mellis at habeam humana in. Momentis sequitur eas sua ulterius probatur cum. Quaeque
poterit vim cognitu via possunt qua. Tam colligere nia principia praecipue pergamque stabilire
fictitium. Lucem ii operi edita leone porro novum ab. Hae quavis hic tam essent quidam altius multis
tum.

Dominum quamdiu ut at caeteri similes. Mox scientiam pla chimaeram nos existenti argumenti. Has
juncta iis ferant atheis urgeat existi dictam. Saporem ii interim dignati assideo ii idearum et ex.
At supponant praeterea ac geometras differant persuasum to. Lectorum fallebar ha de an id dependet.

Sentiens intuebar ineptire ea du tangitur. Multi mo inter plane du an. Is at bitavi auditu oculis at
istius primas ad. Diversis dei eam noluisse totumque nia non postquam. Potuerit rationis methodum
imponere sex una supponam. Infiniti ignorata se parentes liberius is reliquas ea eo tangimus.
Discrimen societati persuasus im de is differant aggredior existimem.

Cap hos fidem imo versa mem nolle. Forte id is ea situs aciem si brevi ipsas eorum. Hocque eos
contra essent realis cau. Innatas nec meipsum cui mallent futurus cum videtur. Nulli etiam du novas
vetus at tanti. Velitis ad vi referam judicio similia credidi in. Non fuse apud data opus hos nolo
quos. In haec sola foco fore at ac ecce. Corpora ab angelos odoratu ei cognitu co. Humani seriem
ingens dum sic usu hocque dem.
";

macro_rules! send_att_data {
    ($data:expr, $end:expr) => {
        async {
            let data = BasicFrame::new($data, ::bo_tie_att::LE_U_FIXED_CHANNEL_ID);

            let mut fragments = data.into_fragments($end.max_transmission_size().into()).unwrap();

            let mut first = true;

            while let Some(fragment) = fragments.next() {
                let l2cap_fragment = L2capFragment::new(first, fragment);

                first = false;

                $end.send(l2cap_fragment).await.unwrap();
            }
        }
    };
}

macro_rules! send_raw_signal {
    ($raw_signal:expr, $end:expr) => {
        async {
            let data = ControlFrame::new($raw_signal, ::bo_tie_l2cap::signals::LE_U_SIGNAL_CHANNEL_ID);

            let mut fragments = data.into_fragments($end.max_transmission_size().into()).unwrap();

            let mut first = true;

            while let Some(fragment) = fragments.next() {
                let l2cap_fragment = L2capFragment::new(first, fragment);

                first = false;

                $end.send(l2cap_fragment).await.unwrap();
            }
        }
    };
}

macro_rules! send_credit_frame {
    ($k_frame:expr, $end:expr) => {
        async {
            let mut fragments = $k_frame.into_fragments($end.max_transmission_size().into()).unwrap();

            let mut first = true;

            while let Some(fragment) = fragments.next() {
                let l2cap_fragment = L2capFragment::new(first, fragment);

                first = false;

                $end.send(l2cap_fragment).await.unwrap();
            }
        }
    };
}
macro_rules! send_sdu_no_credit_check {
    ($sdu:expr, $channel_id:expr, $mps: expr, $end:expr, $pdu_count:expr) => {
        async {
            let sdu = CreditBasedSdu::new($sdu, $channel_id, $mps);

            let mut packets = sdu.into_packets().unwrap();

            let mut count: usize = $pdu_count;

            loop {
                if count == 0 {
                    break;
                }

                let Some(packet) = packets.next() else { break };

                count -= 1;

                send_credit_frame!(packet, $end).await;
            }

            packets
        }
    };
}

macro_rules! recv_le_connect_response {
    ($end:expr, $expected_credits:expr) => {
        async {
            let mut connect_response = Vec::with_capacity(18);

            while connect_response.len() < 18 {
                let fragment = $end.recv().await.unwrap().unwrap();

                connect_response.extend(fragment.into_inner())
            }

            // check the code
            assert_eq!(connect_response[4], 0x15);

            // check the credits
            assert_eq!(
                <u16>::from_le_bytes([connect_response[14], connect_response[15]]),
                $expected_credits
            );

            // check the response
            assert_eq!(<u16>::from_le_bytes([connect_response[16], connect_response[17]]), 0);

            LeULink::try_channel_from_raw(<u16>::from_le_bytes([connect_response[8], connect_response[9]])).unwrap()
        }
    };
}

/// Test for multiple channels receiving at the "same time"
#[tokio::test]
async fn le_multiple_receiving() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            send_att_data!(TEST_MESSAGE_ATT.iter().copied(), end).await;

            // connect request for first channel
            send_raw_signal!([0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0xFF, 0xFF, 23, 0, 0xFF, 0xFF], end).await;

            let peer_cid_1 = recv_le_connect_response!(end, <u16>::MAX).await;

            // sending 4 fragments to the first channel
            let mut c1_packets = send_sdu_no_credit_check!(
                TEST_MESSAGE_CREDIT_CHANNEL_1.iter().copied(),
                peer_cid_1,
                23,
                end,
                4 // number of k-frames sent in macro expansion
            )
            .await;

            // connect request for second channel
            send_raw_signal!([0x14, 1, 10, 0, 0x80, 0, 0x41, 0, 0xFF, 0xFF, 23, 0, 10, 0], end).await;

            let peer_cid_2 = recv_le_connect_response!(end, <u16>::MAX).await;

            // not sending any fragments this time
            let mut c2_packets =
                send_sdu_no_credit_check!(TEST_MESSAGE_CREDIT_CHANNEL_2.iter().copied(), peer_cid_2, 23, end, 0).await;

            let c1_remaining = c1_packets.get_remaining_count();
            let c2_remaining = c2_packets.get_remaining_count();

            let top = min(c1_remaining, c2_remaining);

            let bottom = max(c1_remaining, c2_remaining);

            let split_odds = 100 * top / bottom;

            loop {
                let (next, or_next) = if rand::random::<usize>() % 100 <= split_odds {
                    (&mut c1_packets, &mut c2_packets)
                } else {
                    (&mut c2_packets, &mut c1_packets)
                };

                if let Some(next) = next.next() {
                    send_credit_frame!(next, end).await;
                } else if let Some(next) = or_next.next() {
                    send_credit_frame!(next, end).await;
                } else {
                    break;
                }
            }

            assert!(c1_packets.next().is_none());
            assert!(c2_packets.next().is_none());
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .enable_signalling_channel()
                .enable_attribute_channel()
                .build();

            let mut cid_1 = None;

            let mut cid_2 = None;

            let mut checklist = [false; 5];

            while checklist != [true; 5] {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, channel } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            let channel = request
                                .accept_le_credit_based_connection(channel)
                                .initially_given_credits(<u16>::MAX)
                                .send_success_response()
                                .await
                                .unwrap();

                            if cid_1.is_none() {
                                checklist[0] = true;

                                cid_1 = channel.get_channel_id().into()
                            } else if cid_2.is_none() {
                                checklist[1] = true;

                                cid_2 = channel.get_channel_id().into()
                            }
                        }
                        _ => panic!("recieved unexpected signal {signal:?}"),
                    },
                    LeUNext::AttributeChannel { pdu, .. } => {
                        checklist[2] = true;

                        assert_eq!(pdu.get_payload(), TEST_MESSAGE_ATT);
                    }
                    LeUNext::CreditBasedChannel(CreditBasedChannelNext::Sdu { sdu, channel, .. }) => {
                        if Some(channel.get_channel_id()) == cid_1 {
                            checklist[3] = true;

                            assert_eq!(sdu, TEST_MESSAGE_CREDIT_CHANNEL_1);
                        }

                        if Some(channel.get_channel_id()) == cid_2 {
                            checklist[4] = true;

                            assert_eq!(sdu, TEST_MESSAGE_CREDIT_CHANNEL_2);
                        }
                    }
                    next => panic!("received unexpected: {next:?}"),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_attribute_channel_dropped_while_receiving() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let fragment = L2capFragment::new(true, [23, 0, 4, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]);

            end.send(fragment).await.unwrap();

            let fragment = L2capFragment::new(false, [23]);

            end.send(fragment).await.unwrap();

            // sending a bad signal to exit test
            let fragment = L2capFragment::new(true, [4, 0, 5, 0, 0xFF, 1, 0, 0]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .enable_signalling_channel()
                .use_vec_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::AttributeChannel { .. } => panic!("received on ATT channel"),
                        LeUNext::SignallingChannel { signal, ..} => match signal {
                            ReceivedLeUSignal::UnknownSignal { code, ..} => if code == 0xFF { break }
                            _ => panic!("receive unexpected signal {signal:?}")
                        },
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => link.disable_att_channel(),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_signalling_channel_dropped_while_receiving() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let fragment = L2capFragment::new(true, [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 23]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [0, 23, 0, 10, 0]);

            end.send(fragment).await.unwrap();

            // sending data to the ATT channel to exit test
            let fragment = L2capFragment::new(true, [1, 0, 4, 0, 0xFF]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .enable_signalling_channel()
                .use_vec_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::SignallingChannel { .. } => panic!("received on ATT channel"),
                        LeUNext::AttributeChannel { ..} => break,
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => link.disable_signalling_channel(),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_security_manager_channel_dropped_while_receiving() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let fragment = L2capFragment::new(true, [23, 0, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]);

            end.send(fragment).await.unwrap();

            let fragment = L2capFragment::new(false, [23]);

            end.send(fragment).await.unwrap();

            // sending a bad signal to exit test
            let fragment = L2capFragment::new(true, [4, 0, 5, 0, 0xFF, 1, 0, 0]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_security_manager_channel()
                .enable_signalling_channel()
                .use_vec_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::SecurityManagerChannel { .. } => panic!("received on SM channel"),
                        LeUNext::SignallingChannel { signal, ..} => match signal {
                            ReceivedLeUSignal::UnknownSignal { code, ..} => if code == 0xFF { break }
                            _ => panic!("receive unexpected signal {signal:?}")
                        },
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => link.disable_security_manager_channel(),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_dyn_channel_dropped_while_receiving() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            // request a dynamic channel
            let fragment = L2capFragment::new(
                true,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 23, 0, 23, 0, 0, 0],
            );

            end.send(fragment).await.unwrap();

            let received = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                received,
                [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 23, 0, 23, 0, 10, 0, 0, 0]
            );

            // the raw channel id of the peer is [received[8], received[9]]
            let fragment = L2capFragment::new(true, [23, 0, received[8], received[9], 21, 0, 3, 4, 5, 6, 7, 8, 9]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]);

            end.send(fragment).await.unwrap();

            let fragment = L2capFragment::new(false, [23]);

            end.send(fragment).await.unwrap();

            // sending a bad signal to exit test
            let fragment = L2capFragment::new(true, [4, 0, 5, 0, 0xFF, 1, 0, 0]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            let mut peer_cid = None;

            loop {
                tokio::select! {
                    next = link.next() => match &mut next.unwrap() {
                        LeUNext::SignallingChannel { signal, channel} => match signal {
                            ReceivedLeUSignal::UnknownSignal { code, ..} if *code == 0xFF => break,
                            ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                                peer_cid = request.get_source_cid().into();

                                request.accept_le_credit_based_connection(channel)
                                    .initially_given_credits(10)
                                    .send_success_response()
                                    .await
                                    .unwrap();
                            }
                            _ => panic!("receive unexpected signal {signal:?}")
                        },
                        LeUNext::CreditBasedChannel(_) => panic!("unexpected credit channel data"),
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => {
                        link.get_signalling_channel().unwrap().request_disconnection(peer_cid.unwrap()).await.unwrap();
                    },
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_att_channel_dropped_while_receiving_with_unused() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let fragment = L2capFragment::new(true, [23, 0, 4, 0, 0x4, 2, 3, 4, 5, 6, 7, 8, 9]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]);

            end.send(fragment).await.unwrap();

            let fragment = L2capFragment::new(false, [23]);

            end.send(fragment).await.unwrap();

            let recv = end.recv().await.unwrap().unwrap();

            let recv_payload = recv.into_inner().collect::<Vec<_>>();

            assert_eq!(5, <u16>::from_le_bytes([recv_payload[0], recv_payload[1]]));

            let channel =
                ChannelIdentifier::le_try_from_raw(<u16>::from_le_bytes([recv_payload[2], recv_payload[3]])).unwrap();

            assert_eq!(channel, ChannelIdentifier::Le(LeCid::AttributeProtocol),);

            assert_eq!(recv_payload[4], bo_tie_att::server::ServerPduName::ErrorResponse.into());

            let err: bo_tie_att::pdu::ErrorResponse =
                bo_tie_att::TransferFormatTryFrom::try_from(&recv_payload[5..]).unwrap();

            assert_eq!(err.error, bo_tie_att::pdu::Error::RequestNotSupported);

            // sending a bad signal to exit test
            let fragment = L2capFragment::new(true, [4, 0, 5, 0, 0xFF, 1, 0, 0]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .enable_signalling_channel()
                .enable_unused_fixed_channel_response()
                .use_vec_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::AttributeChannel { .. } => panic!("received on ATT channel"),
                        LeUNext::SignallingChannel { signal, ..} => match signal {
                            ReceivedLeUSignal::UnknownSignal { code, ..} => if code == 0xFF { break }
                            _ => panic!("receive unexpected signal {signal:?}")
                        },
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => link.disable_att_channel(),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_att_channel_dropped_while_receiving_with_unused_no_response() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            // this sends write command which the server should
            // not send an error response regardless of 'unused'.
            let fragment = L2capFragment::new(true, [23, 0, 4, 0, 0x52, 2, 3, 4, 5, 6, 7, 8, 9]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]);

            end.send(fragment).await.unwrap();

            let fragment = L2capFragment::new(false, [23]);

            end.send(fragment).await.unwrap();

            let Err(_) = tokio::time::timeout(std::time::Duration::from_millis(10), end.recv()).await else {
                panic!("expected timeout")
            };

            // sending a bad signal to exit test
            let fragment = L2capFragment::new(true, [4, 0, 5, 0, 0xFF, 1, 0, 0]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .enable_signalling_channel()
                .enable_unused_fixed_channel_response()
                .use_vec_buffer()
                .build();

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::AttributeChannel { .. } => panic!("received on ATT channel"),
                        LeUNext::SignallingChannel { signal, ..} => match signal {
                            ReceivedLeUSignal::UnknownSignal { code, ..} => if code == 0xFF { break }
                            _ => panic!("receive unexpected signal {signal:?}")
                        },
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = barrier.wait() => link.disable_att_channel(),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_sig_channel_dropped_while_receiving_with_unused() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let fragment = L2capFragment::new(true, [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 23]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [0, 23, 0, 10, 0]);

            end.send(fragment).await.unwrap();

            let recv = end.recv().await.unwrap().unwrap();

            let recv_payload = recv.into_inner().collect::<Vec<_>>();

            assert_eq!(6, <u16>::from_le_bytes([recv_payload[0], recv_payload[1]]));

            let channel =
                ChannelIdentifier::le_try_from_raw(<u16>::from_le_bytes([recv_payload[2], recv_payload[3]])).unwrap();

            assert_eq!(channel, ChannelIdentifier::Le(LeCid::LeSignalingChannel),);

            // 0x1 is code for L2CAP_COMMAND_REJECT_RESPONSE
            assert_eq!(recv_payload[4], 0x1);

            assert_eq!(<u16>::from_le_bytes([recv_payload[6], recv_payload[7]]), 2);

            let reason = bo_tie_l2cap::signals::packets::CommandRejectReason::try_from(<u16>::from_le_bytes([
                recv_payload[8],
                recv_payload[9],
            ]))
            .unwrap();

            assert_eq!(reason, CommandRejectReason::CommandNotUnderstood);

            // sending data to the ATT channel to exit test
            let fragment = L2capFragment::new(true, [1, 0, 4, 0, 0xFF]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_attribute_channel()
                .enable_signalling_channel()
                .enable_unused_fixed_channel_response()
                .use_vec_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::SignallingChannel { .. } => panic!("received on ATT channel"),
                        LeUNext::AttributeChannel { ..} => break,
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => link.disable_signalling_channel(),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_security_manager_channel_dropped_while_receiving_with_unused() {
    let barrier = &tokio::sync::Barrier::new(2);

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let fragment = L2capFragment::new(true, [23, 0, 6, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

            end.send(fragment).await.unwrap();

            barrier.wait().await;

            let fragment = L2capFragment::new(false, [10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22]);

            end.send(fragment).await.unwrap();

            let fragment = L2capFragment::new(false, [23]);

            end.send(fragment).await.unwrap();

            let recv = end.recv().await.unwrap().unwrap();

            let recv_payload = recv.into_inner().collect::<Vec<_>>();

            assert_eq!(2, <u16>::from_le_bytes([recv_payload[0], recv_payload[1]]));

            let channel =
                ChannelIdentifier::le_try_from_raw(<u16>::from_le_bytes([recv_payload[2], recv_payload[3]])).unwrap();

            assert_eq!(channel, ChannelIdentifier::Le(LeCid::SecurityManagerProtocol),);

            // 0x5 -> Pairing failed code
            assert_eq!(recv_payload[4], 0x5);

            // 0x5 -> Pairing Not Supported
            assert_eq!(recv_payload[5], 0x5);

            // sending a bad signal to exit test
            let fragment = L2capFragment::new(true, [4, 0, 5, 0, 0xFF, 1, 0, 0]);

            end.send(fragment).await.unwrap();
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_security_manager_channel()
                .enable_signalling_channel()
                .enable_unused_fixed_channel_response()
                .use_vec_buffer()
                .build();

            let mut pin_barrier = pin!(futures::FutureExt::fuse(barrier.wait()));

            loop {
                tokio::select! {
                    next = link.next() => match next.unwrap() {
                        LeUNext::AttributeChannel { .. } => panic!("received on ATT channel"),
                        LeUNext::SignallingChannel { signal, ..} => match signal {
                            ReceivedLeUSignal::UnknownSignal { code, ..} => if code == 0xFF { break }
                            _ => panic!("receive unexpected signal {signal:?}")
                        },
                        next => panic!("received unexpected {next:?}")
                    },
                    _ = &mut pin_barrier => link.disable_security_manager_channel(),
                }
            }
        })
        .run()
        .await;
}
