//! Tests for multiple channels sending/receiving at the same time

use bo_tie_host_tests::PhysicalLink;
use bo_tie_l2cap::channel::id::ChannelIdentifier;
use bo_tie_l2cap::channel::signalling::ReceivedSignal;
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::{BasicFrameChannel, CreditBasedChannel, LeULogicalLink, SignallingChannel};
use futures::{SinkExt, StreamExt};

const TEST_MESSAGE_ATT: &'static str = "🐸📣 this is a test message sent to the ATT channel";

const TEST_MESSAGE_CREDIT_CHANNEL_1: &'static str = "
🐮📣 this is a test message sent to the first credit based channel. It is purposely long as to 
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

const TEST_MESSAGE_CREDIT_CHANNEL_2: &'static str = "
🐱‍🐉📣 this is a test message sent to the second credit based channel. It is purposely long as to 
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

/// Inputs
/// * phy_mtu must be greater than or equal to 4
fn gen_att_fragments(msg: &str, phy_mtu: usize) -> Vec<L2capFragment<Vec<u8>>> {
    let mut msg_byte_iter = msg.bytes().peekable();

    let mut ret = vec![L2capFragment::new(
        true,
        [
            (msg.as_bytes().len() as u16).to_le_bytes()[0],
            (msg.as_bytes().len() as u16).to_le_bytes()[1],
            4,
            0,
        ]
        .into_iter()
        .chain(msg_byte_iter.by_ref().take(phy_mtu - 4))
        .collect(),
    )];

    while msg_byte_iter.peek().is_some() {
        ret.push(L2capFragment::new(
            false,
            msg_byte_iter.by_ref().take(phy_mtu).collect(),
        ))
    }

    ret
}

/// Inputs
/// * phy_mtu must be greater than or equal to 6
fn gen_k_frame_fragments(
    msg: &str,
    phy_mtu: usize,
    channel_id: u16,
    channel_mtu: usize,
    channel_mps: usize,
) -> Vec<Vec<L2capFragment<Vec<u8>>>> {
    assert!(
        msg.as_bytes().len() <= channel_mtu,
        "channel cannot send test message in single SDU"
    );

    let mut msg_byte_iter = msg.bytes().peekable();

    let mut ret = Vec::new();

    let mut sdu_iter = (msg.as_bytes().len() as u16).to_le_bytes().into_iter().fuse();

    while msg_byte_iter.peek().is_some() {
        let mut count = 0;

        let sdu_size = sdu_iter.len();

        let len = std::cmp::min(msg_byte_iter.len(), channel_mps) as u16;

        let mut pdu = vec![L2capFragment::new(
            true,
            [
                len.to_le_bytes()[0],
                len.to_le_bytes()[1],
                channel_id.to_le_bytes()[0],
                channel_id.to_le_bytes()[1],
            ]
            .into_iter()
            .chain(sdu_iter.by_ref())
            .chain(msg_byte_iter.by_ref().take(phy_mtu - 4 - sdu_size))
            .collect::<Vec<u8>>(),
        )];

        count += pdu.first().unwrap().get_data().len() - 4;

        while count < channel_mps && msg_byte_iter.peek().is_some() {
            let how_many = std::cmp::min(phy_mtu, channel_mps - count);

            count += how_many;

            pdu.push(L2capFragment::new(
                false,
                msg_byte_iter.by_ref().take(how_many).collect(),
            ));
        }

        ret.push(pdu);
    }

    ret
}

#[tokio::test]
async fn le_multiple_receiving() {
    let (l_link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(12);

    let (exit_task, mut exit_sig) = tokio::sync::oneshot::channel::<()>();

    let task_handle = tokio::spawn(async move {
        let mut signalling_channel = l_link.get_signalling_channel();

        let mut att_channel = l_link.get_att_channel();

        let mut credit_channel_1 = None;

        let mut credit_channel_2 = None;

        loop {
            tokio::select! {
                credit_channel = multiple_sending_signal_channel(&mut signalling_channel) => {
                    if credit_channel_1.is_none() {
                        credit_channel_1 = Some(credit_channel);
                    } else if credit_channel_2.is_none() {
                        credit_channel_2 = Some(credit_channel)
                    } else {
                        panic!("too many credit channels")
                    }
                },

                _ = multiple_sending_att_channel(&mut att_channel) => (),

                _ = multiple_sending_credit_based_channel_1(&mut credit_channel_1) => (),

                _ = multiple_sending_credit_based_channel_2(&mut credit_channel_2) => (),

                _ = &mut exit_sig => break,
            }
        }
    });

    // send the attribute test message
    for fragment in gen_att_fragments(TEST_MESSAGE_ATT, 12) {
        tx.send(fragment).await.expect("failed to send");
    }

    // connect request for first channel

    tx.send(L2capFragment::new(true, vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0]))
        .await
        .expect("failed to send");

    tx.send(L2capFragment::new(false, vec![0x40, 0, 0xFF, 0xFF, 23, 0, 10, 0]))
        .await
        .expect("failed to send");

    rx.next().await.expect("channel closed");

    rx.next().await.expect("channel closed");

    // send *some* of the PDUs for the first channel
    let mut k_frames = gen_k_frame_fragments(TEST_MESSAGE_CREDIT_CHANNEL_1, 12, 0x40, 0xFFFF, 23);

    for k_frame in k_frames.drain(..k_frames.len() / 2) {
        for fragment in k_frame {
            tx.send(fragment).await.expect("failed to send fragment");
        }
    }

    // connect request for second channel

    tx.send(L2capFragment::new(true, vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0]))
        .await
        .expect("failed to send");

    tx.send(L2capFragment::new(false, vec![0x41, 0, 0xFF, 0xFF, 23, 0, 10, 0]))
        .await
        .expect("failed to send");

    // send the rest of the PDUs for the first channel
    for k_frame in k_frames {
        for fragment in k_frame {
            tx.send(fragment).await.expect("failed to send fragment");
        }
    }

    tokio::time::sleep(std::time::Duration::from_millis(1000)).await;

    exit_task.send(()).expect("failed to send exit signal");

    task_handle.await.expect("task failed");
}

async fn multiple_sending_signal_channel<'a>(
    s: &mut SignallingChannel<'a, LeULogicalLink<PhysicalLink>>,
) -> CreditBasedChannel<'a, LeULogicalLink<PhysicalLink>> {
    loop {
        match s.receive().await.expect("failed to receive ") {
            ReceivedSignal::LeCreditBasedConnectionRequest(request) => {
                break request
                    .create_le_credit_based_connection(s.get_link(), 10)
                    .send_response(s)
                    .await
                    .expect("failed to send LE credit based response")
            }
            signal => panic!("unexpected signal: {signal:?}"),
        }
    }
}

async fn multiple_sending_att_channel<'a>(b: &mut BasicFrameChannel<'a, LeULogicalLink<PhysicalLink>>) {
    let data = b.receive::<Vec<_>>().await.expect("failed to receive");

    let received_message = std::str::from_utf8(data.get_payload()).expect("invalid utf8 received");

    assert_eq!(received_message, TEST_MESSAGE_ATT);
}

async fn multiple_sending_credit_based_channel_1<'a>(
    k: &mut Option<CreditBasedChannel<'a, LeULogicalLink<PhysicalLink>>>,
) {
    if let Some(channel) = k {
        let data = channel.receive::<Vec<_>>().await.expect("failed to receive");

        let received_message = std::str::from_utf8(&data).expect("invalid utf8 received");

        assert_eq!(received_message, TEST_MESSAGE_CREDIT_CHANNEL_1)
    } else {
        std::future::pending().await
    }
}

async fn multiple_sending_credit_based_channel_2<'a>(
    k: &mut Option<CreditBasedChannel<'a, LeULogicalLink<PhysicalLink>>>,
) {
    if let Some(channel) = k {
        let data = channel.receive::<Vec<_>>().await.expect("failed to receive");

        let received_message = std::str::from_utf8(&data).expect("invalid utf8 received");

        assert_eq!(received_message, TEST_MESSAGE_CREDIT_CHANNEL_1)
    } else {
        std::future::pending().await
    }
}

#[tokio::test]
async fn le_unused_channel_receive() {
    let (l_link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(12);

    let barrier_1 = std::sync::Arc::new(tokio::sync::Barrier::new(2));
    let barrier_2 = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let task_barrier_1 = barrier_1.clone();
    let task_barrier_2 = barrier_2.clone();

    let task_handle = tokio::spawn(async move {
        let mut signalling_channel = l_link.get_signalling_channel();

        loop {
            tokio::select! {
                _ = signalling_channel.receive() => panic!("unexpectedly received data"),
                _ = task_barrier_1.wait() => break,
            }
        }

        drop(signalling_channel);

        let mut attribute_channel = l_link.get_att_channel();

        loop {
            tokio::select! {
                _ = attribute_channel.receive::<Vec<_>>() => panic!("unexpectedly received data"),
                _ = task_barrier_2.wait() => break,
            }
        }
    });

    // send a PDU for a dynamic channel
    tx.send(L2capFragment::new(true, vec![5, 0, 0x40, 0, 1, 2, 3, 4, 5]))
        .await
        .expect("failed to send");

    // this should timeout as no response is the
    // expected operation
    tokio::time::timeout(std::time::Duration::from_millis(400), rx.next())
        .await
        .expect_err("expected timeout");

    // send a PDU for the attribute protocol (ATT) fixed channel
    tx.send(L2capFragment::new(true, vec![3, 0, 4, 0, 2, 3, 4]))
        .await
        .expect("failed to send");

    let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.next())
        .await
        .expect("timeout")
        .expect("receiver closed");

    // the expected returned data is the ATT PDU
    // `ATT_ERROR_RSP` with the error code as
    // `request not supported`
    assert_eq!(received.get_data().as_slice(), &[5, 0, 4, 0, 0x1, 0x2, 0, 0, 0x6]);

    // send a PDU for the security manager channel
    // (FYI: the payload of the PDU is gibberish to the SM protocol)
    tx.send(L2capFragment::new(true, vec![4, 0, 6, 0, 1, 2, 3, 4]))
        .await
        .expect("failed to send");

    let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.next())
        .await
        .expect("timeout")
        .expect("receiver closed");

    // the expected returned data is the SM PDU 'pairing
    // failed' with the reason field set as pairing not
    // supported.
    assert_eq!(received.get_data().as_slice(), &[2, 0, 6, 0, 0x5, 0x5]);

    barrier_1.wait().await;

    // send a PDU for the signalling channel
    tx.send(L2capFragment::new(
        true,
        vec![8, 0, 5, 0, 0x2, 1, 4, 0, 0x00, 0x10, 0x40, 0x00],
    ))
    .await
    .expect("failed to send");

    let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.next())
        .await
        .expect("timeout")
        .expect("receiver closed");

    assert_eq!(received.get_data().as_slice(), &[6, 0, 5, 0, 0x1, 1, 2, 0, 0, 0]);

    barrier_2.wait().await;

    task_handle.await.expect("test task failed");
}
