//! Tests for a LE-U Link

use bo_tie_l2cap::channel::id::{ChannelIdentifier, LeCid};
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::BasicFrame;
use futures::StreamExt;

const TEST_DATA: &'static str = "Actualis at conscius supponam ac. Vocem si longo mo co veris \
    entis. Similibus essentiae argumenti sum contingit eae praesenti. Spectatum de jactantur \
    veritatis ut. Negans impetu optima nos postea rectum primas una. Actu iste ego lor haec \
    ipsa quia tria meo. Eam unquam vim obstat eamque nia factam manebo. Anima terea ideas tur \
    putem nec nolim aliae imo. Securum cum ultimum eam nul creatum suppono diversi. Vox pluribus \
    jam chimerae acceptis eos utrimque impellit nihilque.";

#[tokio::test]
async fn minimal_fragments() {
    let (sending_link, _tx, mut rx) = bo_tie_host_tests::create_le_false_link(1);

    let handle = tokio::spawn(async move {
        // using the att channel for testing
        let mut channel = sending_link.get_att_channel();

        let frame = BasicFrame::new(TEST_DATA.bytes().collect::<Vec<u8>>(), channel.get_cid());

        channel.send(frame).await.expect("failed to send gibberish")
    });

    let b1 = rx
        .next()
        .await
        .expect("failed to get 1st byte of pdu len")
        .get_data()
        .first()
        .copied()
        .expect("no bytes in payload");

    let b2 = rx
        .next()
        .await
        .expect("failed to get 2nd byte of pdu len")
        .get_data()
        .first()
        .copied()
        .expect("no bytes in payload");

    let b3 = rx
        .next()
        .await
        .expect("failed to get 1st byte of CID")
        .get_data()
        .first()
        .copied()
        .expect("no bytes in payload");

    let b4 = rx
        .next()
        .await
        .expect("failed to get 2nd byte of CID")
        .get_data()
        .first()
        .copied()
        .expect("no bytes in payload");

    let len = <u16>::from_le_bytes([b1, b2]).into();

    assert_eq!(TEST_DATA.bytes().len(), len);

    let cid =
        LeULink::try_channel_from_raw(<u16>::from_le_bytes([b3, b4])).expect("could not create channel identifier");

    assert_eq!(ChannelIdentifier::Le(LeCid::AttributeProtocol), cid);

    for byte in TEST_DATA.bytes() {
        let next = rx.next().await.expect("failed to receive next byte");

        assert_eq!(next.get_data().len(), 1);

        assert_eq!(*next.get_data().first().unwrap(), byte);
    }

    handle.await.expect("sending link failed");
}

#[tokio::test]
async fn zero_sized_fragments() {
    bo_tie_host_tests::create_le_link(0);
}
