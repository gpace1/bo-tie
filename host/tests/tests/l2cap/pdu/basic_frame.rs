//! Tests for basic data

use bo_tie_l2cap::pdu::{BasicFrame, L2capFragment};
use futures::{SinkExt, StreamExt};

#[tokio::test]
async fn send_single_pdu() {
    let (link, _tx, mut rx) = bo_tie_host_tests::create_le_false_link(100);

    tokio::spawn(async move {
        let mut att_channel = link.get_att_channel();

        let b_frame = BasicFrame::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9], att_channel.get_cid());

        att_channel.send(b_frame).await
    });

    let fragment = rx.next().await.expect("channel closed");

    assert_eq!(
        fragment.get_data().as_slice(),
        [10, 0, 4, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    )
}

#[tokio::test]
async fn send_single_pdu_multiple_fragments() {
    let (link, _tx, mut rx) = bo_tie_host_tests::create_le_false_link(5);

    tokio::spawn(async move {
        let mut att_channel = link.get_att_channel();

        let b_frame = BasicFrame::new(vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9], att_channel.get_cid());

        att_channel.send(b_frame).await
    });

    let fragment_1 = rx.next().await.expect("channel closed");

    assert_eq!(fragment_1.get_data().as_slice(), [10, 0, 4, 0, 0]);

    let fragment_1 = rx.next().await.expect("channel closed");

    assert_eq!(fragment_1.get_data().as_slice(), [1, 2, 3, 4, 5]);

    let fragment_1 = rx.next().await.expect("channel closed");

    assert_eq!(fragment_1.get_data().as_slice(), [6, 7, 8, 9]);
}

#[tokio::test]
async fn receive_single_pdu() {
    let (link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(100);

    let task_handle = tokio::spawn(async move {
        // test will use the ATT channel, but not
        // use it for the ATT protocol.
        let mut att_channel = link.get_att_channel();

        let frame = att_channel
            .receive(&mut Vec::new())
            .await
            .expect("failed to receive b-frame");

        assert_eq!(frame.get_payload().as_slice(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    });

    let b_frame = L2capFragment::new(true, vec![10, 0, 4, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

    tx.send(b_frame).await.expect("failed to send frame");

    task_handle.await.expect("test task failed")
}

#[tokio::test]
async fn receive_single_pdu_multiple_fragments() {
    let (link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(5);

    let task_handle = tokio::spawn(async move {
        // test will use the ATT channel, but not
        // use it for the ATT protocol.
        let mut att_channel = link.get_att_channel();

        let frame = att_channel
            .receive(&mut Vec::new())
            .await
            .expect("failed to receive b-frame");

        assert_eq!(frame.get_payload().as_slice(), &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])
    });

    tx.send(L2capFragment::new(true, vec![10, 0, 4, 0, 0]))
        .await
        .expect("failed to send frame");

    tx.send(L2capFragment::new(false, vec![1, 2, 3, 4, 5]))
        .await
        .expect("failed to send frame");

    tx.send(L2capFragment::new(false, vec![6, 7, 8, 9]))
        .await
        .expect("failed to send frame");

    task_handle.await.expect("test task failed")
}

#[tokio::test]
async fn receive_bad_pdu_len() {
    let (link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(5);

    let task_handle = tokio::spawn(async move {
        // test will use the ATT channel, but not
        // use it for the ATT protocol.
        let mut att_channel = link.get_att_channel();

        match att_channel.receive(&mut Vec::new()).await {
            Err(e) => assert!(e
                .to_string()
                .contains("payload is larger than the payload length field")),
            Ok(_) => panic!("unexpected b-frame received"),
        }
    });

    tx.send(L2capFragment::new(true, vec![8, 0, 4, 0, 0]))
        .await
        .expect("failed to send frame");

    tx.send(L2capFragment::new(false, vec![1, 2, 3, 4, 5]))
        .await
        .expect("failed to send frame");

    tx.send(L2capFragment::new(false, vec![6, 7, 8, 9]))
        .await
        .expect("failed to send frame");

    task_handle.await.expect("test task failed")
}

#[tokio::test]
async fn receive_bad_start_fragment() {
    let (link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(5);

    let task_handle = tokio::spawn(async move {
        // test will use the ATT channel, but not
        // use it for the ATT protocol.
        let mut att_channel = link.get_att_channel();

        match att_channel.receive(&mut Vec::new()).await {
            Err(e) => assert_eq!("unexpected first fragment of PDU", e.to_string()),
            Ok(_) => panic!("unexpected b-frame received"),
        }
    });

    tx.send(L2capFragment::new(true, vec![10, 0, 4, 0, 0]))
        .await
        .expect("failed to send frame");

    tx.send(L2capFragment::new(true, vec![1, 2, 4, 0, 5]))
        .await
        .expect("failed to send frame");

    task_handle.await.expect("test task failed")
}
