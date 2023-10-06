//! Tests for L2CAP signals

use bo_tie_l2cap::channel::id::{ChannelIdentifier, DynChannelId, LeCid};
use bo_tie_l2cap::channel::signalling::{ReceiveSignalError, ReceivedSignal};
use bo_tie_l2cap::channel::InvalidChannel;
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::signals::packets::{
    LeCreditBasedConnectionResponse, LeCreditBasedConnectionResponseResult, LeCreditMps, LeCreditMtu,
    SimplifiedProtocolServiceMultiplexer,
};
use futures::{SinkExt, StreamExt};

#[tokio::test]
pub async fn request_le_credit_connection() {
    let (sending_link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(20);

    let l_handle = tokio::spawn(async move {
        let mut signal_channel = sending_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let mtu = LeCreditMtu::new(0xFFFF);

        let mps = LeCreditMps::new(30);

        let initial_credits = 0xFFFF;

        let request = signal_channel
            .request_le_credit_connection(spsm, mtu, mps, initial_credits)
            .await
            .expect("failed to send init credit connection");

        let credit_based_channel = match signal_channel.receive().await.expect("failed to get response") {
            ReceivedSignal::LeCreditBasedConnectionResponse(response) => response
                .create_le_credit_connection(&request, &sending_link)
                .expect("received rejection response"),
            _ => panic!("received unexpected signal"),
        };

        assert_eq!(
            credit_based_channel.get_this_channel_id(),
            ChannelIdentifier::Le(DynChannelId::new_le(0x40).unwrap())
        );

        assert_eq!(
            credit_based_channel.get_peer_channel_id(),
            ChannelIdentifier::Le(DynChannelId::new_le(0x56).unwrap())
        );

        assert_eq!(credit_based_channel.get_mtu(), 45);

        assert_eq!(credit_based_channel.get_mps(), 23);

        assert_eq!(credit_based_channel.get_peer_credits(), 5);
    });

    let connection_request = rx.next().await.expect("never received LE credit connection request");

    assert!(connection_request.is_start_fragment());

    assert_eq!(
        connection_request.get_data(),
        &[
            14, 0, // pdu len
            5, 0,    // CID (signalling identifier for LE)
            0x14, // code for LE credit based connection request
            1,    // identifier (the expected identifier to be selected by the signalling channel is one)
            10, 0, // data length
            0x80, 0, // Simplified Protocol/Service Multiplexer (connect_left assigns this to 0x80)
            0x40, 0, // source CID (a new signalling channel will use the first dyn channel, 0x40)
            0xFF, 0xFF, // MTU (set to 0xFFFF in macro call of connect_left!)
            30, 0, // MPS (set to 30 in macro call of connect_left!)
            0xFF, 0xFF, // initial credits (set to 0xFFFF in macro call of connect_left!)
        ]
    );

    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x56, 0, 45, 0, 23, 0, 5, 0, 0, 0],
    );

    tx.send(response).await.expect("failed to send response");

    l_handle.await.expect("requesting task failed");
}

#[tokio::test]
pub async fn invalid_channel_id_in_response() {
    let (sending_link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(20);

    let l_handle = tokio::spawn(async move {
        let mut signal_channel = sending_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let mtu = LeCreditMtu::new(0xFFFF);

        let mps = LeCreditMps::new(30);

        let initial_credits = 0xFFFF;

        signal_channel
            .request_le_credit_connection(spsm, mtu, mps, initial_credits)
            .await
            .expect("failed to send init credit connection");

        let err_response = signal_channel.receive().await.err().expect("expected an error");

        assert!(
            err_response.to_string().contains("invalid channel identifier"),
            "actual error: {}",
            err_response.to_string()
        )
    });

    let response = L2capFragment::new(true, vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0, 0, 45, 0, 23, 0, 5, 0, 0, 0]);

    tx.send(response).await.expect("failed to send response");

    l_handle.await.expect("requesting task failed");
}

#[tokio::test]
pub async fn invalid_mtu_in_response() {
    let (sending_link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(20);

    let l_handle = tokio::spawn(async move {
        let mut signal_channel = sending_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let mtu = LeCreditMtu::new(0xFFFF);

        let mps = LeCreditMps::new(30);

        let initial_credits = 0xFFFF;

        signal_channel
            .request_le_credit_connection(spsm, mtu, mps, initial_credits)
            .await
            .expect("failed to send init credit connection");

        let err_response = signal_channel.receive().await.err().expect("expected an error");

        assert!(
            err_response.to_string().contains("the signal's 'MTU' field is invalid"),
            "actual error: {}",
            err_response.to_string()
        )
    });

    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 10, 0, 23, 0, 5, 0, 0, 0],
    );

    tx.send(response).await.expect("failed to send response");

    l_handle.await.expect("requesting task failed");
}

#[tokio::test]
pub async fn invalid_mps_in_response() {
    let (sending_link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(20);

    let l_handle = tokio::spawn(async move {
        let mut signal_channel = sending_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let mtu = LeCreditMtu::new(0xFFFF);

        let mps = LeCreditMps::new(30);

        let initial_credits = 0xFFFF;

        signal_channel
            .request_le_credit_connection(spsm, mtu, mps, initial_credits)
            .await
            .expect("failed to send init credit connection");

        let err_response = signal_channel.receive().await.err().expect("expected an error");

        assert!(
            err_response.to_string().contains("the signal's 'MPS' field is invalid"),
            "actual error: {}",
            err_response.to_string()
        )
    });

    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 23, 0, 6, 0, 5, 0, 0, 0],
    );

    tx.send(response).await.expect("failed to send response");

    l_handle.await.expect("requesting task failed");
}

#[tokio::test]
pub async fn invalid_result_response() {
    let (sending_link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(20);

    let l_handle = tokio::spawn(async move {
        let mut signal_channel = sending_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let mtu = LeCreditMtu::new(0xFFFF);

        let mps = LeCreditMps::new(30);

        let initial_credits = 0xFFFF;

        signal_channel
            .request_le_credit_connection(spsm, mtu, mps, initial_credits)
            .await
            .expect("failed to send init credit connection");

        let err_response = signal_channel.receive().await.err().expect("expected an error");

        assert!(
            err_response
                .to_string()
                .contains("the signal's 'Result' field is invalid"),
            "actual error: {}",
            err_response.to_string()
        )
    });

    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 23, 0, 23, 0, 11, 0, 0xC, 0],
    );

    tx.send(response).await.expect("failed to send response");

    l_handle.await.expect("requesting task failed");
}

#[tokio::test]
pub async fn rejected_request() {
    let (requesting_link, response_link) = bo_tie_host_tests::create_le_link(15);

    let req_handle = tokio::spawn(async move {
        let mut signal_channel = requesting_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let mtu = LeCreditMtu::new(0xFFFF);

        let mps = LeCreditMps::new(30);

        let initial_credits = 0xFFFF;

        signal_channel
            .request_le_credit_connection(spsm, mtu, mps, initial_credits)
            .await
            .expect("failed to send init credit connection");

        match signal_channel.receive().await.expect("failed to receive response") {
            ReceivedSignal::LeCreditBasedConnectionResponse(response) => {
                assert_eq!(
                    response.get_result(),
                    LeCreditBasedConnectionResponseResult::NoResourcesAvailable
                )
            }
            _ => panic!("received unexpected signal"),
        }
    });

    let res_handle = tokio::spawn(async move {
        let mut signal_channel = response_link.get_signalling_channel();

        match signal_channel.receive().await.expect("failed to receive request") {
            ReceivedSignal::LeCreditBasedConnectionRequest(request) => request
                .reject_le_credit_based_connection(
                    &mut signal_channel,
                    LeCreditBasedConnectionResponseResult::NoResourcesAvailable,
                )
                .await
                .expect("failed to send rejection"),
            _ => panic!("received unexpected signal"),
        }
    });

    req_handle.await.expect("requesting task failed");
    res_handle.await.expect("responding task failed");
}
