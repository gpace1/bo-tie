//! Tests for credit based channel implementations

use bo_tie_l2cap::channel::signalling::ReceivedSignal;
use bo_tie_l2cap::link_flavor::{LeULink, LinkFlavor};
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::signals::packets::{LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer};
use futures::{SinkExt, StreamExt};

const TEST_MESSAGE: &'static str = "This is a test message that is sent across a LE credit \
     connection channel. It is shorter than the maximum transfer size but longer than the maximum \
     PDU payload size. This last sentence is just for filling up the test message with further \
     test data";

macro_rules! connect_left {
    ($l_link:expr, $initial_credits:literal) => {
        connect_left!($l_link, 256, 23, $initial_credits)
    };
    ($l_link:expr, $mtu:literal, $mps:literal, $initial_credits:literal) => {{
        let mtu = LeCreditMtu::new($mtu);
        let mps = LeCreditMps::new($mps);

        let mut signal_channel = $l_link.get_signalling_channel();

        let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

        let request = signal_channel
            .request_le_credit_connection(spsm, mtu, mps, $initial_credits)
            .await
            .expect("failed to send init credit connection");

        let credit_based_channel = match signal_channel.receive().await.expect("failed to get response") {
            ReceivedSignal::LeCreditBasedConnectionResponse(response) => {
                response.create_le_credit_connection(&request, &$l_link)
            }
            _ => panic!("received unexpected signal"),
        };

        (credit_based_channel, signal_channel)
    }};
}

macro_rules! connect_right {
    ($r_link:expr, $init_credits:literal) => {{
        let mut signal_channel = $r_link.get_signalling_channel();

        let credit_based_channel = match signal_channel.receive().await.expect("failed to get request") {
            ReceivedSignal::LeCreditBasedConnectionRequest(request) => request
                .create_le_credit_based_connection(&$r_link, $init_credits)
                .send_response(&mut signal_channel)
                .await
                .expect("failed to send response"),
            _ => panic!("received unexpected signal"),
        };

        (credit_based_channel, signal_channel)
    }};
}

#[tokio::test]
async fn le_credit_connection() {
    let (l_link, r_link) = bo_tie_host_tests::create_le_link(10); // arbitrary size less than the mps

    let l_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let r_barrier = l_barrier.clone();

    let l_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = //connect_left!(l_link, 280, 60, 10);
            {
                let mut signal_channel = l_link.get_signalling_channel();

                let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

                let mtu = LeCreditMtu::new(280);

                let mps = LeCreditMps::new(60);

                let initial_credits = 10;

               let request =  signal_channel
                    .request_le_credit_connection(spsm, mtu, mps, initial_credits)
                    .await
                    .expect("failed to send init credit connection");

                let credit_based_channel = match signal_channel.receive().await.expect("failed to get response") {
                    ReceivedSignal::LeCreditBasedConnectionResponse(response) => {
                        response.create_le_credit_connection(&request, &l_link)
                    }
                    _ => panic!("received unexpected signal"),
                };

                (credit_based_channel, signal_channel)
            };

        let mut maybe_send_task = credit_based_channel
            .send(TEST_MESSAGE.bytes())
            .await
            .expect("failed to initially send data");

        while let Some(send_task) = maybe_send_task.take() {
            let signal = signalling_channel.receive().await.expect("failed to receive signal");

            match signal {
                ReceivedSignal::FlowControlCreditIndication(ind) => {
                    maybe_send_task = send_task
                        .inc_and_send(&mut credit_based_channel, ind.get_credits())
                        .await
                        .expect("failed to send more credit PDUs");
                }
                _ => (),
            }
        }

        loop {
            let signal = signalling_channel.receive().await.expect("failed to receive");

            if let ReceivedSignal::DisconnectRequest(request) = signal {
                assert_eq!(request.source_cid, credit_based_channel.get_peer_channel_id());
                assert_eq!(request.destination_cid, credit_based_channel.get_this_channel_id());

                request
                    .send_disconnect_response(&mut signalling_channel)
                    .await
                    .expect("failed to send response");

                break;
            }
        }

        l_barrier.wait().await;
    });

    let r_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = connect_right!(r_link, 5);

        let data: Vec<u8> = credit_based_channel.receive().await.expect("failed to receive");

        let message = std::str::from_utf8(&data).expect("invalid utf8");

        assert_eq!(TEST_MESSAGE, message);

        signalling_channel
            .request_connection_disconnection(&credit_based_channel)
            .await
            .expect("failed to send disconnection request");

        let response = signalling_channel
            .receive()
            .await
            .expect("failed to receive disconnect");

        if let ReceivedSignal::DisconnectResponse(_) = response {
            // nothing to do if response received
        } else {
            panic!("unexpected received signal")
        }

        r_barrier.wait().await;
    });

    l_handle.await.expect("l task failed");

    r_handle.await.expect("r task failed");
}

#[tokio::test]
async fn drop_channel_in_middle_of_sending() {
    let (l_link, r_link) = bo_tie_host_tests::create_le_link(LeULink::SUPPORTED_MTU.into());

    let l_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let r_barrier = l_barrier.clone();

    let l_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = connect_left!(l_link, 256, 32, 10);

        // only two k-frames will be sent as the other
        // credit based channel has only given two credits.
        credit_based_channel
            .send(TEST_MESSAGE.bytes())
            .await
            .expect("failed to initially send data");

        // deliberately dropped to indicate the intention of this test
        drop(credit_based_channel);

        l_barrier.wait().await;
    });

    let r_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = connect_right!(r_link, 2);

        tokio::time::timeout(std::time::Duration::from_millis(500), async {
            let data: Vec<u8> = credit_based_channel.receive().await.expect("failed to receive");

            let message = std::str::from_utf8(&data).expect("invalid utf8");

            assert_ne!(TEST_MESSAGE, message);
        })
        .await
        .expect_err("timeout waiting for credit based channel");

        r_barrier.wait().await;
    });

    l_handle.await.expect("l handle failed");

    r_handle.await.expect("r handle failed");
}
