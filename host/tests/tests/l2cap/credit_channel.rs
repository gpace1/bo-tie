//! Tests for credit based channel implementations

use bo_tie_l2cap::channel::id::DynChannelId;
use bo_tie_l2cap::channel::signalling::ReceivedSignal;
use bo_tie_l2cap::signals::packets::{
    LeCreditBasedConnectionRequest, LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer,
};
use std::num::NonZeroU8;

#[tokio::test]
async fn le_credit_channel() {
    const TEST_MESSAGE: &'static str = "This is a test message that is sent across a LE credit \
     connection channel. It is shorter than the maximum transfer size but longer than the maximum \
     PDU payload size. This last sentence is just for filling up the test message with further \
     test data";

    let (l_link, r_link) = bo_tie_host_tests::create_le_link(10); // arbitrary size less than the mps

    let l_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let r_barrier = l_barrier.clone();

    tokio::spawn(async move {
        let mtu = LeCreditMtu::new(280);
        let mps = LeCreditMps::new(60);

        let mut signal_channel = l_link.get_signalling_channel();

        let request = LeCreditBasedConnectionRequest {
            identifier: NonZeroU8::new(1).unwrap(),
            spsm: SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
            source_dyn_cid: DynChannelId::new_dyn_le(0x40).unwrap(),
            mtu,
            mps,
            initial_credits: 10,
        };

        signal_channel
            .request_le_credit_connection(request)
            .await
            .expect("failed to send init credit connection");

        let mut credit_based_channel = match signal_channel.receive().await.expect("failed to get response") {
            ReceivedSignal::LeCreditBasedConnectionResponse(response) => {
                response.create_le_credit_connection(&request, &l_link)
            }
            _ => panic!("received unexpected signal"),
        };

        let mut maybe_send_task = credit_based_channel
            .send([1, 2, 3, 4])
            .await
            .expect("failed to initially send data");

        while let Some(send_task) = maybe_send_task.take() {
            tokio::select! {

                signal_result = signal_channel.receive() => {
                    let signal = signal_result.expect("failed to receive signal");

                    match signal {
                        ReceivedSignal::FlowControlCreditIndication(ind) => {
                            maybe_send_task = send_task.inc_and_send(&mut credit_based_channel, ind.get_credits())
                                .await
                                .expect("failed to send more credit PDUs");
                        }
                        _ => ()
                    }
                }
            }
        }

        loop {
            let signal = signal_channel.receive().await.expect("failed to receive");

            if let ReceivedSignal::DisconnectRequest(request) = signal {
                assert_eq!(request.source_cid, credit_based_channel.get_peer_channel_id());
                assert_eq!(request.destination_cid, credit_based_channel.get_this_channel_id());

                request
                    .send_disconnect_response(&mut signal_channel)
                    .await
                    .expect("failed to send response");

                break;
            }
        }

        l_barrier.wait().await;
    });

    tokio::spawn(async move {
        let mut signal_channel = r_link.get_signalling_channel();

        let mut credit_based_channel = match signal_channel.receive().await.expect("failed to get request") {
            ReceivedSignal::LeCreditBasedConnectionRequest(request) => request
                .create_le_credit_based_connection(&r_link, 5)
                .send_response(&mut signal_channel)
                .await
                .expect("failed to send response"),
            _ => panic!("received unexpected signal"),
        };

        let data: Vec<u8> = credit_based_channel.receive().await.expect("failed to receive");

        let message = std::str::from_utf8(&data).expect("invalid utf8");

        assert_eq!(TEST_MESSAGE, message);

        signal_channel
            .request_connection_disconnection(&credit_based_channel)
            .await
            .expect("failed to send disconnection request");

        let response = signal_channel.receive().await.expect("failed to receive disconnect");

        if let ReceivedSignal::DisconnectResponse(_) = response {
            // nothing to do if response received
        } else {
            panic!("unexpected received signal")
        }

        r_barrier.wait().await;
    });
}
