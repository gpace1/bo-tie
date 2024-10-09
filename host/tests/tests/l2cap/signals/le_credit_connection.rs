//! Tests for L2CAP signals

use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_l2cap::pdu::{ControlFrame, FragmentIterator, FragmentL2capPdu, L2capFragment};
use bo_tie_l2cap::signalling::{ConvertSignalError, ReceivedLeUSignal};
use bo_tie_l2cap::signals::packets::{
    LeCreditBasedConnectionResponseResult, LeCreditMps, LeCreditMtu, SignalCode, SimplifiedProtocolServiceMultiplexer,
};
use bo_tie_l2cap::signals::{SignalError, LE_U_SIGNAL_CHANNEL_ID};
use bo_tie_l2cap::{LeULogicalLink, LeULogicalLinkNextError, LeUNext, PhysicalLink};

#[tokio::test]
async fn le_credit_connection() {
    let test_message = b"hello and welcome to the test. Lorem ipsum dolor sit amet, \
            consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna \
            aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip \
            ex ea commodo consequat.";

    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut test_message_iter = test_message.into_iter().copied();

            let mut credit_channel_id = None;

            let mut channel_sending = None;

            loop {
                match link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, .. } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            let mut signalling_channel = link.get_signalling_channel().unwrap();

                            if credit_channel_id.is_none() {
                                let channel_builder =
                                    request.accept_le_credit_based_connection(&mut signalling_channel);

                                let channel_id = channel_builder.send_success_response().await.unwrap();

                                credit_channel_id = Some(channel_id);
                            } else {
                                request
                                    .reject_le_credit_based_connection(
                                        &mut link.get_signalling_channel().unwrap(),
                                        LeCreditBasedConnectionResponseResult::NoResourcesAvailable,
                                    )
                                    .await
                                    .unwrap()
                            }
                        }
                        _ => panic!("received unexpected signal {signal:?}"),
                    },
                    LeUNext::CreditIndication {
                        credits_given: 1..,
                        mut channel,
                    } => {
                        channel_sending = match channel_sending.take() {
                            None => channel.send(&mut test_message_iter).await.unwrap(),
                            Some(sending) => sending
                                .continue_sending(
                                    &mut link.get_credit_based_channel(credit_channel_id.unwrap()).unwrap(),
                                )
                                .await
                                .unwrap(),
                        }
                    }
                    next => panic!("unexpected next {next:?}"),
                }
            }
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let le_connect_request = link
                .get_signalling_channel()
                .unwrap()
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(2048),
                    LeCreditMps::new(23),
                    0,
                )
                .await
                .unwrap();

            let response = if let LeUNext::SignallingChannel { signal, .. } = link.next().await.unwrap() {
                match signal {
                    ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) => response,
                    ReceivedLeUSignal::CommandRejectRsp(response) => {
                        panic!("received command reject response: {response:?}")
                    }
                    signal => panic!("received unexpected signal {signal:?}"),
                }
            } else {
                panic!("received unexpected next event");
            };

            if response.get_result() != LeCreditBasedConnectionResponseResult::ConnectionSuccessful {
                panic!("received connection result {:?}", response.get_result())
            }

            response
                .create_le_credit_connection(&le_connect_request, &mut link.get_signalling_channel().unwrap())
                .unwrap();

            let channel_id = le_connect_request.get_source_cid();

            let mut channel = link.get_credit_based_channel(channel_id).unwrap();

            channel.give_credits_to_peer(32).await.unwrap();

            let sdu = match link.next().await.unwrap() {
                LeUNext::CreditBasedChannel { sdu, .. } => sdu,
                next => panic!("unexpected next: {next:?}"),
            };

            let received_message = core::str::from_utf8(&sdu).unwrap();

            assert_eq!(core::str::from_utf8(test_message).unwrap(), received_message)
        })
        .run()
        .await;
}

pub async fn invalid_response_test_factory<I>(response: I, expected_error: SignalError)
where
    I: IntoIterator<Item = u8>,
    <I as IntoIterator>::IntoIter: ExactSizeIterator,
{
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            // wait for the request

            let mut counter = 0;

            loop {
                let fragment = end.recv().await.unwrap().unwrap();

                counter += fragment.into_inner().count();

                // request is always le connection request, so just count the bytes received
                if counter >= 18 {
                    break;
                }
            }

            // send bad response
            let control_frame = ControlFrame::new(response, LE_U_SIGNAL_CHANNEL_ID);

            let mut fragments = control_frame
                .into_fragments(end.max_transmission_size().into())
                .unwrap();

            let mut is_first = true;

            while let Some(fragment) = fragments.next() {
                let fragment = L2capFragment::new(is_first, fragment);

                is_first = false;

                end.send(fragment).await.expect("failed to send response fragment");
            }
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end).enable_signalling_channel().build();

            let mut signal_channel = link.get_signalling_channel().unwrap();

            let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

            let mtu = LeCreditMtu::new(0xFFFF);

            let mps = LeCreditMps::new(30);

            let initial_credits = 0xFFFF;

            signal_channel
                .request_le_credit_connection(spsm, mtu, mps, initial_credits)
                .await
                .expect("failed to send init credit connection");

            match link.next().await.err().expect("expected an error") {
                LeULogicalLinkNextError::RecombineControlFrame(ConvertSignalError::InvalidFormat(
                    SignalCode::LeCreditBasedConnectionResponse,
                    received_error,
                )) => {
                    assert_eq!(received_error, expected_error)
                }
                err => panic!("received wrong error: {err:?}"),
            }
        })
        .run()
        .await;
}

#[tokio::test]
pub async fn invalid_channel_id_in_response() {
    let response = [0x15, 1, 10, 0, 0, 0, 45, 0, 23, 0, 5, 0, 0, 0];

    let error = SignalError::InvalidChannel;

    invalid_response_test_factory(response, error).await;
}

#[tokio::test]
pub async fn invalid_mtu_in_response() {
    let response = [0x15, 1, 10, 0, 0x40, 0, 10, 0, 23, 0, 5, 0, 0, 0];

    let error = SignalError::InvalidField("MTU");

    invalid_response_test_factory(response, error).await;
}

#[tokio::test]
pub async fn invalid_mps_in_response() {
    let response = [0x15, 1, 10, 0, 0x40, 0, 23, 0, 6, 0, 5, 0, 0, 0];

    let error = SignalError::InvalidField("MPS");

    invalid_response_test_factory(response, error).await;
}

#[tokio::test]
pub async fn invalid_result_response() {
    let response = [0x15, 1, 10, 0, 0x40, 0, 23, 0, 23, 0, 11, 0, 0xC, 0];

    let error = SignalError::InvalidField("Result");

    invalid_response_test_factory(response, error).await;
}

#[tokio::test]
pub async fn response_with_rejected_request() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end).enable_signalling_channel().build();

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel {
                        signal: ReceivedLeUSignal::LeCreditBasedConnectionRequest(request),
                        channel,
                    } => {
                        request
                            .reject_le_credit_based_connection(
                                channel,
                                LeCreditBasedConnectionResponseResult::NoResourcesAvailable,
                            )
                            .await
                            .unwrap();
                    }
                    next => panic!("unexpected next: {next:?}"),
                }
            }
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end).enable_signalling_channel().build();

            let mut signalling_channel = link.get_signalling_channel().unwrap();

            let spsm = SimplifiedProtocolServiceMultiplexer::new_dyn(0x80);

            let mtu = LeCreditMtu::new(0xFFFF);

            let mps = LeCreditMps::new(30);

            let initial_credits = 0xFFFF;

            signalling_channel
                .request_le_credit_connection(spsm, mtu, mps, initial_credits)
                .await
                .expect("failed to send init credit connection");

            let response = match link.next().await.unwrap() {
                LeUNext::SignallingChannel {
                    signal: ReceivedLeUSignal::LeCreditBasedConnectionResponse(response),
                    ..
                } => response,
                next => panic!("unexpected next: {next:?}"),
            };

            assert_eq!(
                response.get_result(),
                LeCreditBasedConnectionResponseResult::NoResourcesAvailable
            )
        })
        .run()
        .await;
}

async fn invalid_request_test_factory<I>(request: I, expected_error: SignalError)
where
    I: IntoIterator<Item = u8>,
    <I as IntoIterator>::IntoIter: ExactSizeIterator,
{
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let control_frame = ControlFrame::new(request, LE_U_SIGNAL_CHANNEL_ID);

            let mut fragments = control_frame
                .into_fragments(end.max_transmission_size().into())
                .unwrap();

            let mut is_first = true;

            while let Some(fragment) = fragments.next() {
                let fragment = L2capFragment::new(is_first, fragment);

                is_first = false;

                end.send(fragment).await.expect("failed to send response fragment");
            }
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end).enable_signalling_channel().build();

            match link.next().await.err().expect("expected an error") {
                LeULogicalLinkNextError::RecombineControlFrame(ConvertSignalError::InvalidFormat(
                    SignalCode::LeCreditBasedConnectionRequest,
                    received_error,
                )) => assert_eq!(received_error, expected_error),
                err => panic!("received unexpected error: {err:?}"),
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn invalid_spsm_in_request() {
    let request = [0x14, 1, 10, 0, 0, 0, 0x40, 0, 23, 0, 23, 0, 100, 0];

    let error = SignalError::InvalidSpsm;

    invalid_request_test_factory(request, error).await;
}

#[tokio::test]
async fn invalid_source_cid_in_request() {
    let request = [0x14, 1, 10, 0, 0x80, 0, 0, 0, 23, 0, 23, 0, 100, 0];

    let error = SignalError::InvalidChannel;

    invalid_request_test_factory(request, error).await;
}

#[tokio::test]
async fn invalid_mtu_in_request() {
    let request = [0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 10, 0, 23, 0, 100, 0];

    let error = SignalError::InvalidField("MTU");

    invalid_request_test_factory(request, error).await;
}

#[tokio::test]
async fn invalid_mps_in_request() {
    let request = [0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 23, 0, 10, 0, 100, 0];

    let error = SignalError::InvalidField("MPS");

    invalid_request_test_factory(request, error).await;
}
