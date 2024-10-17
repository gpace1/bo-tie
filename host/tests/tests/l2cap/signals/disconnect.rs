use bo_tie_host_tests::PhysicalLinkLoop;
use bo_tie_l2cap::cid::{ChannelIdentifier, DynChannelId};
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::signalling::{DisconnectResponseError, ReceivedLeUSignal};
use bo_tie_l2cap::signals::packets::{LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer};
use bo_tie_l2cap::{LeULogicalLink, LeUNext, PhysicalLink};
use log::error;

/// Tests for the Disconnect Request and Response L2CAP signals

#[tokio::test]
async fn le_credit_connection_disconnect_source_disconnected() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut source_cid = None;
            let mut destination_cid = None;

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, channel } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            source_cid = Some(request.get_source_cid());

                            let dyn_channel = request
                                .accept_le_credit_based_connection(channel)
                                .initially_given_credits(10)
                                .send_success_response()
                                .await
                                .unwrap();

                            destination_cid = Some(dyn_channel.get_channel_id());
                        }
                        ReceivedLeUSignal::DisconnectRequest(request) => {
                            assert_eq!(request.destination_cid, destination_cid.unwrap());

                            assert_eq!(request.source_cid, source_cid.unwrap());

                            request.send_disconnect_response(channel).await.unwrap();

                            assert!(link.get_credit_based_channel(destination_cid.unwrap()).is_none());
                        }
                        _ => panic!("received unexpected signal {signal:?}"),
                    },
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut sig_channel = link.get_signalling_channel().unwrap();

            let request = sig_channel
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(23),
                    200,
                )
                .await
                .unwrap();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) = signal else {
                panic!("unexpected signal");
            };

            let dyn_channel = response.create_le_credit_connection(&request, &mut channel).unwrap();

            let this_channel_id = dyn_channel.get_channel_id();

            let peer_channel_id = dyn_channel.get_peer_channel_id();

            channel.request_disconnection(this_channel_id).await.unwrap();

            let LeUNext::SignallingChannel { signal, .. } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::DisconnectResponse(response) = signal else {
                panic!("unexpected signal")
            };

            assert_eq!(this_channel_id, response.source_cid);

            assert_eq!(peer_channel_id, response.destination_cid);

            assert!(link.get_credit_based_channel(this_channel_id).is_none());
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_credit_connection_disconnect_source_disconnected_bad_source_cid() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let le_connect_request = L2capFragment::new(
                true,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 250, 0, 23, 0, 10, 0],
            );

            end.send(le_connect_request).await.unwrap();

            let le_connect_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                le_connect_response,
                [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 250, 0, 23, 0, 10, 0, 0, 0]
            );

            let disconnect_request = L2capFragment::new(true, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x40, 0, 0x7f, 0]);

            end.send(disconnect_request).await.unwrap();

            std::future::pending::<()>().await;
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut source_cid = None;
            let mut destination_cid = None;

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, channel } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            source_cid = Some(request.get_source_cid());

                            let dyn_channel = request
                                .accept_le_credit_based_connection(channel)
                                .initially_given_credits(10)
                                .send_success_response()
                                .await
                                .unwrap();

                            destination_cid = Some(dyn_channel.get_channel_id());
                        }
                        ReceivedLeUSignal::DisconnectRequest(request) => {
                            let Err(DisconnectResponseError::InvalidSourceChannelIdentifier(_)) =
                                request.send_disconnect_response(channel).await
                            else {
                                panic!("unexpected error")
                            };

                            assert!(link.get_credit_based_channel(destination_cid.unwrap()).is_some());

                            break;
                        }
                        _ => panic!("received unexpected signal {signal:?}"),
                    },
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_credit_connection_disconnect_source_disconnected_bad_destination_cid() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut source_cid = None;
            let mut destination_cid = None;

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, channel } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            source_cid = Some(request.get_source_cid());

                            let dyn_channel = request
                                .accept_le_credit_based_connection(channel)
                                .initially_given_credits(10)
                                .send_success_response()
                                .await
                                .unwrap();

                            destination_cid = Some(dyn_channel.get_channel_id());
                        }
                        ReceivedLeUSignal::DisconnectRequest(request) => {
                            let Err(DisconnectResponseError::InvalidDestinationChannelIdentifier(_)) =
                                request.send_disconnect_response(channel).await
                            else {
                                panic!("unexpected error")
                            };

                            assert!(link.get_credit_based_channel(destination_cid.unwrap()).is_some());
                        }
                        _ => panic!("received unexpected signal {signal:?}"),
                    },
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .set_verify(|mut end| async move {
            let le_connect_request = L2capFragment::new(
                true,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 250, 0, 23, 0, 10, 0],
            );

            end.send(le_connect_request).await.unwrap();

            let le_connect_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                le_connect_response,
                [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 250, 0, 23, 0, 10, 0, 0, 0]
            );

            let disconnect_request = L2capFragment::new(true, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x7f, 0, 0x40, 0]);

            end.send(disconnect_request).await.unwrap();

            let error_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(error_response, [10, 0, 5, 0, 1, 1, 6, 0, 2, 0, 0x7f, 0, 0x40, 0]);
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_credit_connection_disconnect_source_disconnected_race() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut source_cid = None;
            let mut destination_cid = None;

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, channel } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            source_cid = Some(request.get_source_cid());

                            let dyn_channel = request
                                .accept_le_credit_based_connection(channel)
                                .initially_given_credits(10)
                                .send_success_response()
                                .await
                                .unwrap();

                            let this_channel_id = dyn_channel.get_channel_id();

                            destination_cid = Some(this_channel_id);

                            channel.request_disconnection(this_channel_id).await.unwrap();

                            assert!(link.get_credit_based_channel(this_channel_id).is_none());
                        }
                        ReceivedLeUSignal::DisconnectRequest(request) => {
                            // it's a race!
                            request.send_disconnect_response(channel).await.unwrap();

                            assert!(link.get_credit_based_channel(destination_cid.unwrap()).is_none());
                        }
                        _ => panic!("received unexpected signal {signal:?}"),
                    },
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .set_verify(|mut end| async move {
            let le_connect_request = L2capFragment::new(
                true,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 250, 0, 23, 0, 10, 0],
            );

            end.send(le_connect_request).await.unwrap();

            let le_connect_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                le_connect_response,
                [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 250, 0, 23, 0, 10, 0, 0, 0]
            );

            let disconnect_request = L2capFragment::new(true, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x40, 0, 0x40, 0]);

            end.send(disconnect_request).await.unwrap();

            let disconnect_request = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(disconnect_request, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x40, 0, 0x40, 0]);

            let error_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(error_response, [10, 0, 5, 0, 1, 1, 6, 0, 2, 0, 0x40, 0, 0x40, 0]);
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_credit_connection_disconnect_destination_disconnected() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut sig_channel = link.get_signalling_channel().unwrap();

            let request = sig_channel
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(23),
                    200,
                )
                .await
                .unwrap();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) = signal else {
                panic!("unexpected signal");
            };

            let dyn_channel = response.create_le_credit_connection(&request, &mut channel).unwrap();

            let this_channel_id = dyn_channel.get_channel_id();

            let peer_channel_id = dyn_channel.get_peer_channel_id();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::DisconnectRequest(request) = signal else {
                panic!("unexpected signal")
            };

            assert_eq!(peer_channel_id, request.source_cid);

            assert_eq!(this_channel_id, request.destination_cid);

            request.send_disconnect_response(&mut channel).await.unwrap();

            core::future::pending::<()>().await;
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let mut source_cid = None;
            let mut destination_cid = None;

            loop {
                match &mut link.next().await.unwrap() {
                    LeUNext::SignallingChannel { signal, channel } => match signal {
                        ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => {
                            source_cid = Some(request.get_source_cid());

                            let dyn_channel = request
                                .accept_le_credit_based_connection(channel)
                                .initially_given_credits(10)
                                .send_success_response()
                                .await
                                .unwrap();

                            let this_channel_id = dyn_channel.get_channel_id();

                            destination_cid = Some(this_channel_id);

                            channel.request_disconnection(this_channel_id).await.unwrap();

                            assert!(link.get_credit_based_channel(this_channel_id).is_none());
                        }
                        ReceivedLeUSignal::DisconnectResponse(response) => {
                            assert_eq!(response.destination_cid, destination_cid.unwrap());

                            assert_eq!(response.source_cid, source_cid.unwrap());

                            break;
                        }
                        _ => panic!("received unexpected signal {signal:?}"),
                    },
                    next => panic!("received unexpected {next:?}"),
                }
            }
        })
        .run()
        .await;
}

#[tokio::test]
async fn le_credit_connection_disconnect_destination_bad_source_cid() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|mut end| async move {
            let le_connect_request = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                le_connect_request,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0, 1, 23, 0, 10, 0]
            );

            let le_connect_response =
                L2capFragment::new(true, [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 250, 0, 23, 0, 10, 0, 0, 0]);

            end.send(le_connect_response).await.unwrap();

            let disconnect_request = L2capFragment::new(true, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x40, 0, 0x7f, 0]);

            end.send(disconnect_request).await.unwrap();

            std::future::pending::<()>().await;
        })
        .set_verify(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let request = link
                .get_signalling_channel()
                .unwrap()
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(23),
                    10,
                )
                .await
                .unwrap();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) = signal else {
                panic!("unexpected signal");
            };

            let dyn_channel = response.create_le_credit_connection(&request, &mut channel).unwrap();

            let this_channel_id = dyn_channel.get_channel_id();

            let peer_channel_id = dyn_channel.get_peer_channel_id();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::DisconnectRequest(request) = signal else {
                panic!("unexpected signal")
            };

            assert_ne!(peer_channel_id, request.source_cid);

            assert_eq!(this_channel_id, request.destination_cid);

            let Err(DisconnectResponseError::InvalidSourceChannelIdentifier(_)) =
                request.send_disconnect_response(&mut channel).await
            else {
                panic!("unexpected error")
            };
        })
        .run()
        .await
}

#[tokio::test]
async fn le_credit_connection_disconnect_destination_bad_destination_cid() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let request = link
                .get_signalling_channel()
                .unwrap()
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(23),
                    10,
                )
                .await
                .unwrap();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) = signal else {
                panic!("unexpected signal");
            };

            let dyn_channel = response.create_le_credit_connection(&request, &mut channel).unwrap();

            let this_channel_id = dyn_channel.get_channel_id();

            let peer_channel_id = dyn_channel.get_peer_channel_id();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::DisconnectRequest(request) = signal else {
                panic!("unexpected signal")
            };

            assert_eq!(peer_channel_id, request.source_cid,);

            assert_ne!(this_channel_id, request.destination_cid);

            let Err(DisconnectResponseError::InvalidDestinationChannelIdentifier(_)) =
                request.send_disconnect_response(&mut channel).await
            else {
                panic!("unexpected error")
            };

            std::future::pending::<()>().await;
        })
        .set_verify(|mut end| async move {
            let le_connect_request = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                le_connect_request,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0, 1, 23, 0, 10, 0]
            );

            let le_connect_response =
                L2capFragment::new(true, [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 250, 0, 23, 0, 10, 0, 0, 0]);

            end.send(le_connect_response).await.unwrap();

            let disconnect_request = L2capFragment::new(true, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x7f, 0, 0x40, 0]);

            end.send(disconnect_request).await.unwrap();

            let err_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(err_response, [10, 0, 5, 0, 1, 1, 6, 0, 2, 0, 0x7f, 0, 0x40, 0])
        })
        .run()
        .await
}

#[tokio::test]
async fn le_credit_connection_disconnect_destination_bad_destination_race() {
    PhysicalLinkLoop::default()
        .test_scaffold()
        .set_tested(|end| async {
            let mut link = LeULogicalLink::builder(end)
                .enable_signalling_channel()
                .use_vec_buffer()
                .use_vec_sdu_buffer()
                .build();

            let request = link
                .get_signalling_channel()
                .unwrap()
                .request_le_credit_connection(
                    SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                    LeCreditMtu::new(256),
                    LeCreditMps::new(23),
                    10,
                )
                .await
                .unwrap();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) = signal else {
                panic!("unexpected signal");
            };

            let dyn_channel = response.create_le_credit_connection(&request, &mut channel).unwrap();

            let this_channel_id = dyn_channel.get_channel_id();

            let peer_channel_id = dyn_channel.get_peer_channel_id();

            // race is on!
            link.get_signalling_channel()
                .unwrap()
                .request_disconnection(this_channel_id)
                .await
                .unwrap();

            let LeUNext::SignallingChannel { signal, mut channel } = link.next().await.unwrap() else {
                panic!("unexpected next");
            };

            let ReceivedLeUSignal::DisconnectRequest(request) = signal else {
                panic!("unexpected signal")
            };

            assert_eq!(peer_channel_id, request.source_cid,);

            assert_eq!(this_channel_id, request.destination_cid);

            request.send_disconnect_response(&mut channel).await.unwrap();

            std::future::pending::<()>().await;
        })
        .set_verify(|mut end| async move {
            let le_connect_request = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(
                le_connect_request,
                [14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0, 1, 23, 0, 10, 0]
            );

            let le_connect_response =
                L2capFragment::new(true, [14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 250, 0, 23, 0, 10, 0, 0, 0]);

            end.send(le_connect_response).await.unwrap();

            let disconnect_request = L2capFragment::new(true, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x40, 0, 0x40, 0]);

            end.send(disconnect_request).await.unwrap();

            let disconnect_request = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(disconnect_request, [8, 0, 5, 0, 0x6, 1, 4, 0, 0x40, 0, 0x40, 0]);

            let err_response = end.recv().await.unwrap().unwrap().into_inner().collect::<Vec<_>>();

            assert_eq!(err_response, [10, 0, 5, 0, 1, 1, 6, 0, 2, 0, 0x40, 0, 0x40, 0])
        })
        .run()
        .await
}
