use bo_tie_host_tests::PhysicalLink;
use bo_tie_l2cap::channel::id::DynChannelId;
use bo_tie_l2cap::channel::signalling::ReceivedSignal;
use bo_tie_l2cap::pdu::BasicFrame;
use bo_tie_l2cap::signals::packets::{
    LeCreditBasedConnectionRequest, LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer,
};
use bo_tie_l2cap::{BasicFrameChannel, CreditBasedChannel, LeULogicalLink};
use std::num::NonZeroU8;
use std::sync::Arc;
use futures::StreamExt;
use tokio::sync::Barrier;

enum LeChannelType<'a> {
    Fixed(BasicFrameChannel<'a, LeULogicalLink<PhysicalLink>>),
    Credit(CreditBasedChannel<'a, LeULogicalLink<PhysicalLink>>),
}

/// Test for multiple channels running at the same time.
#[tokio::test]
async fn le_link_multiple_channels() {
    const CHANNEL_COUNT: usize = 0x80 - 0x40 + 2; // dynamic channels + 2 fixed channels

    let (l_link, r_link) = bo_tie_host_tests::create_le_link(10);

    let l_end = Arc::new(Barrier::new(2));

    let r_end = l_end.clone();

    let l_test_data: Vec<Vec<u8>> = tokio::task::spawn_blocking(|| {
        (0..CHANNEL_COUNT)
            .map(|_| {
                let test_data_size: usize = rand::random::<u16>().into();

                let mut rng: rand_chacha::ChaCha8Rng = rand::SeedableRng::from_entropy();

                let mut test_data = Vec::new();

                test_data.resize(test_data_size, 0u8);

                rand::RngCore::fill_bytes(&mut rng, &mut test_data);

                test_data
            })
            .collect::<Vec<_>>()
    })
    .await
    .expect("failed to generate test data");

    let r_test_data = l_test_data.clone();

    tokio::spawn(async move {
        let mut signalling_channel = l_link.get_signalling_channel();

        let mut channels = Vec::with_capacity(CHANNEL_COUNT);

        channels.push(LeChannelType::Fixed(l_link.get_att_channel()));
        channels.push(LeChannelType::Fixed(l_link.get_sm_channel()));

        let (next, _) = futures::stream::iter((0x40..=0x7f).map(|source_cid| Box::pin( async {
            let request = LeCreditBasedConnectionRequest {
                identifier: NonZeroU8::new(1).unwrap(),
                spsm: SimplifiedProtocolServiceMultiplexer::new_dyn(0x80),
                source_dyn_cid: DynChannelId::new_dyn_le(source_cid).unwrap(),
                mtu: LeCreditMtu::new(53),
                mps: LeCreditMps::new(256),
                initial_credits: 10,
            };

            signalling_channel
                .request_le_credit_connection(request)
                .await
                .map_err(|_| format!("failed to send request for {:?}", request))
                .unwrap();

            let response = signalling_channel.receive().await.expect("failed to receive signal");

            let credit_based_connection = if let ReceivedSignal::LeCreditBasedConnectionResponse(response) = response {
                response.create_le_credit_connection(&request, &l_link)
            } else {
                panic!("received unexpected signal")
            };

            channels.push(LeChannelType::Credit(credit_based_connection))
        })))
            .buffer_unordered(0x80 - 0x40)
            .into_future()
            .await;

        assert!(next.is_none(), "not all connections were made");

        // shuffling the channels to test robustness
        let mut rng: rand_chacha::ChaCha8Rng = rand::SeedableRng::seed_from_u64(rand::random());

        rand::seq::SliceRandom::shuffle(channels.as_mut_slice(), &mut rng);

        let stream = futures::stream::iter(channels.into_iter().zip(l_test_data.into_iter()).map(
            |(channel, test_data)| async move {
                match channel {
                    LeChannelType::Fixed(mut fixed) => {
                        let b_frame = BasicFrame::new(test_data, fixed.get_cid());

                        fixed.send(b_frame).await.expect("failed to send data on fixed channel");
                    }
                    LeChannelType::Credit(mut credit) => {
                        let maybe_send = credit.send(test_data).await.expect("failed to send data");

                        while let Some(send_more) = maybe_send {
                            signalling_channel.
                        }
                    }
                }
            },
        ));

        l_end.wait().await;
    });

    tokio::spawn(async move {
        let mut signalling_channel = r_link.get_signalling_channel();

        let mut channels = Vec::with_capacity(0x80 - 0x40 + 2);

        channels.push(LeChannelType::Fixed(r_link.get_att_channel()));
        channels.push(LeChannelType::Fixed(r_link.get_sm_channel()));

        let this_cids_list = (0x40..=0x7f).collect::<Vec<u16>>();

        while !this_cids_list.is_empty() {
            let request = signalling_channel
                .receive()
                .await
                .expect("failed to receive le credit connection request");

            let credit_based_connection = if let ReceivedSignal::LeCreditBasedConnectionRequest(request) = request {
                let mut connection_builder = request.create_le_credit_based_connection(&r_link, 5);

                connection_builder.set_responded_mtu(23);
                connection_builder.set_responded_mps(100);

                connection_builder
                    .send_response(&mut signalling_channel)
                    .await
                    .expect("failed to send response")
            } else {
                panic!("unexpected request received")
            };

            channels.push(LeChannelType::Credit(credit_based_connection))
        }

        r_end.wait().await;
    });
}

// test drop of channel
// -> in middle of rx
// -> in middle of tx

// test drop fo collection
// -> in middle of rx
// -> in middle of tx
