//! Tests for credit based frames

use bo_tie_l2cap::channel::signalling::ReceivedLeUSignal;
use bo_tie_l2cap::pdu::L2capFragment;
use bo_tie_l2cap::signals::packets::{LeCreditMps, LeCreditMtu, SimplifiedProtocolServiceMultiplexer};
use futures::{SinkExt, StreamExt};

const TEST_MESSAGE: &'static str = "At enatare effectu docetur ad. Deveniri invenero earumque rum 
quadrati fas sed. Concilium sufficere etc evidentes eversioni uno. Inge voce volo eas quae regi vel 
suas rom. Praesertim non praecipuum cui religionis inchoandum cum. Fallar cur volunt ita vixque.

Apta volo ac ea etsi. Assentiar quantitas apparebat tribuebam age existimem his hic. Quae fal jam 
imo modo tur scio. Verum ita falli cap cum nonne fas. Ipse omne ejus male cum aut aspi. Studiose 
efficere ex materiam obtinent de quanquam. Tamque nec forsan secedo egisse uno solius. Deteriorem 
sui cohaereant suo pensitatis immortalem.

Ut sciri ausim de at ad certe pedem. Immittant is spontaneo et cognoscam desumptas ne. Matura cap 
scioli quoque non latera quinta instar. Sensum co sumpta quibus ad decipi si. Sui agi somnio genere 
hac maxima pictas deo fallam. Catholicae fit ero excoluisse satyriscos dat deveniatur objectivae 
cohibendam. Dictam mandat usu non rum doctum mox.

Ullo fore suo imo novo fas quid meam fit. Ab quovis tribuo certis is juvare posset fuerim. Vi 
mentes at inquam ha mutata reipsa quanta in. Curant colore ea contra et deesse. Ii materia degenda 
to sentire si in diutius fructum ultimum. Formaliter indefinite potentiali at in ex occurrebat 
catholicae id expectabam. Opiniones at credibile ad in omniscium.

Ad inquiram constare si diversis generali profecta. Clara leone et prima ex. Agendum insuper sui 
lus uti scripta proinde eae plausum subesse. Certas etc calida opinio qualia vul suo cogito rom 
paucos. Objectioni mutationum eo attendendo varietates facillimum id ad. Adjuvetis tam deciperer 
conflatos aut rei exhibetur ibi consuetae. Quare puram eae est dicam ima. Excludat se ex tangatur 
machinae alicujus.

Nia admittere rem sit obversari judicarem. Ipse quas ei ipsa at ut nunc. Ob et me debere ex necdum 
sicque latere quibus dubito. Utcunque ab ne examinem co ad loquendo. Cito sive unde quas etc inde 
hac. Venturum se habeatur id captivus. Iii profecto vis inficior iis sequutus judicare physicam 
gurgitem.

Admonitus distincte jam est cogitatio succedens opinantem archetypi. Ita geometriam sub parentibus 
pensitatis pro. Progressus ut inchoandum abducendam eo dulcedinem exponantur quaerantur. Co im 
contingit existeret at confidere. Cognoscam nam jam cunctaque qui importare. Cum numeri ero sensus 
facere regula accepi. Curam paulo hac mei rea cui solus tactu istae.

Ii alterius ferventi momentum co cohiberi notitiam si. Veram sed ipsos longe supra nam pla vitae 
cui. Eo et ad potest ausint clarae. Modi viam atra ii cera ea plus hinc. Hic efficitur cur 
formantur desinerem his corporeas percipior. Ubi indefinite sim deteriorem mem transferre lus. 
Animalia mei cernitur cui pendeant figmenta ejusmodi. Tangatur una acceptis lor intuebar deceptor 
sub quaesita. Reducantur cau nam perficitur ubi nec incidissem.

Atra ob sola quam spem ergo ii co ei. His perfecti mentibus rei habentem originem cui. Suo 
defectibus potentiale scripturis hoc vul appellatur. Inveniant accepisse videbatur dem pro 
opinionis. Contrarium exhibentur affectibus hac imo seu. Punctum infusum hic ubi rei membris 
scripti. Ope nam veat nul aër dura plus.

Tamquam ita veritas res equidem. Ea in ad expertus paulatim poterunt. Imo volo aspi novi tur.
 Ferre hic neque vulgo hae athei spero. Tantumdem naturales excaecant notaverim etc cau perfacile 
 occurrere. Loco visa to du huic at in dixi aër. ";

macro_rules! request_connect {
    ($l_link:expr, $initial_credits:literal) => {
        request_connect!($l_link, 256, 23, $initial_credits)
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
            ReceivedLeUSignal::LeCreditBasedConnectionResponse(response) => response
                .create_le_credit_connection(&request, &$l_link)
                .expect("unexpected connection rejection"),
            _ => panic!("received unexpected signal"),
        };

        (credit_based_channel, signal_channel)
    }};
}

macro_rules! connect_response {
    ($r_link:expr, $init_credits:literal) => {{
        let mut signal_channel = $r_link.get_signalling_channel();

        let credit_based_channel = match signal_channel.receive().await.expect("failed to get request") {
            ReceivedLeUSignal::LeCreditBasedConnectionRequest(request) => request
                .create_le_credit_based_connection(&$r_link, $init_credits)
                .send_success_response(&mut signal_channel)
                .await
                .expect("failed to send response"),
            _ => panic!("received unexpected signal"),
        };

        (credit_based_channel, signal_channel)
    }};
}

#[tokio::test]
async fn send_single_pdu() {
    let (link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(100);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = request_connect!(link, 256, 256, 0);

        credit_channel.send([0, 1, 2, 3, 4]).await.expect("failed to send SDU");
    });

    rx.next().await.expect("failed to get connect request");

    // send back the connect response
    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 0xFF, 0, 0xFF, 0, 5, 0, 0, 0],
    );

    tx.send(response).await.expect("failed to send connection response");

    let received = rx.next().await.expect("unexpected channel closure");

    assert!(received.is_start_fragment());

    assert_eq!(received.get_data(), &[7, 0, 0x40, 0, 5, 0, 0, 1, 2, 3, 4,]);

    task_handle.await.expect("test task failed");
}

#[tokio::test]
async fn send_single_pdu_multiple_fragments() {
    let (link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(10);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = request_connect!(link, 256, 256, 0);

        credit_channel
            .send([0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            .await
            .expect("failed to send SDU");
    });

    // two fragments will be received as the MTU of
    // the false link is 10.
    rx.next().await.expect("failed to get connect request");
    rx.next().await.expect("failed to get connect request (p2)");

    // send back the connect response
    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 0xFF, 0, 0xFF, 0, 5, 0, 0, 0],
    );

    tx.send(response).await.expect("failed to send connection response");

    let receive_1 = rx.next().await.expect("unexpected channel closure");

    assert!(receive_1.is_start_fragment());

    assert_eq!(receive_1.get_data(), &[18, 0, 0x40, 0, 16, 0, 0, 1, 2, 3]);

    let receive_2 = rx.next().await.expect("unexpected channel closure");

    assert_eq!(receive_2.get_data(), &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13]);

    let receive_3 = rx.next().await.expect("unexpected channel closure");

    assert_eq!(receive_3.get_data(), &[14, 15]);

    task_handle.await.expect("test task failed");
}

#[tokio::test]
async fn send_multiple_pdu_for_sdu() {
    let (link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(10);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, mut signalling_channel) = request_connect!(link, 256, 23, 0);

        let mut maybe_service_data = credit_channel
            .send([
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
                54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64,
            ])
            .await
            .expect("failed to send SDU");

        let inc = match signalling_channel
            .receive()
            .await
            .expect("failed to receive flow control inc")
        {
            ReceivedLeUSignal::FlowControlCreditIndication(inc) => inc,
            _ => panic!("received unexpected signal"),
        };

        maybe_service_data = maybe_service_data
            .expect("maybe_service_data is None")
            .inc_and_send(&mut credit_channel, inc.get_credits())
            .await
            .expect("failed to send more k-frames");

        let inc = match signalling_channel
            .receive()
            .await
            .expect("failed to receive flow control inc")
        {
            ReceivedLeUSignal::FlowControlCreditIndication(inc) => inc,
            _ => panic!("received unexpected signal"),
        };

        maybe_service_data = maybe_service_data
            .expect("maybe_service_data is None")
            .inc_and_send(&mut credit_channel, inc.get_credits())
            .await
            .expect("failed to send more k-frames");

        assert!(maybe_service_data.is_none());
    });

    // two fragments will be received as the MTU of
    // the false link is 10.
    rx.next().await.expect("failed to get connect request");
    rx.next().await.expect("failed to get connect request (p2)");

    // send back the connect response
    let response = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x15, 1, 10, 0, 0x40, 0, 0xFF, 0, 0xFF, 0, 0, 0, 0, 0],
    );

    tx.send(response).await.expect("failed to send connection response");

    // first k-frame broken into fragments
    let first_k_frame: &[&[u8]] = &[
        &[23, 0, 0x40, 0, 65, 0, 0, 1, 2, 3],
        &[4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        &[14, 15, 16, 17, 18, 19, 20],
    ];

    let second_k_frame: &[&[u8]] = &[
        &[23, 0, 0x40, 0, 21, 22, 23, 24, 25, 26],
        &[27, 28, 29, 30, 31, 32, 33, 34, 35, 36],
        &[37, 38, 39, 40, 41, 42, 43],
    ];

    let third_k_frame: &[&[u8]] = &[
        &[21, 0, 0x40, 0, 44, 45, 46, 47, 48, 49],
        &[50, 51, 52, 53, 54, 55, 56, 57, 58, 59],
        &[60, 61, 62, 63, 64],
    ];

    match tokio::time::timeout(std::time::Duration::from_millis(100), rx.next()).await {
        Ok(None) => panic!("unexpected receiver closed"),
        Ok(_) => panic!("unexpected receive when no credits"),
        Err(_) => {
            // there were no credits "given" to the task's
            // credit based channel, so the future returned
            // by `rx.next()` is expected to never complete.

            // send the flow control indication
            let fc_ind = L2capFragment::new(true, vec![8, 0, 5, 0, 0x16, 1, 4, 0, 0x40, 0, 1, 0]);

            tx.send(fc_ind).await.expect("failed to send credit indication");
        }
    };

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), first_k_frame[0]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), first_k_frame[1]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), first_k_frame[2]);

    match tokio::time::timeout(std::time::Duration::from_millis(100), rx.next()).await {
        Ok(None) => panic!("unexpected receiver closed"),
        Ok(_) => panic!("unexpected receive when no credits"),
        Err(_) => {
            // there was only one credit given to the task's
            // credit based channel, so now there should be
            // no more.

            // send the flow control indication; enough
            // credits (2) are given to complete the test.
            let fc_ind = L2capFragment::new(true, vec![8, 0, 5, 0, 0x16, 1, 4, 0, 0x40, 0, 2, 0]);

            tx.send(fc_ind).await.expect("failed to send credit indication");
        }
    };

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), second_k_frame[0]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), second_k_frame[1]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), second_k_frame[2]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), third_k_frame[0]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), third_k_frame[1]);

    let recv = rx.next().await.expect("unexpected channel closure");

    assert_eq!(recv.get_data(), third_k_frame[2]);

    task_handle.await.expect("test task failed");
}

#[tokio::test]
async fn recv_single_pdu() {
    let (link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(100);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = connect_response!(link, 1);

        assert_eq!(credit_channel.get_this_channel_id().to_val(), 0x40);

        assert_eq!(credit_channel.get_peer_channel_id().to_val(), 0x40);

        let sdu: Vec<u8> = credit_channel
            .receive(&mut Vec::new(), false)
            .await
            .expect("failed to receive")
            .expect("expected SDU");

        assert_eq!(&sdu, &[0, 1, 2, 3, 4, 5]);

        assert_eq!(credit_channel.get_received_pdu_count(), 1);
    });

    let connect_request = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0xFF, 0, 0xFF, 0, 0, 0],
    );

    tx.send(connect_request).await.expect("failed to send");

    assert_eq!(rx.next().await.expect("failed to recv").get_data()[2], 5);

    let k_frame = L2capFragment::new(true, vec![8, 0, 0x40, 0, 6, 0, 0, 1, 2, 3, 4, 5]);

    tx.send(k_frame).await.expect("failed to send");

    task_handle.await.expect("test task failed");
}

#[tokio::test]
async fn recv_single_pdu_multi_fragments() {
    let (link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(10);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = connect_response!(link, 1);

        let sdu: Vec<u8> = credit_channel
            .receive(&mut Vec::new(), false)
            .await
            .expect("failed to receive")
            .expect("expected SDU");

        assert_eq!(&sdu, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    });

    let connect_request_1 = L2capFragment::new(true, vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0]);

    let connect_request_2 = L2capFragment::new(false, vec![0x40, 0, 0xFF, 0, 0xFF, 0, 0, 0]);

    tx.send(connect_request_1).await.expect("channel closed");

    tx.send(connect_request_2).await.expect("channel closed");

    // 2x rx for full response
    rx.next().await.expect("failed to receive connect response");
    rx.next().await.expect("failed to receive connect response");

    // send the data
    let fragment_1 = L2capFragment::new(true, vec![13, 0, 0x40, 0, 11, 0, 0, 1, 2, 3]);
    let fragment_2 = L2capFragment::new(false, vec![4, 5, 6, 7, 8, 9, 10]);

    tx.send(fragment_1).await.expect("channel closed");
    tx.send(fragment_2).await.expect("channel closed");

    task_handle.await.expect("test task failed");
}

#[tokio::test]
async fn recv_single_pdu_bad_fragment_start_indicator() {
    let (link, mut tx, mut rx) = bo_tie_host_tests::create_le_false_link(10);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = connect_response!(link, 1);

        match credit_channel.receive(&mut Vec::new(), false).await {
            Err(e) => assert_eq!("unexpected first fragment of PDU", &e.to_string()),
            Ok(_) => panic!("unexpected data return"),
        }
    });

    let connect_request_1 = L2capFragment::new(true, vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0]);

    let connect_request_2 = L2capFragment::new(false, vec![0x40, 0, 0xFF, 0, 0xFF, 0, 0, 0]);

    tx.send(connect_request_1).await.expect("channel closed");

    tx.send(connect_request_2).await.expect("channel closed");

    // 2x rx for full response
    rx.next().await.expect("failed to receive connect response");
    rx.next().await.expect("failed to receive connect response");

    // >> both fragments are start fragments <<
    let fragment_1 = L2capFragment::new(true, vec![13, 0, 0x40, 0, 11, 0, 0, 1, 2, 3]);
    let fragment_2 = L2capFragment::new(true, vec![4, 0, 0x40, 0, 4, 5, 6, 7]);

    tx.send(fragment_1).await.expect("channel closed");
    tx.send(fragment_2).await.expect("channel closed");

    task_handle.await.expect("test task failed");
}

#[tokio::test]
async fn receive_multiple_pdu_for_sdu() {
    let (link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(10);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = connect_response!(link, 0xFFFF);

        let sdu = credit_channel
            .receive(&mut Vec::new(), false)
            .await
            .expect("failed to receive")
            .expect("expected SDU");

        assert_eq!(
            &sdu,
            &[
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27,
                28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53,
                54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99,
            ]
        );
    });

    let connect_request = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0xFF, 0, 23, 0, 0, 0],
    );

    tx.send(connect_request).await.expect("channel closed");

    let fragments = [
        // first pdu
        L2capFragment::new(true, vec![23, 0, 0x40, 0, 100, 0, 0, 1, 2, 3]),
        L2capFragment::new(false, vec![4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
        L2capFragment::new(false, vec![14, 15, 16, 17, 18, 19, 20]),
        // second
        L2capFragment::new(true, vec![23, 0, 0x40, 0, 21, 22, 23, 24, 25, 26]),
        L2capFragment::new(false, vec![27, 28, 29, 30, 31, 32, 33, 34, 35, 36]),
        L2capFragment::new(false, vec![37, 38, 39, 40, 41, 42, 43]),
        // third
        L2capFragment::new(true, vec![23, 0, 0x40, 0, 44, 45, 46, 47, 48, 49]),
        L2capFragment::new(false, vec![50, 51, 52, 53, 54, 55, 56, 57, 58, 59]),
        L2capFragment::new(false, vec![60, 61, 62, 63, 64, 65, 66]),
        // forth
        L2capFragment::new(true, vec![23, 0, 0x40, 0, 67, 68, 69, 70, 71, 72]),
        L2capFragment::new(false, vec![73, 74, 75, 76, 77, 78, 79, 80, 81, 82]),
        L2capFragment::new(false, vec![83, 84, 85, 86, 87, 88, 89]),
        // forth
        L2capFragment::new(true, vec![10, 0, 0x40, 0, 90, 91, 92, 93, 94, 95]),
        L2capFragment::new(false, vec![96, 97, 98, 99]),
    ];

    for fragment in fragments {
        tx.send(fragment).await.expect("failed to send fragment")
    }

    task_handle.await.expect("test task failed")
}

#[tokio::test]
async fn incorrect_sdu_length() {
    let (link, mut tx, _rx) = bo_tie_host_tests::create_le_false_link(10);

    let task_handle = tokio::spawn(async move {
        let (mut credit_channel, _) = connect_response!(link, 1);

        match credit_channel.receive(&mut Vec::new(), false).await {
            Err(e) => assert_eq!("SDU length field does not match SDU size", &e.to_string()),
            Ok(_) => panic!("unexpected SDU data"),
        }
    });

    let connect_request = L2capFragment::new(
        true,
        vec![14, 0, 5, 0, 0x14, 1, 10, 0, 0x80, 0, 0x40, 0, 0xFF, 0, 23, 0, 0, 0],
    );

    tx.send(connect_request).await.expect("channel closed");

    let fragments = [
        // first pdu
        L2capFragment::new(true, vec![23, 0, 0x40, 0, 29, 0, 0, 1, 2, 3]),
        L2capFragment::new(false, vec![4, 5, 6, 7, 8, 9, 10, 11, 12, 13]),
        L2capFragment::new(false, vec![14, 15, 16, 17, 18, 19, 20]),
        // second
        L2capFragment::new(true, vec![9, 0, 0x40, 0, 21, 22, 23, 24, 25, 26]),
        L2capFragment::new(false, vec![27, 28, 29]),
    ];

    for fragment in fragments {
        tx.send(fragment).await.expect("failed to send fragment")
    }

    task_handle.await.expect("test task failed")
}

#[tokio::test]
async fn connection_disconnection() {
    let (l_link, r_link) = bo_tie_host_tests::create_le_link(10); // arbitrary size less than the mps

    let l_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let r_barrier = l_barrier.clone();

    let l_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = request_connect!(l_link, 0xFFFF, 60, 10);

        let mut maybe_send_task = credit_based_channel
            .send(TEST_MESSAGE.bytes())
            .await
            .expect("failed to initially send data");

        while let Some(send_task) = maybe_send_task.take() {
            let signal = signalling_channel.receive().await.expect("failed to receive signal");

            match signal {
                ReceivedLeUSignal::FlowControlCreditIndication(ind) => {
                    maybe_send_task = send_task
                        .inc_and_send(&mut credit_based_channel, ind.get_credits())
                        .await
                        .expect("failed to send more credit PDUs");
                }
                _ => (),
            }
        }

        // wait for disconnect request

        loop {
            let signal = signalling_channel.receive().await.expect("failed to receive");

            if let ReceivedLeUSignal::DisconnectRequest(request) = signal {
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
        let (mut credit_based_channel, mut signalling_channel) = connect_response!(r_link, 5);

        let data = credit_based_channel
            .receive(&mut Vec::new(), false)
            .await
            .expect("failed to receive")
            .expect("expected SDU");

        let message = std::str::from_utf8(&data).expect("invalid utf8");

        assert_eq!(TEST_MESSAGE, message);

        assert_eq!(
            TEST_MESSAGE.bytes().len() / 60 /* the mps */ + if 0 == TEST_MESSAGE.bytes().len() % 60 { 0 } else { 1},
            credit_based_channel.get_received_pdu_count()
        );

        assert_eq!(credit_based_channel.get_received_pdu_count(), 0);

        // send disconnection

        signalling_channel
            .request_disconnection(&mut credit_based_channel)
            .await
            .expect("failed to send disconnection request");

        let response = signalling_channel
            .receive()
            .await
            .expect("failed to receive disconnect");

        if let ReceivedLeUSignal::DisconnectResponse(_) = response {
            // nothing to do if response received
        } else {
            panic!("unexpected response signal: {response:?}")
        }

        r_barrier.wait().await;
    });

    tokio::try_join!(l_handle, r_handle).expect("task failed");
}

#[tokio::test]
async fn credit_crunch() {
    let (l_link, r_link) = bo_tie_host_tests::create_le_link(10); // arbitrary size less than the mps

    let l_barrier = std::sync::Arc::new(tokio::sync::Barrier::new(2));

    let r_barrier = l_barrier.clone();

    let l_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = request_connect!(l_link, 0xFFFF, 60, 0);

        let mut test_message = TEST_MESSAGE.bytes();

        let mut sdu_sender = credit_based_channel
            .send(&mut test_message)
            .await
            .expect("failed to send data")
            .expect("expected data to be incomplete");

        loop {
            let signal = signalling_channel.receive().await.expect("receive failed");

            if let ReceivedLeUSignal::FlowControlCreditIndication(ind) = signal {
                sdu_sender = match sdu_sender
                    .inc_and_send(&mut credit_based_channel, ind.get_credits())
                    .await
                    .expect("failed to send")
                {
                    Some(sdu_sender) => sdu_sender,
                    None => break,
                };
            }
        }

        l_barrier.wait().await;
    });

    let r_handle = tokio::spawn(async move {
        let (mut credit_based_channel, mut signalling_channel) = connect_response!(r_link, 2);

        let buffer = &mut Vec::new();

        let data = loop {
            if let Some(data) = credit_based_channel
                .receive(buffer, true)
                .await
                .expect("failed to receive")
            {
                break data;
            } else {
                credit_based_channel
                    .give_credits_to_peer(&mut signalling_channel, 1)
                    .await
                    .expect("peer credits");

                assert_eq!(credit_based_channel.get_credits_given(), 1)
            }
        };

        let message = std::str::from_utf8(&data).expect("invalid utf8");

        assert_eq!(TEST_MESSAGE, message);

        r_barrier.wait().await;
    });

    tokio::try_join!(r_handle, l_handle).expect("task failed");
}
