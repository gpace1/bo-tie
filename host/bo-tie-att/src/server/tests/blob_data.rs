//! Tests around reading blobbed data from a server

use super::{pdu_into_acl_data, DummyConnection};
use crate::server::tests::{DummyRecvFut, DummySendFut};
use crate::{
    pdu,
    server::{NoQueuedWrites, Server, ServerAttributes, ServerPduName},
    Attribute, AttributePermissions, AttributeRestriction, TransferFormatError, TransferFormatInto,
    TransferFormatTryFrom, Uuid,
};
use bo_tie_l2cap::{BasicFrame, ConnectionChannel, MinimumMtu};
use bo_tie_util::buffer::de_vec::DeVec;
use std::sync::Arc;
use tokio::sync::Mutex;

/// A connection channel that counts the number of payload bytes sent
///
/// Keeps the number of bytes that were sent as part of the l2cap payload in the last call to
/// `send`. `send` will also panic if the sent ATT data is a error response.
#[derive(Default)]
struct SendWatchConnection {
    sent_data: core::cell::RefCell<Vec<u8>>,
}

impl SendWatchConnection {
    fn reset_data(&self) {
        self.sent_data.borrow_mut().clear();
    }

    fn len_of_data(&self) -> usize {
        self.sent_data.borrow().len()
    }
}

impl ConnectionChannel for SendWatchConnection {
    type SendBuffer = DeVec<u8>;
    type SendFut<'a> = DummySendFut;
    type SendErr = usize;
    type RecvBuffer = DeVec<u8>;
    type RecvFut<'a> = DummyRecvFut;

    fn send(&self, data: BasicFrame<Vec<u8>>) -> Self::SendFut<'_> {
        let pdu_name = ServerPduName::try_from(data.get_payload()[0]);

        // add the attribute value bytes and skip the header
        match pdu_name {
            Ok(ServerPduName::ReadBlobResponse) => {
                self.sent_data.borrow_mut().extend_from_slice(&data.get_payload()[1..])
            }

            Ok(ServerPduName::ReadResponse) => self.sent_data.borrow_mut().extend_from_slice(&data.get_payload()[1..]),

            Ok(ServerPduName::ErrorResponse) => panic!(
                "Server sent error `{:?}`",
                <pdu::Pdu<pdu::ErrorResponse> as TransferFormatTryFrom>::try_from(data.get_payload())
                    .unwrap()
                    .get_parameters()
                    .error
            ),

            p => panic!("Unexpected pdu: {:?}", p),
        }

        let payload_len = data.get_payload().len();

        // Validate that the payload length is less than the MTU
        assert!(
            payload_len <= self.get_mtu(),
            "Expected l2cap payloads no larger than {}, tried \
            to send {} bytes",
            self.get_mtu(),
            payload_len
        );

        DummySendFut
    }

    fn set_mtu(&mut self, _: u16) {}

    fn get_mtu(&self) -> usize {
        bo_tie_l2cap::LeU::MIN_SUPPORTED_MTU
    }

    fn max_mtu(&self) -> usize {
        bo_tie_l2cap::LeU::MIN_SUPPORTED_MTU
    }

    fn min_mtu(&self) -> usize {
        bo_tie_l2cap::LeU::MIN_SUPPORTED_MTU
    }

    fn receive_fragment(&mut self) -> Self::RecvFut<'_> {
        DummyRecvFut
    }
}

/// Dynamically sized attribute
///
/// # Note
/// This is not actually Send or Sync, but it is given these traits to get around generic
/// requirements when adding this to a `ServerAttributes`.
#[derive(Clone, Default, PartialEq)]
struct DynSizedAttribute {
    data: Vec<usize>,
}

impl TransferFormatInto for DynSizedAttribute {
    fn len_of_into(&self) -> usize {
        self.data.len() * core::mem::size_of::<usize>()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.data.build_into_ret(into_ret)
    }
}

impl TransferFormatTryFrom for DynSizedAttribute {
    fn try_from(_: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        unimplemented!("DynSizedAttribute is not implemented to be written to")
    }
}

struct BlobTestInfo<Q> {
    att_uuid: Uuid,
    att_val: Arc<Mutex<DynSizedAttribute>>,
    att_handle: u16,
    server: Server<Q>,
}

impl BlobTestInfo<NoQueuedWrites> {
    #[cfg(feature = "tokio")]
    fn new() -> Self {
        let mut server_attribute = ServerAttributes::new();

        let att_uuid = Uuid::from_u16(0x1u16);

        let att_val: Arc<Mutex<DynSizedAttribute>> = Arc::default();

        let att = Attribute::new(
            att_uuid,
            [AttributePermissions::Read(AttributeRestriction::None)].to_vec(),
            att_val.clone(),
        );

        let att_handle = server_attribute.push_accessor(att);

        let mut server = Server::new(server_attribute, NoQueuedWrites);

        server.give_permissions_to_client(crate::FULL_READ_PERMISSIONS);

        Self {
            att_uuid,
            att_val,
            att_handle,
            server,
        }
    }
}

fn rand_usize_vec(size: usize) -> Vec<usize> {
    let mut v = Vec::with_capacity(size);

    (0..size).for_each(|_| v.push(rand::random()));

    v
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn blobbing_from_blob_request() {
    let mut connection_channel = SendWatchConnection::default();

    let mut bti = BlobTestInfo::new();

    // amount of bytes sent from the attribute value in a pdu to the imaginary client. The minus
    // one is because each read blob response has a 1 byte header
    let sent_bytes = connection_channel.max_mtu() - 1;

    let item_size = std::mem::size_of::<usize>();

    let item_cnt = item_size * sent_bytes;

    // Test no blobbing made with data that doesn't have a sent size

    let request_1 = pdu_into_acl_data(pdu::read_blob_request(bti.att_handle, 0));

    bti.server
        .process_att_pdu(&mut connection_channel, &request_1)
        .await
        .unwrap();

    assert!(bti.server.blob_data.is_none());

    connection_channel.reset_data();

    // Test data that should cause blobbing when read

    bti.att_val.lock().await.data = rand_usize_vec(item_cnt);

    let request_2 = pdu_into_acl_data(pdu::read_blob_request(bti.att_handle, 0));

    bti.server
        .process_att_pdu(&mut connection_channel, &request_2)
        .await
        .unwrap();

    assert!(bti.server.blob_data.is_some());

    assert_eq!(
        bti.server.blob_data.as_ref().unwrap().tf_data,
        TransferFormatInto::into(&bti.att_val.lock().await.data)
    );

    assert_eq!(bti.server.blob_data.as_ref().unwrap().handle, bti.att_handle);

    // Amount sent should be the maximum amount
    assert_eq!(connection_channel.len_of_data(), sent_bytes);

    // Get rest of data. This should be an exact amount sent, meaning every message sent should
    // contain the MTU amount of data.
    for offset in (sent_bytes..(item_cnt * item_size)).step_by(sent_bytes) {
        let request = pdu_into_acl_data(pdu::read_blob_request(bti.att_handle, offset as u16));

        bti.server
            .process_att_pdu(&mut connection_channel, &request)
            .await
            .unwrap();

        let expected_sent = if (offset + sent_bytes) < (item_cnt * item_size) {
            offset + sent_bytes
        } else {
            item_cnt * item_size
        };

        assert_eq!(connection_channel.len_of_data(), expected_sent);
    }

    // The algorithm needs to keep alive the data as the client doesn't know that the data is
    // complete and a client would normally request again with the offset equal to the data length
    // (offset == data length is what it doesn't know).
    assert!(bti.server.blob_data.is_some());

    let request_last = pdu_into_acl_data(pdu::read_blob_request(bti.att_handle, (item_cnt * item_size) as u16));

    bti.server
        .process_att_pdu(&mut connection_channel, &request_last)
        .await
        .unwrap();

    assert!(bti.server.blob_data.is_none());

    connection_channel.reset_data();

    // Testing a quirk of the blob read. In the doc it mentions that blobs do not drop if reads
    // do not cause blobbing

    let blob_request_tangent = pdu_into_acl_data(pdu::read_blob_request(bti.att_handle, 0));

    bti.server
        .process_att_pdu(&mut connection_channel, &blob_request_tangent)
        .await
        .unwrap();

    // Put the max amount of bytes within a read that will not cause blobbing
    let other_data = (0..sent_bytes - 1).map(|v| v as u8).collect::<Vec<_>>();

    let other_handle = bti.server.push(crate::Attribute::new(
        1u16.into(),
        crate::FULL_READ_PERMISSIONS.to_vec(),
        other_data,
    ));

    let read_request_tangent = pdu_into_acl_data(pdu::read_request(other_handle));

    bti.server
        .process_att_pdu(&mut connection_channel, &read_request_tangent)
        .await
        .unwrap();

    assert_eq!(
        bti.server.blob_data.as_ref().unwrap().tf_data,
        TransferFormatInto::into(&bti.att_val.lock().await.data)
    );
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn blobbing_from_read_request_test() {
    let mut blob_info = BlobTestInfo::new();

    let request_1 = pdu_into_acl_data(pdu::read_request(blob_info.att_handle));

    blob_info
        .server
        .process_att_pdu(&mut DummyConnection, &request_1)
        .await
        .unwrap();

    assert!(blob_info.server.blob_data.is_none());

    blob_info.att_val.lock().await.data = rand_usize_vec(32);

    let request_2 = pdu_into_acl_data(pdu::read_request(blob_info.att_handle));

    blob_info
        .server
        .process_att_pdu(&mut DummyConnection, &request_2)
        .await
        .unwrap();

    assert!(blob_info.server.blob_data.is_some());
}

#[tokio::test]
#[cfg(feature = "tokio")]
async fn blobbing_from_read_by_type() {
    let mut blob_info = BlobTestInfo::new();

    let request_1 = pdu_into_acl_data(pdu::read_by_type_request(.., blob_info.att_uuid));

    blob_info
        .server
        .process_att_pdu(&mut DummyConnection, &request_1)
        .await
        .unwrap();

    assert!(blob_info.server.blob_data.is_none());

    blob_info.att_val.lock().await.data = rand_usize_vec(32);

    let request_2 = pdu_into_acl_data(pdu::read_by_type_request(.., blob_info.att_uuid));

    blob_info
        .server
        .process_att_pdu(&mut DummyConnection, &request_2)
        .await
        .unwrap();

    assert!(blob_info.server.blob_data.is_some());
}
