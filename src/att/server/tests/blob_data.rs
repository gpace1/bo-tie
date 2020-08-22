//! Tests around reading blobbed data from a server

use futures::executor::block_on;
use crate::{
    att::{
        pdu,
        TransferFormatError,
        TransferFormatInto,
        TransferFormatTryFrom,
        Attribute,
        AttributePermissions,
        AttributeRestriction,
        server::{
            PinnedFuture,
            Server,
            ServerAttributes,
            ServerAttributeValue,
            ServerPduName,
            NoQueuedWrites,
        },
    },
    UUID,
    l2cap::{
        AclDataFragment,
        ConnectionChannel,
        MinimumMtu,
    },
};
use super::{DummyConnection,pdu_into_acl_data};

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

    fn len_of_data(&self) -> usize { self.sent_data.borrow().len() }
}

impl crate::l2cap::ConnectionChannel for SendWatchConnection {

    fn send(&self, data: crate::l2cap::AclData) -> crate::l2cap::SendFut {
        use std::convert::TryFrom;

        let pdu_name = ServerPduName::try_from(data.get_payload()[0]);

        // add the attribute value bytes and skip the header
        match pdu_name {
            Ok( ServerPduName::ReadBlobResponse ) =>
                self.sent_data.borrow_mut().extend_from_slice( &data.get_payload()[1..] ),

            Ok( ServerPduName::ReadResponse ) =>
                self.sent_data.borrow_mut().extend_from_slice( &data.get_payload()[1..] ),

            Ok(ServerPduName::ErrorResponse) =>
                panic!("Server sent error `{:?}`",
                    <pdu::Pdu<pdu::ErrorResponse> as TransferFormatTryFrom>::try_from(
                        data.get_payload()
                    )
                    .unwrap()
                    .get_parameters()
                    .error
                ),

            p => panic!("Unexpected pdu: {:?}", p),
        }

        let payload_len = data.get_payload().len();

        // Validate that the payload length is less than the MTU
        assert!( payload_len <= self.get_mtu(), "Expected l2cap payloads no larger than {}, tried \
            to send {} bytes", self.get_mtu(), payload_len );

        crate::l2cap::SendFut::new(true)
    }

    fn set_mtu(&self, _: u16) {}

    fn get_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn max_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn min_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn receive(&self, _: &core::task::Waker) -> Option<Vec<AclDataFragment>> { Some(Vec::new()) }
}

/// Dynamically sized attribute
///
/// # Note
/// This is not actually Send or Sync, but it is given these traits to get around generic
/// requirements when adding this to a `ServerAttributes`.
#[derive(Clone,Default)]
struct DynSizedAttribute {
    data: std::rc::Rc<std::cell::RefCell<Vec<usize>>>
}

unsafe impl Send for DynSizedAttribute {}
unsafe impl Sync for DynSizedAttribute {}

impl TransferFormatInto for DynSizedAttribute {

    fn len_of_into(&self) -> usize {
        self.data.borrow().len() * core::mem::size_of::<usize>()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        (*self.data.borrow()).build_into_ret(into_ret)
    }
}

impl TransferFormatTryFrom for DynSizedAttribute {
    fn try_from(_: &[u8]) -> Result<Self, TransferFormatError> where Self: Sized {
        unimplemented!("DynSizedAttribute is not implemented to be written to")
    }
}

impl ServerAttributeValue for DynSizedAttribute {

    type Value = Vec<usize>;

    fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
        where F: FnOnce(&Self::Value) -> T + Unpin + 'a
    {
        Box::pin( async move { f(&*self.data.borrow()) } )
    }

    fn write_val(&mut self, _: Self::Value) -> PinnedFuture<'_, ()> {
        unimplemented!()
    }

    fn eq<'a>(&'a self, other: &'a Self::Value) -> PinnedFuture<'a, bool> {
        Box::pin( async move { &*self.data.borrow() == other } )
    }
}

struct BlobTestInfo<'c,C,Q> {
    att_uuid: UUID,
    att_val: DynSizedAttribute,
    att_handle: u16,
    server: crate::att::server::Server<'c,C,Q>,
}

impl<'a,C: ConnectionChannel> BlobTestInfo<'a,C,NoQueuedWrites> {
    fn new(dc: &'a C) -> Self {

        let mut server_attribute = ServerAttributes::new();

        let att_uuid = 0x1u16.into();

        let att_val = DynSizedAttribute::default();

        let att = Attribute::new(
            att_uuid,
            [AttributePermissions::Read(AttributeRestriction::None)].into(),
            att_val.clone(),
        );

        let att_handle = server_attribute.push(att);

        let mut server = Server::new(dc, server_attribute, NoQueuedWrites);

        server.give_permissions_to_client(crate::att::FULL_READ_PERMISSIONS);

        Self { att_uuid, att_val, att_handle, server }
    }
}

fn rand_usize_vec(size: usize) -> Vec<usize> {
    let mut v = Vec::with_capacity(size);

    (0..size).for_each(|_| v.push(rand::random()) );

    v
}

#[test]
fn blobbing_from_blob_request() {

    let connection = SendWatchConnection::default();

    let mut bti = BlobTestInfo::new(&connection);

    // amount of bytes sent from the attribute value in a pdu to the imaginary client. The minus
    // one is because each read blob response has a 1 byte header
    let sent_bytes = connection.max_mtu() - 1;

    let item_size = std::mem::size_of::<usize>();

    let item_cnt = item_size * sent_bytes;

    // Test no blobbing made with data that doesn't have a sent size

    let request_1 = pdu_into_acl_data( pdu::read_blob_request(bti.att_handle, 0) );

    block_on( bti.server.process_acl_data( &request_1 ) ).unwrap();

    assert!(bti.server.blob_data.is_none());

    connection.reset_data();

    // Test data that should cause blobbing when read

    *bti.att_val.data.borrow_mut() = rand_usize_vec(item_cnt);

    let request_2 = pdu_into_acl_data( pdu::read_blob_request(bti.att_handle, 0) );

    block_on( bti.server.process_acl_data( &request_2 ) ).unwrap();

    assert!( bti.server.blob_data.is_some() );

    assert_eq!(
        bti.server.blob_data.as_ref().unwrap().tf_data,
        TransferFormatInto::into(&*bti.att_val.data.borrow())
    );

    assert_eq!( bti.server.blob_data.as_ref().unwrap().handle, bti.att_handle );

    // Amount sent should be the maximum amount
    assert_eq!( connection.len_of_data(), sent_bytes );

    // Get rest of data. This should be an exact amount sent, meaning every message sent should
    // contain the MTU amount of data.
    for offset in (sent_bytes..(item_cnt * item_size)).step_by(sent_bytes) {
        let request = pdu_into_acl_data( pdu::read_blob_request(bti.att_handle, offset as u16) );

        block_on( bti.server.process_acl_data(&request) ).unwrap();

        let expected_sent = if (offset + sent_bytes) < (item_cnt * item_size) {
            offset + sent_bytes
        } else {
            item_cnt * item_size
        };

        assert_eq!( connection.len_of_data(), expected_sent );
    }

    // The algorithm needs to keep alive the data as the client doesn't know that the data is
    // complete and a client would normally request again with the offset equal to the data length
    // (offset == data length is what it doesn't know).
    assert!( bti.server.blob_data.is_some() );

    let request_last = pdu_into_acl_data(
        pdu::read_blob_request(bti.att_handle, (item_cnt * item_size) as u16)
    );

    block_on( bti.server.process_acl_data(&request_last) ).unwrap();

    assert!( bti.server.blob_data.is_none() );

    connection.reset_data();

    // Testing a quirk of the blob read. In the doc it mentions that blobs do not drop if reads
    // do not cause blobbing

    let blob_request_tangent = pdu_into_acl_data( pdu::read_blob_request(bti.att_handle, 0) );

    block_on( bti.server.process_acl_data(&blob_request_tangent) ).unwrap();

    // Put the max amount of bytes within a read that will not cause blobbing
    let other_data = (0..sent_bytes - 1).map(|v| v as u8).collect::<Vec<_>>();

    let other_handle = bti.server.push(
        crate::att::Attribute::new(
            1u16.into(),
            crate::att::FULL_READ_PERMISSIONS.to_vec(),
            other_data
        )
    );

    let read_request_tangent = pdu_into_acl_data( pdu::read_request(other_handle) );

    block_on( bti.server.process_acl_data(&read_request_tangent) ).unwrap();

    assert_eq!(
        bti.server.blob_data.as_ref().unwrap().tf_data,
        TransferFormatInto::into(&*bti.att_val.data.borrow())
    );
}

#[test]
fn blobbing_from_read_request_test() {

    let mut blob_info = BlobTestInfo::new(&DummyConnection);

    let request_1 = pdu_into_acl_data( pdu::read_request(blob_info.att_handle) );

    block_on( blob_info.server.process_acl_data(&request_1) ).unwrap();

    assert!( blob_info.server.blob_data.is_none() );

    *blob_info.att_val.data.borrow_mut() = rand_usize_vec(32);

    let request_2 = pdu_into_acl_data( pdu::read_request(blob_info.att_handle) );

    block_on( blob_info.server.process_acl_data(&request_2) ).unwrap();

    assert!( blob_info.server.blob_data.is_some() );
}

#[test]
fn blobbing_from_read_by_type() {

    let mut blob_info = BlobTestInfo::new(&DummyConnection);

    let request_1 = pdu_into_acl_data( pdu::read_by_type_request(.., blob_info.att_uuid) );

    block_on( blob_info.server.process_acl_data(&request_1) ).unwrap();

    assert!( blob_info.server.blob_data.is_none() );

    *blob_info.att_val.data.borrow_mut() = rand_usize_vec(32);

    let request_2 = pdu_into_acl_data( pdu::read_by_type_request(.., blob_info.att_uuid) );

    block_on( blob_info.server.process_acl_data(&request_2) ).unwrap();

    assert!( blob_info.server.blob_data.is_some() );
}