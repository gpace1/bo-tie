//! Attribute Server tests

mod permissions;

use std::sync::Arc;
use crate::att::{TransferFormatError, Attribute, AttributePermissions, AttributeRestriction};
use crate::att::server::{PinnedFuture, ServerAttributes};

struct DummyConnection;

impl crate::l2cap::ConnectionChannel for DummyConnection {
    fn send(&self, _: crate::l2cap::AclData) -> crate::l2cap::SendFut {
        crate::l2cap::SendFut::new(true)
    }

    fn set_mtu(&self, _: u16) {}

    fn get_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn max_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn min_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn receive(&self, _: &Waker) -> Option<Vec<AclDataFragment>> { Some(Vec::new()) }
}

mod permission_tests {

}

/// Dynamically sized attribute
///
/// # Note
/// This is not actually Send or Sync, but it is given these traits to get around generic
/// requirements when adding this to a `ServerAttributes`
#[derive(Clone,Default)]
struct DynSizedAttribute {
    data: Vec<u8>
}

unsafe impl Send for DynSizedAttribute {}
unsafe impl Sync for DynSizedAttribute {}

impl crate::att::TransferFormatInto for DynSizedAttribute {
    fn len_of_into(&self) -> usize {
        self.data.len()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&*self.data);
    }
}

impl crate::att::TransferFormatTryFrom for DynSizedAttribute {
    fn try_from(_: &[u8]) -> Result<Self, TransferFormatError> where Self: Sized {
        unimplemented!("DynSizedAttribute is not implemented to be written to")
    }
}

impl crate::att::server::ServerAttributeValue for DynSizedAttribute {

    type Value = Vec<u8>;

    fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
        where F: FnOnce(&Self::Value) -> T + Unpin + 'a
    {
        Box::pin( async move { f(&*self.data) } )
    }

    fn write_val(&mut self, _: Self::Value) -> PinnedFuture<'_, ()> {
        unimplemented!()
    }

    fn eq<'a>(&'a self, other: &'a Self::Value) -> PinnedFuture<'a, bool> {
        Box::pin( async move { &*self.data == other } )
    }
}

#[test]
fn blobbing_test() {

    let mut server_attribute = ServerAttributes::new();

    let att_uuid = 0x1u16.into();

    let att_val = DynSizedAttribute::default();

    let att = Attribute::new(
        att_uuid,
        [AttributePermissions::Read(AttributeRestriction::None)].into(),
        att_val.clone(),
    );

    let att_handle = server_attribute.push(att);

    let server = super::Server::new(&DummyConnection, server_attribute);


}