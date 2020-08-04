//! Attribute Server tests

mod permissions;
mod blob_data;

use crate::l2cap::{MinimumMtu, AclDataFragment};

struct DummyConnection;

impl crate::l2cap::ConnectionChannel for DummyConnection {
    fn send(&self, _: crate::l2cap::AclData) -> crate::l2cap::SendFut {
        crate::l2cap::SendFut::new(true)
    }

    fn set_mtu(&self, _: u16) {}

    fn get_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn max_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn min_mtu(&self) -> usize { crate::l2cap::LeU::MIN_MTU }

    fn receive(&self, _: &core::task::Waker) -> Option<Vec<AclDataFragment>> { Some(Vec::new()) }
}
