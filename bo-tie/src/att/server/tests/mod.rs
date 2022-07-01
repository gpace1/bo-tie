//! Attribute Server tests

mod basic_queue_writer;
mod blob_data;
mod permissions;

use crate::att::server::PinnedFuture;
use crate::att::{pdu, TransferFormatInto};
use crate::l2cap::{BasicInfoFrame, ConnectionChannel, L2capFragment, MinimumMtu};

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

/// A false connection.
///
/// Sending to this connection will send nothing and consequently receiving will also return
/// nothing (but not `None`, instead an empty vector).
struct DummyConnection;

struct DummySendFut;

impl Future for DummySendFut {
    type Output = Result<(), ()>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}

impl ConnectionChannel for DummyConnection {
    type SendFut = DummySendFut;
    type SendFutErr = ();

    fn send(&self, _: crate::l2cap::BasicInfoFrame) -> Self::SendFut {
        DummySendFut
    }

    fn set_mtu(&self, _: u16) {
        unimplemented!()
    }

    fn get_mtu(&self) -> usize {
        crate::l2cap::LeU::MIN_MTU
    }

    fn max_mtu(&self) -> usize {
        crate::l2cap::LeU::MIN_MTU
    }

    fn min_mtu(&self) -> usize {
        crate::l2cap::LeU::MIN_MTU
    }

    fn receive(&self, _: &core::task::Waker) -> Option<Vec<L2capFragment>> {
        Some(Vec::new())
    }
}

#[derive(Clone)]
struct AMutex<D>(std::sync::Arc<futures::lock::Mutex<D>>);

impl<D> From<D> for AMutex<D> {
    fn from(data: D) -> Self {
        AMutex(std::sync::Arc::new(futures::lock::Mutex::new(data)))
    }
}

impl<D> super::ServerAttributeValue for AMutex<D>
where
    D: std::cmp::PartialEq,
{
    type Value = D;

    fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
    where
        F: FnOnce(&Self::Value) -> T + Unpin + 'a,
    {
        Box::pin(async move { f(&*self.0.lock().await) })
    }

    fn write_val(&mut self, val: Self::Value) -> PinnedFuture<'_, ()> {
        Box::pin(async move { *self.0.lock().await = val })
    }

    fn eq<'a>(&'a self, other: &'a Self::Value) -> PinnedFuture<'a, bool> {
        Box::pin(async move { &*self.0.lock().await == other })
    }
}

/// A connection that stores the last sent payload
#[derive(Default)]
struct PayloadConnection {
    sent: std::cell::Cell<Vec<u8>>,
}

impl ConnectionChannel for PayloadConnection {
    type SendFut = DummySendFut;
    type SendFutErr = ();

    fn send(&self, data: BasicInfoFrame) -> Self::SendFut {
        self.sent.set(data.get_payload().to_vec());

        DummySendFut
    }

    fn set_mtu(&self, _: u16) {
        unimplemented!()
    }

    fn get_mtu(&self) -> usize {
        crate::l2cap::LeU::MIN_MTU
    }

    fn max_mtu(&self) -> usize {
        crate::l2cap::LeU::MIN_MTU
    }

    fn min_mtu(&self) -> usize {
        crate::l2cap::LeU::MIN_MTU
    }

    fn receive(&self, _: &core::task::Waker) -> Option<Vec<L2capFragment>> {
        unimplemented!("Pdu Connection does not permit receiving")
    }
}

fn pdu_into_acl_data<D: TransferFormatInto>(pdu: pdu::Pdu<D>) -> BasicInfoFrame {
    BasicInfoFrame::new(TransferFormatInto::into(&pdu), crate::att::L2CAP_CHANNEL_ID)
}
