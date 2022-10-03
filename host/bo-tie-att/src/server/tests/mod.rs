//! Attribute Server tests

mod basic_queue_writer;
mod blob_data;
mod permissions;

use crate::server::PinnedFuture;
use crate::{pdu, TransferFormatInto};
use alloc::vec::Vec;
use bo_tie_l2cap::send_future::Error;
use bo_tie_l2cap::{BasicFrameError, BasicInfoFrame, ConnectionChannel, L2capFragment, MinimumMtu};
use bo_tie_util::buffer::de_vec::DeVec;
use bo_tie_util::buffer::TryExtend;
use core::{
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
    type Output = Result<(), Error<()>>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}

struct DummyRecvFut;

impl Future for DummyRecvFut {
    type Output = Option<Result<L2capFragment<DeVec<u8>>, BasicFrameError<<DeVec<u8> as TryExtend<u8>>::Error>>>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        panic!("DummyRecvFut cannot receive")
    }
}

impl ConnectionChannel for DummyConnection {
    type SendBuffer = DeVec<u8>;
    type SendFut<'a> = DummySendFut;
    type SendFutErr = ();
    type RecvBuffer = DeVec<u8>;
    type RecvFut<'a> = DummyRecvFut;

    fn send(&self, _: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
        DummySendFut
    }

    fn set_mtu(&mut self, _: u16) {
        unimplemented!()
    }

    fn get_mtu(&self) -> usize {
        bo_tie_l2cap::LeU::MIN_MTU
    }

    fn max_mtu(&self) -> usize {
        bo_tie_l2cap::LeU::MIN_MTU
    }

    fn min_mtu(&self) -> usize {
        bo_tie_l2cap::LeU::MIN_MTU
    }

    fn receive(&mut self) -> Self::RecvFut<'_> {
        DummyRecvFut
    }
}

#[derive(Clone)]
struct AMutex<D>(std::sync::Arc<tokio::sync::Mutex<D>>);

impl<D> From<D> for AMutex<D> {
    fn from(data: D) -> Self {
        AMutex(std::sync::Arc::new(tokio::sync::Mutex::new(data)))
    }
}

impl<D> super::ServerAttributeValue for AMutex<D>
where
    D: std::cmp::PartialEq + Send + Sync,
{
    type Value = D;

    fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
    where
        F: FnOnce(&Self::Value) -> T + Unpin + Send + Sync + 'a,
    {
        let mutex = self.0.clone();

        Box::pin(async move { f(&*mutex.lock().await) })
    }

    fn write_val(self: &mut Self, val: Self::Value) -> PinnedFuture<'_, ()> {
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
    type SendBuffer = DeVec<u8>;
    type SendFut<'a> = DummySendFut;
    type SendFutErr = ();
    type RecvBuffer = DeVec<u8>;
    type RecvFut<'a> = DummyRecvFut;

    fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> {
        self.sent.set(data.get_payload().to_vec());

        DummySendFut
    }

    fn set_mtu(&mut self, _: u16) {
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

    fn receive(&mut self) -> Self::RecvFut<'_> {
        DummyRecvFut
    }
}

fn pdu_into_acl_data<D: TransferFormatInto>(pdu: pdu::Pdu<D>) -> BasicInfoFrame<Vec<u8>> {
    BasicInfoFrame::new(TransferFormatInto::into(&pdu), crate::L2CAP_CHANNEL_ID)
}
