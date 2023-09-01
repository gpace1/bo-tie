//! Attribute Server tests

mod basic_queue_writer;
mod blob_data;
mod permissions;

use crate::client::ClientPduName;
use crate::pdu::{ExecuteWriteFlag, HandleRange, ReadBlobRequest, TypeRequest};
use crate::server::{NoQueuedWrites, ServerAttributes};
use crate::{pdu, Server, TransferFormatInto};
use alloc::vec::Vec;
use bo_tie_core::buffer::de_vec::DeVec;
use bo_tie_core::buffer::TryExtend;
use bo_tie_host_util::Uuid;
use bo_tie_l2cap::send_future::Error;
use bo_tie_l2cap::{BasicFrame, BasicFrameError, ChannelIdentifier, ConnectionChannel, L2capFragment, MinimumMtu};
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
    type Output = Result<(), Error<usize>>;

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
    type SendErr = usize;
    type RecvBuffer = DeVec<u8>;
    type RecvFut<'a> = DummyRecvFut;

    fn send(&self, _: BasicFrame<Vec<u8>>) -> Self::SendFut<'_> {
        DummySendFut
    }

    fn set_mtu(&mut self, _: u16) {
        unimplemented!()
    }

    fn get_mtu(&self) -> usize {
        bo_tie_l2cap::LeULink::SUPPORTED_MTU
    }

    fn max_mtu(&self) -> usize {
        bo_tie_l2cap::LeULink::SUPPORTED_MTU
    }

    fn min_mtu(&self) -> usize {
        bo_tie_l2cap::LeULink::SUPPORTED_MTU
    }

    fn receive_fragment(&mut self) -> Self::RecvFut<'_> {
        DummyRecvFut
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
    type SendErr = usize;
    type RecvBuffer = DeVec<u8>;
    type RecvFut<'a> = DummyRecvFut;

    fn send(&self, data: BasicFrame<Vec<u8>>) -> Self::SendFut<'_> {
        self.sent.set(data.get_payload().to_vec());

        DummySendFut
    }

    fn set_mtu(&mut self, _: u16) {
        unimplemented!()
    }

    fn get_mtu(&self) -> usize {
        bo_tie_l2cap::LeULink::SUPPORTED_MTU
    }

    fn max_mtu(&self) -> usize {
        bo_tie_l2cap::LeULink::SUPPORTED_MTU
    }

    fn min_mtu(&self) -> usize {
        bo_tie_l2cap::LeULink::SUPPORTED_MTU
    }

    fn receive_fragment(&mut self) -> Self::RecvFut<'_> {
        DummyRecvFut
    }
}

fn pdu_into_acl_data<D: TransferFormatInto>(pdu: pdu::Pdu<D>) -> BasicFrame<Vec<u8>> {
    BasicFrame::new(TransferFormatInto::into(&pdu), crate::L2CAP_CHANNEL_ID)
}

fn is_send<T: Future + Send>(t: T) {}

#[allow(dead_code)]
fn send_test<C>(mut c: C)
where
    C: ConnectionChannel + Send,
    <C::RecvBuffer as TryExtend<u8>>::Error: Send,
    C::SendErr: Send,
    for<'a> C::SendFut<'a>: Send,
{
    let attributes = ServerAttributes::new();

    let mut server = Server::new(attributes, NoQueuedWrites);

    is_send(server.process_exchange_mtu_request(&mut c, 0));

    is_send(server.process_write_request(&mut c, &[]));

    is_send(server.process_read_request(&mut c, 0));

    is_send(server.process_find_information_request(
        &mut c,
        HandleRange {
            starting_handle: 0,
            ending_handle: 0,
        },
    ));

    is_send(server.process_find_by_type_value_request(&mut c, &[]));

    is_send(server.process_read_by_type_request(
        &mut c,
        TypeRequest {
            handle_range: HandleRange {
                starting_handle: 0,
                ending_handle: 0,
            },
            attr_type: Uuid::from_u16(0),
        },
    ));

    is_send(server.process_read_blob_request(&mut c, ReadBlobRequest { handle: 0, offset: 0 }));

    is_send(server.process_prepare_write_request(&mut c, &[]));

    is_send(server.process_execute_write_request(&mut c, ExecuteWriteFlag::CancelAllPreparedWrites));

    is_send(server.process_parsed_att_pdu(&mut c, ClientPduName::FindInformationRequest, &[]));

    is_send(server.process_att_pdu(&mut c, &BasicFrame::new(Vec::new(), ChannelIdentifier::NullIdentifier)))
}
