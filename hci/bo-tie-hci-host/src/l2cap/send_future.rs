//! Implementation of the `SendFuture` of `PhysicalLink` for `LeLink`

use crate::l2cap::LeLink;
use crate::{AclBroadcastFlag, AclPacketBoundary, HciAclData};
use bo_tie_core::buffer::Buffer;
use bo_tie_hci_util::{ConnectionChannelEnds, ConnectionHandle, FromConnectionIntraMessage, Sender};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

enum State<'a, C: ConnectionChannelEnds>
where
    C::Sender: 'a,
{
    TakingBuffer(C::TakeBuffer),
    Sending(
        C::Sender,
        Option<FromConnectionIntraMessage<C::ToBuffer>>,
        Option<<C::Sender as Sender>::SendFuture<'a>>,
    ),
}

// todo: temporarily use `IntoIter` for the payload while the definition the associated send future
//  of `PhysicalLink` is `SendFut<'a>` instead of `SendFut<'a, T>`. See to-do note on `SendFut`
//  within `PhysicalLink` for explanation why it is temporarily done this way.
enum PreMessage {
    Acl {
        connection_handle: ConnectionHandle,
        packet_boundary_flag: AclPacketBoundary,
        broadcast_flag: AclBroadcastFlag,
        payload: alloc::vec::IntoIter<u8>,
    },
}

impl PreMessage {
    fn into_message<B>(self, mut buffer: B) -> FromConnectionIntraMessage<B>
    where
        B: Buffer,
    {
        match self {
            PreMessage::Acl {
                connection_handle,
                packet_boundary_flag,
                broadcast_flag,
                payload,
            } => {
                buffer.try_extend(payload).expect("back capacity error");

                log::info!(
                    "(HCI) sending L2CAP {}fragment: {:?}",
                    if let AclPacketBoundary::FirstNonFlushable = packet_boundary_flag {
                        "starting "
                    } else {
                        ""
                    },
                    &*buffer
                );

                let acl_data = HciAclData::new(connection_handle, packet_boundary_flag, broadcast_flag, buffer);

                let packet = acl_data.into_inner_packet().expect("front capacity error");

                FromConnectionIntraMessage::Acl(packet)
            }
        }
    }
}

pub struct SendFuture<'a, C: ConnectionChannelEnds> {
    channel_ends: &'a mut C,
    state: State<'a, C>,
    pre_message: Option<PreMessage>,
}

impl<'a, C: ConnectionChannelEnds> SendFuture<'a, C> {
    pub(super) fn new_le<T>(link: &'a mut LeLink<C>, fragment: bo_tie_l2cap::pdu::L2capFragment<T>) -> Self
    where
        T: IntoIterator<Item = u8>,
    {
        let connection_handle = link.get_handle();

        let packet_boundary_flag = if fragment.is_start_fragment() {
            AclPacketBoundary::FirstNonFlushable
        } else {
            AclPacketBoundary::ContinuingFragment
        };

        let broadcast_flag = AclBroadcastFlag::NoBroadcast;

        let payload = fragment
            .into_inner()
            .into_iter()
            .collect::<alloc::vec::Vec<_>>()
            .into_iter();

        let pre_message = PreMessage::Acl {
            connection_handle,
            packet_boundary_flag,
            broadcast_flag,
            payload,
        }
        .into();

        let take_buffer_future = link.channel_ends.take_to_buffer(link.front_cap, link.back_cap);

        let state = State::TakingBuffer(take_buffer_future);

        let channel_ends = &mut link.channel_ends;

        Self {
            channel_ends,
            state,
            pre_message,
        }
    }
}

impl<C: ConnectionChannelEnds> Future for SendFuture<'_, C> {
    type Output = Result<(), <C::Sender as Sender>::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match &mut this.state {
                State::TakingBuffer(take_buffer) => match unsafe { Pin::new_unchecked(take_buffer) }.poll(cx) {
                    Poll::Ready(buffer) => {
                        let message = this.pre_message.take().unwrap().into_message(buffer);

                        let sender = this.channel_ends.get_sender();

                        this.state = State::Sending(sender, Some(message), None);
                    }
                    Poll::Pending => break Poll::Pending,
                },
                State::Sending(_, None, Some(send_fut)) => break unsafe { Pin::new_unchecked(send_fut) }.poll(cx),
                State::Sending(sender, message, none) => {
                    let message = message.take().expect("missing message");

                    // Transmute the lifetime. The `sender` has not moved from
                    // State::Sending nor will it be moved for the lifetime that
                    // the `send_future` exists.
                    let send_future = unsafe { core::mem::transmute(sender.send(message)) };

                    *none = Some(send_future)
                }
            }
        }
    }
}
