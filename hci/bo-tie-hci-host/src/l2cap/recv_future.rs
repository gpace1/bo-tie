//! Implementation of the `RecvFut` of `PhysicalLink` for `LeLink`

use crate::l2cap::LeLink;
use crate::{AclPacketBoundary, HciAclData, HciAclPacketError};
use bo_tie_core::buffer::IntoExactSizeIterator;
use bo_tie_hci_util::{ConnectionChannelEnds, Receiver, ToConnectionDataIntraMessage};
use bo_tie_l2cap::pdu::L2capFragment;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

pub struct RecvFuture<'a, C: ConnectionChannelEnds> {
    data_receiver: &'a mut C::DataReceiver,
}

impl<'a, C: ConnectionChannelEnds> RecvFuture<'a, C> {
    pub(super) fn new_le(link: &'a mut LeLink<C>) -> Self {
        let data_receiver = link.channel_ends.get_mut_data_receiver();

        Self { data_receiver }
    }

    fn on_data(
        data: Option<ToConnectionDataIntraMessage<C::FromBuffer>>,
    ) -> Option<Result<L2capFragment<<C::FromBuffer as IntoExactSizeIterator>::IntoExactIter>, HciAclPacketError>> {
        match data {
            Some(ToConnectionDataIntraMessage::Acl(data)) => {
                let hci_data = match HciAclData::try_from_buffer(data) {
                    Ok(data) => data,
                    Err(e) => return Some(Err(e)),
                };

                log::info!(
                    "(HCI) received L2CAP {}fragment: {:?}",
                    if let AclPacketBoundary::FirstNonFlushable = hci_data.packet_boundary_flag {
                        "starting "
                    } else {
                        ""
                    },
                    hci_data.get_payload().iter().copied().collect::<Vec<u8>>()
                );

                Some(Ok(hci_data.into_l2cap_fragment()))
            }
            Some(ToConnectionDataIntraMessage::Sco(_)) => Some(Err(HciAclPacketError::Other(
                "synchronous connection data is not implemented",
            ))),
            Some(ToConnectionDataIntraMessage::Iso(_)) => Some(Err(HciAclPacketError::Other(
                "isochronous connection data is not implemented",
            ))),
            None | Some(ToConnectionDataIntraMessage::Disconnect(_)) => None,
        }
    }
}

impl<'a, C: ConnectionChannelEnds> Future for RecvFuture<'a, C> {
    type Output =
        Option<Result<L2capFragment<<C::FromBuffer as IntoExactSizeIterator>::IntoExactIter>, HciAclPacketError>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe { self.get_unchecked_mut() }
            .data_receiver
            .poll_recv(cx)
            .map(|output| RecvFuture::<C>::on_data(output))
    }
}
