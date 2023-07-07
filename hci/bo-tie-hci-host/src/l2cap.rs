//! L2CAP Connection types
//!
//! This is not an implementation of `L2CAP`, that can be found within [`bo-tie-l2cap`]. This module
//! contains the types that implement the traits of `bo-tie-l2cap` so they can be used by the L2CAP
//! protocol.

use crate::{AclBroadcastFlag, AclPacketBoundary, Connection, HciAclData, HciAclPacketError, TryIntoLeL2capError};
use bo_tie_core::buffer::IntoExactSizeIterator;
use bo_tie_hci_util::{ConnectionChannelEnds, ConnectionHandle, Receiver, Sender, ToConnectionDataIntraMessage};
use bo_tie_l2cap::LeULogicalLink;
use core::future::Future;
use core::pin::Pin;

/// A L2CAP connection for LE
///
/// This is the [`PhysicalLink`] implementation for a connection to another device via Bluetooth Low
/// Energy.
///
/// ```
/// # use bo_tie_hci_util::HostChannelEnds;
/// # async fn _doc<H>(mut host: bo_tie_hci_host::Host<H>) -> Result<(), Box<dyn std::error::Error>>
/// # where
/// #     H: HostChannelEnds,
/// #     <H as HostChannelEnds>::ConnectionChannelEnds: 'static
/// # {
/// use bo_tie_hci_host::Next;
/// match host.next().await? {
///     Next::NewConnection(connection) => {
///         let le_phy_link = connection.try_into_le()?;
///
///         let logical_link = le_phy_link.into_logical_link();
///     }
///     _ => (), // not relevant to `LeL2cap`
/// }
///
/// # Ok(())
/// # }
/// ```
///
/// [`PhysicalLink`]: bo_tie_l2cap::PhysicalLink
pub struct LeL2cap<C: ConnectionChannelEnds> {
    handle: ConnectionHandle,
    hci_max_payload_size: usize,
    channel_ends: C,
}

impl<C: ConnectionChannelEnds> TryFrom<Connection<C>> for LeL2cap<C> {
    type Error = TryIntoLeL2capError<C>;

    fn try_from(c: Connection<C>) -> Result<Self, Self::Error> {
        Connection::<C>::try_into_le(c)
    }
}

impl<C: ConnectionChannelEnds> LeL2cap<C> {
    pub(crate) fn new(handle: ConnectionHandle, hci_max_payload_size: usize, channel_ends: C) -> Self {
        Self {
            handle,
            hci_max_payload_size,
            channel_ends,
        }
    }

    /// Convert this `LeL2Cap` into a [`LeULogicalLink`]
    pub fn into_logical_link(self) -> LeULogicalLink<Self> {
        LeULogicalLink::new(self)
    }

    /// Get the connection handle
    pub fn get_handle(&self) -> ConnectionHandle {
        self.handle
    }

    /// Get the receiver
    pub fn get_receiver(&self) -> &C::DataReceiver {
        self.channel_ends.get_data_receiver()
    }

    /// Get the sender
    pub fn get_sender(&self) -> C::Sender {
        self.channel_ends.get_sender()
    }

    /// Get the fragmentation size
    ///
    /// Data sent to (or received from) the connected device cannot exceed this size. This is
    /// equivalent to the Controller's maximum size of the payload for a HCI ACL packet of LE data.
    pub fn fragment_size(&self) -> usize {
        self.hci_max_payload_size
    }
}

impl<C> bo_tie_l2cap::PhysicalLink for LeL2cap<C>
where
    C: ConnectionChannelEnds,
{
    type SendFut<'a> = Pin<alloc::boxed::Box<dyn Future<Output = Result<(), Self::SendErr>> + 'a>> where Self: 'a;
    type SendErr = <C::Sender as Sender>::Error;
    type RecvFut<'a> = Pin<alloc::boxed::Box<dyn Future<Output = Option<Result<bo_tie_l2cap::pdu::L2capFragment<Self::RecvData>, Self::RecvErr>>> + 'a>> where Self: 'a;
    type RecvData = <C::FromBuffer as IntoExactSizeIterator>::IntoExactIter;
    type RecvErr = HciAclPacketError;

    fn max_transmission_size(&self) -> usize {
        self.fragment_size()
    }

    fn send<'s, T>(&'s mut self, fragment: bo_tie_l2cap::pdu::L2capFragment<T>) -> Self::SendFut<'s>
    where
        T: 's + IntoIterator<Item = u8>,
    {
        use bo_tie_core::buffer::TryExtend;

        let connection_handle = self.handle;

        let packet_boundary_flag = if fragment.is_start_fragment() {
            AclPacketBoundary::FirstNonFlushable
        } else {
            AclPacketBoundary::ContinuingFragment
        };

        let broadcast_flag = AclBroadcastFlag::NoBroadcast;

        let payload = fragment.into_inner();

        let future = async move {
            let mut buffer = self
                .channel_ends
                .take_to_buffer(None, self.max_transmission_size())
                .await;

            buffer.try_extend(payload).unwrap();

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

            let packet = acl_data.into_inner_packet().unwrap();

            let message = bo_tie_hci_util::FromConnectionIntraMessage::Acl(packet).into();

            self.channel_ends.get_sender().send(message).await
        };

        alloc::boxed::Box::pin(future)
    }

    fn recv(&mut self) -> Self::RecvFut<'_> {
        let future = async move {
            let data = self.channel_ends.get_mut_data_receiver().recv().await;

            match data {
                Some(ToConnectionDataIntraMessage::Acl(data)) => {
                    let hci_data = match HciAclData::try_from_buffer(data) {
                        Ok(data) => data,
                        Err(e) => return Some(Err(e)),
                    };

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
        };

        alloc::boxed::Box::pin(future)
    }
}

impl<C> From<LeL2cap<C>> for LeULogicalLink<LeL2cap<C>>
where
    C: ConnectionChannelEnds,
{
    fn from(physical_link: LeL2cap<C>) -> Self {
        LeULogicalLink::new(physical_link)
    }
}

impl<T> HciAclData<T> {
    fn into_l2cap_fragment(self) -> bo_tie_l2cap::pdu::L2capFragment<T::IntoExactIter>
    where
        T: IntoExactSizeIterator,
    {
        use bo_tie_l2cap::pdu::L2capFragment;

        match self.packet_boundary_flag {
            AclPacketBoundary::ContinuingFragment => L2capFragment::new(false, self.payload.into_iter()),
            _ => L2capFragment::new(true, self.payload.into_iter()),
        }
    }
}
