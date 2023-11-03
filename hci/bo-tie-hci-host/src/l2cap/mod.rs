//! L2CAP Connection types
//!
//! This is not an implementation of `L2CAP`, that can be found within [`bo-tie-l2cap`]. This module
//! contains the types that implement the traits of `bo-tie-l2cap` so they can be used by the L2CAP
//! protocol.

mod recv_future;
mod send_future;

use crate::{AclPacketBoundary, Connection, ConnectionKind, HciAclData, HciAclPacketError, TryIntoLeL2capError};
use bo_tie_core::buffer::IntoExactSizeIterator;
use bo_tie_hci_util::events::parameters::{LeConnectionCompleteData, LeEnhancedConnectionCompleteData};
use bo_tie_hci_util::{ConnectionChannelEnds, ConnectionHandle, Sender};
use bo_tie_l2cap::LeULogicalLink;

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
pub struct LeLink<C> {
    front_cap: usize,
    back_cap: usize,
    hci_max_payload_size: usize,
    kind: ConnectionKind,
    channel_ends: C,
}

impl<C: ConnectionChannelEnds> TryFrom<Connection<C>> for LeLink<C> {
    type Error = TryIntoLeL2capError<C>;

    fn try_from(c: Connection<C>) -> Result<Self, Self::Error> {
        Connection::<C>::try_into_le(c)
    }
}

impl<C: ConnectionChannelEnds> LeLink<C> {
    pub(crate) fn new(
        front_cap: usize,
        back_cap: usize,
        hci_max_payload_size: usize,
        kind: ConnectionKind,
        channel_ends: C,
    ) -> Self {
        Self {
            front_cap,
            back_cap,
            hci_max_payload_size,
            kind,
            channel_ends,
        }
    }

    /// Get the receiver
    pub fn get_receiver(&mut self) -> &mut C::DataReceiver {
        self.channel_ends.get_mut_data_receiver()
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

    /// Get the connection handle
    pub fn get_handle(&self) -> ConnectionHandle {
        match &self.kind {
            ConnectionKind::Le(c) => c.connection_handle,
            ConnectionKind::LeEnh(c) => c.connection_handle,
            ConnectionKind::BrEdr(_) | ConnectionKind::BrEdrSco(_) => unreachable!(),
        }
    }

    /// Get the peer address
    ///
    /// This returns the address of the connected device.
    pub fn get_peer_address(&self) -> bo_tie_core::BluetoothDeviceAddress {
        match &self.kind {
            ConnectionKind::Le(c) => c.peer_address,
            ConnectionKind::LeEnh(c) => c.peer_address,
            ConnectionKind::BrEdr(_) | ConnectionKind::BrEdrSco(_) => unreachable!(),
        }
    }

    /// Check if the peer is using a public address
    pub fn is_peer_address_public(&self) -> bool {
        use crate::events::parameters::LeConnectionAddressType;
        use crate::le::AddressType;

        match &self.kind {
            ConnectionKind::BrEdr(_) | ConnectionKind::BrEdrSco(_) => unreachable!(),
            ConnectionKind::Le(c) => c.peer_address_type == LeConnectionAddressType::PublicDeviceAddress,
            ConnectionKind::LeEnh(c) => c.peer_address_type == AddressType::PublicDeviceAddress,
        }
    }

    /// Check if the peer is using a random address
    pub fn is_peer_address_random(&self) -> bool {
        use crate::events::parameters::LeConnectionAddressType;
        use crate::le::AddressType;

        match &self.kind {
            ConnectionKind::BrEdr(_) | ConnectionKind::BrEdrSco(_) => unreachable!(),
            ConnectionKind::Le(c) => c.peer_address_type == LeConnectionAddressType::RandomDeviceAddress,
            ConnectionKind::LeEnh(c) => c.peer_address_type == AddressType::RandomDeviceAddress,
        }
    }

    /// Get the LE connection data
    ///
    /// This returns the connection data if the HCI sent the LE [`ConnectionComplete`] event.
    ///
    /// [`ConnectionComplete`]: crate::events::LeMeta::ConnectionComplete
    pub fn get_le_connection_data(&self) -> Option<&LeConnectionCompleteData> {
        if let ConnectionKind::Le(data) = &self.kind {
            Some(data)
        } else {
            None
        }
    }

    /// Get the LE enhanced connection data
    ///
    /// This returns the enhanced connection data if the HCI sent the LE
    /// [`EnhancedConnectionComplete`] event.
    ///
    /// [`EnhancedConnectionComplete`]: crate::events::LeMeta::EnhancedConnectionComplete
    pub fn get_le_enhanced_connection_data(&self) -> Option<&LeEnhancedConnectionCompleteData> {
        if let ConnectionKind::LeEnh(data) = &self.kind {
            Some(data)
        } else {
            None
        }
    }
}

impl<C> bo_tie_l2cap::PhysicalLink for LeLink<C>
where
    C: ConnectionChannelEnds,
{
    type SendFut<'a> = send_future::SendFuture<'a, C> where Self: 'a;
    type SendErr = <C::Sender as Sender>::Error;
    type RecvFut<'a> = recv_future::RecvFuture<'a, C> where Self: 'a;
    type RecvData = <C::FromBuffer as IntoExactSizeIterator>::IntoExactIter;
    type RecvErr = HciAclPacketError;

    fn max_transmission_size(&self) -> usize {
        self.fragment_size()
    }

    fn send<T>(&mut self, fragment: bo_tie_l2cap::pdu::L2capFragment<T>) -> Self::SendFut<'_>
    where
        T: IntoIterator<Item = u8>,
    {
        send_future::SendFuture::new_le(self, fragment)
    }

    fn recv(&mut self) -> Self::RecvFut<'_> {
        recv_future::RecvFuture::new_le(self)
    }
}

impl<C> bo_tie_l2cap::PhysicalLink for &mut LeLink<C>
where
    C: ConnectionChannelEnds,
{
    type SendFut<'a> = send_future::SendFuture<'a, C> where Self: 'a;
    type SendErr = <C::Sender as Sender>::Error;
    type RecvFut<'a> = recv_future::RecvFuture<'a, C> where Self: 'a;
    type RecvData = <C::FromBuffer as IntoExactSizeIterator>::IntoExactIter;
    type RecvErr = HciAclPacketError;

    fn max_transmission_size(&self) -> usize {
        (**self).max_transmission_size()
    }

    fn send<T>(&mut self, fragment: bo_tie_l2cap::pdu::L2capFragment<T>) -> Self::SendFut<'_>
    where
        T: IntoIterator<Item = u8>,
    {
        (**self).send(fragment)
    }

    fn recv(&mut self) -> Self::RecvFut<'_> {
        (**self).recv()
    }
}

impl<C> From<LeLink<C>> for LeULogicalLink<LeLink<C>>
where
    C: ConnectionChannelEnds,
{
    fn from(physical_link: LeLink<C>) -> Self {
        LeULogicalLink::new(physical_link)
    }
}

impl<'a, C> From<&'a mut LeLink<C>> for LeULogicalLink<&'a mut LeLink<C>>
where
    C: ConnectionChannelEnds + 'a,
{
    fn from(physical_link: &'a mut LeLink<C>) -> Self {
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
