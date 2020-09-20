#[cfg(feature = "flow-ctrl")] pub(super) mod flow_manager;

use alloc::vec::Vec;
use core::{
    future::Future,
    ops::Deref,
    pin::Pin,
    task::{Context,Poll},
};
use crate::l2cap::{AclData, AclDataFragment, ConnectionChannel};
use super::{
    common,
    HostInterface,
    HciAclDataInterface,
    HciAclData,
    AclPacketBoundary,
    AclBroadcastFlag,
};
#[cfg(feature = "flow-ctrl")] use core::task::Waker;
#[cfg(feature = "flow-ctrl")] use flow_manager::HciDataPacketFlowManager;
#[cfg(feature = "flow-ctrl")] pub use flow_manager::AsyncLock;
#[cfg(feature = "flow-ctrl")] use super::HostControllerInterface;

/// A HCI channel for a LE-U Logical Link
///
/// This is a HCI connection channel over L2CAP. It is only for a L2CAP LE-U logical link as it does
/// not support an ACL-U link. The default configuration for a LE-U logical link will be used for
/// data sent and received through this channel. This configuration cannot be changed as there is
/// no attached flow controller. The user of this channel must be aware of both the controllers
/// maximum HCI data packet size and the amount of packets sent to the HCI LE data buffer (or the
/// shared with BR/EDR data buffer if there is no LE only data buffer).
#[bo_tie_macros::host_interface]
pub(super) struct HciLeUChannel<I,HI>
where HI: Deref<Target = HostInterface<I>>,
      I: HciAclDataInterface
{
    mtu: core::cell::Cell<usize>,
    maximum_mtu: usize,
    minimum_mtu: usize,
    handle: common::ConnectionHandle,
    hi: HI,
}

#[bo_tie_macros::host_interface]
impl<I,HI> HciLeUChannel<I,HI>
where HI: Deref<Target = HostInterface<I>>,
      I: HciAclDataInterface
{
    /// Create a new raw `HciLeUChannel`
    ///
    /// This HciLeUChannel provides no flow control of sent data to the controller. It up to the
    /// user to make sure that the host does not send either to large of data packets or to many
    /// data packets to the controller.
    pub fn new_raw<T>(hi: HI, handle: common::ConnectionHandle, max_mtu: T) -> Self
        where T: Into<Option<u16>>
    {
        use crate::l2cap::MinimumMtu;

        let maximum_mtu: usize = max_mtu.into()
            .map(|mtu| <usize>::from(mtu).max(crate::l2cap::LeU::MIN_MTU))
            .unwrap_or(crate::l2cap::LeU::MIN_MTU);

        hi.interface.start_receiver(handle);

        HciLeUChannel {
            mtu: crate::l2cap::LeU::MIN_MTU.into(),
            maximum_mtu,
            minimum_mtu: crate::l2cap::LeU::MIN_MTU.into(),
            handle,
            hi,
        }
    }
}

#[bo_tie_macros::host_interface]
impl<I,HI> HciLeUChannel<I,HI>
where HI: Deref<Target = HostInterface<I>>,
      I: HciAclDataInterface,
      Self: crate::l2cap::ConnectionChannel,
{
    /// Get the MTU for a specified data packet
    ///
    /// Data packets can have a different MTU based on the request to use a specified MTU by `data`.
    fn get_send_mtu(&self, data: &AclData) -> usize {
        match data.get_mtu() {
            crate::l2cap::AclDataSuggestedMtu::Minimum => self.min_mtu(),

            crate::l2cap::AclDataSuggestedMtu::Channel => self.get_mtu(),

            crate::l2cap::AclDataSuggestedMtu::Mtu(mtu) =>
                self.get_mtu().min(mtu).max(self.min_mtu())
        }
    }
}

/// The 'raw' connection channel implementation
///
/// This implementation uses a [`RawSender`](RawSender) for `SendFut`, which provides no flow
/// control on the number of packets that can be sent to the controller (from the host). However,
/// the packet size is limited to the minimum size for the type of connection channel (either LE
/// or ACL)
#[bo_tie_macros::host_interface(flow_ctrl_concrete = "NoFlowControl")]
impl<I,HI> crate::l2cap::ConnectionChannel for HciLeUChannel<I,HI>
where HI: Deref<Target = HostInterface<I>>,
      I: HciAclDataInterface,
{
    type SendFut = RawSender;

    type SendFutErr = ();

    fn send(&self, data: AclData ) -> Self::SendFut {

        let mtu = self.get_send_mtu(&data);

        let packet = data.into_raw_data();

        packet.chunks(mtu + HciAclData::HEADER_SIZE).enumerate().for_each(|(i, chunk)| {
            let hci_acl_data = if i == 0 {
                HciAclData::new(
                    self.handle,
                    AclPacketBoundary::FirstNonFlushable,
                    AclBroadcastFlag::NoBroadcast,
                    chunk.to_vec()
                )
            } else {
                HciAclData::new(
                    self.handle,
                    AclPacketBoundary::ContinuingFragment,
                    AclBroadcastFlag::NoBroadcast,
                    chunk.to_vec()
                )
            };

            self.hi.interface.send(hci_acl_data).expect("Failed to send hci acl data");
        });

        RawSender
    }

    fn set_mtu(&self, mtu: u16) {
        self.mtu.set( <usize>::from(mtu).max(self.min_mtu()).min(self.max_mtu()) );
    }

    fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    fn max_mtu(&self) -> usize {
        self.maximum_mtu
    }

    fn min_mtu(&self) -> usize {
        self.minimum_mtu
    }

    fn receive(&self, waker: &core::task::Waker)
    -> Option<alloc::vec::Vec<crate::l2cap::AclDataFragment>>
    {
        self.hi.interface
            .receive(&self.handle, waker)
            .and_then( |received| match received {
                Ok( packets ) => packets.into_iter()
                    .map( |packet| packet.into_acl_fragment() )
                    .collect::<Vec<AclDataFragment>>()
                    .into(),
                Err( e ) => {
                    log::error!("Failed to receive data: {}", e);
                    Vec::new().into()
                },
            })
    }
}

#[cfg(feature = "flow-ctrl")]
impl<I,HI,M> HciLeUChannel<I,HI,HciDataPacketFlowManager<M>>
where HI: Deref<Target = HostInterface<I,HciDataPacketFlowManager<M>>>,
      I: HostControllerInterface + HciAclDataInterface + 'static,
      M: flow_manager::AsyncLock,
{
    /// Create a new `HciLeUChannel` with a `HciDataPacketFlowManager` for LE-U
    pub async fn new_le_flow_manager(hi: HI, handle: common::ConnectionHandle) -> Self {
        use crate::l2cap::MinimumMtu;

        Self {
            mtu: crate::l2cap::LeU::MIN_MTU.into(),
            maximum_mtu: <u16>::MAX as usize, // maximum a L2CAP pdu can handle
            minimum_mtu: crate::l2cap::LeU::MIN_MTU,
            handle,
            hi,
        }
    }
}

#[cfg(feature = "flow-ctrl")]
impl<I,HI,M,L,G> crate::l2cap::ConnectionChannel
for HciLeUChannel<I,HI,HciDataPacketFlowManager<M>>
where HI: Deref<Target = HostInterface<I,HciDataPacketFlowManager<M>>> + Unpin + Clone +
          'static,
      I: HciAclDataInterface + HostControllerInterface + Unpin + 'static,
      M: AsyncLock<Guard=G,Locker=L> + 'static,
      L: Future<Output=G> + 'static,
      G: 'static,
{
    type SendFut = flow_manager::SendFuture<HI,I>;

    type SendFutErr = flow_manager::FlowControllerError<I>;

    fn send(&self, data: AclData) -> Self::SendFut {
        flow_manager::SendFuture::new(
            self.hi.clone(),
            data,
            self.handle
        )
    }

    fn set_mtu(&self, mtu: u16) {
        self.mtu.set( <usize>::from(mtu).max(self.min_mtu()).min(self.max_mtu()) );
    }

    fn get_mtu(&self) -> usize {
        self.mtu.get()
    }

    fn max_mtu(&self) -> usize {
        self.maximum_mtu
    }

    fn min_mtu(&self) -> usize {
        self.minimum_mtu
    }

    fn receive(&self, waker: &Waker) -> Option<Vec<AclDataFragment>> {
        self.hi.interface
            .receive(&self.handle, waker)
            .and_then( |received| match received {
                Ok( packets ) => packets.into_iter()
                    .map( |packet| packet.into_acl_fragment() )
                    .collect::<Vec<AclDataFragment>>()
                    .into(),
                Err( e ) => {
                    log::error!("Failed to receive data: {}", e);
                    Vec::new().into()
                },
            })
    }
}

#[bo_tie_macros::host_interface]
impl<I,HI> core::ops::Drop for HciLeUChannel<I,HI>
where HI: Deref<Target = HostInterface<I>>,
      I: HciAclDataInterface
{
    fn drop(&mut self) {
        self.hi.interface.stop_receiver(&self.handle)
    }
}

/// A marker struct for no flow control
///
/// When enabling "flow-ctrl" the implementation for a raw channel conflicts without using this
/// structure with the `l2cap::ConnectionChannel` implementation. This is used as the concrete type
/// for the flow controller.
#[cfg(feature = "flow-ctrl")]
pub struct NoFlowControl;

/// A 'raw' sender
///
/// This is used for the sending future in a raw connection channel. This sender provides no flow
/// control capabilities and can either overflow or
pub(super) struct RawSender;

impl Future for RawSender {
    type Output = Result<(),()>;

    fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
        Poll::Ready(Ok(()))
    }
}