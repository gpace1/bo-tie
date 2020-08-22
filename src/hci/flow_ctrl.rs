use super::{
    HostInterface,
    common,
    HciAclDataInterface,
    HciAclData,
    AclPacketBoundary,
    AclBroadcastFlag,
};
use alloc::vec::Vec;

/// A HCI channel for a LE-U Logical Link
///
/// This is a HCI connection channel over L2CAP. It is only for a L2CAP LE-U logical link as it does
/// not support an ACL-U link. The default configuration for a LE-U logical link will be used for
/// data sent and received through this channel. This configuration cannot be changed as there is
/// no attached flow controller
pub struct HciLeUChannel<I,HI,F>
    where HI: core::ops::Deref<Target = HostInterface<I>>,
          I: HciAclDataInterface
{
    mtu: core::cell::Cell<usize>,
    maximum_mtu: usize,
    handle: common::ConnectionHandle,
    hi: HI,
    flow_controller: F,
}

impl<I,HI> HciLeUChannel<I,HI,NoFlowController>
    where HI: core::ops::Deref<Target = HostInterface<I>>,
          I: HciAclDataInterface
{
    /// Create a new `HciLeUChannel`
    ///
    /// The LE-U channel will be initialized with the default
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
            handle,
            hi,
            flow_controller: NoFlowController,
        }
    }
}

impl<I,HI,F> HciLeUChannel<I,HI,F>
    where HI: core::ops::Deref<Target = HostInterface<I>>,
          I: HciAclDataInterface,
          Self: crate::l2cap::ConnectionChannel,
{
    fn get_send_mtu(&self, data: &crate::l2cap::AclData) -> usize {
        use crate::l2cap::ConnectionChannel;

        match data.get_mtu() {
            crate::l2cap::AclDataSuggestedMtu::Minimum => self.min_mtu(),

            crate::l2cap::AclDataSuggestedMtu::Channel => self.get_mtu(),

            crate::l2cap::AclDataSuggestedMtu::Mtu(mtu) =>
                self.get_mtu().min(mtu).max(self.min_mtu())
        }
    }
}

impl<I,HI> crate::l2cap::ConnectionChannel for HciLeUChannel<I,HI,NoFlowController>
    where HI: core::ops::Deref<Target = HostInterface<I>>,
          I: HciAclDataInterface,
{
    fn send(&self, data: crate::l2cap::AclData ) -> crate::l2cap::SendFut {

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

        self.flow_controller.new_send_fut()
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
        <crate::l2cap::LeU as crate::l2cap::MinimumMtu>::MIN_MTU
    }

    fn receive(&self, waker: &core::task::Waker)
               -> Option<alloc::vec::Vec<crate::l2cap::AclDataFragment>>
    {
        use crate::l2cap::AclDataFragment;

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

impl<I,HI,F> core::ops::Drop for HciLeUChannel<I,HI,F>
    where HI: core::ops::Deref<Target = HostInterface<I>>,
          I: HciAclDataInterface
{
    fn drop(&mut self) {
        self.hi.interface.stop_receiver(&self.handle)
    }
}

/// A false flow controller
///
/// This does nothing. `SendFut` created from it never await.
pub struct NoFlowController;

impl NoFlowController {
    fn new_send_fut(&self) -> crate::l2cap::SendFut {
        crate::l2cap::SendFut::new(true)
    }
}