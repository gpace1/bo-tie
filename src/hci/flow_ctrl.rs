use super::{
    HostInterface,
    common,
    HciAclDataInterface,
    HciAclData,
    AclPacketBoundary,
    AclBroadcastFlag,
    HostControllerInterface
};
use alloc::{
    vec::Vec,
    sync::Arc,
};
use core::{
    future::Future,
    task::{Poll,Context,Waker},
    pin::Pin,
};

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

/// A host to Bluetooth controller data flow manager for ACL data
///
/// This is a manager of the host to controller *packet based* flow control. It is designed to keep
/// track of the amount of available buffer space on the controller to not overflow it. It provides
/// a small buffer to place packets that are ready for transport, but once that buffer is full it
/// will block any threads looking to send data and log an error.
///
/// This is not a flow control manager for HCI command packets, it is only applicable for HCI *data*
/// packets. Protocols that use the HCI data transport layer **must not** send packets with the
/// 'continuing fragment of higher layer message' flag checked. This manager will perform
/// fragmentation of packets with payloads that are too large for the controller to handle.
///
/// # Data Fragmentation
///
/// Before sending data to the controller, the `HciDataPacketFlowManager` will determine if data
/// must be fragmented. Data that exceeds the maximum HCI ACL data packet size for the controller
/// will be fragmented to the max size, but fragmentation entails awaiting for all other `send`
/// calls. Because there is only a start fragment and continuing fragment flags for ACL data, there
/// is no way to have multiple threads send fragments to the controller at the same time. When
/// `data` requires fragmentation, other contexts are blocked from sending until all fragments of
/// `data` are sent. Fragmenting data at a higher level, and calling send for each of those
/// fragments, can reduce or prevent (if the fragments don't need to be fragmented).
///
/// # WARNING
/// For now this only works for one buffer on the system. It doesn't differentiate between BR/EDR
/// and LE. To do that it needs to keep track of connection handles, assign them with one buffer
/// or the other, and have multiple counts for each buffer.
///
/// # TODO Note
/// This is implemented only to support LE-U. See the note for `setup_completed_packets_callback`
/// for what needs to changed when implementing ACL-U buffer support.
#[derive(Debug, Default)]
struct HciDataPacketFlowManager {
    /// Once someone starts sending, they have a total lock until all data fragments are sent. There
    /// is no way multiple contexts to send fragmented data to the controller at the same time.
    sender_lock: Arc<futures::lock::Mutex<()>>,
    /// The maximum size of the payload for each packet
    max_packet_payload_size: usize,
    /// The current used space of the controller's buffer. This number increases for each sent HCI
    /// data payload, and decreases when the controller reports that data was freed from its
    /// buffers.
    controller_used_space: Arc<core::sync::atomic::AtomicUsize>,
    /// The size, in packets, of the controllers buffer
    controller_buffer_size: usize,
    /// The current waker
    current_waker: Arc<core::sync::atomic::AtomicPtr<Waker>>,
}

impl HciDataPacketFlowManager {

    /// Create a new HCI data packet flow manager for LE data.
    pub async fn new_le<I,E>( hi: &HostInterface<I> ) -> Self
    where I: HostControllerInterface + HciAclDataInterface + Send + Sync + 'static,
          E: futures::task::Spawn,
    {
        use super::{
            le::mandatory::read_buffer_size as le_read_buffer_size,
            info_params::read_buffer_size
        };

        let current_waker: Arc<core::sync::atomic::AtomicPtr<Waker>> = Arc::default();

        let controller_used_space: Arc<core::sync::atomic::AtomicUsize>  = Arc::default();

        // Check the controller for a LE data buffer, if it doesn't exist then use the ACL data
        // buffer.
        //
        // pl -> The maximum packet size for each LE-U ACL data packet (the entire packet, header
        //       plus the payload)
        // pc -> The size of the data buffer in the controller.
        let (pl, pc) = match le_read_buffer_size::send(&hi).await.unwrap() {
            le_read_buffer_size::BufferSize{ packet_len: Some(pl), packet_cnt: Some(pc), .. } => {
                (pl as usize, pc as usize)
            },
            _ => {
                let buff_info = read_buffer_size::send(&hi).await.unwrap();

                (buff_info.hc_acl_data_packet_len, buff_info.hc_total_num_acl_data_packets)
            },
        };

        log::info!("Maximum HCI ACL data size: {}", pl);
        log::info!("Controller ACL LE data buffer size: {}", pc);

        Self::setup_completed_packets_callback(
            current_waker.clone(),
            controller_used_space.clone(),
            hi,
        );

        Self {
            sender_lock: Arc::default(),
            max_packet_payload_size: pl.into(),
            controller_used_space,
            controller_buffer_size: pc.into(),
            current_waker: Arc::default(),
        }
    }

    /// Get the maximum packet size that the controller can receive
    ///
    /// When calling
    /// [`send`](crate::protocol::bluetooth::HciDataPacketFlowManager::send)
    /// , it may fragment the data sent to the function before sending each
    /// fragment to the controller. This has some issues (read the doc for `send`) which can be
    /// mitigated by fragmenting at a higher layer than the HCI. This can be used for determining
    /// the fragmentation size at a higher layer.
    pub fn get_max_packet_size(&self) -> usize {
        self.max_packet_payload_size
    }

    /// Create a matcher that will be used to set the available data buffer space.
    ///
    /// This callback is used for tracking the *Number of Completed Packets Event* from the
    /// controller. This implementation relies on never polling to completion to maintain a
    /// matcher within the driver. The event is sent at will by the controller. Generally the event
    /// is sent periodically by the controller, but the host must assume that it may be sent
    /// randomly.
    ///
    /// Normally when waiting on a event, the `receive_event` function of `HostControllerInterface`
    /// is called at least twice, first to setup the waker and matcher for the driver then lastly to
    /// clear the waker and matcher from the driver and get the event data. This takes advantage of
    /// this and never recalls `receive_event` after the first time. The provides waker to
    /// `receive_event` does not wake anything and the provides matcher will never return true. This
    /// should ensure that the driver will never remove the matcher for the *Number of Completed
    /// Packets Event*, **but the consequences of this is that the user can no longer await for this
    /// event in their library or application** for the lifetime of the matcher. The matcher is tied
    /// to all instances of a `ConnectionChannel` associated with a single instance of a
    /// `HciDataPacketFlowManager`.
    ///
    /// # TODO Note
    /// As this is currently implemented, it doesn't differentiate between the ACL controller buffer
    /// and the LE controller buffer when counting the number of freed space. When implementing ACL
    /// the 'freed' count needs to be divided between ACL-U and LE-U. Doing this may mean that
    /// two wakers could be supported, one for ACL-U and one for LE-U.
    fn setup_completed_packets_callback<I>(
        current_waker: Arc<core::sync::atomic::AtomicPtr<Waker>>,
        used_space: Arc<core::sync::atomic::AtomicUsize>,
        interface: &HostInterface<I>,
    ) where I: HostControllerInterface + HciAclDataInterface + Send + Sync + 'static,
    {
        use core::sync::atomic::Ordering;
        use core::task::{RawWakerVTable, RawWaker};

        fn c_wake(_: *const ()) -> RawWaker { RawWaker(core::ptr::null(), &WAKER_V_TABLE) }
        fn n_wake(_: *const ()) {}
        fn r_wake(_: *const ()) {}
        fn d_wake(_: *const ()) {}

        const WAKER_V_TABLE: RawWakerVTable = RawWakerVTable::new(c_wake, n_wake, r_wake, d_wake);

        let dummy_waker = unsafe { Waker::from_raw(RawWaker(core::ptr::null(), &WAKER_V_TABLE)) };

        let event = crate::hci::events::Events::NumberOfCompletedPackets;

        let matcher = Arc::pin( move |e_data: &superevents::EventsData| {
            match e_data {
                EventsData::NumberOfCompletedPackets(info) => {

                    let freed = info.into_iter()
                        .map(|d| <usize>::from(d.number_of_completed_packets))
                        .sum();

                    loop {
                        let old = used_space.load(Ordering::Relaxed);

                        match used_space.compare_exchange_weak(
                            old,
                            old.checked_sub(freed).unwrap_or_default(),
                            Ordering::SeqCst,
                            Ordering::Acquire,
                        ) {
                            Ok(_) => break,
                            _ => ()
                        }
                    }

                    let waker_ptr = current_waker.load(Ordering::Relaxed);

                    unsafe {waker_ptr.as_ref()}.map( |waker| waker.wake_by_ref() );
                },
                _ => (),
            }

            false
        });

        if interface.receive_event(event, dummy_waker, matcher).is_some() {
            panic!("Received an event result when expected `None` from call to receive_event in \
                HciDataPacketFlowManager::setup_completed_packets_callback")
        }
    }

    /// Send ACL data to controller
    ///
    /// This function will send data to the controller as long as the controller has space for the
    /// data within its buffers.
    ///
    /// When it is determined that the controller
    pub async fn send<I>(&self, interface: &I, data: HciAclData)
    -> Result<usize, FlowControllerError<I>>
    where I: HciAclDataInterface + HostControllerInterface
    {
        use core::sync::atomic::Ordering;

        let rslt = async {
            // The order of operations for this function is critically important in order for having
            // the most efficient and correct implementation for sending

            match self.fragment(data) {
                Ok(vec_data) => {
                    // Fragmented sending requires exclusive access to the HCI interface
                    let _lock = self.sender_lock.lock().await;

                    // Setting the waker before returning the
                    self.set_waker().await;

                    let buffer_used_space = self.controller_used_space.load(Ordering::SeqCst);

                    if self.controller_buffer_size < (vec_data.len() + buffer_used_space)
                    {
                        self.controller_used_space.fetch_add(vec_data.len(), Ordering::Acquire);

                        vec_data.into_iter()
                            .try_for_each(|data| interface.send(data).map(|_| ()))
                            .map_err(FlowControllerError::from_de)
                    } else {
                        let send_amount = self.controller_buffer_size
                            .checked_sub(buffer_used_space)
                            .unwrap_or_default();

                        self.controller_used_space.fetch_add(send_amount, Ordering::Acquire);

                        let mut data_itr = vec_data.into_iter();

                        data_itr.by_ref()
                            .enumerate()
                            .take_while(|(i, _)| i < &send_amount)
                            .try_for_each(|(_, data)| interface.send(data).map(|_| ()))
                            .map_err(FlowControllerError::from_de)?;

                        self.wait_for_controller(interface, data_itr).await
                    }
                }
                Err(single_data) => {
                    let _lock = self.sender_lock.lock().await;

                    self.set_waker().await;

                    let buffer_used_space = self.controller_used_space.load(Ordering::SeqCst);

                    if self.controller_buffer_size < buffer_used_space {
                        interface.send(single_data).map(|_| ())
                            .map_err(FlowControllerError::from_de)
                    } else {
                        self.wait_for_controller(interface, Some(single_data)).await
                    }
                }
            }
        }
            .await;

        self.clear_waker();

        rslt.map(|_| 0)
    }

    /// Non-flush-able data fragmentation
    ///
    /// This converts HCI ACL data whose payload is larger then the maximum payload size that the
    /// controller can handle into fragments that the controller can handle. If 'data' doesn't need
    /// to be fragmented, then it just returned as an Error.
    ///
    /// # Panic
    /// If data has a packet boundary flag indicating a complete L2CAP PDU and the payload is larger
    /// then the controller's accepted payload size, this function produces a panic.
    fn fragment(&self, data: HciAclData)
                -> Result<Vec<HciAclData>, HciAclData>
    {
        if data.get_payload().len() > self.max_packet_payload_size {

            // This is just for AMP-U. This packet boundary cannot be used by any data transport
            // except for AMP
            if let AclPacketBoundary::CompleteL2capPdu = data.get_packet_boundary_flag() {
                panic!("Size of payload ")
            }

            let mut first_packet = true;

            let fragments = data.get_payload()
                .chunks(self.max_packet_payload_size)
                .map(|chunk| HciAclData::new(
                    *data.get_handle(),
                    if first_packet {
                        first_packet = false;

                        data.get_packet_boundary_flag()
                    } else {
                        AclPacketBoundary::ContinuingFragment
                    },
                    data.get_broadcast_flag(),
                    chunk.to_vec(),
                ))
                .collect();

            Ok(fragments)

        } else {
            Err(data)
        }
    }

    /// Set the waker from the current context
    ///
    /// This function is about as questionably safe as it could possibly be. It uses a future
    /// to acquire the waker of the current context. It does this by boxing a clone of the waker,
    /// consuming the box into a raw pointer, and setting the member `current_waker`. The method
    /// `clear_waker` can be called after
    async fn set_waker(&self) {
        use core::sync::atomic::Ordering;

        struct WakerSetter<'a>(&'a HciDataPacketFlowManager);

        impl Future for WakerSetter<'_> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let waker_ptr = Box::into_raw( Box::new(cx.waker().clone()) );

                self.get_mut().0.current_waker.store(waker_ptr, Ordering::Relaxed);

                Poll::Ready(())
            }
        }

        WakerSetter(self).await;
    }

    /// Clear the Waker
    ///
    /// This function will clear the allocated waker clone, or do nothing if current_waker is null.
    /// This function assumes that the pointer is valid if it is not null.
    fn clear_waker(&self) {
        use core::sync::atomic::Ordering;

        let waker_ptr = self.current_waker.swap(core::ptr::null_mut(), Ordering::Relaxed);

        if ! waker_ptr.is_null() {
            unsafe { Box::from_raw(waker_ptr) };
        }
    }

    /// Wait for the controller to free up space
    ///
    /// This will await for space on the controller to free up before sending more data to the
    /// controller. It does this for *one* thread at a time. It cannot handle multiple threads
    /// awaiting the same event.
    ///
    /// # WARNING
    /// This function **must** be called within the same context as the method `set_waker`. This
    /// function relies on the waker set by `set_waker` to continue polling.
    async fn wait_for_controller<I,D>(&self, interface: &I, data: D)
                                      -> Result<(), FlowControllerError<I>>
        where I: HciAclDataInterface + HostControllerInterface,
              D: core::iter::IntoIterator<Item=HciAclData>
    {
        use core::sync::atomic::Ordering;

        /// A future that returns Ready when one HCI data packet can be sent to the controller.
        ///
        /// This future, when polled to completion will only indicate that one packet can be sent,
        /// it will not determine if multiple packets may be sent.
        struct FreedFut<'a>(&'a HciDataPacketFlowManager);

        impl Future for FreedFut<'_> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {

                let this = self.get_mut().0;

                loop {
                    let used_buff = this.controller_used_space.load(Ordering::Relaxed);

                    if used_buff >= this.get_max_packet_size() {
                        log::trace!("Awaiting for space to be freed up in the controller");
                        break Poll::Pending
                    } else if this.controller_used_space.compare_exchange_weak(
                        used_buff,
                        used_buff + 1,
                        Ordering::SeqCst,
                        Ordering::Acquire
                    ).is_ok()
                    {
                        break Poll::Ready(())
                    } else {
                        continue
                    }
                }
            }
        }

        for packet in data.into_iter() {

            FreedFut(self).await;

            interface.send(packet).map_err(FlowControllerError::from_de)?;
        }

        Ok(())
    }
}

impl Drop for HciDataPacketFlowManager {
    fn drop(&mut self) {
        self.end_thread.take().and_then( |sender| sender.send(()).ok() );
    }
}

/// Sender locking for sending data to the controller
///
/// If data sent to the controller is larger than the largest packet size to the controller, it is
/// fragmented into multiple HCI ACL data packets. This is fine when only one context is sending
/// data, but when multiple are sending data at the same time the fragments can get mixed up. This
/// is because there are only a start fragment indicators and a continuing fragment indicator for
/// HCI ACL data. Thus senders must be locked to one context until the entire fragmented message
/// is sent to the controller.
mod sender_lock {
    use core::sync::atomic::AtomicUsize;
    use futures::task::Waker;

    const LOCKED: usize = 0;
    const UNLOCKED: usize = 0;

    pub struct SenderLock {
        state: AtomicUsize,
        wakers: slab::Slab<Wakers>,
    }

    impl SenderLock {
        fn new() -> Self {
            SenderLock {
                state: AtomicUsize::default(),
                wakers: slab::Slab<Wakers>,
            }
        }
    }
}