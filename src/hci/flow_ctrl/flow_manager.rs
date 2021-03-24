//! A host to Bluetooth controller data flow manager for ACL data
//!
//! This is a manager of the host to controller *packet based* flow control. It is designed to keep
//! track of the amount of available buffer space on the controller to not overflow it. It monitors
//! the HCI data buffer on the controller and blocks pends any data sending futures once the buffer
//! is full. There must only be one `HciDataPacketFlowManager` per HCI data buffer, so there can be
//! one for LE and one for BR/EDR so long as the controller has different buffers for each.
//!
//! This flow manager relies on the *Number of Completed Packets Event* from the controller to
//! determine the number of freed entries of the data buffer. Once that is received, and the
//! event indicates that one or more entries have freed within the buffer, the a future
//! awaiting to send data will be be awoken. Only one sender can send HCI data to the controller,
//! multiple senders cannot send data to it at the same time. This due to the possibility of a
//! sender requiring fragmentation of its data or the controller receiving a mix of bytes from
//! multiple senders. If the last future to send a HCI data packet to controller was in the middle
//! of sending fragments of a complete PDU, it will continuously be awoken until the entire PDU is
//! sent. No other futures for sending will be awoken until the current future is finished even when
//! the controller buffers fill.
//!
//! This is not a flow control manager for HCI command packets, it is only applicable for HCI *data*
//! packets. Protocols that use the HCI data transport layer **must not** send packets with the
//! 'continuing fragment of higher layer message' flag checked as this manager will perform
//! fragmentation of packets. It is required to do the fragmentation to guarantee that only
//! contiguous fragments of a complete PDUs are sent.
//!
//! # Data Fragmentation
//!
//! Before sending data to the controller, the `HciDataPacketFlowManager` will determine if data
//! must be fragmented. Data that exceeds the maximum HCI ACL data packet size for the controller
//! will be fragmented to the max size, but fragmentation entails awaiting for all other `send`
//! calls. Because there is only a start fragment and continuing fragment flags for ACL data, there
//! is no way to have multiple threads send fragments to the controller at the same time. When
//! `data` requires fragmentation, other contexts are blocked from sending until all fragments of
//! `data` are sent. Fragmenting data at a higher level, and calling send for each of those
//! fragments, can reduce or prevent (if the fragments don't need to be fragmented).
//!
//! # WARNING
//! For now this only works for one buffer on the HCI. It doesn't differentiate between BR/EDR
//! and LE. To do that it needs to keep track of connection handles, assign them with one buffer
//! or the other, and have multiple counts for each buffer.
//!
//! # TODO Note
//! This is implemented only to support LE-U. See the note for `setup_completed_packets_callback`
//! for what needs to changed when implementing ACL-U buffer support.

use crate::hci::{AclBroadcastFlag, AsyncLock, EventMatcher};
use crate::{
    hci::{
        common::ConnectionHandle, AclPacketBoundary, HciAclData, HciAclDataInterface, HostControllerInterface,
        HostInterface,
    },
    l2cap::AclData,
};
use alloc::{boxed::Box, sync::Arc};
use core::{
    future::Future,
    pin::Pin,
    sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

/// Monitoring information of a controllers buffers
#[derive(Default)]
struct BufferMonitorInfo {
    /// The current used space of the controller's buffer. This number increases for each sent HCI
    /// data payload, and decreases when the controller reports that data was freed from its
    /// buffers.
    used_space: AtomicUsize,
    /// The current waker
    current_waker: AtomicPtr<Waker>,
    /// Matcher flag that may be required for clearing the matching method given to the driver.
    match_flag: AtomicBool,
}

impl BufferMonitorInfo {
    /// Create the matcher
    ///
    /// Only one matcher should be created per `BufferMonitorInfo` (not for every
    /// `Arc<BufferMonitorInfo>`)
    fn create_matcher(self: Arc<Self>) -> Pin<Arc<impl EventMatcher>> {
        use crate::hci::events::EventsData;

        Arc::pin(move |e_data: &EventsData| match e_data {
            EventsData::NumberOfCompletedPackets(info) => {
                let freed = info.iter().map(|d| <usize>::from(d.number_of_completed_packets)).sum();

                loop {
                    let old = self.used_space.load(Ordering::Relaxed);

                    match self.used_space.compare_exchange_weak(
                        old,
                        old.checked_sub(freed).unwrap_or_default(),
                        Ordering::SeqCst,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        _ => (),
                    }
                }

                let waker_ptr = self.current_waker.load(Ordering::Relaxed);

                unsafe { waker_ptr.as_ref() }.map(|waker| waker.wake_by_ref());

                self.match_flag.load(Ordering::Relaxed)
            }

            _ => false,
        })
        .into()
    }
}

/// A manager of sent data to a buffers controller
///
/// This is a manager for the host's asynchronous data sent to the controller. It provides not flow
/// management for commands or synchronous data sent from the host. It initializes by first
/// querying the controller for its buffer information and then from then on will pend the host
/// context awaiting to send when this flow manager determines that the buffer is full.
///
/// This flow manager cannot be created without a mutex, because it requires exclusive access to the
/// controller for one send channel if the data sent to the controller is fragmented. The
/// implementation of the mutex does not matter, but it must be lockable.
///
/// See the module level documentation for full details.
#[derive(Default)]
pub struct HciDataPacketFlowManager<M> {
    /// Once someone starts sending, they have a total lock until all data fragments are sent. There
    /// is no way for multiple contexts to send data to the controller at the same time.
    sender_lock: M,
    /// The maximum size of the payload for each *hci* packet
    max_packet_payload_size: usize,
    /// The size, in packets, of the controllers buffer
    controller_buffer_size: usize,
    /// Information used for monitoring the receive buffer on the bluetooth controller
    controller_buffer_info: Arc<BufferMonitorInfo>,
    /// A reference to the matcher, used only to up the strong count for the lifetime of `Self`
    _matcher: Option<Pin<Arc<dyn EventMatcher>>>,
}

impl<M> HciDataPacketFlowManager<M> {
    /// Get the maximum **L2CAP** ACL data payload that the controller can receive.
    ///
    /// This is the same as the maximum HCI ACL data payload size minus the header size of a L2CAP
    /// packet.
    pub fn get_max_payload_size(&self) -> usize {
        self.max_packet_payload_size - crate::l2cap::AclData::HEADER_SIZE
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
    fn fragment(
        &self,
        mtu: usize,
        data: &AclData,
        connection_handle: ConnectionHandle,
    ) -> Result<alloc::vec::Vec<HciAclData>, HciAclData> {
        if data.get_payload().len() > mtu {
            let mut first_packet = true;

            let fragments = data
                .into_raw_data()
                .chunks(mtu)
                .map(|chunk| {
                    HciAclData::new(
                        connection_handle,
                        if first_packet {
                            first_packet = false;

                            AclPacketBoundary::FirstNonFlushable
                        } else {
                            AclPacketBoundary::ContinuingFragment
                        },
                        AclBroadcastFlag::NoBroadcast,
                        chunk.to_vec(),
                    )
                })
                .collect();

            Ok(fragments)
        } else {
            Err(HciAclData::new(
                connection_handle,
                AclPacketBoundary::FirstNonFlushable,
                AclBroadcastFlag::NoBroadcast,
                data.into_raw_data(),
            ))
        }
    }

    /// Set the waker from the current context
    ///
    /// This function is about as questionably safe as it could possibly be. It uses a future
    /// to acquire the waker of the current context. It does this by boxing a clone of the waker,
    /// consuming the box into a raw pointer, and setting the member `current_waker`. The method
    /// `clear_waker` can be called after
    async fn set_waker(&self) {
        struct WakerSetter<'a, T>(&'a HciDataPacketFlowManager<T>);

        impl<T> Future for WakerSetter<'_, T> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let waker_ptr = Box::into_raw(Box::new(cx.waker().clone()));

                self.get_mut()
                    .0
                    .controller_buffer_info
                    .current_waker
                    .store(waker_ptr, Ordering::Relaxed);

                Poll::Ready(())
            }
        }

        WakerSetter(self).await;
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
    async fn wait_for_controller<I, D>(&self, interface: &I, data: D) -> Result<(), FlowControllerError<I>>
    where
        I: HciAclDataInterface,
        D: core::iter::IntoIterator<Item = HciAclData>,
    {
        /// A future that returns Ready when one HCI data packet can be sent to the controller.
        ///
        /// This future, when polled to completion will only indicate that one packet can be sent,
        /// it will not determine if multiple packets may be sent.
        struct FreedFut<'a, T>(&'a HciDataPacketFlowManager<T>);

        impl<T> Future for FreedFut<'_, T> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
                let this = self.get_mut().0;

                loop {
                    let used_buff = this.controller_buffer_info.used_space.load(Ordering::Relaxed);

                    if used_buff >= this.controller_buffer_size {
                        break Poll::Pending;
                    } else if this
                        .controller_buffer_info
                        .used_space
                        .compare_exchange_weak(used_buff, used_buff + 1, Ordering::SeqCst, Ordering::Acquire)
                        .is_ok()
                    {
                        break Poll::Ready(());
                    } else {
                        continue;
                    }
                }
            }
        }

        for packet in data.into_iter() {
            FreedFut(self).await;

            interface.send(packet)?;
        }

        Ok(())
    }
}

impl<M> HciDataPacketFlowManager<M> {
    /// Initialize the HCI data packet flow manager for LE data.
    ///
    /// This performs a series of steps to get the information from the controller and process the
    /// number of packets that are currently sitting within the Bluetooth Controller's HCI receive
    /// buffer. The first thing done is to query the Controller for the LE and regular HCI data
    /// receiver buffer to get the maximum packet size and the size of the buffer. Next thing done
    /// is the setup of a matcher for the *Number Of Completed Packets* event sent to the host. The
    /// matcher is a bit of a hack as the buffer packet count is updated without requiring the user
    /// of this library to process the event.
    ///
    /// # Panic
    /// Input `hi` must be the only reference to the inner `HostInterface` as a mutable reference
    /// must be made to the inner `HostInterface`.
    pub async fn initialize<I>(hi: &mut HostInterface<I, M>)
    where
        I: HostControllerInterface + HciAclDataInterface + 'static,
        M: 'static,
    {
        use crate::hci::{info_params::read_buffer_size, le::mandatory::read_buffer_size as le_read_buffer_size};

        // Check the controller for a LE data buffer, if it doesn't exist then use the ACL data
        // buffer.
        //
        // pl -> The maximum packet size for each LE-U ACL data packet (the entire packet, header
        //       plus the payload)
        // pc -> The size of the data buffer in the controller.
        let (pl, pc) = match le_read_buffer_size::send(&hi).await.unwrap() {
            le_read_buffer_size::BufferSize {
                packet_len: Some(pl),
                packet_cnt: Some(pc),
                ..
            } => (pl as usize, pc as usize),

            _ => {
                let buff_info = read_buffer_size::send(&hi).await.unwrap();

                (
                    buff_info.hc_acl_data_packet_len,
                    buff_info.hc_total_num_acl_data_packets,
                )
            }
        };

        log::info!("Maximum HCI ACL data size: {}", pl);
        log::info!("Controller ACL LE data buffer size: {}", pc);

        hi.flow_controller.max_packet_payload_size = pl.into();

        hi.flow_controller.controller_buffer_size = pc.into();

        let matcher = hi.flow_controller.controller_buffer_info.clone().create_matcher();

        Self::setup_completed_packets_callback(hi.as_ref(), matcher.clone());

        hi.flow_controller._matcher = Some(matcher as Pin<Arc<dyn EventMatcher>>);
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
    /// event in their library or application for the lifetime of the matcher**. The matcher is tied
    /// to all instances of a `ConnectionChannel` associated with an instance of a
    /// `HciDataPacketFlowManager`.
    ///
    /// # TODO Note
    /// As this is currently implemented, it doesn't differentiate between the ACL controller buffer
    /// and the LE controller buffer when counting the number of freed space. When implementing ACL
    /// the 'freed' count needs to be divided between ACL-U and LE-U.
    fn setup_completed_packets_callback<I>(interface: &I, matcher: Pin<Arc<impl EventMatcher + 'static>>)
    where
        I: HostControllerInterface,
    {
        use core::task::{RawWaker, RawWakerVTable};
        fn c_wake(_: *const ()) -> RawWaker {
            RawWaker::new(core::ptr::null(), &WAKER_V_TABLE)
        }
        fn n_wake(_: *const ()) {}
        fn r_wake(_: *const ()) {}
        fn d_wake(_: *const ()) {}

        const WAKER_V_TABLE: RawWakerVTable = RawWakerVTable::new(c_wake, n_wake, r_wake, d_wake);

        let dummy_waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &WAKER_V_TABLE)) };

        let event = Some(crate::hci::events::Events::NumberOfCompletedPackets);

        // Attach the matcher to the device specific base crate of the HCI
        if interface.receive_event(event, &dummy_waker, matcher).is_some() {
            panic!(
                "Received an event result when expected `None` from call to receive_event in \
                HciDataPacketFlowManager::setup_completed_packets_callback"
            )
        }
    }

    /// Send ACL data to controller
    ///
    /// This function will send data to the controller as long as the controller has space for the
    /// data within its buffers. This doesn't query the controller for its buffer space (which
    /// cannot be done through the HCI as specified in the specification). When it is determined
    /// that the controller has enough room for one or more packets, the future will be awoken to
    /// send more packets to the controller.
    pub async fn send_hci_data<I>(
        &self,
        interface: &I,
        data: AclData,
        connection_handle: ConnectionHandle,
        mtu: usize,
    ) -> Result<(), FlowControllerError<I>>
    where
        I: HciAclDataInterface,
        M: for<'a> AsyncLock<'a>,
    {
        match self.fragment(mtu, &data, connection_handle) {
            Ok(vec_data) => {
                // Fragmented sending requires exclusive access to the HCI interface
                let _lock = AsyncLock::lock(&self.sender_lock).await;

                self.set_waker().await;

                let buffer_used_space = self.controller_buffer_info.used_space.load(Ordering::SeqCst);

                if self.controller_buffer_size > (vec_data.len() + buffer_used_space) {
                    self.controller_buffer_info
                        .used_space
                        .fetch_add(vec_data.len(), Ordering::Acquire);

                    vec_data
                        .into_iter()
                        .try_for_each(|data| interface.send(data).map(|_| ()))
                } else {
                    let send_amount = self
                        .controller_buffer_size
                        .checked_sub(buffer_used_space)
                        .unwrap_or_default();

                    self.controller_buffer_info
                        .used_space
                        .fetch_add(send_amount, Ordering::Acquire);

                    let mut data_itr = vec_data.into_iter();

                    data_itr
                        .by_ref()
                        .enumerate()
                        .take_while(|(i, _)| i < &send_amount)
                        .try_for_each(|(_, data)| interface.send(data).map(|_| ()))?;

                    self.wait_for_controller(interface, data_itr).await
                }
            }
            Err(single_data) => {
                let _lock = self.sender_lock.lock().await;

                self.set_waker().await;

                let buffer_used_space = self.controller_buffer_info.used_space.load(Ordering::SeqCst);

                if self.controller_buffer_size < buffer_used_space {
                    interface.send(single_data).map(|_| ())
                } else {
                    self.wait_for_controller(interface, Some(single_data)).await
                }
            }
        }
    }
}

impl<M> Drop for HciDataPacketFlowManager<M> {
    fn drop(&mut self) {
        self.controller_buffer_info.match_flag.store(true, Ordering::Relaxed);
    }
}

pub(super) type FlowControllerError<I> = <I as HciAclDataInterface>::SendAclDataError;

/// A future for sending HCI data packets to the controller
pub struct SendFuture<Hci, I>
where
    I: HciAclDataInterface,
{
    hi: Hci,
    mtu: usize,
    data: Option<AclData>,
    handle: ConnectionHandle,
    fut: Option<Pin<Box<dyn Future<Output = Result<(), FlowControllerError<I>>>>>>,
}

impl<Hci, I> SendFuture<Hci, I>
where
    I: HciAclDataInterface,
{
    pub fn new(hi: Hci, mtu: usize, data: AclData, handle: ConnectionHandle) -> Self {
        SendFuture {
            hi,
            mtu,
            data: Some(data),
            handle,
            fut: None,
        }
    }
}

impl<M, Hci, I> Future for SendFuture<Hci, I>
where
    Hci: core::ops::Deref<Target = HostInterface<I, M>> + Clone + Unpin + 'static,
    I: HciAclDataInterface + Unpin,
    M: for<'a> AsyncLock<'a>,
{
    type Output = Result<(), FlowControllerError<I>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        match this.fut.as_mut() {
            None => {
                let hi_clone = this.hi.clone();
                let data = this.data.take().unwrap();
                let handle = this.handle;
                let mtu = this.mtu;

                this.fut = Some(Box::pin(async move {
                    hi_clone
                        .flow_controller
                        .send_hci_data(&hi_clone.interface, data, handle, mtu)
                        .await
                }));

                this.fut.as_mut().unwrap()
            }
            Some(fut) => fut,
        }
        .as_mut()
        .poll(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hci::events::{Events, EventsData, Multiple, NumberOfCompletedPacketsData};
    use crate::hci::{
        events, opcodes, CommandParameter, EventMatcher, HciAclDataInterface, HostControllerInterface, HostInterface,
    };
    use std::sync::Mutex;

    #[derive(Clone)]
    struct TestInterface {
        /// The matcher used by the flow controller for NumberOfCompletedPackets event
        matcher: Arc<Mutex<Option<Pin<Arc<dyn EventMatcher>>>>>,
        /// Event data (used for command complete)
        e_data: Arc<Mutex<Option<EventsData>>>,
        /// Increases for each item sent, decreases within thread
        sent_cnt: Arc<AtomicUsize>,
    }

    impl TestInterface {
        const MAX_PAYLOAD_SIZE: u16 = 33;
        const BUFFER_SIZE: u8 = 12;

        fn thread(self) {
            use rand_core::RngCore;

            let mut rand = rand_core::OsRng::default();

            loop {
                std::thread::sleep(std::time::Duration::from_millis(rand.next_u64() % 100));

                let cnt = self.sent_cnt.load(Ordering::Relaxed) as u64;

                let mod_cnt = if cnt == 1 {
                    2
                } else if cnt == 0 {
                    1
                } else {
                    cnt
                };

                let sub_amount = rand.next_u64() % mod_cnt;

                self.sent_cnt.fetch_sub(sub_amount as usize, Ordering::Relaxed);

                let event_data = EventsData::NumberOfCompletedPackets(Multiple::from(&[NumberOfCompletedPacketsData {
                    connection_handle: ConnectionHandle::try_from(1).unwrap(),
                    number_of_completed_packets: sub_amount as u16,
                }] as &[_]));

                if let Some(matcher) = self.matcher.lock().unwrap().as_ref() {
                    // When the match returns true, the flow controller is using this to indicate
                    // that the matching is finished.
                    if matcher.match_event(&event_data) {
                        break;
                    }
                }
            }
        }
    }

    impl Default for TestInterface {
        fn default() -> Self {
            let interface = TestInterface {
                matcher: Arc::default(),
                e_data: Arc::default(),
                sent_cnt: Arc::default(),
            };

            let interface_clone = interface.clone();

            std::thread::spawn(move || interface_clone.thread());

            interface
        }
    }

    impl HostControllerInterface for TestInterface {
        type SendCommandError = usize;
        type ReceiveEventError = usize;

        fn send_command<D, W>(&self, _: &D, _: W) -> Result<bool, Self::SendCommandError>
        where
            D: CommandParameter,
            W: Into<Option<Waker>>,
        {
            match D::COMMAND {
                opcodes::HCICommand::LEController(opcodes::LEController::ReadBufferSize) => {
                    let packet_len = Self::MAX_PAYLOAD_SIZE.to_le_bytes();

                    *self.e_data.lock().unwrap() =
                        Some(events::EventsData::CommandComplete(events::CommandCompleteData {
                            number_of_hci_command_packets: 10,
                            command_opcode: Some(
                                opcodes::HCICommand::LEController(opcodes::LEController::ReadBufferSize)
                                    .as_opcode_pair()
                                    .as_opcode(),
                            ),
                            raw_data: vec![0, packet_len[0], packet_len[1], Self::BUFFER_SIZE],
                        }));
                }

                opcodes::HCICommand::InformationParameters(opcodes::InformationParameters::ReadBufferSize) => {
                    unimplemented!("Reading the BR/EDR buffer size isn't not implemented")
                }

                opcode => panic!("Received unexpected command {:?}", opcode),
            };

            Ok(true)
        }

        fn receive_event<P>(
            &self,
            event: Option<Events>,
            _: &Waker,
            matcher: Pin<Arc<P>>,
        ) -> Option<Result<EventsData, Self::ReceiveEventError>>
        where
            P: EventMatcher + Send + Sync + 'static,
        {
            if event == Some(events::Events::NumberOfCompletedPackets) {
                *self.matcher.lock().unwrap() = Some(matcher);
            }

            self.e_data.lock().unwrap().take().map(|event_data| Ok(event_data))
        }
    }

    impl HciAclDataInterface for TestInterface {
        type SendAclDataError = usize;
        type ReceiveAclDataError = usize;

        fn send(&self, data: HciAclData) -> Result<usize, Self::SendAclDataError> {
            assert!(
                data.get_payload().len() <= Self::MAX_PAYLOAD_SIZE as usize,
                "{} !<= {}",
                data.get_payload().len(),
                Self::MAX_PAYLOAD_SIZE,
            );

            let loaded = self.sent_cnt.fetch_add(1, Ordering::Relaxed);

            // `<` comparison instead of `<=` as this is a fetch_add return.
            assert!(
                loaded < Self::BUFFER_SIZE as usize,
                "{} !< {}",
                loaded,
                Self::BUFFER_SIZE,
            );

            Ok(0)
        }

        fn start_receiver(&self, _: ConnectionHandle) {}

        fn stop_receiver(&self, _: &ConnectionHandle) {}

        fn receive(
            &self,
            _: &ConnectionHandle,
            _: &Waker,
        ) -> Option<Result<Vec<HciAclData>, Self::ReceiveAclDataError>> {
            None
        }
    }

    #[derive(Default)]
    struct TestLock {
        mux: futures::lock::Mutex<()>,
    }

    impl<'a> AsyncLock<'a> for TestLock {
        type Guard = futures::lock::MutexGuard<'a, ()>;
        type Locker = futures::lock::MutexLockFuture<'a, ()>;

        fn lock(&'a self) -> Self::Locker {
            self.mux.lock()
        }
    }

    #[test]
    fn flow_manager_test() {
        use crate::l2cap::{ChannelIdentifier, ConnectionChannel};
        use futures::executor::block_on;

        let hci = block_on(HostInterface::<TestInterface, TestLock>::new());

        let handle = ConnectionHandle::try_from(0x11).unwrap();

        let cc = hci.clone().flow_ctrl_channel(handle, 50);

        const TEST_DATA_CNT: usize = 1000;

        let mut test_data = Vec::from([0; TEST_DATA_CNT]);

        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut test_data);

        let data = AclData::new(test_data, ChannelIdentifier::NullIdentifier);

        block_on(cc.send(data)).unwrap();
    }
}
