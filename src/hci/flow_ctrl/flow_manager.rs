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
//! For now this only works for one buffer on the system. It doesn't differentiate between BR/EDR
//! and LE. To do that it needs to keep track of connection handles, assign them with one buffer
//! or the other, and have multiple counts for each buffer.
//!
//! # TODO Note
//! This is implemented only to support LE-U. See the note for `setup_completed_packets_callback`
//! for what needs to changed when implementing ACL-U buffer support.

use alloc::{
    sync::Arc,
    boxed::Box,
};
use core::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::atomic::{Ordering, AtomicPtr, AtomicBool, AtomicUsize},
    task::{Waker,Poll,Context},
};
use crate::{
    hci::{
        AclPacketBoundary,
        common::ConnectionHandle,
        HciAclData,
        HciAclDataInterface,
        HostInterface,
        HostControllerInterface,
    },
    l2cap::AclData,
};
use crate::hci::AclBroadcastFlag;


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
#[derive(Debug, Default)]
pub struct HciDataPacketFlowManager<M> {
    /// Once someone starts sending, they have a total lock until all data fragments are sent. There
    /// is no way multiple contexts to send fragmented data to the controller at the same time.
    sender_lock: Arc<M>,
    /// The maximum size of the payload for each *hci* packet
    max_packet_payload_size: usize,
    /// The minimum size of the payload for each *hci* packet. This is the same as the L2CAP min.
    min_packet_payload_size: usize,
    /// The current used space of the controller's buffer. This number increases for each sent HCI
    /// data payload, and decreases when the controller reports that data was freed from its
    /// buffers.
    controller_used_space: Arc<AtomicUsize>,
    /// The size, in packets, of the controllers buffer
    controller_buffer_size: usize,
    /// The current waker
    current_waker: Arc<AtomicPtr<Waker>>,
    /// Matcher flag for clearing the matching method.
    match_flag: Arc<AtomicBool>,
}

impl<M> HciDataPacketFlowManager<M> {

    /// Get the maximum HCI acl data payload that the controller can receive
    ///
    /// When calling
    /// [`send`](crate::protocol::bluetooth::HciDataPacketFlowManager::send)
    /// , it may fragment the data sent to the function before sending each
    /// fragment to the controller. This has some issues (read the doc for `send`) which can be
    /// mitigated by fragmenting at a higher layer than the HCI. This can be used for determining
    /// the fragmentation size at a higher layer.
    pub fn get_max_payload_size(&self) -> usize {
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
        used_space: Arc<AtomicUsize>,
        interface: &HostInterface<I>,
        match_flag: Arc<AtomicBool>
    )
    where I: HostControllerInterface + HciAclDataInterface,
    {
        use core::task::{RawWakerVTable, RawWaker};
        use crate::hci::events::EventsData;

        fn c_wake(_: *const ()) -> RawWaker { RawWaker::new(core::ptr::null(), &WAKER_V_TABLE) }
        fn n_wake(_: *const ()) {}
        fn r_wake(_: *const ()) {}
        fn d_wake(_: *const ()) {}

        const WAKER_V_TABLE: RawWakerVTable = RawWakerVTable::new(c_wake, n_wake, r_wake, d_wake);

        let dummy_waker = unsafe {
            Waker::from_raw(RawWaker::new(core::ptr::null(), &WAKER_V_TABLE))
        };

        let event = Some(crate::hci::events::Events::NumberOfCompletedPackets);

        let matcher = Arc::pin( move |e_data: &EventsData| {
            match e_data {
                EventsData::NumberOfCompletedPackets(info) => {

                    let freed = info.iter()
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

                    match_flag.load(Ordering::Relaxed)
                },
                _ => false,
            }
        });

        if interface.as_ref().receive_event(event, &dummy_waker, matcher).is_some() {
            panic!("Received an event result when expected `None` from call to receive_event in \
                HciDataPacketFlowManager::setup_completed_packets_callback")
        }
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
    fn fragment(&self, data: &AclData, connection_handle: ConnectionHandle)
    -> Result<alloc::vec::Vec<HciAclData>, HciAclData>
    {

        if data.get_payload().len() + AclData::HEADER_SIZE > self.max_packet_payload_size {

            let mut first_packet = true;

            let fragments = data.into_raw_data()
                .chunks(self.max_packet_payload_size)
                .map(|chunk| HciAclData::new(
                    connection_handle,
                    if first_packet {
                        first_packet = false;

                        AclPacketBoundary::FirstNonFlushable
                    } else {
                        AclPacketBoundary::ContinuingFragment
                    },
                    AclBroadcastFlag::NoBroadcast,
                    chunk.to_vec(),
                ))
                .collect();

            Ok(fragments)

        } else {
            Err( HciAclData::new(
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

        struct WakerSetter<'a,T>(&'a HciDataPacketFlowManager<T>);

        impl<T> Future for WakerSetter<'_,T> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
                let waker_ptr = Box::into_raw( Box::new(cx.waker().clone()) );

                self.get_mut().0.current_waker.store(waker_ptr, Ordering::Relaxed);

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
    async fn wait_for_controller<I,D>(&self, interface: &I, data: D)
    -> Result<(), FlowControllerError<I>>
    where I: HciAclDataInterface,
          D: core::iter::IntoIterator<Item=HciAclData>
    {
        /// A future that returns Ready when one HCI data packet can be sent to the controller.
        ///
        /// This future, when polled to completion will only indicate that one packet can be sent,
        /// it will not determine if multiple packets may be sent.
        struct FreedFut<'a,T>(&'a HciDataPacketFlowManager<T>);

        impl<T> Future for FreedFut<'_,T> {
            type Output = ();

            fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {

                let this = self.get_mut().0;

                loop {
                    let used_buff = this.controller_used_space.load(Ordering::Relaxed);

                    if used_buff >= this.get_max_payload_size() {
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

            interface.send(packet)?;
        }

        Ok(())
    }
}

impl<M,L,G> HciDataPacketFlowManager<M>
where M: AsyncLock<Guard=G,Locker=L> + Default,
      L: Future<Output=G>
{
    /// Create a new HCI data packet flow manager for LE data.
    pub async fn new_le<I>( hi: &HostInterface<I> ) -> Self
    where I: HostControllerInterface + HciAclDataInterface + 'static,
    {
        use crate::hci::{
            le::mandatory::read_buffer_size as le_read_buffer_size,
            info_params::read_buffer_size
        };
        use crate::l2cap::MinimumMtu;

        let current_waker: Arc<AtomicPtr<Waker>> = Arc::default();

        let controller_used_space: Arc<AtomicUsize>  = Arc::default();

        let match_flag: Arc<AtomicBool> = Arc::default();

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
            match_flag.clone(),
        );

        Self {
            sender_lock: Arc::default(),
            max_packet_payload_size: pl.into(),
            min_packet_payload_size: crate::l2cap::LeU::MIN_MTU,
            controller_used_space,
            controller_buffer_size: pc.into(),
            current_waker: Arc::default(),
            match_flag,
        }
    }

    /// Send ACL data to controller
    ///
    /// This function will send data to the controller as long as the controller has space for the
    /// data within its buffers. This doesn't query the controller for its buffer space (which
    /// cannot be done through the HCI as specified in the specification). When it is determined
    /// that the controller has enough room for one or more packets, the future will be awoken to
    /// send more packets to the controller.
    pub async fn send<Hci,I>(
        self: Arc<Self>,
        hi: Hci,
        data: AclData,
        connection_handle: ConnectionHandle
    ) -> Result<(), FlowControllerError<I>>
    where Hci: core::ops::Deref<Target = HostInterface<I>>,
          I: HciAclDataInterface,
    {
        match self.fragment(&data, connection_handle) {
            Ok(vec_data) => {
                // Fragmented sending requires exclusive access to the HCI interface
                let _lock = self.sender_lock.lock().await;

                self.set_waker().await;

                let buffer_used_space = self.controller_used_space.load(Ordering::SeqCst);

                if self.controller_buffer_size < (vec_data.len() + buffer_used_space)
                {
                    self.controller_used_space.fetch_add(vec_data.len(), Ordering::Acquire);

                    vec_data.into_iter().try_for_each(|data| hi.as_ref().send(data).map(|_| ()))
                } else {
                    let send_amount = self.controller_buffer_size
                        .checked_sub(buffer_used_space)
                        .unwrap_or_default();

                    self.controller_used_space.fetch_add(send_amount, Ordering::Acquire);

                    let mut data_itr = vec_data.into_iter();

                    data_itr.by_ref()
                        .enumerate()
                        .take_while(|(i, _)| i < &send_amount)
                        .try_for_each(|(_, data)| hi.as_ref().send(data).map(|_| ()))?;

                    self.wait_for_controller(hi.as_ref(), data_itr).await
                }
            }
            Err(single_data) => {
                let _lock = self.sender_lock.lock().await;

                self.set_waker().await;

                let buffer_used_space = self.controller_used_space.load(Ordering::SeqCst);

                if self.controller_buffer_size < buffer_used_space {
                    hi.as_ref().send(single_data).map(|_| ())
                } else {
                    self.wait_for_controller(hi.as_ref(), Some(single_data)).await
                }
            }
        }
    }
}

impl<M> Drop for HciDataPacketFlowManager<M> {
    fn drop(&mut self) {
        self.match_flag.store(true, Ordering::Relaxed);
    }
}

pub(super) type FlowControllerError<I> = <I as HciAclDataInterface>::SendAclDataError;


/// A trait for implementing an asynchronous locking.
///
/// This is needed for a flow controller as fragmented data must be sent contiguously to the
/// controller. The lock ensures that no other sender can send data to the controller until all
/// fragments are sent.
pub trait AsyncLock {
    type Guard;
    type Locker: Future<Output = Self::Guard>;

    fn lock(&self) -> Self::Locker;
}

pub struct SendFuture<M,Hci,I> where I: HciAclDataInterface + HostControllerInterface {
    manager: Arc<HciDataPacketFlowManager<M>>,
    hi: Hci,
    data: Option<AclData>,
    handle: ConnectionHandle,
    fut: Option<Pin<Box<dyn Future<Output=Result<(), FlowControllerError<I> > > > >>,
}

impl<M,Hci,I> SendFuture<M,Hci,I> where I: HciAclDataInterface + HostControllerInterface {
    pub fn new(
        manager: Arc<HciDataPacketFlowManager<M>>,
        hi: Hci,
        data: AclData,
        handle: ConnectionHandle
    ) -> Self {
        SendFuture {
            manager,
            hi,
            data: Some(data),
            handle,
            fut: None
        }
    }
}

impl<M,Hci,I,G,L> Future for SendFuture<M,Hci,I>
where Hci: core::ops::Deref<Target = HostInterface<I>> + Clone + Unpin + 'static,
      I: HciAclDataInterface + HostControllerInterface + Unpin + 'static,
      M: AsyncLock<Guard=G,Locker=L> + Default + 'static,
      L: Future<Output=G> + 'static,
      G: 'static
{
    type Output = Result<(), FlowControllerError<I>>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {

        let this = self.get_mut();

        match this.fut.as_mut() {
            None => {
                this.fut = Some( Box::pin( this.manager.clone().send(
                    this.hi.clone(),
                    this.data.take().unwrap(),
                    this.handle)
                ) );

                this.fut.as_mut().unwrap()
            },
            Some(fut) => fut,
        }.as_mut().poll(cx)
    }
}