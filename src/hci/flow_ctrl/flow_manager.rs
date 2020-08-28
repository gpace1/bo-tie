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

use alloc::sync::Arc;
use core::{
    cell::Cell,
    future::Future,
    mem::MaybeUninit,
    pin::Pin,
    sync::atomic::{Ordering, AtomicPtr, AtomicBool, spin_loop_hint},
    task::{Waker,Poll,Context},
};
use crate::hci::{
    AclPacketBoundary,
    HciAclData,
    HciAclDataInterface,
    HostInterface,
    HostControllerInterface,
};


// /// A manager of sent data to a buffers controller
// ///
// /// See the module level documentation for full details.
// #[derive(Debug, Default)]
// struct HciDataPacketFlowManager {
//     /// Once someone starts sending, they have a total lock until all data fragments are sent. There
//     /// is no way multiple contexts to send fragmented data to the controller at the same time.
//     sender_lock: Arc<futures::lock::Mutex<()>>,
//     /// The maximum size of the payload for each packet
//     max_packet_payload_size: usize,
//     /// The current used space of the controller's buffer. This number increases for each sent HCI
//     /// data payload, and decreases when the controller reports that data was freed from its
//     /// buffers.
//     controller_used_space: Arc<core::sync::atomic::AtomicUsize>,
//     /// The size, in packets, of the controllers buffer
//     controller_buffer_size: usize,
//     /// The current waker
//     current_waker: Arc<core::sync::atomic::AtomicPtr<Waker>>,
// }
//
// impl HciDataPacketFlowManager {
//
//     /// Create a new HCI data packet flow manager for LE data.
//     pub async fn new_le<I,E>( hi: &HostInterface<I> ) -> Self
//         where I: HostControllerInterface + HciAclDataInterface + Send + Sync + 'static,
//               E: futures::task::Spawn,
//     {
//         use crate::hci::{
//             le::mandatory::read_buffer_size as le_read_buffer_size,
//             info_params::read_buffer_size
//         };
//
//         let current_waker: Arc<core::sync::atomic::AtomicPtr<Waker>> = Arc::default();
//
//         let controller_used_space: Arc<core::sync::atomic::AtomicUsize>  = Arc::default();
//
//         // Check the controller for a LE data buffer, if it doesn't exist then use the ACL data
//         // buffer.
//         //
//         // pl -> The maximum packet size for each LE-U ACL data packet (the entire packet, header
//         //       plus the payload)
//         // pc -> The size of the data buffer in the controller.
//         let (pl, pc) = match le_read_buffer_size::send(&hi).await.unwrap() {
//             le_read_buffer_size::BufferSize{ packet_len: Some(pl), packet_cnt: Some(pc), .. } => {
//                 (pl as usize, pc as usize)
//             },
//             _ => {
//                 let buff_info = read_buffer_size::send(&hi).await.unwrap();
//
//                 (buff_info.hc_acl_data_packet_len, buff_info.hc_total_num_acl_data_packets)
//             },
//         };
//
//         log::info!("Maximum HCI ACL data size: {}", pl);
//         log::info!("Controller ACL LE data buffer size: {}", pc);
//
//         Self::setup_completed_packets_callback(
//             current_waker.clone(),
//             controller_used_space.clone(),
//             hi,
//         );
//
//         Self {
//             sender_lock: Arc::default(),
//             max_packet_payload_size: pl.into(),
//             controller_used_space,
//             controller_buffer_size: pc.into(),
//             current_waker: Arc::default(),
//         }
//     }
//
//     /// Get the maximum packet size that the controller can receive
//     ///
//     /// When calling
//     /// [`send`](crate::protocol::bluetooth::HciDataPacketFlowManager::send)
//     /// , it may fragment the data sent to the function before sending each
//     /// fragment to the controller. This has some issues (read the doc for `send`) which can be
//     /// mitigated by fragmenting at a higher layer than the HCI. This can be used for determining
//     /// the fragmentation size at a higher layer.
//     pub fn get_max_packet_size(&self) -> usize {
//         self.max_packet_payload_size
//     }
//
//     /// Create a matcher that will be used to set the available data buffer space.
//     ///
//     /// This callback is used for tracking the *Number of Completed Packets Event* from the
//     /// controller. This implementation relies on never polling to completion to maintain a
//     /// matcher within the driver. The event is sent at will by the controller. Generally the event
//     /// is sent periodically by the controller, but the host must assume that it may be sent
//     /// randomly.
//     ///
//     /// Normally when waiting on a event, the `receive_event` function of `HostControllerInterface`
//     /// is called at least twice, first to setup the waker and matcher for the driver then lastly to
//     /// clear the waker and matcher from the driver and get the event data. This takes advantage of
//     /// this and never recalls `receive_event` after the first time. The provides waker to
//     /// `receive_event` does not wake anything and the provides matcher will never return true. This
//     /// should ensure that the driver will never remove the matcher for the *Number of Completed
//     /// Packets Event*, **but the consequences of this is that the user can no longer await for this
//     /// event in their library or application** for the lifetime of the matcher. The matcher is tied
//     /// to all instances of a `ConnectionChannel` associated with a single instance of a
//     /// `HciDataPacketFlowManager`.
//     ///
//     /// # TODO Note
//     /// As this is currently implemented, it doesn't differentiate between the ACL controller buffer
//     /// and the LE controller buffer when counting the number of freed space. When implementing ACL
//     /// the 'freed' count needs to be divided between ACL-U and LE-U. Doing this may mean that
//     /// two wakers could be supported, one for ACL-U and one for LE-U.
//     fn setup_completed_packets_callback<I>(
//         current_waker: Arc<core::sync::atomic::AtomicPtr<Waker>>,
//         used_space: Arc<core::sync::atomic::AtomicUsize>,
//         interface: &HostInterface<I>,
//     ) where I: HostControllerInterface + HciAclDataInterface + Send + Sync + 'static,
//     {
//         use core::sync::atomic::Ordering;
//         use core::task::{RawWakerVTable, RawWaker};
//         use crate::hci::events::EventsData;
//
//         fn c_wake(_: *const ()) -> RawWaker { RawWaker(core::ptr::null(), &WAKER_V_TABLE) }
//         fn n_wake(_: *const ()) {}
//         fn r_wake(_: *const ()) {}
//         fn d_wake(_: *const ()) {}
//
//         const WAKER_V_TABLE: RawWakerVTable = RawWakerVTable::new(c_wake, n_wake, r_wake, d_wake);
//
//         let dummy_waker = unsafe { Waker::from_raw(RawWaker(core::ptr::null(), &WAKER_V_TABLE)) };
//
//         let event = crate::hci::events::Events::NumberOfCompletedPackets;
//
//         let matcher = Arc::pin( move |e_data: &superevents::EventsData| {
//             match e_data {
//                 EventsData::NumberOfCompletedPackets(info) => {
//
//                     let freed = info.into_iter()
//                         .map(|d| <usize>::from(d.number_of_completed_packets))
//                         .sum();
//
//                     loop {
//                         let old = used_space.load(Ordering::Relaxed);
//
//                         match used_space.compare_exchange_weak(
//                             old,
//                             old.checked_sub(freed).unwrap_or_default(),
//                             Ordering::SeqCst,
//                             Ordering::Acquire,
//                         ) {
//                             Ok(_) => break,
//                             _ => ()
//                         }
//                     }
//
//                     let waker_ptr = current_waker.load(Ordering::Relaxed);
//
//                     unsafe {waker_ptr.as_ref()}.map( |waker| waker.wake_by_ref() );
//                 },
//                 _ => (),
//             }
//
//             false
//         });
//
//         if interface.receive_event(event, dummy_waker, matcher).is_some() {
//             panic!("Received an event result when expected `None` from call to receive_event in \
//                 HciDataPacketFlowManager::setup_completed_packets_callback")
//         }
//     }
//
//     /// Send ACL data to controller
//     ///
//     /// This function will send data to the controller as long as the controller has space for the
//     /// data within its buffers.
//     ///
//     /// When it is determined that the controller
//     pub async fn send<I>(&self, interface: &I, data: HciAclData)
//     -> Result<usize, FlowControllerError<I>>
//     where I: HciAclDataInterface + HostControllerInterface
//     {
//         use core::sync::atomic::Ordering;
//
//         let rslt = async {
//             // The order of operations for this function is critically important in order for having
//             // the most efficient and correct implementation for sending
//
//             match self.fragment(data) {
//                 Ok(vec_data) => {
//                     // Fragmented sending requires exclusive access to the HCI interface
//                     let _lock = self.sender_lock.lock().await;
//
//                     // Setting the waker before returning the
//                     self.set_waker().await;
//
//                     let buffer_used_space = self.controller_used_space.load(Ordering::SeqCst);
//
//                     if self.controller_buffer_size < (vec_data.len() + buffer_used_space)
//                     {
//                         self.controller_used_space.fetch_add(vec_data.len(), Ordering::Acquire);
//
//                         vec_data.into_iter()
//                             .try_for_each(|data| interface.send(data).map(|_| ()))
//                             .map_err(FlowControllerError::from_de)
//                     } else {
//                         let send_amount = self.controller_buffer_size
//                             .checked_sub(buffer_used_space)
//                             .unwrap_or_default();
//
//                         self.controller_used_space.fetch_add(send_amount, Ordering::Acquire);
//
//                         let mut data_itr = vec_data.into_iter();
//
//                         data_itr.by_ref()
//                             .enumerate()
//                             .take_while(|(i, _)| i < &send_amount)
//                             .try_for_each(|(_, data)| interface.send(data).map(|_| ()))
//                             .map_err(FlowControllerError::from_de)?;
//
//                         self.wait_for_controller(interface, data_itr).await
//                     }
//                 }
//                 Err(single_data) => {
//                     let _lock = self.sender_lock.lock().await;
//
//                     self.set_waker().await;
//
//                     let buffer_used_space = self.controller_used_space.load(Ordering::SeqCst);
//
//                     if self.controller_buffer_size < buffer_used_space {
//                         interface.send(single_data).map(|_| ())
//                             .map_err(FlowControllerError::from_de)
//                     } else {
//                         self.wait_for_controller(interface, Some(single_data)).await
//                     }
//                 }
//             }
//         }
//             .await;
//
//         self.clear_waker();
//
//         rslt.map(|_| 0)
//     }
//
//     /// Non-flush-able data fragmentation
//     ///
//     /// This converts HCI ACL data whose payload is larger then the maximum payload size that the
//     /// controller can handle into fragments that the controller can handle. If 'data' doesn't need
//     /// to be fragmented, then it just returned as an Error.
//     ///
//     /// # Panic
//     /// If data has a packet boundary flag indicating a complete L2CAP PDU and the payload is larger
//     /// then the controller's accepted payload size, this function produces a panic.
//     fn fragment(&self, data: HciAclData)
//                 -> Result<Vec<HciAclData>, HciAclData>
//     {
//         if data.get_payload().len() > self.max_packet_payload_size {
//
//             // This is just for AMP-U. This packet boundary cannot be used by any data transport
//             // except for AMP
//             if let AclPacketBoundary::CompleteL2capPdu = data.get_packet_boundary_flag() {
//                 panic!("Size of payload ")
//             }
//
//             let mut first_packet = true;
//
//             let fragments = data.get_payload()
//                 .chunks(self.max_packet_payload_size)
//                 .map(|chunk| HciAclData::new(
//                     *data.get_handle(),
//                     if first_packet {
//                         first_packet = false;
//
//                         data.get_packet_boundary_flag()
//                     } else {
//                         AclPacketBoundary::ContinuingFragment
//                     },
//                     data.get_broadcast_flag(),
//                     chunk.to_vec(),
//                 ))
//                 .collect();
//
//             Ok(fragments)
//
//         } else {
//             Err(data)
//         }
//     }
//
//     /// Set the waker from the current context
//     ///
//     /// This function is about as questionably safe as it could possibly be. It uses a future
//     /// to acquire the waker of the current context. It does this by boxing a clone of the waker,
//     /// consuming the box into a raw pointer, and setting the member `current_waker`. The method
//     /// `clear_waker` can be called after
//     async fn set_waker(&self) {
//         use core::sync::atomic::Ordering;
//
//         struct WakerSetter<'a>(&'a HciDataPacketFlowManager);
//
//         impl Future for WakerSetter<'_> {
//             type Output = ();
//
//             fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
//                 let waker_ptr = Box::into_raw( Box::new(cx.waker().clone()) );
//
//                 self.get_mut().0.current_waker.store(waker_ptr, Ordering::Relaxed);
//
//                 Poll::Ready(())
//             }
//         }
//
//         WakerSetter(self).await;
//     }
//
//     /// Clear the Waker
//     ///
//     /// This function will clear the allocated waker clone, or do nothing if current_waker is null.
//     /// This function assumes that the pointer is valid if it is not null.
//     fn clear_waker(&self) {
//         use core::sync::atomic::Ordering;
//
//         let waker_ptr = self.current_waker.swap(core::ptr::null_mut(), Ordering::Relaxed);
//
//         if ! waker_ptr.is_null() {
//             unsafe { Box::from_raw(waker_ptr) };
//         }
//     }
//
//     /// Wait for the controller to free up space
//     ///
//     /// This will await for space on the controller to free up before sending more data to the
//     /// controller. It does this for *one* thread at a time. It cannot handle multiple threads
//     /// awaiting the same event.
//     ///
//     /// # WARNING
//     /// This function **must** be called within the same context as the method `set_waker`. This
//     /// function relies on the waker set by `set_waker` to continue polling.
//     async fn wait_for_controller<I,D>(&self, interface: &I, data: D)
//                                       -> Result<(), FlowControllerError<I>>
//         where I: HciAclDataInterface + HostControllerInterface,
//               D: core::iter::IntoIterator<Item=HciAclData>
//     {
//         use core::sync::atomic::Ordering;
//
//         /// A future that returns Ready when one HCI data packet can be sent to the controller.
//         ///
//         /// This future, when polled to completion will only indicate that one packet can be sent,
//         /// it will not determine if multiple packets may be sent.
//         struct FreedFut<'a>(&'a HciDataPacketFlowManager);
//
//         impl Future for FreedFut<'_> {
//             type Output = ();
//
//             fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
//
//                 let this = self.get_mut().0;
//
//                 loop {
//                     let used_buff = this.controller_used_space.load(Ordering::Relaxed);
//
//                     if used_buff >= this.get_max_packet_size() {
//                         log::trace!("Awaiting for space to be freed up in the controller");
//                         break Poll::Pending
//                     } else if this.controller_used_space.compare_exchange_weak(
//                         used_buff,
//                         used_buff + 1,
//                         Ordering::SeqCst,
//                         Ordering::Acquire
//                     ).is_ok()
//                     {
//                         break Poll::Ready(())
//                     } else {
//                         continue
//                     }
//                 }
//             }
//         }
//
//         for packet in data.into_iter() {
//
//             FreedFut(self).await;
//
//             interface.send(packet).map_err(FlowControllerError::from_de)?;
//         }
//
//         Ok(())
//     }
// }
//
// impl Drop for HciDataPacketFlowManager {
//     fn drop(&mut self) {
//         self.end_thread.take().and_then( |sender| sender.send(()).ok() );
//     }
// }

/// A marker for the busy state of a link
///
/// This is just a marker, you cannot dereference this pointer. Its used for referring to something
/// that is guaranteed to not be a *valid* state of a `SenderNodePtr
///
/// When a `SenderNodePtr` contains this pointer for member 'ptr' it is used to indicate that
/// something is currently 'busy' with the link and it cannot be touched until it is changed to
/// another state.
static BUSY_LINK: &usize = &0usize;

/// A state-based pointer to a SenderNode
///
/// There are two different states of a `SendNodePtr`. The pointer can either be in the *valid*
/// or *busy* state. When the pointer is *valid* it means that it currently contains a valid pointer
/// to either a `SenderNode` that is currently in memory or is equal to null to indicate that it
/// doesn't point to a `SenderNode`. When the pointer is in the *busy* state then there is some
/// context that has currently doing something with the pointer. Everything else must wait until
/// the state of the pointer changes back to *valid* before they can do something with it.
///
/// The *busy* state must be detected for before modifying the pointed to value. If the current
/// pointer is pointed to the *busy* marker, then all operations to set the pointer will need to
/// loop until they can acquire the *busy* state for themselves. Only one context at a time may
/// 'own the busy state. As a result a `SendNodePtr` is not lock-free, as the *busy* state is
/// effectively a locking mechanism. When a context changes the state to *busy* it is considered to
/// own the *busy* state. All other contexts that do not own the *busy* state must wait until the
/// state is changed before they can proceed to try to own the *busy* state for themselves. The
/// value of the *value* state can only be changed by the `SendNodePtr` that  currently owns the
/// *busy* state (the value is changed when the context changes the state from *busy* to *value*).
///
/// For this pointer to work the `SenderNodes` that are pointed to (when this is in the *valid*
/// state) must be pinned within memory.
struct SenderNodePtr{
    /// The state pointer
    ptr: AtomicPtr<SenderNode>,
    busy_val: Cell<Option<*mut SenderNode>>,
}

unsafe impl Send for SenderNodePtr {}
unsafe impl Sync for SenderNodePtr {}

impl SenderNodePtr {

    /// Create a new SenderNode
    ///
    /// This will create a node that is currently in the *unoccupied* state.
    pub fn new() -> Self {
        SenderNodePtr {
            ptr: AtomicPtr::new(core::ptr::null_mut()),
            busy_val: Cell::new(None),
        }
    }

    /// Try to acquire an owned *busy* state.
    ///
    /// This does not loop to acquire an owned *busy* state and may spuriously fail.
    pub fn own_busy(&self) -> Result<(),()> {
        // Wait for the pointer check with `BUSY_LINK` to fail; success means some other context
        // is currently using this pointer.
        let valid = match self.ptr.compare_exchange(
            BUSY_LINK as *const _ as *mut _,
            BUSY_LINK as *const _ as *mut _,
            Ordering::Acquire,
            Ordering::Acquire
        ) {
            Ok(_) => return Err(()),
            Err(valid) => valid
        };

        // Now try to set the pointer to *Self::BUSY_LINK* to own the *busy* state
        match self.ptr.compare_exchange_weak(
            valid,
            BUSY_LINK as *const _ as *mut _,
            Ordering::Acquire,
            Ordering::Relaxed
        ) {
            Ok(valid) => {
                self.busy_val.set( valid.into() );
                Ok(())
            },
            Err(_) => Err(()),
        }
    }

    /// Release the busy state and re-enter the old valid state
    ///
    /// This returns true if the *busy* state was owned by this and subsequently released. False if
    /// the pointer is in another state or this doesn't currently own the *busy* state. When the
    /// *busy* state is released the pointer will equal `busy_val`.
    pub fn release_busy(&self) {
        self.busy_val.take().map(|old| self.ptr.store(old, Ordering::Release) );
    }

    /// Set the pointer to a valid state
    ///
    /// This function is used for setting the value of the pointer when the pointer is in the
    /// *valid* state, however the current state must be the owned `busy` state. The provided
    /// reference `node_ref` will not be set to the pointer until the `release_busy` function is
    /// called.
    ///
    /// `true` is returned when if the current state is the owned *busy* state.
    pub fn set_and_release(&self, node_ref: *mut SenderNode) {
        self.busy_val.take().map(|_| self.ptr.store(node_ref, Ordering::Release) );
    }

    /// Get the pointer
    ///
    /// The pointer can only be retrieved during an owned Busy state
    pub fn get_ptr(&self) -> Option<*mut SenderNode> {
        let ret = self.busy_val.get();

        debug_assert_ne!(ret, Some(BUSY_LINK as *const _ as *mut _));

        ret
    }
}

/// A node for a future sender of `HciDataPacketFlowManager`
///
/// This is a node of a linked list of other `SenderNode`s. A `SenderNode` is designed to be
/// pinned in place and deliberately does not implement `Unpin` as it requires that all other
/// `SenderNode`s within the linked list be immovable. This allows for a `SenderNode` to not be
/// allocated but still used within a linked list.
///
/// Inserting a `SenderNode` into a linked list can be done with the 'insert_before' method, however
/// removing a node can only be done by dropping the instance.
///
/// Only use the public functions outside of the implementation for `SendNode`.
///
/// # Note
/// When creating a linked list of these nodes, locking occurs when both links between two
/// consecutive nodes are put into an owned busy state. Once a lock occurs
struct SenderNode {
    future: *mut crate::l2cap::SendFut,
    next: SenderNodePtr,
    prev: SenderNodePtr,
    _pin: core::marker::PhantomPinned,
}

impl SenderNode {

    /// Create a new `SenderNode`
    pub fn new(future: *mut crate::l2cap::SendFut) -> Self {
        SenderNode {
            future,
            next: SenderNodePtr::new(),
            prev: SenderNodePtr::new(),
            _pin: core::marker::PhantomPinned,
        }
    }

    /// Busy lock the `next` node pointer and next node's `prev` pointer
    ///
    /// This method loops until it can set the state of `next` and the `next` node's `prev` to busy.
    /// When looping is done, this `SendNode` will own both busy states for these pointers. If
    /// `next` is a null pointer, then only it goes into an owned busy state. The returns is a
    /// reference to the node pointed to by `next` if `next` is not a null pointer.
    ///
    /// # Note
    /// The prev to next busy acquire is always submissive to a next to busy operation (this
    /// function). One direction must be submissive to the other, and this function's operation was
    /// chosen to be dominate because it is used more likely to be used than the other operation.
    ///
    /// This function is dominate because after it acquires own *busy* for `self.next` it will never
    /// give it up until the operation completes.
    ///
    /// Without a dom
    fn busy_lock_next_to_prev<'a,'b>(&self) -> Option<&'b SenderNode> {
        let mut spin_cnt: u64 = 0;

        loop { if let Ok(_) = self.next.own_busy() { break } spin_cnt += 1; std::thread::yield_now();; }

        let ret = unsafe { self.next.get_ptr().unwrap().as_ref() }.map(|next_node| {
            loop { if let Ok(_) = next_node.prev.own_busy() { break } spin_cnt += 1; std::thread::yield_now();; }

            next_node
        });

        println!("prev_to_next 1 for {:?} spin count {}", std::thread::current().id(), spin_cnt );

        ret
    }

    /// Busy lock the `prev` node pointer and the previous node's `next` pointer
    ///
    /// This method loops until it can set the state of `next` and the `next` node's `prev` to busy.
    /// When looping is done, this `SendNode` will own both busy states for these pointers. If
    /// `next` is a null pointer, then only it goes into an owned busy state. The returns is a
    /// reference to the node pointed to by `next` if `next` is not a null pointer.
    ///
    /// # Note
    /// The prev to next busy acquire (this function) is always submissive to a next to busy
    /// operation. One direction must be submissive to the other, and this function's operation was
    /// chosen to be submissive because it is less likely to be used than the other operation.
    ///
    /// This function is submissive because if it cannot acquire own *busy* state for
    /// `prev_node.next` it will release its own *busy* state for `self.prev`.
    fn busy_lock_prev_to_next<'a, 'b>(&self) -> Option<&'b SenderNode> {
        let mut spin_cnt: u64 = 0;

        let ret = loop {

            spin_cnt += 1;

            if let Err(_) = self.prev.own_busy() {
                std::thread::yield_now();;
                continue
            }

            match unsafe { self.prev.get_ptr().unwrap().as_ref() } {

                None => break None,

                Some(prev_node) =>
                    if let Err(_) = prev_node.next.own_busy() {
                        self.prev.release_busy();
                        std::thread::yield_now();;
                    } else {
                        break Some(prev_node)
                    }
            }
        };

        println!("prev_to_next 1 for {:?} spin count {}", std::thread::current().id(), spin_cnt );

        ret
    }

    /// Insert this item before `next`
    pub fn insert_before(self: Pin<&Self>, next: Pin<&Self>) {

        println!("inserting before for {:?}", std::thread::current().id() );

        let this = unsafe { Pin::into_inner_unchecked(self) };
        let next_mut = unsafe { Pin::into_inner_unchecked(next) };

        if let Some(prev) = next_mut.busy_lock_prev_to_next() {
            prev.next.set_and_release(this as *const _ as *mut _);
        }

        next_mut.prev.set_and_release(this as *const _ as *mut _);
    }
}

impl Drop for SenderNode {
    fn drop(&mut self) {

        match (self.busy_lock_next_to_prev(), self.busy_lock_prev_to_next()) {

            ( Some(next), Some(prev) ) => {
                next.prev.set_and_release( prev as *const _ as *mut _ );
                prev.next.set_and_release( next as *const _ as *mut _ );
            }

            ( Some(next), None ) => next.prev.set_and_release( core::ptr::null_mut() ),

            ( None, Some(prev) ) => prev.next.set_and_release( core::ptr::null_mut() ),

            _ => ()
        };

        println!("dropped {:?}", std::thread::current().id());
    }
}

impl core::ops::Deref for SenderNode {
    type Target = dyn Future<Output = ()>;

    fn deref(&self) -> &Self::Target {
        unimplemented!()
    }
}

impl core::ops::DerefMut for SenderNode {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unimplemented!()
    }
}

/// A linked list of SenderNodes
///
/// This is a queue of SenderNodes for use with a flow control manager for locking who can send at
/// a given time. This is a doubly linked list but it designed to be a FIFO. Entries can only be
/// pushed onto the end of the list and entries can only be taken from the front of the list.
///
/// Please only use the public methods outside the implementation for `SenderNodeLinkedList`
///
/// # Note
/// Both members are dummy nodes to mark the star and end of the list, there are no associated
/// futures with them.
struct SenderNodeLinkedList {
    start: SenderNode,
    end: SenderNode,
    new: AtomicBool,
}

unsafe impl Send for SenderNodeLinkedList {}
unsafe impl Sync for SenderNodeLinkedList {}

impl SenderNodeLinkedList {

    /// Create a new `SenderNodeLinkedList`
    fn new() -> Self {
        SenderNodeLinkedList {
            start: SenderNode::new( core::ptr::null_mut() ),
            end:   SenderNode::new( core::ptr::null_mut() ),
            new:   AtomicBool::new( true ),
        }
    }

    /// Insert the first item **ever** into the linked list
    ///
    /// This method must be called once, but should only be used by the push method. This is not to
    /// be called if the list is empty but a prior entry (or entries) were removed until it was
    /// empty. This should only be called after a `SendNodeLinkedList` was created and the first
    /// element is to be added to the list. After it is called once it should not be called again.
    fn insert_first_ever(&self, node: Pin<&SenderNode>) {

        const NULL: *mut SenderNode = core::ptr::null_mut();

        loop {
            if let Err(_) = self.start.next.own_busy() {
                spin_loop_hint();

                continue
            }

            if let Err(_) = self.end.prev.own_busy() {
                self.start.next.release_busy();
                spin_loop_hint();

                continue
            } else {
                break
            }
        }

        println!("Owned busy for {:?}", std::thread::current().id() );

        #[allow(unreachable_code)]
        match (self.start.next.get_ptr(), self.end.prev.get_ptr()) {

            (Some(NULL), Some(NULL)) => {

                // `node` is not in the list so directly setting the links without checking if
                // they are busy is fine.

                node.next.ptr.store(&self.end as *const _ as *mut _, Ordering::Relaxed);

                node.prev.ptr.store(&self.start as *const _ as *mut _, Ordering::Relaxed);

                let node_ptr = node.get_ref() as *const _ as *mut _;

                self.start.next.set_and_release(node_ptr);

                self.end.prev.set_and_release(node_ptr);

                self.new.store(false, Ordering::Release);
            }

            (Some(_), Some(_)) => {
                // Some context has already inserted the first element

                self.start.next.release_busy();

                self.end.prev.release_busy();

                unsafe { Pin::new_unchecked(self) }.push(node);
            }

            (None, _) | (_, None) => panic!("This should never occur, this is a logic error"),
        }
    }

    /// Push an element onto the end of the list
    pub fn push(self: Pin<&Self>, node: Pin<&SenderNode>) {
        if self.new.load(Ordering::Relaxed) {
            self.get_ref().insert_first_ever(node)
        } else {
            node.insert_before( unsafe { self.map_unchecked(|this| &this.end) } )
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn linked_list_thread_test() {

        lazy_static::lazy_static! {
            static ref LINKED_LIST: SenderNodeLinkedList = SenderNodeLinkedList::new();
        };

        let linked_list_ref = unsafe { Pin::new_unchecked(&*LINKED_LIST) };

        let threads = (0..10).into_iter()
            .map( |_| std::thread::spawn( move || {

                let node = SenderNode::new( core::ptr::null_mut() );

                let pinned_node = unsafe { Pin::new_unchecked(&node) };

                linked_list_ref.push(pinned_node);

            }))
            .collect::<Vec<_>>();

        threads.into_iter()
            .for_each(|handle| handle.join().unwrap() )
    }
}