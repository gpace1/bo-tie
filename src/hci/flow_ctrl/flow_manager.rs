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
    cell::Cell,
    fmt::Debug,
    future::Future,
    mem::transmute,
    ops::{Deref,DerefMut},
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
    state_ptr: AtomicPtr<SenderNode>,
    busy_val: Cell<Option<*mut SenderNode>>,
    _pin: core::marker::PhantomPinned,
}

impl SenderNodePtr {

    /// Create a new SenderNode
    ///
    /// This will create a node that is currently in the *unoccupied* state.
    pub fn new() -> Self {
        SenderNodePtr {
            state_ptr: AtomicPtr::new(core::ptr::null_mut()),
            busy_val: Cell::new(None),
            _pin: core::marker::PhantomPinned,
        }
    }

    /// Try to acquire an owned *busy* state.
    ///
    /// This does not loop to acquire an owned *busy* state and may spuriously fail.
    pub fn own_busy(&self) -> Result<(),()> {
        // Wait for the pointer check with `BUSY_LINK` to fail; success means some other context
        // is currently using this pointer.
        let valid = match self.state_ptr.compare_exchange(
            BUSY_LINK as *const _ as *mut _,
            BUSY_LINK as *const _ as *mut _,
            Ordering::Acquire,
            Ordering::Acquire
        ) {
            Ok(_) => return Err(()),
            Err(valid) => valid
        };

        // Now try to set the pointer to *Self::BUSY_LINK* to own the *busy* state
        match self.state_ptr.compare_exchange_weak(
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
        self.busy_val.take().map(|old| self.state_ptr.store(old, Ordering::Release) );
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
        self.busy_val.take().map(|_| self.state_ptr.store(node_ref, Ordering::Release) );
    }

    /// Get the pointer
    ///
    /// This function can only be called during an owned busy state. Undefined behaviour can occur
    /// if this is called when the pointer is not in an owned busy state.
    pub unsafe fn get_ptr(&self) -> Option<*mut SenderNode> {
        self.busy_val.get()
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
/// # Waking
/// Each node contains an optional waker used for waking the associated context. This waker is only
/// optional because the required start and end nodes of the linked list and the case where a node
/// is added to an empty list do not need an assigned waker. Secondly, its easier to take and move
/// a Waker when it is wrapped within an `Option`.
///
/// The member `start_node_ptr` points to the start node within the list. When a node is dropped, it
/// checks to see if its previous pointer is equal to this pointer. When it is it will take the
/// waker in the next node of the list and waker. *This is the only place, and can be the only
/// place, where this can occur*. The waker will not be touched, and cannot be due to
/// synchronization reasons, under any other condition.
///
/// # Note
/// When creating a linked list of these nodes, locking occurs when both links between two
/// consecutive nodes are put into an owned busy state. Once a lock occurs
struct SenderNode {
    waker: Option<Waker>,
    start_node_ptr: *const SenderNode,
    next: SenderNodePtr,
    prev: SenderNodePtr,
}

impl SenderNode {

    /// Create a new `SenderNode`
    ///
    /// This takes the waker to wake the future that is used for awaiting the mutex lock.
    pub fn new(waker: Waker) -> Self {
        SenderNode {
            waker: waker.into(),
            start_node_ptr: core::ptr::null(),
            next: SenderNodePtr::new(),
            prev: SenderNodePtr::new(),
        }
    }

    /// Create a start or end node
    ///
    /// These nodes are created without a waker. They are not part of the list of nodes used for
    /// awaiting for the mutex lock.
    pub fn new_start_or_end() -> Self {
        SenderNode {
            waker: None,
            start_node_ptr: core::ptr::null(),
            next: SenderNodePtr::new(),
            prev: SenderNodePtr::new(),
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
    /// function). One direction must be submissive to the other to reduce the time of spin-looping.
    /// This operation was chosen to be dominate as it is used less than the submissive operation.
    ///
    /// This function is dominate because after it acquires own *busy* for `self.next` it will never
    /// give it up until the function completes.
    fn busy_lock_next_mut_to_prev<'a,'b>(&self) -> Option<&'b mut SenderNode> {

        loop {
            if let Ok(_) = self.next.own_busy() { break }
            spin_loop_hint();
        }

        unsafe { self.next.get_ptr().unwrap().as_mut() }.map(|next_node| {
            loop {
                if let Ok(_) = next_node.prev.own_busy() { break }
                spin_loop_hint();
            }

            next_node
        })
    }

    /// Busy lock the `prev` node pointer and the previous node's `next` pointer
    ///
    /// This method loops until it can set the state of `next` and the `next` node's `prev` to busy.
    /// When looping is done, this `SendNode` will own both busy states for these pointers. If
    /// `next` is a null pointer, then only it goes into an owned busy state. The returns is a
    /// reference to the node pointed to by `next` if `next` is not a null pointer.
    ///
    /// # Note
    /// The prev to next busy acquire (this function) is always submissive to a next to prev acquire
    /// operation. One direction must be submissive to the other to improve performance of the .
    ///
    /// This function is submissive because if it cannot acquire own *busy* state for
    /// `prev_node.next` it will release its own *busy* state for `self.prev`.
    fn busy_lock_prev_to_next<'a, 'b>(&'a self) -> Option<&'b SenderNode> {
        loop {
            if let Err(_) = self.prev.own_busy() {
                spin_loop_hint();
                continue
            }

            match unsafe { self.prev.get_ptr().unwrap().as_ref() } {

                None => break None,

                Some(prev_node) =>
                    if let Err(_) = prev_node.next.own_busy() {
                        self.prev.release_busy();
                        spin_loop_hint();
                    } else {
                        break Some(prev_node)
                    }
            }
        }
    }

    /// Insert this item before `next`
    ///
    /// This will insert this `SenderNode` before node `next`. This node cannot be part of *any*
    /// linked list, it must be an orphan node. If it is part of a linked list, than that linked
    /// list's links will become invalid and operations will produce undefined behaviour.
    ///
    /// self is not pinned here because a node is required to be pinned only *after* the node is in
    /// the linked list, thus it technically only needs to be pinned after `insert_before` returns.
    pub fn insert_before(self: &mut Self, next: Pin<&Self>, start_ptr: *const Self) {

        debug_assert_eq!( self.next.state_ptr.load(Ordering::Relaxed), core::ptr::null_mut() );
        debug_assert_eq!( self.prev.state_ptr.load(Ordering::Relaxed), core::ptr::null_mut() );
        debug_assert_ne!( next.prev.state_ptr.load(Ordering::Relaxed), core::ptr::null_mut() );
        debug_assert_ne!( start_ptr,                                   core::ptr::null_mut() );

        let next_ref = unsafe { Pin::into_inner_unchecked(next) };

        self.start_node_ptr = start_ptr;

        self.next.state_ptr.store(next_ref as *const _ as *mut _, Ordering::Release);

        if let Some(prev_ref) = next_ref.busy_lock_prev_to_next() {

            self.prev.state_ptr.store(prev_ref as *const _ as *mut _, Ordering::Release);

            prev_ref.next.set_and_release(self as *const _ as *mut _);
        }

        next_ref.prev.set_and_release(self as *const _ as *mut _);
    }

    /// Get a pointer to the next node
    ///
    /// This will return the next node in the list if it exists. If this cannot return the next node
    /// then `Err(_)` is returned, if there is no next node then `Some(None)` is returned. The
    /// next node cannot be retrieved if the pointer to the next node (`self.next`) is in the *busy*
    /// state.
    pub fn next_node_ptr(&self) -> Result<*const SenderNode, ()> {
        let next_ptr = self.next.state_ptr.load(Ordering::Acquire);

        if next_ptr == BUSY_LINK as *const _ as *mut _ {
            Err(())
        } else {
            Ok( next_ptr as *const _ )
        }
    }
}

impl Drop for SenderNode {
    fn drop(&mut self) {

        match (self.busy_lock_next_mut_to_prev(), self.busy_lock_prev_to_next()) {

            ( Some(next), Some(prev) ) => {

                // Call wake on the next node's waker if this is the first item in the list
                //
                // Please note the linked list's `new` method takes advantage of this check to
                // set an uninitialized waker for the start and end nodes.
                if prev as *const _ == self.start_node_ptr {
                    // The return of take is not unwrapped because the next node might be the
                    // end_node which has no waker
                    if let Some(waker) = next.waker.take() { waker.wake() }
                }

                next.prev.set_and_release( prev as *const _ as *mut _ );
                prev.next.set_and_release( next as *const _ as *mut _ );
            }

            _ => (), // Item was never added to the list
        };
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
/// Nodes of the linked list can only be removed by dropping them. The important location of this
/// list is the first item in it as that node is the one who has acquired the mutex lock. Thus only
/// when an item goes out of scope and it's drop implementation is called can it be removed from the
/// list. This is also follows the mutex-guard pattern of having locks acquired for as long as the
/// guard isn't dropped.
///
/// Please only use the public methods outside the implementation for `SenderNodeLinkedList`
///
/// # Note
/// Both members are dummy nodes to mark the star and end of the list, there are no associated
/// futures with them.
struct SenderNodeLinkedList {
    start: SenderNode,
    end: SenderNode,
    unlinked: AtomicBool,
}

unsafe impl Sync for SenderNodeLinkedList {}

impl SenderNodeLinkedList {

    /// Create a new `SenderNodeLinkedList`
    fn new() -> Self {
        println!("Busy address {:?}", BUSY_LINK as *const _);
        // Using uninitialized memory is safe here because these nodes do not have a link back to
        // the start node.
        SenderNodeLinkedList {
            start: SenderNode::new_start_or_end(),
            end:   SenderNode::new_start_or_end(),
            unlinked:   AtomicBool::new( true ),
        }
    }

    /// Insert the first item **ever** into the linked list
    ///
    /// Insert the first item into the list. This must be called to insert the first item in the
    /// list, but after that it is inefficient to continue to call this. It should only be called
    /// again due to a race condition between multiple threads trying to insert the first node.
    ///
    /// The return is a boolean to indicate if this item is the first node within the list. A return
    /// of true does not necessarily mean that `node` was the first item put into the list.
    fn insert_first_ever(&self, node: Pin<&mut SenderNode>) -> bool {

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

        #[allow(unreachable_code)]
        match unsafe { (self.start.next.get_ptr(), self.end.prev.get_ptr() ) } {

            (Some(NULL), Some(NULL)) => {

                // `node` is not in the list so directly setting the links without checking if
                // they are busy is OK.

                let node_ptr = &node as *const _ as *mut _;

                node.next.state_ptr.store(&self.end as *const _ as *mut _, Ordering::Relaxed);

                node.prev.state_ptr.store(&self.start as *const _ as *mut _, Ordering::Relaxed);

                unsafe { node.get_unchecked_mut().start_node_ptr = &self.start as *const _ };

                self.start.next.set_and_release(node_ptr);

                self.end.prev.set_and_release(node_ptr);

                self.unlinked.store(false, Ordering::Release);

                true
            }

            (Some(_), Some(_)) => {
                // Some context has already inserted the first element

                self.start.next.release_busy();

                self.end.prev.release_busy();

                unsafe { Pin::new_unchecked(self) }.push(node)
            }

            (None, _) | (_, None) => panic!("This should never occur, this is a logic error"),
        }
    }

    /// Push an element onto the end of the list
    ///
    /// If this function returns true then this node was the first node in the list. However if
    /// `false` is returned, that only guarantees that the item was not *pushed* onto the first
    /// position. It may become the first in-between the time the first position was checked and the
    /// boolean was returned.
    pub fn push(self: Pin<&Self>, node: Pin<&mut SenderNode>) -> bool {
        if self.unlinked.load(Ordering::Relaxed) {
            self.get_ref().insert_first_ever(node)
        } else {
            let node_mut = unsafe { node.get_unchecked_mut() };

            let start_ptr = &self.start as *const _;

            node_mut.insert_before( unsafe { Pin::new_unchecked( &self.end ) }, start_ptr );

            self.as_ref().is_first( node_mut )
        }
    }

    /// Checks if `node` is the first item in the linked list
    ///
    /// `true` is returned if `node` is the first item in the list, otherwise false is returned.
    /// However, `false` doesn't mean that the item is not *currently* the first item in the list.
    /// In-between the time the first position was checked and the value was returned, `node` could
    /// have been put into the first place of the linked list. Thus a return of `true` guarantees
    /// that the item is in the first position whereas a return of `false` does not guarantee that
    /// the item is not in the first position.
    pub fn is_first(&self, node: &SenderNode) -> bool {

        let first_ptr = loop { if let Ok(ptr) = self.start.next_node_ptr() { break ptr } };

        first_ptr == node as *const _
    }
}

/// A no-allocation, future driven mutex
///
/// This mutex is designed to work within no_std environments, however it should not be used with
/// std, and especially with an operating system with a preemptive scheduler. This implementation
/// relies on atomic spinlocks and pinning to provide a linked list queue of awaiting futures.
/// Each future has a ticket that must be pinned in memory as it is pointed to the other members of
/// the linked list.
///
/// # `alloc` Feature
/// While allocation is not needed for this mutex to function, it does does make using this mutex
/// easier.
struct SenderMutex<T> {
    item: T,
    await_list: SenderNodeLinkedList
}

impl<T> SenderMutex<T> {

    /// Create a new `NoStdSenderMutes` in a pinned `Arc`
    pub fn new( item: T ) -> Self {
        Self { item, await_list: SenderNodeLinkedList::new() }
    }

    /// Create a future that is both the locker and guard of the mutex data.
    ///
    /// This method returns a future that once polled to completion will return a reference to the
    /// data of the mutex. Unlike method `lock`, the output of this future is not a mutex guard and
    /// its lifetime is tied to the lifetime of the future.
    ///
    /// ```
    /// # use core::pin::Pin;
    /// # use core::ops::Deref;
    ///
    /// async fn example<T>(mutex: Pin<impl Deref<Target=SenderMutex<T>>>) {
    ///
    ///     let mut lock_guard = mutex.as_ref().lock_guard();
    ///
    ///     let data_mut = lock_guard.await;
    /// }
    /// ```
    ///
    /// # Note
    /// Normally for asynchronous mutex implementation, the output of the future isn't tied to the
    /// lifetime of the future. These implementations normally return a guard whose lifetime matches
    /// the lifetime the lock. Unfortunately because of the implementation of this mutex, there is
    /// an interal ticket that not only must life for both the lifetime of the future and the gaurd,
    /// but also must be pinned within memory. And because the ticket is pinned in memory, it cannot
    /// be moved from the future to the gaurd. Thus the return of this function is both the locking
    /// future and guard of the mutex data. If you decide to look at the code, the ticket is the
    /// struct member `node`.
    pub fn lock_guard<'a>(self: Pin<&'a Self>)
    -> impl Future<Output = impl DerefMut<Target = T> + 'a > + 'a
    {
        let fut = NoStdLockingFuture::new(&self.get_ref());

        // This works because pin is represented as a transparent. This is done because
        // Pin::new_unchecked requires NoStdLockingFuture to implement Deref, but implementing
        // Deref would be useless.
        unsafe { transmute::<_, Pin<NoStdLockingFuture<'a, T>>>( fut ) }
    }

    pub fn lock<'a>(self: Pin<&'a Self>) -> Pin<Box<impl Future<Output = MutexGuard<'a, T>> + 'a>> {
        Box::pin(AllocLockingFuture::new(&self.get_ref()))
    }
}

/// Async Lock
///
/// This is the locking guard returned by
/// [`guard_lock`]
struct NoStdLockingFuture<'a,T> {
    await_list_ref: &'a SenderNodeLinkedList,
    node: Option<SenderNode>,
    item_ptr: *mut T,
}

impl<'a,T> NoStdLockingFuture<'a, T> {

    fn new(mutex: &'a SenderMutex<T>) -> Self {

        let await_list_ref = &mutex.await_list;

        let item_ptr = &mutex.item as *const _ as *mut _;

        Self {
            await_list_ref,
            node: None,
            item_ptr,
        }
    }
}

/// Implementation of `Future` for a pinned `NoStdLockingFuture`
///
/// `Future` is implemented for a *pinned* `NoStdLockingFuture` instead of just a
/// `NoStdLockingFuture` as a reference to the `SendNode` is part to the output `NoStdMutexGuard`.
/// As explained in the doc for `lock`
///
/// # Warning
/// This takes advantage that `Pin` is represented as transparent (`#[repr(transmute)]`). There is
/// no way to implement Deref and DerefMut as that causes a conflicting implementation with the
/// implementation of pin for
impl<'a, T: 'a> Future for Pin<NoStdLockingFuture<'a, T>> {
    type Output = DataRef<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {

        // This requires pin to be transparent
        let this = unsafe { transmute::<Pin<&mut Self>,&mut NoStdLockingFuture<'a, T>>(self) };

        if if this.node.is_none() {

            this.node = SenderNode::new( cx.waker().clone() ).into();

            let pinned_node = unsafe { Pin::new_unchecked( this.node.as_mut().unwrap() ) };

            let pinned_list = unsafe { Pin::new_unchecked( this.await_list_ref ) };

            pinned_list.push(pinned_node)

        } else {
            this.await_list_ref.is_first( this.node.as_ref().unwrap() )
        } {
            Poll::Ready( DataRef::new(this) )
        } else {
            Poll::Pending
        }
    }
}

/// A locking future for use with allocation
///
/// This provides a more user friendly way of locking. When polled to completion it returns a mutex
/// guard instead of the reference `NoStdLockingFuture` returns.
struct AllocLockingFuture<'a, T> {
    await_list_ref: &'a SenderNodeLinkedList,
    ticket: Option<Pin<Box<SenderNode>>>,
    item_ptr: *mut T
}

impl<'a, T> AllocLockingFuture<'a, T> {
    fn new(mutex: &'a SenderMutex<T> ) -> Self {
        Self {
            await_list_ref: &mutex.await_list,
            ticket: None,
            item_ptr: &mutex.item as *const _ as *mut _,
        }
    }
}

impl<'a,T: 'a> Future for AllocLockingFuture<'a, T> {
    type Output = MutexGuard<'a, T>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.get_mut();

        if if this.ticket.is_none() {
            let mut node = Box::pin( SenderNode::new(cx.waker().clone()) );

            let is_first = unsafe { Pin::new_unchecked(this.await_list_ref) }.push( node.as_mut() );

            this.ticket = node.into();

            is_first
        } else {
            this.await_list_ref.is_first( &this.ticket.as_ref().unwrap() )
        } {
            Poll::Ready( MutexGuard::new(this) )
        } else {
            Poll::Pending
        }
    }
}

struct MutexGuard<'a,T> {
    item_ptr: *mut T,
    ticket: Pin<Box<SenderNode>>,
    _pd: core::marker::PhantomData<&'a T>,
}

impl<'a, T> MutexGuard<'a,T> {

    /// Create a new MutexGuard
    ///
    /// # Panic
    /// This will panic if member `ticket` of input `fut` is `None`.
    fn new(fut: &mut AllocLockingFuture<'a, T>) -> Self {
        Self {
            item_ptr: fut.item_ptr,
            ticket: fut.ticket.take().unwrap(),
            _pd: core::marker::PhantomData
        }
    }
}

/// A way for the user to refer to the Mutex data
///
/// This is not a lock guard, it provides no way of `guarding` the mutex lock until it is dropped.
/// All it provides is a way to `Deref` and `DerefMut` to the Mutex data. The biggest difference is
/// that a Guard can be moved away from the future that was used to lock the mutex whereas this
/// cannot. See the doc for
pub struct DataRef<'a, T> {
    fut: &'a NoStdLockingFuture<'a, T>,
}

impl<'a, T> DataRef<'a, T> {

    fn new(fut: &'a NoStdLockingFuture<'a, T> ) -> Self {
        Self { fut }
    }
}

impl<T> Deref for DataRef<'_, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        unsafe { &*self.fut.item_ptr }
    }
}

impl<T> DerefMut for DataRef<'_, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.fut.item_ptr}
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[ignore]
    fn linked_list_collide_thread_test() {

        lazy_static::lazy_static! {
            static ref LINKED_LIST: SenderNodeLinkedList = SenderNodeLinkedList::new();
        };

        let linked_list_ref = unsafe { Pin::new_unchecked(&*LINKED_LIST) };

        for _ in 0..100 {
            let threads = (0..1000).into_iter()
                .map(|_| std::thread::spawn(move || {

                    let mut node = SenderNode::new( futures::task::noop_waker() );

                    let pinned_node = unsafe { Pin::new_unchecked(&mut node) };

                    linked_list_ref.push(pinned_node);
                }))
                .collect::<Vec<_>>();

            threads.into_iter()
                .for_each(|handle| handle.join().unwrap())
        }
    }

    #[test]
    #[ignore]
    fn linked_list_barrier_thread_test() {
        use std::sync::Barrier;

        lazy_static::lazy_static! {
            static ref LINKED_LIST: SenderNodeLinkedList = SenderNodeLinkedList::new();
        };

        let linked_list_ref = unsafe { Pin::new_unchecked(&*LINKED_LIST) };

        let barrier = Arc::new(Barrier::new(50));

        for c in 0..100 {

            println!("******************** run {} ***********************", c);

            let threads = (0..50).into_iter()
                .map(|_| {
                    let wall = barrier.clone();

                    std::thread::spawn(move || {

                        let mut node = SenderNode::new( futures::task::noop_waker() );

                        let pinned_node = unsafe { Pin::new_unchecked(&mut node) };

                        linked_list_ref.push(pinned_node);

                        wall.wait();

                        std::mem::forget(node)
                    })
                })
                .collect::<Vec<_>>();

            threads.into_iter()
                .for_each(|handle| handle.join().unwrap())
        }
    }
}