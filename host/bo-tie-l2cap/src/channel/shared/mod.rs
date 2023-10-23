//! Shared processing of received L2CAP fragments
//!
//! When receiving a fragment, the destination channel for the fragment cannot be determined until
//! the basic header has been processed. The basic header consists of the PDU length and channel
//! identifier values. Once the channel identifier has been received then the appropriate channel
//! can complete processing of the received fragment and subsequent fragments for the PDU.
//!
//! Until the channel identifier is processed, and channel is allowed to process a received
//! fragment. Once the channel identifier is processed, the logical link is "owned" by the
//! respective channel until all bytes of the PDU are received.

use crate::channel::id::{ChannelIdentifier, LeCid};
pub(crate) use crate::channel::shared::unused::{ReceiveDataProcessor, UnusedChannelResponse};
use crate::channel::InvalidChannel;
use crate::pdu::L2capFragment;
use crate::{LogicalLink, PhysicalLink};
use core::cell::{Cell, RefCell, UnsafeCell};
use core::task::Poll;

mod unused;

/// The basic header of every L2CAP PDU
#[derive(Copy, Clone)]
struct BasicHeader {
    pub length: u16,
    pub channel_id: ChannelIdentifier,
}

/// A [`L2capFragment`] with its attached basic header
///
/// This is used to pass a L2CAP fragment with its associated basic header. If this is the start
/// fragment, the actual fragment data will also contain all or part of the basic header in the raw
/// L2CAP PDU form.
pub struct BasicHeadedFragment<T> {
    header: BasicHeader,
    is_beginning: bool,
    data: T,
}

impl<T> BasicHeadedFragment<T> {
    pub fn get_pdu_length(&self) -> u16 {
        self.header.length
    }

    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.header.channel_id
    }

    /// Returns true if the data is the starting data of the L2CAP PDU
    ///
    /// # Note
    /// This may not necessarily mean that the starting fragment led to the creation of this
    /// `BasicHeadedFragment`. The size of initial fragments could have been smaller than the basic
    /// header.
    pub fn is_start_of_data(&self) -> bool {
        self.is_beginning
    }

    pub fn into_data(self) -> T {
        self.data
    }
}

/// The 'shared l2cap raw data processor'
///
/// This is a trick (based on polling) for `select!` like systems where basic L2CAP data processing
/// is done through *any* channel receive future.
///
/// This does not do much as it really only processes the *Basic Header* (see the *Data Packet
/// Format* of the L2CAP part of the Bluetooth Spec.). If the basic header *happens* to contain the
/// same channel identifier as the current executing future then the same future will poll to
/// completion, but most likely the executing is not the correct future and
struct BasicHeaderProcessor {
    length: Cell<ProcessorLengthState>,
    channel_id: Cell<ProcessorChannelIdentifier>,
}

impl BasicHeaderProcessor {
    fn init() -> Self {
        BasicHeaderProcessor {
            length: Cell::new(ProcessorLengthState::None),
            channel_id: Cell::new(ProcessorChannelIdentifier::None),
        }
    }

    /// Process a fragment.
    ///
    /// This process a fragment up to the point of being able to determine the channel identifier
    /// of the L2CAP payload. `this_channel` is used for determining both the logical link and
    /// whether this happens to be the exact channel for the L2CAP data.
    ///
    /// This will return a length and channel id (as a `(u16, ChannelIdentifier)`) if `this_channel`
    /// happens to be the exact same channel.
    ///
    /// # Starting Fragment
    /// A starting fragment will reset the state back to the initial state (both fields `length` and
    /// `channel_id` are set to `None`). This does not validate that the starting fragment flag was
    /// valid.
    ///
    /// # Return (meanings)
    /// * `Pending` => Either:
    ///     - Input `fragment` could not construct a complete header.
    ///     - The basic header was created but the channel calling this method is not the same as
    ///       the channel identified within the header.
    /// * `Ready(Ok(Ok(_))` => The header was created so this fragment and any following fragments
    ///     for this L2CAP PDU are for the channel calling this method.
    /// * `Ready(Ok(Err(_))` => The header was neither for `this_channel` nor any channel within
    ///    `active_channels`.
    /// * `Ready(Err(InvalidChannel))` => The peer send a channel that was invalid for this L2CAP
    ///    logical link (the physical link should be closed by the user in this case).
    fn process<L, T>(
        &self,
        fragment: &mut L2capFragment<T>,
        this_channel: Option<ChannelIdentifier>,
        active_channels: &[ChannelIdentifier],
    ) -> Result<BasicHeadProcessOutput, InvalidChannel>
    where
        L: LogicalLink,
        T: Iterator<Item = u8>,
    {
        if fragment.is_start_fragment() {
            self.length.set(ProcessorLengthState::None);
            self.channel_id.set(ProcessorChannelIdentifier::None);
        }

        for byte in &mut fragment.data {
            match (self.length.get(), self.channel_id.get()) {
                (ProcessorLengthState::None, ProcessorChannelIdentifier::None) => {
                    self.length.set(ProcessorLengthState::FirstByte(byte))
                }
                (ProcessorLengthState::FirstByte(v), ProcessorChannelIdentifier::None) => self
                    .length
                    .set(ProcessorLengthState::Complete(<u16>::from_le_bytes([v, byte]))),
                (ProcessorLengthState::Complete(_), ProcessorChannelIdentifier::None) => {
                    self.channel_id.set(ProcessorChannelIdentifier::FirstByte(byte))
                }
                (ProcessorLengthState::Complete(_), ProcessorChannelIdentifier::FirstByte(v)) => {
                    let raw_channel = <u16>::from_le_bytes([v, byte]);

                    let channel_id = <L::Flavor as crate::link_flavor::LinkFlavor>::try_channel_from_raw(raw_channel)
                        .ok_or_else(|| InvalidChannel::new::<L::Flavor>(raw_channel))?;

                    self.channel_id.set(ProcessorChannelIdentifier::Complete(channel_id));

                    let basic_header = self.get_basic_header().unwrap();

                    return if Some(channel_id) == this_channel {
                        // the channel calling this method is the same as
                        // the destination channel for this PDU
                        Ok(BasicHeadProcessOutput::PduIsForThisChannel(basic_header))
                    } else if active_channels.binary_search(&channel_id).is_err() {
                        // channel for the PDU is not currently being used
                        Ok(BasicHeadProcessOutput::PduIsForUnusedChannel(basic_header))
                    } else {
                        Ok(BasicHeadProcessOutput::PduIsForDifferentChannel(basic_header))
                    };
                }
                _ => unreachable!("unexpected state of SharedL2capRawDataProcessor"),
            }
        }

        Ok(BasicHeadProcessOutput::Undetermined)
    }

    /// Get the Basic Header
    ///
    /// This gets the basic header, if the basic header was established.
    pub fn get_basic_header(&self) -> Option<BasicHeader> {
        match (self.length.get(), self.channel_id.get()) {
            (ProcessorLengthState::Complete(length), ProcessorChannelIdentifier::Complete(channel_id)) => {
                Some(BasicHeader { length, channel_id })
            }
            _ => None,
        }
    }

    pub fn clear_basic_header(&self) {
        self.length.set(ProcessorLengthState::None);
        self.channel_id.set(ProcessorChannelIdentifier::None);
    }
}

enum BasicHeadProcessOutput {
    Undetermined,
    PduIsForDifferentChannel(BasicHeader),
    PduIsForThisChannel(BasicHeader),
    PduIsForUnusedChannel(BasicHeader),
}

/// Enumeration of a [`BasicHeaderProcessor`] length
#[derive(Copy, Clone)]
enum ProcessorLengthState {
    None,
    FirstByte(u8),
    Complete(u16),
}

/// Enumeration of a [`BasicHeaderProcessor`]  channel identifier
#[derive(Copy, Clone)]
enum ProcessorChannelIdentifier {
    None,
    FirstByte(u8),
    Complete(ChannelIdentifier),
}

/// Shared Physical Linking
///
/// The physical link is shared by all connection channels associated with it. When data is sent or
/// received, only one connection channel can use the physical link until the entire L2CAP PDU is
/// sent or acquired. This is used to ensure that sending and receiving with multiple channels
/// is safe.
///
/// # Safety
/// This type is inherently unsafe to use outside of this library. It unsafely implements `Sync`,
/// even though the type is not `Sync` safe. Every channel (an other types) that use a reference to
/// `SharedPhysicalLink` must be `!Sync` to ensure that this is not unsafely used in a `Sync`
/// situation.
///
/// # How This Works
/// If you look at the implementation of [`PhysicalLink`] both methods `send` and `recv` require
/// mutable access to the implementation, but there are multiple channels that wish to have
/// references to the physical link. To ensure safety, only one channel may *exclusively* call
/// `send` or `recv` and poll the corresponding returned future. No channel may call `send` or
/// `recv` until the previously generated future is dropped.
///
/// ### Receiving
/// The "exception" however is in the initial basic header processing when receiving. When a L2CAP
/// PDU is received, it is unknown who the receiver is (if any) until the channel identifier is
/// acquired. During this stage, any channel processor will be used to receive L2CAP fragments until
/// the connection channel is determined.
///
/// Once the channel identifier is determined, and that channel exists then only that channel may
/// call `recv` until the entire PDU is acquired. However if the channel does not exist then `recv`
/// may be called by any channel processor until the end of the L2CAP PDU is reached.
///
/// In any part of this process, once `recv` is called, `recv` cannot be called again until the
/// future returned is dropped.
///
/// ### Resetting
/// After a full PDU is sent or received, the channel must call `clear_owner` to reset the
/// `SharedPhysicalLink`. This allows for the next PDU to be sent or received. `clear_owner` can be
/// thought of as releasing the lock of a mutex.  
///
/// [`PhysicalLink`]: PhysicalLink
pub struct SharedPhysicalLink<P: PhysicalLink, U: UnusedChannelResponse> {
    owner: Cell<PhysicalLinkOwner>,
    channels: RefCell<alloc::vec::Vec<ChannelIdentifier>>,
    next_new_dyn_channel: Cell<ChannelIdentifier>,
    physical_link: UnsafeCell<P>,
    basic_header_processor: BasicHeaderProcessor,
    stasis_fragment: Cell<Option<BasicHeadedFragment<P::RecvData>>>,
    drop_data: Cell<Option<U::ReceiveProcessor>>,
    wakeup: Cell<Option<core::task::Waker>>,
}

unsafe impl<P: PhysicalLink + Sync, U: UnusedChannelResponse + Sync> Sync for SharedPhysicalLink<P, U> {}

impl<P, U> SharedPhysicalLink<P, U>
where
    P: PhysicalLink,
    U: UnusedChannelResponse,
    U::ReceiveProcessor: Copy,
{
    pub(crate) fn new(physical_link: P) -> Self {
        let owner = Cell::new(PhysicalLinkOwner::None);

        let channels = RefCell::default();

        let next_new_dyn_channel = Cell::new(crate::channel::id::DynChannelId::new_le(0x40).unwrap().into());

        let basic_header_processor = BasicHeaderProcessor::init();

        let stasis_fragment = Cell::new(None);

        let physical_link = UnsafeCell::new(physical_link);

        let drop_data = Cell::default();

        let wakeup = Cell::default();

        Self {
            owner,
            channels,
            next_new_dyn_channel,
            physical_link,
            basic_header_processor,
            stasis_fragment,
            drop_data,
            wakeup,
        }
    }

    pub(crate) fn get_fragmentation_size(&self) -> usize {
        unsafe { &*self.physical_link.get() }.max_transmission_size()
    }

    pub(crate) fn is_channel_used(&self, id: ChannelIdentifier) -> bool {
        self.channels.borrow().binary_search(&id).is_ok()
    }

    pub(crate) fn clear_owner(&self) {
        self.basic_header_processor.clear_basic_header();

        self.owner.set(PhysicalLinkOwner::None);

        self.wakeup.take().map(|waker| waker.wake());
    }

    /// Add a channel to this `SharedPhysicalLink`
    ///
    /// `true` is returned if the channel is successfully added, but `false` is returned if the
    /// channel already exists with the input `id`.
    pub(crate) fn add_channel(&self, id: ChannelIdentifier) -> bool {
        let mut borrowed_channels = self.channels.borrow_mut();

        if let Err(index) = borrowed_channels.binary_search(&id) {
            borrowed_channels.insert(index, id);

            true
        } else {
            false
        }
    }

    /// Dynamically allocate a new channel
    ///
    /// This will create a new dynamically created channel and return the channel identifier.
    ///
    /// `None` is returned if all dynamic allocated channels are already used
    pub(crate) fn new_le_dyn_channel(&self) -> Option<crate::channel::id::DynChannelId<crate::LeULink>> {
        use crate::channel::id::DynChannelId;
        use crate::link_flavor::LeULink;

        let orig_next = self.next_new_dyn_channel.get();

        loop {
            let mut channels_mref = self.channels.borrow_mut();

            let channel = self.next_new_dyn_channel.get();

            self.next_new_dyn_channel.set({
                let next_val = channel.to_val() + 1;

                if next_val <= *DynChannelId::<LeULink>::LE_BOUNDS.end() {
                    ChannelIdentifier::Le(LeCid::DynamicallyAllocated(DynChannelId::new_unchecked(next_val)))
                } else {
                    ChannelIdentifier::Le(LeCid::DynamicallyAllocated(DynChannelId::new_unchecked(
                        *DynChannelId::<LeULink>::LE_BOUNDS.start(),
                    )))
                }
            });

            if let Err(index) = channels_mref.binary_search(&channel) {
                channels_mref.insert(index, channel);

                break Some(DynChannelId::new_unchecked(channel.to_val()));
            } else {
                if self.next_new_dyn_channel.get().to_val() == orig_next.to_val() {
                    break None;
                }
            }
        }
    }

    /// Remove a channel from sharing the physical link.
    pub(crate) fn remove_channel(&self, channel_id: ChannelIdentifier) {
        match self.owner.get() {
            PhysicalLinkOwner::Sender(id) if id == channel_id => {
                self.owner.set(PhysicalLinkOwner::None);

                self.wakeup.take().map(|waker| waker.wake());

                self.basic_header_processor.clear_basic_header();
            }
            PhysicalLinkOwner::Receiver(id, count) if id == channel_id => {
                self.owner.set(PhysicalLinkOwner::AnyReceiver);

                self.wakeup.take().map(|waker| waker.wake());

                if self.drop_data.get().is_some() {
                    return;
                }

                if let Some(basic_header) = self.basic_header_processor.get_basic_header() {
                    // the basic header was processed, the dropped
                    // channel would have any previously received
                    // PDU fragments.

                    let receive_data = U::new_junked_data(basic_header.length.into(), count, basic_header.channel_id);

                    self.drop_data.set(Some(receive_data));
                }
            }
            _ => (),
        }

        let mut borrowed_channels = self.channels.borrow_mut();

        if let Ok(index) = borrowed_channels.binary_search(&channel_id) {
            borrowed_channels.remove(index);
        }
    }

    /// Maybe send a fragment
    ///
    /// This is used for maybe sending a fragment through the link. For the 'first' channel that
    /// calls this method, it takes ownership and
    pub(crate) fn maybe_send<'s, T>(
        &'s self,
        context: &mut core::task::Context,
        owner: ChannelIdentifier,
        fragment: L2capFragment<T>,
    ) -> Poll<P::SendFut<'s>>
    where
        T: 's + IntoIterator<Item = u8>,
    {
        if self.owner.get().is_none() {
            debug_assert!(fragment.is_start_fragment(), "expected starting fragment");

            self.owner.set(PhysicalLinkOwner::Sender(owner))
        } else if self.owner.get() != PhysicalLinkOwner::Sender(owner) {
            self.wakeup.set(context.waker().clone().into());

            return Poll::Pending;
        }

        let fragment = L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        };

        unsafe { self.physical_link.get().as_mut().unwrap().send(fragment).into() }
    }

    /// Receive a Fragment
    ///
    /// This method is unsafe as it does not check if the caller is the correct `owner`. Before this
    /// method is called, `self.owner` must be checked to ensure the caller is the correct owner.
    async unsafe fn recv_fragment(&self) -> Result<L2capFragment<P::RecvData>, MaybeRecvError<P, U>> {
        let mut_ref = self.physical_link.get().as_mut().unwrap();

        mut_ref
            .recv()
            .await
            .ok_or(MaybeRecvError::Disconnected)?
            .map_err(|e| MaybeRecvError::RecvError(e))
    }

    /// Maybe receive the header
    ///
    /// # Output
    /// The return is two results
    /// * The outer result is the general 'is everything ok?'. If this returns an error the user
    ///   (of the lib) should probably disconnect or end the link.
    /// * The inner result is used to determine if there was a fragment for this channel or a PDU
    ///   drop or reject that was *handled* by this channel. An `Ok(_)` of the inner is always a
    ///   fragment for the channel that called this method, an `Err(_)` will be for a complete PDU
    ///   that did not match any channel currently used. For `Err(None)` the channel doesn't need
    ///   to send a response, for a `Err(Some(_))` the channel should send the generated response.
    ///
    /// ## PDU Drop/Reject (recap)
    /// Dropping or Rejecting occurs whenever a PDU is received with a channel identifier of a
    /// channel that is not currently used by the link layer instance.
    fn maybe_recv_header_process<L: LogicalLink>(
        &self,
        owner: ChannelIdentifier,
        fragment: &mut L2capFragment<P::RecvData>,
    ) -> Result<MaybeReceiveHeaderOutput, MaybeRecvError<P, U>> {
        self.basic_header_processor.clear_basic_header();

        let active_channels = self.channels.borrow();

        let process_output = self
            .basic_header_processor
            .process::<L, _>(fragment, Some(owner), &**active_channels)?;

        drop(active_channels);

        match process_output {
            BasicHeadProcessOutput::Undetermined => Ok(MaybeReceiveHeaderOutput::Undetermined),
            BasicHeadProcessOutput::PduIsForDifferentChannel(basic_header) => {
                Ok(MaybeReceiveHeaderOutput::PduIsForDifferentChannel(basic_header))
            }
            BasicHeadProcessOutput::PduIsForThisChannel(basic_header) => {
                Ok(MaybeReceiveHeaderOutput::FragmentIsForOwner(basic_header))
            }
            BasicHeadProcessOutput::PduIsForUnusedChannel(basic_header) => {
                Ok(MaybeReceiveHeaderOutput::UnusedChannelPdu(basic_header))
            }
        }
    }

    /// Maybe receive BasicHeadedFragment`
    ///
    /// This is used by *all* channels for *maybe* receiving a [`BasicHeadedFragment`].
    ///
    /// This is a first-come-maybe-served operation. Before any data is processed, the 'first'
    /// channel to call `maybe_recv` after being awoken is given the job to process the received
    /// bytes. This may continue multiple times if the fragment size is smaller than the basic
    /// header (the initial receiver will be the only one able to continue receiving) .
    ///
    /// Every channel's data type starts with a basic header. For channels that use a more complex
    /// PDU they will need to further clarify the fields of the PDU within their own implementation.
    ///
    /// # Input Owner
    /// For channels, `owner` must always be `Some(id)` where id is the channel identifier. The only
    /// exception where `owner` is be `None` is for a collection.
    pub(crate) async fn maybe_recv<L: LogicalLink>(
        &self,
        owner: ChannelIdentifier,
    ) -> Result<Result<BasicHeadedFragment<P::RecvData>, U::Response>, MaybeRecvError<P, U>> {
        loop {
            let count = core::future::poll_fn(|context| match self.owner.get() {
                PhysicalLinkOwner::Receiver(current, count) if current == owner => {
                    return Poll::Ready(count);
                }
                PhysicalLinkOwner::None => {
                    self.owner.set(PhysicalLinkOwner::Receiver(owner, 0));

                    Poll::Ready(0)
                }
                PhysicalLinkOwner::AnyReceiver => {
                    self.owner.set(PhysicalLinkOwner::Receiver(owner, 0));

                    Poll::Ready(0)
                }
                _ => {
                    self.wakeup.set(context.waker().clone().into());

                    Poll::Pending
                }
            })
            .await;

            let maybe_stasis_fragment = self.stasis_fragment.take();

            if let Some(statis) = maybe_stasis_fragment {
                if let Some(v) = self.process_stasis_fragment(statis)? {
                    return Ok(v);
                }
            } else {
                let mut fragment = unsafe { self.recv_fragment().await? };

                match (
                    fragment.is_start_fragment(),
                    self.basic_header_processor.get_basic_header(),
                    self.drop_data.get(),
                ) {
                    (false, Some(basic_header), Some(drop_data)) => {
                        let basic_headed_fragment = BasicHeadedFragment {
                            header: basic_header,
                            is_beginning: false,
                            data: fragment.into_inner(),
                        };

                        if let Some(rsp) = self.process_dumped_fragment(drop_data, basic_headed_fragment)? {
                            self.owner.set(PhysicalLinkOwner::None);

                            self.wakeup.take().map(|waker| waker.wake());

                            break Ok(Err(rsp));
                        }
                    }
                    (true, _, _) | (false, None, _) => {
                        match self.maybe_recv_header_process::<L>(owner, &mut fragment)? {
                            MaybeReceiveHeaderOutput::FragmentIsForOwner(basic_header) => {
                                let new_count = count + fragment.get_data().len();

                                self.owner.set(PhysicalLinkOwner::Receiver(owner, new_count));

                                let basic_headed_fragment = BasicHeadedFragment {
                                    header: basic_header,
                                    is_beginning: true,
                                    data: fragment.into_inner(),
                                };

                                break Ok(Ok(basic_headed_fragment));
                            }
                            MaybeReceiveHeaderOutput::PduIsForDifferentChannel(basic_header) => {
                                self.owner.set(PhysicalLinkOwner::Receiver(basic_header.channel_id, 0));

                                self.wakeup.take().map(|waker| waker.wake());

                                let basic_headed_fragment = BasicHeadedFragment {
                                    header: basic_header,
                                    is_beginning: true,
                                    data: fragment.into_inner(),
                                };

                                self.stasis_fragment.set(Some(basic_headed_fragment));
                            }
                            MaybeReceiveHeaderOutput::UnusedChannelPdu(header) => {
                                let drop_data = U::new_response_data(header.length.into(), header.channel_id);

                                let basic_headed_fragment = BasicHeadedFragment {
                                    header,
                                    is_beginning: true,
                                    data: fragment.into_inner(),
                                };

                                // note: process_dumped_fragment will set
                                // `self.drop_data` to `drop_data` before
                                // it will return `None`.
                                if let Some(response) =
                                    self.process_dumped_fragment(drop_data, basic_headed_fragment)?
                                {
                                    break Ok(Err(response));
                                }
                            }
                            MaybeReceiveHeaderOutput::Undetermined => (),
                        }
                    }
                    (false, Some(basic_header), _) => {
                        // this if should only succeed when the owner
                        // is the same as in the PDU's header. The owner
                        // should have locked the processing by this point.
                        debug_assert_eq!(owner, basic_header.channel_id);

                        let basic_headed_fragment = BasicHeadedFragment {
                            header: basic_header,
                            is_beginning: false,
                            data: fragment.into_inner(),
                        };

                        break Ok(Ok(basic_headed_fragment));
                    }
                }
            }
        }
    }

    fn process_stasis_fragment(
        &self,
        basic_headed_fragment: BasicHeadedFragment<P::RecvData>,
    ) -> Result<Option<Result<BasicHeadedFragment<P::RecvData>, U::Response>>, MaybeRecvError<P, U>> {
        if let Some(drop_data) = self.drop_data.take() {
            if let Some(response) = self.process_dumped_fragment(drop_data, basic_headed_fragment)? {
                Ok(Some(Err(response)))
            } else {
                Ok(None)
            }
        } else {
            Ok(Some(Ok(basic_headed_fragment)))
        }
    }

    /// Process a dumped fragment
    ///
    /// This will only return a `U::Response` whenever there is a response to send. Otherwise it
    /// will return `None`, regardless of if all fragments of the PDU have been processed.
    fn process_dumped_fragment(
        &self,
        mut drop_data: U::ReceiveProcessor,
        fragment: BasicHeadedFragment<P::RecvData>,
    ) -> Result<Option<U::Response>, MaybeRecvError<P, U>> {
        if drop_data
            .process(fragment)
            .map_err(|e| MaybeRecvError::DumpRecvError(e))?
        {
            self.clear_owner();

            self.drop_data.take();

            Ok(U::try_generate_response(drop_data))
        } else {
            self.drop_data.set(Some(drop_data));

            Ok(None)
        }
    }
}

enum MaybeReceiveHeaderOutput {
    Undetermined,
    PduIsForDifferentChannel(BasicHeader),
    FragmentIsForOwner(BasicHeader),
    UnusedChannelPdu(BasicHeader),
}

/// Errors for the methods [`maybe_recv`] and [`maybe_recv_collection`]
///
/// [`maybe_recv`]: SharedPhysicalLink::maybe_recv
/// [`maybe_recv_collection`]: SharedPhysicalLink::pre_receive_collection
pub enum MaybeRecvError<P: PhysicalLink, U: UnusedChannelResponse> {
    Disconnected,
    RecvError(P::RecvErr),
    InvalidChannel(InvalidChannel),
    DumpRecvError(<U::ReceiveProcessor as ReceiveDataProcessor>::Error),
}

impl<P: PhysicalLink, U: UnusedChannelResponse> From<InvalidChannel> for MaybeRecvError<P, U> {
    fn from(ic: InvalidChannel) -> Self {
        MaybeRecvError::InvalidChannel(ic)
    }
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum PhysicalLinkOwner {
    /// No current owner
    ///
    /// When there is no physical link owner, any sending or receiving channel can become the owner.
    None,
    /// Occupied by a channel sending a L2CAP PDU
    Sender(ChannelIdentifier),
    /// Occupied by a channel receiving a L2CAP PDU
    ///
    /// The second field is the number of bytes received so far (excluding the basic header).
    ///
    /// If the receiving channel is dropped while the current owner, this state changes to
    /// `AnyReceiver` and the currently being received L2CAP PDU is treated as a [*junked*] frame.
    ///
    /// [*junked*]: UnusedChannelResponse::new_junked_data
    Receiver(ChannelIdentifier, usize),
    /// Receiving a L2CAP PDU that any channel can process
    ///
    /// This means any receiver can 'own' the physical link, but all senders must await until the
    /// `PhysicalLinkOwner` is `None`. This occurs whenever the basic header hasn't been received
    /// yet, or a channel does not exist for the received PDU.
    AnyReceiver,
}

impl PhysicalLinkOwner {
    fn is_none(&self) -> bool {
        match self {
            PhysicalLinkOwner::None => true,
            _ => false,
        }
    }
}
