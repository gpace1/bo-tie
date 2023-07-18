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

use crate::channel::id::ChannelIdentifier;
pub(crate) use crate::channel::shared::unused::{ReceiveDataProcessor, UnusedChannelResponse};
use crate::channel::InvalidChannel;
use crate::pdu::L2capFragment;
use crate::PhysicalLink;
use core::cell::{Cell, RefCell, UnsafeCell};
use core::task::Poll;

mod unused;

/// A [`L2capFragment`] with its attached header
///
/// This is used to pass a L2CAP fragment with its associated header.
pub struct BasicHeadedFragment<T> {
    pub length: u16,
    pub channel_id: ChannelIdentifier,
    pub fragment: L2capFragment<T>,
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
    fn process<T>(
        &self,
        fragment: &mut L2capFragment<T>,
        this_channel: ChannelIdentifier,
        active_channels: &[ChannelIdentifier],
    ) -> Result<BasicHeadProcessOutput, InvalidChannel>
    where
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

                    // the top level enum is used as the way to check the
                    // logical link type. Every call to `process_start`
                    // is done by the same logical link.

                    let channel_id = match this_channel {
                        ChannelIdentifier::Le(_) => ChannelIdentifier::le_try_from_raw(raw_channel)
                            .map_err(|_| InvalidChannel::new_le(raw_channel)),
                        ChannelIdentifier::Acl(_) => ChannelIdentifier::acl_try_from_raw(raw_channel)
                            .map_err(|_| InvalidChannel::new_acl(raw_channel)),
                        ChannelIdentifier::Apb(_) => ChannelIdentifier::apb_try_from_raw(raw_channel)
                            .map_err(|_| InvalidChannel::new_apb(raw_channel)),
                    }?;

                    self.channel_id.set(ProcessorChannelIdentifier::Complete(channel_id));

                    return if channel_id == this_channel {
                        // the channel calling this method is the same as
                        // the destination channel for this PDU
                        Poll::Ready(Ok(Ok(self.get_basic_header().unwrap())))
                    } else if active_channels.binary_search(&channel_id).is_err() {
                        // channel is not used by the library user
                        Poll::Ready(Ok(Err(self.get_basic_header().unwrap())))
                    } else {
                        context.waker().clone().wake();

                        Poll::Pending
                    };
                }
                _ => unreachable!("unexpected state of SharedL2capRawDataProcessor"),
            }
        }

        Poll::Pending
    }

    /// Get the Basic Header
    ///
    /// This gets the basic header, if the basic header was established.
    pub fn get_basic_header(&self) -> Option<(u16, ChannelIdentifier)> {
        match (self.length.get(), self.channel_id.get()) {
            (ProcessorLengthState::Complete(length), ProcessorChannelIdentifier::Complete(channel_id)) => {
                Some((length, channel_id))
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
    PduIsForDifferentChannel(ChannelIdentifier),
    PduIsForThisChannel(u16, ChannelIdentifier),
    PduIsForUnusedChannel(u16, ChannelIdentifier),
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
/// ## How This Works
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
    owner: core::cell::Cell<PhysicalLinkOwner<U::ReceiveData>>,
    channels: core::cell::RefCell<alloc::vec::Vec<ChannelIdentifier>>,
    physical_link: core::cell::UnsafeCell<P>,
    basic_header_processor: BasicHeaderProcessor,
    stasis_fragment: core::cell::Cell<Option<L2capFragment<P::RecvData>>>,
}

impl<P, U> SharedPhysicalLink<P, U>
where
    P: PhysicalLink,
    U: UnusedChannelResponse,
{
    pub fn new(physical_link: P) -> Self {
        let owner = core::cell::Cell::new(PhysicalLinkOwner::None);

        let channels = core::cell::RefCell::default();

        let basic_header_processor = BasicHeaderProcessor::init();

        let stasis_fragment = core::cell::Cell::new(None);

        let physical_link = core::cell::UnsafeCell::new(physical_link);

        Self {
            owner,
            channels,
            physical_link,
            basic_header_processor,
            stasis_fragment,
        }
    }

    pub fn get_fragmentation_size(&self) -> usize {
        unsafe { &*self.physical_link.get() }.max_transmission_size()
    }

    pub fn is_channel_used(&self, id: ChannelIdentifier) -> bool {
        self.channels.borrow().binary_search(&id).is_ok()
    }

    pub fn clear_owner(&self) {
        self.basic_header_processor.clear_basic_header();

        self.owner.set(PhysicalLinkOwner::None);
    }

    /// Add a channel to this `SharedPhysicalLink`
    ///
    /// `true` is returned if the channel is successfully added, however if the channel already
    /// exists `false` is returned.
    pub fn add_channel(&self, id: ChannelIdentifier) -> bool {
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
    pub fn new_le_dyn_channel(&self) -> Option<crate::channel::id::DynChannelId<crate::LeULink>> {
        use crate::channel::id::DynChannelId;
        use crate::link_flavor::LeULink;

        let mut channel_val = *DynChannelId::<LeULink>::LE_BOUNDS.start();

        while let Ok(channel) = DynChannelId::<LeULink>::new_le(channel_val) {
            let channel = ChannelIdentifier::Le(channel);

            let mut channels_mref = self.channels.borrow_mut();

            if let Err(index) = channels_mref.binary_search(&channel) {
                channels_mref.insert(index, channel);

                return Some(DynChannelId::new_unchecked(channel_val));
            } else {
                channel_val += 1
            }
        }

        None
    }

    /// Remove a channel from sharing the physical link.
    pub fn remove_channel(&self, id: ChannelIdentifier) {
        let mut borrowed_channels = self.channels.borrow_mut();

        if let Ok(index) = borrowed_channels.binary_search(&id) {
            borrowed_channels.remove(index);
        }
    }

    pub fn maybe_send<'s, T>(&'s self, owner: ChannelIdentifier, fragment: L2capFragment<T>) -> Poll<P::SendFut<'s>>
    where
        T: 's + IntoIterator<Item = u8>,
    {
        if self.owner.get().is_none() {
            debug_assert!(fragment.is_start_fragment(), "expected starting fragment");

            self.owner.set(PhysicalLinkOwner::Sender(owner))
        } else if self.owner.get() != PhysicalLinkOwner::Sender(owner) {
            // TODO Note:
            // It may be possible for two things to try to send
            // "at the same time", however there should be no
            // reason to require "waking". This is because sending
            // can only be done within the same async task. Not
            // 100% sure this is true though....

            return Poll::Pending;
        }

        let fragment = L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        };

        unsafe { self.physical_link.get().as_mut().unwrap().send(fragment).into() }
    }

    pub fn maybe_recv(
        &self,
        owner: ChannelIdentifier,
    ) -> Poll<
        impl Future<
                Output = Result<
                    Poll<Result<BasicHeadedFragment<P::RecvData>, Option<U::Response>>>,
                    MaybeRecvError<P, U>,
                >,
            > + '_,
    > {
        if self.owner.get().is_none() {
            self.owner.set(PhysicalLinkOwner::Receiver(owner))
        } else if !self.owner.get().is_dump_recv() && self.owner.get() != PhysicalLinkOwner::Receiver(owner) {
            return Poll::Pending;
        }

        let future = async move {
            let fragment = unsafe {
                self.physical_link
                    .get()
                    .as_mut()
                    .unwrap()
                    .recv()
                    .await
                    .ok_or(MaybeRecvError::Disconnected)?
                    .map_err(|e| MaybeRecvError::RecvError(e))?
            };

            if self.owner.get().is_dump_recv() {
                let response = self.process_dumped_fragment(fragment).await?;

                Ok(Poll::Ready(Err(response)))
            } else if let Some((len, cid)) = self.basic_header_processor.get_basic_header() {
                let headed_fragment = BasicHeadedFragment {
                    length: len,
                    channel_id: cid,
                    fragment,
                };

                Ok(Poll::Ready(Ok(headed_fragment)))
            } else {
                self.maybe_recv_header_process(owner, fragment)
                    .await
                    .map(|poll| poll.map(|frag| Ok(frag)))
            }
        };

        Poll::Ready(future)
    }

    async fn maybe_recv_header_process(
        &self,
        owner: ChannelIdentifier,
        fragment: L2capFragment<P::RecvData>,
    ) -> Result<Poll<BasicHeadedFragment<P::RecvData>>, MaybeRecvError<P, U>> {
        let mut fragment = Some(fragment);

        core::future::poll_fn(move |context| {
            if fragment.is_none() {
                return Poll::Pending;
            }

            let active_channels = self.channels.borrow();

            let process_output =
                self.basic_header_processor
                    .process(fragment.as_mut().unwrap(), owner, &**active_channels, context);

            drop(active_channels);

            match process_output {
                Poll::Pending => {
                    if let Some((_, cid)) = self.basic_header_processor.get_basic_header() {
                        self.owner.set(PhysicalLinkOwner::Receiver(cid));

                        self.stasis_fragment.set(fragment.take());
                    }

                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(MaybeRecvError::InvalidChannel(e))),
                Poll::Ready(Ok(Ok((len, cid)))) => {
                    let header_fragment = BasicHeadedFragment {
                        length: len,
                        channel_id: cid,
                        fragment: fragment.take().unwrap(),
                    };

                    Poll::Ready(Ok(Poll::Ready(header_fragment)))
                }
                Poll::Ready(Ok(Err((len, cid)))) => {
                    let request_data = U::new_request_data(len.into(), cid);

                    self.owner.set(PhysicalLinkOwner::DumpReceived(request_data));

                    Poll::Pending
                }
            }
        })
        .await
    }

    async fn process_dumped_fragment<T: Iterator<Item = u8> + ExactSizeIterator>(
        &self,
        fragment: L2capFragment<T>,
    ) -> Result<Option<U::Response>, MaybeRecvError<P, U>> {
        let PhysicalLinkOwner::DumpReceived(mut d) = self.owner.get() else {
            unreachable!()
        };

        if d.process(fragment).map_err(|e| MaybeRecvError::DumpRecvError(e))? {
            self.owner.set(PhysicalLinkOwner::None);

            let response = U::generate_response(d);

            Ok(response)
        } else {
            self.owner.set(PhysicalLinkOwner::DumpReceived(d));

            Ok(None)
        }
    }
}

pub enum MaybeRecvError<P: PhysicalLink, U: UnusedChannelResponse> {
    Disconnected,
    RecvError(P::RecvErr),
    InvalidChannel(InvalidChannel),
    DumpRecvError(<U::ReceiveData as ReceiveDataProcessor>::Error),
}

#[derive(Copy, Clone, Debug, PartialEq)]
enum PhysicalLinkOwner<D> {
    /// No current owner
    None,
    /// A dumped L2CAP packet
    ///
    /// Dumped packets occur for L2CAP PDUs to unused or invalid channels.
    DumpReceived(D),
    /// Occupied by a channel sending a L2CAP PDU
    Sender(ChannelIdentifier),
    /// Occupied by a channel receiving a L2CAP PDU
    Receiver(ChannelIdentifier),
}

impl<D> PhysicalLinkOwner<D> {
    fn is_none(&self) -> bool {
        match self {
            PhysicalLinkOwner::None => true,
            _ => false,
        }
    }

    fn is_dump_recv(&self) -> bool {
        match self {
            PhysicalLinkOwner::DumpReceived(_) => true,
            _ => false,
        }
    }
}
