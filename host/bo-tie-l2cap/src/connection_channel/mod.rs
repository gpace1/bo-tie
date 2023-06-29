//! Implementation of various [`ConnectionChannel`] implementations
//!
//! [`ConnectionChannel`]: ConnectionChannel

mod credit_based;
pub mod signalling;

use crate::channels::ChannelIdentifier;
use crate::pdu::credit_frame::CreditBasedFrame;
use crate::pdu::{
    BasicFrame, CreditBasedSdu, FragmentIterator, FragmentL2capPdu, FragmentL2capSdu, PacketsError,
    RecombinePayloadIncrementally,
};
use crate::pdu::{RecombineL2capPdu, SduPacketsIterator};
use crate::{pdu, pdu::L2capFragment, PhysicalLink};
use bo_tie_core::buffer::TryExtend;
use core::future::Future;
use core::task::Poll;
pub use credit_based::UnsentCreditFrames;
pub use signalling::SignallingChannel;

/// A L2CAP connection channel
///
/// Channels that implement this form a L2CAP connection between the two linked devices.
pub trait ConnectionChannel {
    /// Get the channel identifier used on this device
    ///
    /// This returns the channel identifier used by this device for the connection. The peer device
    /// will send PDUs with the returned channel identifier for this connection.
    fn get_this_channel_id(&self) -> ChannelIdentifier;

    /// Get the channel identifier used by the peer device
    ///
    /// This returns the channel identifier used by the peer device for this connection. This device
    /// will send PDUs with the returned channel identifier to the other device.
    fn get_peer_channel_id(&self) -> ChannelIdentifier;

    /// Get the maximum transmission size (MTU)
    ///
    /// This is the maximum transmission size of the service data unit (SDU) for this connection.
    /// `None` is returned if the connection does not have or define a MTU at the L2CAP layer.
    fn get_mtu(&self) -> Option<usize>;

    /// Get the maximum PDU payload size (MPS)
    ///
    /// This is the maximum size of a PDU's payload for this connection. `None` is returned if the
    /// connection does not have or define a MPS at the L2CAP layer.
    fn get_mps(&self) -> Option<usize>;
}

/// A [`L2capFragment`] with its attached header
///
/// This is used to pass a L2CAP fragment with its associated header.
struct HeadedFragment<T> {
    length: u16,
    channel_id: ChannelIdentifier,
    fragment: L2capFragment<T>,
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
    length: core::cell::Cell<ProcessorLengthState>,
    channel_id: core::cell::Cell<ProcessorChannelIdentifier>,
}

impl BasicHeaderProcessor {
    fn init() -> Self {
        BasicHeaderProcessor {
            length: core::cell::Cell::new(ProcessorLengthState::None),
            channel_id: core::cell::Cell::new(ProcessorChannelIdentifier::None),
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
    fn process<T>(
        &self,
        fragment: &mut L2capFragment<T>,
        this_channel: ChannelIdentifier,
        context: &mut core::task::Context,
    ) -> Poll<Result<(u16, ChannelIdentifier), InvalidChannel>>
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

                    // If what called process_start has the exact same
                    // channel ID then return the length and channel id.
                    return if channel_id == this_channel {
                        Poll::Ready(Ok(self.get_basic_header().unwrap()))
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
}

/// Invalid Channel
///
/// This is used to indicate that a channel was invalid for a specific link type.
#[derive(Debug)]
pub struct InvalidChannel(u16, &'static str);

impl InvalidChannel {
    fn new_le(raw_channel: u16) -> Self {
        InvalidChannel(raw_channel, "LE-U")
    }

    fn new_acl(raw_channel: u16) -> Self {
        InvalidChannel(raw_channel, "ACL-U")
    }

    fn new_apb(raw_channel: u16) -> Self {
        InvalidChannel(raw_channel, "APB-U")
    }
}

impl core::fmt::Display for InvalidChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "invalid channel identifier {} for logical link {}", self.0, self.1)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidChannel {}

#[derive(Copy, Clone, Eq, PartialEq)]
enum PhysicalLinkOwner {
    None,
    Sender(ChannelIdentifier),
    Receiver(ChannelIdentifier),
}

impl PhysicalLinkOwner {
    fn is_none(&self) -> bool {
        match self {
            PhysicalLinkOwner::None => true,
            _ => false,
        }
    }
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
pub(crate) struct SharedPhysicalLink<P: PhysicalLink> {
    owner: core::cell::Cell<PhysicalLinkOwner>,
    channels: core::cell::RefCell<alloc::vec::Vec<ChannelIdentifier>>,
    physical_link: core::cell::UnsafeCell<P>,
    basic_header_processor: BasicHeaderProcessor,
    stasis_fragment: core::cell::Cell<Option<L2capFragment<P::RecvData>>>,
}

impl<P> SharedPhysicalLink<P>
where
    P: PhysicalLink,
{
    pub(crate) fn new(physical_link: P) -> Self {
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

    pub(crate) fn is_channel_used(&self, id: ChannelIdentifier) -> bool {
        self.channels.borrow().binary_search(&id).is_ok()
    }

    fn clear_owner(&self) {
        self.owner.set(PhysicalLinkOwner::None);
    }

    /// Add a channel to this `SharedPhysicalLink`
    ///
    /// `true` is returned if the channel is successfully added, however if the channel already
    /// exists `false` is returned.
    fn add_channel(&self, id: ChannelIdentifier) -> bool {
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
    fn new_le_dyn_channel(&self) -> Option<crate::channels::DynChannelId<crate::LeULink>> {
        use crate::channels::DynChannelId;
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
    fn remove_channel(&self, id: ChannelIdentifier) {
        let mut borrowed_channels = self.channels.borrow_mut();

        if let Ok(index) = borrowed_channels.binary_search(&id) {
            borrowed_channels.remove(index);
        }
    }

    /// Get a channel

    fn maybe_send<T>(&self, owner: ChannelIdentifier, fragment: L2capFragment<T>) -> Poll<P::SendFut<'_>>
    where
        T: IntoIterator<Item = u8>,
    {
        if self.owner.get().is_none() {
            debug_assert!(fragment.is_start_fragment(), "expected starting fragment");

            self.owner.set(PhysicalLinkOwner::Sender(owner))
        } else if self.owner.get() != PhysicalLinkOwner::Sender(owner) {
            return Poll::Pending;
        }

        let fragment = L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        };

        unsafe { self.physical_link.get().as_mut().unwrap().send(fragment).into() }
    }

    fn maybe_recv(
        &self,
        owner: ChannelIdentifier,
    ) -> Poll<impl Future<Output = Result<Poll<HeadedFragment<P::RecvData>>, MaybeRecvError<P::RecvErr>>> + '_> {
        if self.owner.get().is_none() {
            self.owner.set(PhysicalLinkOwner::Receiver(owner))
        } else if self.owner.get() != PhysicalLinkOwner::Receiver(owner) {
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
                    .map_err(|e| MaybeRecvError::RecvError(e))?
            };

            if let Some((len, cid)) = self.basic_header_processor.get_basic_header() {
                let headed_fragment = HeadedFragment {
                    length: len,
                    channel_id: cid,
                    fragment,
                };

                Ok(Poll::Ready(headed_fragment))
            } else {
                self.maybe_recv_header_process(owner, fragment).await
            }
        };

        Poll::Ready(future)
    }

    async fn maybe_recv_header_process(
        &self,
        owner: ChannelIdentifier,
        fragment: L2capFragment<P::RecvData>,
    ) -> Result<Poll<HeadedFragment<P::RecvData>>, MaybeRecvError<P::RecvErr>> {
        let mut fragment = Some(fragment);

        core::future::poll_fn(move |context| {
            match self
                .basic_header_processor
                .process(fragment.as_mut().unwrap(), owner, context)
            {
                Poll::Pending => {
                    if self.basic_header_processor.get_basic_header().is_none() {
                        self.clear_owner();

                        self.stasis_fragment.set(fragment.take());
                    }

                    Poll::Pending
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(MaybeRecvError::InvalidChannel(e))),
                Poll::Ready(Ok((len, cid))) => {
                    let header_fragment = HeadedFragment {
                        length: len,
                        channel_id: cid,
                        fragment: fragment.take().unwrap(),
                    };

                    Poll::Ready(Ok(Poll::Ready(header_fragment)))
                }
            }
        })
        .await
    }
}

enum MaybeRecvError<E> {
    RecvError(E),
    InvalidChannel(InvalidChannel),
}

/// A channel that only communicates with Basic Frames
///
/// Many L2CAP channels defined by the Bluetooth Specification only use Basic Frames for
/// communication to a connected device.
pub struct BasicFrameChannel<'a, P>
where
    P: PhysicalLink,
{
    channel_id: ChannelIdentifier,
    link_lock: &'a SharedPhysicalLink<P>,
}

impl<'a, P: PhysicalLink> BasicFrameChannel<'a, P> {
    pub(crate) fn new(channel_id: ChannelIdentifier, link_lock: &'a SharedPhysicalLink<P>) -> Self {
        assert!(link_lock.add_channel(channel_id), "channel already exists");

        BasicFrameChannel { channel_id, link_lock }
    }
}

impl<P: PhysicalLink> BasicFrameChannel<'_, P> {
    /// Get fragmentation size of L2CAP PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    pub fn fragmentation_size(&self) -> usize {
        unsafe { &*self.link_lock.physical_link.get() }.max_transmission_size()
    }

    async fn send_fragment<T>(&mut self, fragment: L2capFragment<T>) -> Result<(), P::SendErr>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut fragment = Some(L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        });

        core::future::poll_fn(move |_| self.link_lock.maybe_send(self.channel_id, fragment.take().unwrap()))
            .await
            .await
    }

    async fn receive_fragment(&mut self) -> Result<HeadedFragment<P::RecvData>, MaybeRecvError<P::RecvErr>> {
        let mut poll = Some(
            match core::future::poll_fn(|_| self.link_lock.maybe_recv(self.channel_id))
                .await
                .await
            {
                Ok(f) => f,
                Err(e) => {
                    self.link_lock.clear_owner();

                    return Err(e);
                }
            },
        );

        Ok(core::future::poll_fn(move |_| poll.take().unwrap()).await)
    }

    /// Send a Basic Frame to the lower layers
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    pub async fn send<T>(&mut self, b_frame: pdu::BasicFrame<T>) -> Result<(), P::SendErr>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let mut is_first = true;

        let mut fragments_iter = b_frame.into_fragments(self.fragmentation_size()).unwrap();

        while let Some(data) = fragments_iter.next() {
            let fragment = L2capFragment::new(is_first, data);

            is_first = false;

            self.send_fragment(fragment).await?;
        }

        // clear owner as the full PDU was sent
        self.link_lock.clear_owner();

        Ok(())
    }

    /// Receive a Basic Frame for this Channel
    pub async fn receive<T>(
        &mut self,
    ) -> Result<BasicFrame<T>, ReceiveError<P::RecvErr, T::Error, pdu::basic_frame::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        let fragment = self.receive_fragment().await?;

        if !fragment.fragment.is_start_fragment() {
            self.link_lock.clear_owner();

            return Err(ReceiveError::new_expect_first_err());
        }

        let mut recombiner = BasicFrame::recombine(fragment.length, fragment.channel_id, &mut ());

        if let Some(b_frame) = recombiner.add(fragment.fragment.data).map_err(|e| {
            self.link_lock.clear_owner();
            ReceiveError::new_recombine(e)
        })? {
            Ok(b_frame)
        } else {
            loop {
                let fragment = self.receive_fragment().await?;

                if fragment.fragment.is_start_fragment() {
                    self.link_lock.clear_owner();

                    return Err(ReceiveError::new_unexpect_first_err());
                }

                if let Some(b_frame) = recombiner
                    .add(fragment.fragment.data)
                    .map_err(|e| ReceiveError::new_recombine(e))?
                {
                    self.link_lock.clear_owner();

                    return Ok(b_frame);
                }
            }
        }
    }
}

impl<P: PhysicalLink> Drop for BasicFrameChannel<'_, P> {
    fn drop(&mut self) {
        self.link_lock.remove_channel(self.channel_id)
    }
}

/// Credit Based Channel
///
/// A channel that only communicates with credit based L2CAP PDUs. This channel is used for LE
/// Credit Based Connections and Enhanced Credit Based Connections.
///
/// A `CreditBasedChannel` is created via signalling packets
pub struct CreditBasedChannel<'a, P>
where
    P: PhysicalLink,
{
    this_channel_id: ChannelIdentifier,
    peer_channel_id: ChannelIdentifier,
    link_lock: &'a SharedPhysicalLink<P>,
    maximum_pdu_payload_size: usize,
    maximum_transmission_size: usize,
    peer_credits: usize,
}

impl<'a, P: PhysicalLink> CreditBasedChannel<'a, P> {
    pub(crate) fn new(
        this_channel_id: ChannelIdentifier,
        peer_channel_id: ChannelIdentifier,
        link_lock: &'a SharedPhysicalLink<P>,
        maximum_packet_size: usize,
        maximum_transmission_size: usize,
        initial_peer_credits: usize,
    ) -> Self {
        assert!(link_lock.add_channel(this_channel_id), "channel already exists");

        CreditBasedChannel {
            this_channel_id,
            peer_channel_id,
            link_lock,
            maximum_pdu_payload_size: maximum_packet_size,
            maximum_transmission_size,
            peer_credits: initial_peer_credits,
        }
    }

    /// Get this channel identifier
    ///
    /// This is the identifier used by this link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by this device then this was the
    /// *source* id within the connection request. If this connection was accepted by this device
    /// then this was the *destination* id within the connection response.
    pub fn get_this_channel_id(&self) -> ChannelIdentifier {
        self.this_channel_id
    }

    /// Get the peer's channel identifier
    ///
    /// This is the identifier used by the peer's link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by the peer device then this was the
    /// *source* id within the connection request. If this connection was accepted by the peer
    /// device then this was the *destination* id within the connection response.
    pub fn get_peer_channel_id(&self) -> ChannelIdentifier {
        self.peer_channel_id
    }

    /// Get the maximum payload size (MPS)
    ///
    /// This is the maximum payload size of a credit based frame. When a SDU is transmitted it is
    /// fragmented to this size (with the exception of the first fragment being two less) and each
    /// fragment is transmitted in a separate k-frame.
    pub fn get_mps(&self) -> u16 {
        self.maximum_pdu_payload_size as u16
    }

    /// Get the maximum transmission size (MTS)
    ///
    /// This is the maximum size of a SDU.
    pub fn get_mts(&self) -> u16 {
        self.maximum_transmission_size as u16
    }

    /// Get the current number of peer credits
    pub fn get_peer_credits(&self) -> u16 {
        self.peer_credits as u16
    }

    /// Add peer credits
    ///
    /// This adds credits given by the peer device. These credits should come from a *L2CAP flow
    /// control credit ind* signal.
    pub fn add_credits(&mut self, amount: u16) {
        self.peer_credits = if let Some(amount) = self.peer_credits.checked_add(amount.into()) {
            core::cmp::min(amount, <u16>::MAX.into())
        } else {
            <u16>::MAX.into()
        }
    }

    /// Get fragmentation size of L2CAP PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    ///
    /// # Note
    /// This not the maximum credit based frame size (k_frame). Instead it is the size in which
    /// credit based frames are fragmented to. Use method [`get_mps`] to get the maximum size of a
    /// k_frame for this channel.
    pub fn fragmentation_size(&self) -> usize {
        unsafe { &*self.link_lock.physical_link.get() }.max_transmission_size()
    }

    async fn send_fragment<T>(&mut self, fragment: L2capFragment<T>) -> Result<(), P::SendErr>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut fragment = Some(L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        });

        core::future::poll_fn(move |_| {
            self.link_lock
                .maybe_send(self.peer_channel_id, fragment.take().unwrap())
        })
        .await
        .await
    }

    async fn receive_fragment(&mut self) -> Result<HeadedFragment<P::RecvData>, MaybeRecvError<P::RecvErr>> {
        let mut poll = Some(
            core::future::poll_fn(|_| self.link_lock.maybe_recv(self.peer_channel_id))
                .await
                .await?,
        );

        Ok(core::future::poll_fn(move |_| poll.take().unwrap()).await)
    }

    async fn send_pdu<I>(&mut self, pdu: CreditBasedFrame<I>) -> Result<(), SendSduError<P::SendErr>>
    where
        I: Iterator<Item = u8> + ExactSizeIterator,
    {
        // boolean for first fragment of a *PDU*
        let mut is_first = true;

        let mut fragments_iter = pdu.into_fragments(self.fragmentation_size()).unwrap();

        while let Some(data) = fragments_iter.next() {
            let fragment = L2capFragment::new(is_first, data);

            is_first = false;

            self.send_fragment(fragment)
                .await
                .map_err(|e| SendSduError::SendErr(e))?;
        }

        // clear owner as the a full PDU was sent
        self.link_lock.clear_owner();

        Ok(())
    }

    /// Send a complete SDU to the lower layers
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    pub async fn send<T>(
        &'a mut self,
        sdu: T,
    ) -> Result<Option<UnsentCreditFrames<'a, P, T::IntoIter>>, SendSduError<P::SendErr>>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator + 'a,
    {
        let sdu = CreditBasedSdu::new(sdu, self.peer_channel_id, self.maximum_pdu_payload_size as u16);

        let mut packets = sdu.into_packets().map_err(|e| SendSduError::SduPacketError(e))?;

        while self.peer_credits != 0 {
            self.peer_credits -= 1;

            if let Some(pdu) = packets.next() {
                self.send_pdu(pdu).await?;
            } else {
                return Ok(None);
            }
        }

        Ok(Some(UnsentCreditFrames::new(self, packets)))
    }

    /// Receive a Credit Based Frame for this channel
    async fn receive_frame<T>(
        &mut self,
    ) -> Result<
        CreditBasedFrame<T>,
        ReceiveError<P::RecvErr, T::Error, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>,
    >
    where
        T: TryExtend<u8> + Default,
    {
        let headed_fragment = self.receive_fragment().await?;

        if !headed_fragment.fragment.is_start_fragment() {
            self.link_lock.clear_owner();

            return Err(ReceiveError::new_expect_first_err());
        }

        let mut meta = pdu::credit_frame::RecombineMeta::new(self.maximum_pdu_payload_size as u16);

        let mut first_recombiner =
            CreditBasedFrame::<T>::recombine(headed_fragment.length, self.peer_channel_id, &mut meta);

        let k_frame = if let Some(first_k_frame) = first_recombiner.add(headed_fragment.fragment.data).map_err(|e| {
            self.link_lock.clear_owner();
            ReceiveError::new_recombine(e)
        })? {
            first_k_frame
        } else {
            loop {
                let fragment = self.receive_fragment().await?;

                if fragment.fragment.is_start_fragment() {
                    return Err(ReceiveError::new_unexpect_first_err());
                }

                if let Some(b_frame) = first_recombiner
                    .add(fragment.fragment.data)
                    .map_err(|e| ReceiveError::new_recombine(e))?
                {
                    break b_frame;
                }
            }
        };

        self.link_lock.clear_owner();

        Ok(k_frame)
    }

    /// Receive a SDU from this Channel
    ///
    /// This awaits until a complete SDU is received. This means that one or more credit based
    /// frames were received and recombined into the SDU.
    ///
    /// # Note
    /// The `Ok(_)` output contains the `sdu`.
    pub async fn receive<T>(
        &mut self,
    ) -> Result<T, ReceiveError<P::RecvErr, T::Error, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>>
    where
        T: TryExtend<u8> + Default + core::ops::Deref<Target = [u8]>,
    {
        let first_k_frame = self.receive_frame::<T>().await?;

        let sdu_len = first_k_frame.get_sdu_length().unwrap();

        let mut sdu: T = first_k_frame.into_payload();

        if (sdu_len as usize) < sdu.len() {
            return Err(ReceiveError::new_invalid_sdu_length());
        } else if (sdu_len as usize) > sdu.len() {
            loop {
                let subsequent_k_frame = self.receive_frame::<T>().await?;

                sdu.try_extend(subsequent_k_frame.into_payload().iter().copied())
                    .map_err(|e| ReceiveError::new_extend_err(e))?;

                if (sdu_len as usize) == sdu.len() {
                    break;
                } else if (sdu_len as usize) < sdu.len() {
                    return Err(ReceiveError::new_invalid_sdu_length());
                }
            }
        }

        Ok(sdu)
    }
}

impl<P: PhysicalLink> ConnectionChannel for CreditBasedChannel<'_, P> {
    fn get_this_channel_id(&self) -> ChannelIdentifier {
        self.this_channel_id
    }

    fn get_peer_channel_id(&self) -> ChannelIdentifier {
        self.peer_channel_id
    }

    fn get_mtu(&self) -> Option<usize> {
        Some(self.maximum_transmission_size)
    }

    fn get_mps(&self) -> Option<usize> {
        Some(self.maximum_pdu_payload_size)
    }
}

impl<P: PhysicalLink> Drop for CreditBasedChannel<'_, P> {
    fn drop(&mut self) {
        self.link_lock.remove_channel(self.this_channel_id)
    }
}

/// Error output by the future [`FragmentReceiver`]
pub struct ReceiveError<R, E, C> {
    inner: ReceiveErrorInner<R, E, C>,
}

impl<R, E, C> ReceiveError<R, E, C> {
    fn new_extend_err(extend_err: E) -> Self {
        let inner = ReceiveErrorInner::TryExtend(extend_err);

        Self { inner }
    }

    fn new_expect_first_err() -> Self {
        let inner = ReceiveErrorInner::ExpectedFirstFragment;

        Self { inner }
    }

    fn new_unexpect_first_err() -> Self {
        let inner = ReceiveErrorInner::UnexpectedFirstFragment;

        Self { inner }
    }

    fn new_recombine(e: C) -> Self {
        let inner = ReceiveErrorInner::Recombine(e);

        Self { inner }
    }

    fn new_invalid_sdu_length() -> Self {
        let inner = ReceiveErrorInner::InvalidSduLength;

        Self { inner }
    }
}

impl<R, E, C> From<MaybeRecvError<R>> for ReceiveError<R, E, C> {
    fn from(maybe: MaybeRecvError<R>) -> Self {
        let inner = ReceiveErrorInner::Maybe(maybe);

        ReceiveError { inner }
    }
}

impl<R, E, C> core::fmt::Debug for ReceiveError<R, E, C>
where
    R: core::fmt::Debug,
    E: core::fmt::Debug,
    C: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.inner {
            ReceiveErrorInner::TryExtend(e) => write!(f, "TryExtend({e:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::RecvError(r)) => write!(f, "RecvError({r:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::InvalidChannel(c)) => write!(f, "{c:?}"),
            ReceiveErrorInner::Recombine(e) => write!(f, "Recombine({e:?})"),
            ReceiveErrorInner::ExpectedFirstFragment => f.write_str("ExpectedFirstFragment"),
            ReceiveErrorInner::UnexpectedFirstFragment => f.write_str("UnexpectedFirstFragment"),
            ReceiveErrorInner::InvalidSduLength => f.write_str("InvalidSduLength"),
        }
    }
}

impl<R, E, C> core::fmt::Display for ReceiveError<R, E, C>
where
    R: core::fmt::Display,
    E: core::fmt::Display,
    C: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.inner {
            ReceiveErrorInner::TryExtend(e) => write!(f, "failed to extend buffer {e:}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::RecvError(r)) => write!(f, "receive error: {r:}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::InvalidChannel(c)) => write!(f, "{c:}"),
            ReceiveErrorInner::Recombine(e) => write!(f, "recombine error: {e:}"),
            ReceiveErrorInner::ExpectedFirstFragment => f.write_str("expected first fragment of PDU"),
            ReceiveErrorInner::UnexpectedFirstFragment => f.write_str("unexpected first fragment of PDU"),
            ReceiveErrorInner::InvalidSduLength => f.write_str("SDU length field does not match SDU size"),
        }
    }
}

#[cfg(feature = "std")]
impl<R, E, C> std::error::Error for ReceiveError<R, E, C>
where
    R: std::error::Error,
    E: std::error::Error,
    C: std::error::Error,
{
}

enum ReceiveErrorInner<R, E, C> {
    Maybe(MaybeRecvError<R>),
    TryExtend(E),
    Recombine(C),
    ExpectedFirstFragment,
    UnexpectedFirstFragment,
    InvalidSduLength,
}

/// Error when sending a SDU
///
/// This is returned as the error type for method [`send`] of `CreditBasedChannel`.
///
/// [`send`]: CreditBasedChannel::send
#[derive(Debug)]
pub enum SendSduError<E> {
    SendErr(E),
    SduPacketError(PacketsError),
}

impl<E> core::fmt::Display for SendSduError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendSduError::SendErr(e) => write!(f, "error sending PDU, {e:}"),
            SendSduError::SduPacketError(e) => write!(f, "error converting SDU to PDUs, {e:}"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error> std::error::Error for SendSduError<E> {}
