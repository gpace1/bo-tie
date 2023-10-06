//! Implementation of various [`ConnectionChannel`] implementations
//!
//! [`ConnectionChannel`]: ConnectionChannel

pub mod collection;
mod credit_based;
pub mod id;
mod shared;
pub mod signalling;

use crate::channel::id::ChannelIdentifier;
use crate::channel::shared::{BasicHeadedFragment, MaybeRecvError, ReceiveDataProcessor};
use crate::pdu::credit_frame::CreditBasedFrame;
use crate::pdu::{
    BasicFrame, CreditBasedSdu, FragmentIterator, FragmentL2capPdu, FragmentL2capSdu, PacketsError,
    RecombinePayloadIncrementally,
};
use crate::pdu::{RecombineL2capPdu, SduPacketsIterator};
use crate::{pdu, pdu::L2capFragment, LogicalLink, PhysicalLink};
use bo_tie_core::buffer::TryExtend;
pub use credit_based::CreditServiceData;
pub(crate) use shared::{SharedPhysicalLink, UnusedChannelResponse};
pub use signalling::SignallingChannel;

/// Enumeration for dynamic channel source and destination CIDs
pub(crate) enum ChannelDirection {
    Source(ChannelIdentifier),
    Destination(ChannelIdentifier),
}

impl ChannelDirection {
    fn get_channel(&self) -> ChannelIdentifier {
        match self {
            ChannelDirection::Source(c) => *c,
            ChannelDirection::Destination(d) => *d,
        }
    }
}

/// A L2CAP connection channel
///
/// Channels that implement this form a L2CAP connection between the two linked devices.
pub trait ConnectionChannel {
    /// Get the source channel identifier for the connection
    ///
    /// The return is the channel identifier used as the *source* identifier for the connection.
    fn get_source_channel_id(&self) -> ChannelIdentifier;

    /// Get the destination channel identifier for the connection
    ///
    /// The return is the channel identifier used as the *destination* identifier for the
    /// connection.
    fn get_destination_channel_id(&self) -> ChannelIdentifier;

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

/// Invalid Channel
///
/// This is used to indicate that a channel was invalid for a specific link type.
#[derive(Debug)]
pub struct InvalidChannel(u16, &'static str);

impl InvalidChannel {
    fn new<L: crate::link_flavor::LinkFlavor>(raw_channel: u16) -> Self {
        InvalidChannel(raw_channel, core::any::type_name::<L>())
    }
}

impl core::fmt::Display for InvalidChannel {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "invalid channel identifier {} for logical link {}", self.0, self.1)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidChannel {}

/// A channel that only communicates with Basic Frames
///
/// Many L2CAP channels defined by the Bluetooth Specification only use Basic Frames for
/// communication to a connected device.
pub struct BasicFrameChannel<'a, L: LogicalLink> {
    channel_id: ChannelIdentifier,
    logical_link: &'a L,
}

impl<'a, L: LogicalLink> BasicFrameChannel<'a, L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: &'a L) -> Self {
        assert!(
            logical_link.get_shared_link().add_channel(channel_id),
            "channel already exists"
        );

        BasicFrameChannel {
            channel_id,
            logical_link,
        }
    }
}

impl<L: LogicalLink> BasicFrameChannel<'_, L> {
    /// Get the Channel Identifier (CID)
    pub fn get_cid(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get fragmentation size of L2CAP PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    pub fn fragmentation_size(&self) -> usize {
        self.logical_link.get_shared_link().get_fragmentation_size()
    }

    async fn send_fragment<T>(
        &mut self,
        fragment: L2capFragment<T>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut fragment = Some(L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        });

        core::future::poll_fn(move |_| {
            self.logical_link
                .get_shared_link()
                .maybe_send(self.channel_id, fragment.take().unwrap())
        })
        .await
        .await
    }

    async fn receive_fragment(
        &mut self,
    ) -> Result<
        BasicHeadedFragment<<L::PhysicalLink as PhysicalLink>::RecvData>,
        MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>,
    > {
        loop {
            match self
                .logical_link
                .get_shared_link()
                .maybe_recv::<L>(self.channel_id)
                .await
            {
                Ok(Ok(f)) => break Ok(f),
                Ok(Err(reject_response)) => {
                    let output = self.send_inner(reject_response).await;

                    output.map_err(|_| MaybeRecvError::Disconnected)?;
                }
                Err(e) => {
                    self.logical_link.get_shared_link().clear_owner();

                    break Err(e);
                }
            }
        }
    }

    async fn send_inner<T>(&mut self, pdu: T) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: FragmentL2capPdu,
    {
        let mut is_first = true;

        let mut fragments_iter = pdu.into_fragments(self.fragmentation_size()).unwrap();

        while let Some(data) = fragments_iter.next() {
            let fragment = L2capFragment::new(is_first, data);

            is_first = false;

            self.send_fragment(fragment).await?;
        }

        // clear owner as the full PDU was sent
        self.logical_link.get_shared_link().clear_owner();

        Ok(())
    }

    /// Send a Basic Frame to the lower layers
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    pub async fn send<T>(&mut self, b_frame: BasicFrame<T>) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let output = self.send_inner(b_frame).await;

        self.logical_link.get_shared_link().clear_owner();

        output
    }

    async fn receive_inner<T>(
        &mut self,
    ) -> Result<BasicFrame<T>, ReceiveError<L, T::Error, pdu::basic_frame::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        let fragment = self.receive_fragment().await?;

        if !fragment.fragment.is_start_fragment() {
            return Err(ReceiveError::new_expect_first_err());
        }

        let mut recombiner = BasicFrame::recombine(fragment.length, fragment.channel_id, &mut ());

        if let Some(b_frame) = recombiner
            .add(fragment.fragment.data)
            .map_err(|e| ReceiveError::new_recombine(e))?
        {
            Ok(b_frame)
        } else {
            loop {
                let fragment = self.receive_fragment().await?;

                if fragment.fragment.is_start_fragment() {
                    return Err(ReceiveError::new_unexpect_first_err());
                }

                if let Some(b_frame) = recombiner
                    .add(fragment.fragment.data)
                    .map_err(|e| ReceiveError::new_recombine(e))?
                {
                    return Ok(b_frame);
                }
            }
        }
    }

    /// Receive a Basic Frame for this Channel
    pub async fn receive<T>(
        &mut self,
    ) -> Result<BasicFrame<T>, ReceiveError<L, T::Error, pdu::basic_frame::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        let output = self.receive_inner().await;

        self.logical_link.get_shared_link().clear_owner();

        output
    }
}

impl<L: LogicalLink> Drop for BasicFrameChannel<'_, L> {
    fn drop(&mut self) {
        self.logical_link.get_shared_link().remove_channel(self.channel_id)
    }
}

/// Credit Based Channel
///
/// A channel that only communicates with credit based L2CAP PDUs. This channel is used for LE
/// Credit Based Connections and Enhanced Credit Based Connections.
///
/// A `CreditBasedChannel` is created via signalling packets
pub struct CreditBasedChannel<'a, L: LogicalLink> {
    this_channel_id: ChannelDirection,
    peer_channel_id: ChannelDirection,
    logical_link: &'a L,
    maximum_pdu_payload_size: usize,
    maximum_transmission_size: usize,
    peer_credits: usize,
}

impl<'a, L: LogicalLink> CreditBasedChannel<'a, L> {
    pub(crate) fn new(
        this_channel_id: ChannelDirection,
        peer_channel_id: ChannelDirection,
        logical_link: &'a L,
        maximum_packet_size: usize,
        maximum_transmission_size: usize,
        initial_peer_credits: usize,
    ) -> Self {
        CreditBasedChannel {
            this_channel_id,
            peer_channel_id,
            logical_link,
            maximum_pdu_payload_size: maximum_packet_size,
            maximum_transmission_size,
            peer_credits: initial_peer_credits,
        }
    }

    /// Get the source channel identifier for this connection
    ///
    /// The return is the source channel identifier in the initialization request PDU that was used
    /// to create this credit based channel.
    pub fn get_source_channel_id(&self) -> ChannelIdentifier {
        match (&self.this_channel_id, &self.peer_channel_id) {
            (ChannelDirection::Source(c), _) => *c,
            (_, ChannelDirection::Source(c)) => *c,
            _ => unreachable!(),
        }
    }

    /// Get the destination channel identifier for this connection
    ///
    /// The return is the destination channel identifier in the initialization response PDU that was
    /// used to create this credit based channel.
    pub fn get_destination_channel_id(&self) -> ChannelIdentifier {
        match (&self.this_channel_id, &self.peer_channel_id) {
            (ChannelDirection::Destination(d), _) => *d,
            (_, ChannelDirection::Destination(d)) => *d,
            _ => unreachable!(),
        }
    }

    /// Get this channel identifier
    ///
    /// This is the identifier used by this link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by this device then this was the
    /// *source* id within the connection request. If this connection was accepted by this device
    /// then this was the *destination* id within the connection response.
    pub fn get_this_channel_id(&self) -> ChannelIdentifier {
        self.this_channel_id.get_channel()
    }

    /// Get the peer's channel identifier
    ///
    /// This is the identifier used by the peer's link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by the peer device then this was the
    /// *source* id within the connection request. If this connection was accepted by the peer
    /// device then this was the *destination* id within the connection response.
    pub fn get_peer_channel_id(&self) -> ChannelIdentifier {
        self.peer_channel_id.get_channel()
    }

    /// Get the maximum payload size (MPS)
    ///
    /// This is the maximum PDU payload size of a credit based frame. When a SDU is transmitted it
    /// is fragmented to this size (with the exception of the first fragment being two less) and
    /// each fragment is transmitted in a separate k-frame.
    pub fn get_mps(&self) -> u16 {
        self.maximum_pdu_payload_size as u16
    }

    /// Get the maximum transmission unit (MTU)
    ///
    /// This is the maximum size of a SDU.
    pub fn get_mtu(&self) -> u16 {
        self.maximum_transmission_size as u16
    }

    /// Get the current number of credits given to this channel by the connected device
    pub fn get_peer_credits(&self) -> u16 {
        self.peer_credits as u16
    }

    /// Add credits given by the peer
    ///
    /// This adds credits given by the peer device. These credits should come from a *L2CAP flow
    /// control credit ind* signal.
    pub fn add_peer_credits(&mut self, amount: u16) {
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
        self.logical_link.get_shared_link().get_fragmentation_size()
    }

    async fn send_fragment<T>(
        &mut self,
        fragment: L2capFragment<T>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: IntoIterator<Item = u8>,
    {
        let mut fragment = Some(L2capFragment {
            start_fragment: fragment.start_fragment,
            data: fragment.data.into_iter(),
        });

        core::future::poll_fn(move |_| {
            self.logical_link
                .get_shared_link()
                .maybe_send(self.this_channel_id.get_channel(), fragment.take().unwrap())
        })
        .await
        .await
    }

    async fn send_pdu_inner<T>(
        &mut self,
        pdu: T,
    ) -> Result<(), SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>>
    where
        T: FragmentL2capPdu,
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

        Ok(())
    }

    async fn send_pdu<I>(
        &mut self,
        pdu: CreditBasedFrame<I>,
    ) -> Result<(), SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>>
    where
        I: Iterator<Item = u8> + ExactSizeIterator,
    {
        let output = self.send_pdu_inner(pdu).await;

        self.logical_link.get_shared_link().clear_owner();

        output
    }

    /// Send a complete SDU to the lower layers
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    pub async fn send<T>(
        &mut self,
        sdu: T,
    ) -> Result<Option<CreditServiceData<T::IntoIter>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let sdu = CreditBasedSdu::new(sdu, self.get_peer_channel_id(), self.maximum_pdu_payload_size as u16);

        let mut packets = sdu.into_packets().map_err(|e| SendSduError::SduPacketError(e))?;

        while self.peer_credits != 0 {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better with async)
            let next = packets.next().map(|cfb| cfb.map_to_vec_iter());

            if let Some(pdu) = next {
                self.send_pdu(pdu).await?;
            } else {
                return Ok(None);
            }
        }

        Ok(Some(CreditServiceData::new(
            self.peer_channel_id.get_channel(),
            packets,
        )))
    }

    async fn receive_fragment(
        &mut self,
    ) -> Result<
        BasicHeadedFragment<<L::PhysicalLink as PhysicalLink>::RecvData>,
        MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>,
    > {
        loop {
            match self
                .logical_link
                .get_shared_link()
                .maybe_recv::<L>(self.this_channel_id.get_channel())
                .await
            {
                Ok(Ok(f)) => break Ok(f),
                Ok(Err(reject_response)) => {
                    let output = self.send_pdu_inner(reject_response).await;

                    output.map_err(|_| MaybeRecvError::Disconnected)?;
                }
                Err(e) => {
                    self.logical_link.get_shared_link().clear_owner();

                    break Err(e);
                }
            }
        }
    }

    /// Inner method of `receive_frame`
    async fn receive_frame_inner<T>(
        &mut self,
    ) -> Result<
        CreditBasedFrame<T>,
        ReceiveError<L, T::Error, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>,
    >
    where
        T: TryExtend<u8> + Default,
    {
        let headed_fragment = self.receive_fragment().await?;

        if !headed_fragment.fragment.is_start_fragment() {
            return Err(ReceiveError::new_expect_first_err());
        }

        let mut meta = pdu::credit_frame::RecombineMeta::new(self.maximum_pdu_payload_size as u16);

        let mut first_recombiner =
            CreditBasedFrame::<T>::recombine(headed_fragment.length, self.peer_channel_id.get_channel(), &mut meta);

        let k_frame = if let Some(first_k_frame) = first_recombiner
            .add(headed_fragment.fragment.data)
            .map_err(|e| ReceiveError::new_recombine(e))?
        {
            first_k_frame
        } else {
            loop {
                let bh_fragment = self.receive_fragment().await?;

                if bh_fragment.fragment.is_start_fragment() {
                    return Err(ReceiveError::new_unexpect_first_err());
                }

                if let Some(b_frame) = first_recombiner
                    .add(bh_fragment.fragment.data)
                    .map_err(|e| ReceiveError::new_recombine(e))?
                {
                    break b_frame;
                }
            }
        };

        Ok(k_frame)
    }

    /// Receive a Credit Based Frame for this channel
    async fn receive_frame<T>(
        &mut self,
    ) -> Result<
        CreditBasedFrame<T>,
        ReceiveError<L, T::Error, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>,
    >
    where
        T: TryExtend<u8> + Default,
    {
        let output = self.receive_frame_inner().await;

        self.logical_link.get_shared_link().clear_owner();

        output
    }

    /// Receive a SDU from this Channel
    ///
    /// This returns a future for awaiting until a complete SDU is received. The future will keep
    /// awaiting receiving credit based frames (k-frames) until every k-frame that was used to
    /// transport the SDU is received.
    ///
    /// The first k-frame received will be used to determine the size of the SDU. The output future
    /// counts the bytes in the first k-frame and subsequent received k-frames until the number
    /// matches the determined SDU size. The future will not poll to completion until either the
    /// entire SDU is received or an error occurs.
    ///
    /// # Note
    /// This returned future may get 'forever pend' if the peer of this credit based channel has
    /// run out of credits to be able send k-frames to this device. The method
    /// [`give_credits_to_peer`] can be used on the signalling channel in order to give the peer
    /// more credits so it can complete the sending of the SDU.
    ///
    /// [`give_credits_to_peer`]
    pub async fn receive<T>(
        &mut self,
    ) -> Result<T, ReceiveError<L, T::Error, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>>
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

impl<L: LogicalLink> ConnectionChannel for CreditBasedChannel<'_, L> {
    fn get_source_channel_id(&self) -> ChannelIdentifier {
        self.get_source_channel_id()
    }

    fn get_destination_channel_id(&self) -> ChannelIdentifier {
        self.get_destination_channel_id()
    }

    fn get_this_channel_id(&self) -> ChannelIdentifier {
        self.get_this_channel_id()
    }

    fn get_peer_channel_id(&self) -> ChannelIdentifier {
        self.get_peer_channel_id()
    }

    fn get_mtu(&self) -> Option<usize> {
        Some(self.maximum_transmission_size)
    }

    fn get_mps(&self) -> Option<usize> {
        Some(self.maximum_pdu_payload_size)
    }
}

impl<L: LogicalLink> Drop for CreditBasedChannel<'_, L> {
    fn drop(&mut self) {
        self.logical_link
            .get_shared_link()
            .remove_channel(self.this_channel_id.get_channel())
    }
}

/// Error output by the future [`FragmentReceiver`]
pub struct ReceiveError<L: LogicalLink, E, C> {
    inner: ReceiveErrorInner<L, E, C>,
}

impl<L: LogicalLink, E, C> ReceiveError<L, E, C> {
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

    fn new_disconnected() -> Self {
        let inner = ReceiveErrorInner::Maybe(MaybeRecvError::Disconnected);

        Self { inner }
    }
}

impl<L, E, C> From<MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>> for ReceiveError<L, E, C>
where
    L: LogicalLink,
{
    fn from(maybe: MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>) -> Self {
        let inner = ReceiveErrorInner::Maybe(maybe);

        ReceiveError { inner }
    }
}

impl<L, E, C> core::fmt::Debug for ReceiveError<L, E, C>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Debug,
    E: core::fmt::Debug,
    C: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.inner {
            ReceiveErrorInner::TryExtend(e) => write!(f, "TryExtend({e:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::Disconnected) => f.write_str("Disconnected"),
            ReceiveErrorInner::Maybe(MaybeRecvError::RecvError(r)) => write!(f, "RecvError({r:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::DumpRecvError(d)) => write!(f, "DumpRecvError({d:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::InvalidChannel(c)) => write!(f, "{c:?}"),
            ReceiveErrorInner::Recombine(e) => write!(f, "Recombine({e:?})"),
            ReceiveErrorInner::ExpectedFirstFragment => f.write_str("ExpectedFirstFragment"),
            ReceiveErrorInner::UnexpectedFirstFragment => f.write_str("UnexpectedFirstFragment"),
            ReceiveErrorInner::InvalidSduLength => f.write_str("InvalidSduLength"),
        }
    }
}

impl<L, E, C> core::fmt::Display for ReceiveError<L, E, C>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Display,
    E: core::fmt::Display,
    C: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.inner {
            ReceiveErrorInner::TryExtend(e) => write!(f, "failed to extend buffer {e:}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::Disconnected) => f.write_str("peer device disconnected"),
            ReceiveErrorInner::Maybe(MaybeRecvError::RecvError(r)) => write!(f, "receive error: {r:}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::DumpRecvError(d)) => write!(f, "receive error (dump): {d:?}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::InvalidChannel(c)) => write!(f, "{c:}"),
            ReceiveErrorInner::Recombine(e) => write!(f, "recombine error: {e:}"),
            ReceiveErrorInner::ExpectedFirstFragment => f.write_str("expected first fragment of PDU"),
            ReceiveErrorInner::UnexpectedFirstFragment => f.write_str("unexpected first fragment of PDU"),
            ReceiveErrorInner::InvalidSduLength => f.write_str("SDU length field does not match SDU size"),
        }
    }
}

#[cfg(feature = "std")]
impl<L, E, C> std::error::Error for ReceiveError<L, E, C>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        std::error::Error,
    E: std::error::Error,
    C: std::error::Error,
{
}

enum ReceiveErrorInner<L: LogicalLink, E, C> {
    Maybe(MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>),
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
    IncorrectChannel,
}

impl<E> core::fmt::Display for SendSduError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SendSduError::SendErr(e) => write!(f, "error sending PDU, {e:}"),
            SendSduError::SduPacketError(e) => write!(f, "error converting SDU to PDUs, {e:}"),
            SendSduError::IncorrectChannel => f.write_str("incorrect channel used for this operation"),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error> std::error::Error for SendSduError<E> {}
