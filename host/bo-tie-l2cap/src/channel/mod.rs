//! L2CAP Channels
//!
//! This module defines different types of channels used by logical links.

mod credit_based;
pub mod id;
pub mod signalling;
mod unused;

use crate::channel::id::{ChannelIdentifier, LeCid};
use crate::channel::signalling::ReceivedLeUSignal;
use crate::channel::unused::LeUUnusedChannelResponseRecombiner;
use crate::link_flavor::LinkFlavor;
use crate::pdu::basic_frame::BasicFrameRecombinerIntoRef;
use crate::pdu::credit_frame::{self, CreditBasedFrame, CreditBasedFrameRecombinerIntoRef};
use crate::pdu::{
    BasicFrame, CreditBasedSdu, PacketsError, RecombineL2capPduIntoRef, RecombinePayloadIncrementally,
    RecombinePayloadIncrementallyIntoRef,
};
use crate::pdu::{RecombineL2capPdu, SduPacketsIterator};
use crate::signalling::ReceiveLeUSignalRecombineBuilder;
use crate::{pdu::L2capFragment, LogicalLink, PhysicalLink, PhysicalLinkExt};
use bo_tie_core::buffer::TryExtend;
pub(crate) use credit_based::ChannelCredits;
pub use credit_based::CreditServiceData;
pub use signalling::SignallingChannel;

/// Enumeration of a [`BasicHeaderProcessor`] length
#[derive(Copy, Clone, Debug)]
enum ProcessorLengthState {
    None,
    FirstByte(u8),
    Complete(u16),
}

/// Enumeration of a [`BasicHeaderProcessor`]  channel identifier
#[derive(Copy, Clone, Debug)]
enum ProcessorChannelIdentifier {
    None,
    FirstByte(u8),
    Complete(ChannelIdentifier),
}

/// The basic header of every L2CAP PDU
#[derive(Copy, Clone)]
pub(crate) struct BasicHeader {
    pub length: u16,
    pub channel_id: ChannelIdentifier,
}

/// The 'basic header' processor for incoming L2CAP data
///
/// This is used for processing the basic header of a L2CAP data to determine which channel the PDU
/// is set to.
#[derive(Debug)]
pub(crate) struct BasicHeaderProcessor {
    length: core::cell::Cell<ProcessorLengthState>,
    channel_id: core::cell::Cell<ProcessorChannelIdentifier>,
}

impl BasicHeaderProcessor {
    pub(crate) fn new() -> Self {
        BasicHeaderProcessor {
            length: core::cell::Cell::new(ProcessorLengthState::None),
            channel_id: core::cell::Cell::new(ProcessorChannelIdentifier::None),
        }
    }

    /// Process a fragment.
    ///
    /// This is used to process fragments of an L2CAP PDU until the basic header can be determined.
    ///
    /// This may need to be called multiple times until all byes of the basic header are received.
    /// The method will attempt to form the `BasicHeader` on every call to it, storing whatever it
    /// could obtain of the header from the currently input fragment. Once all bytes of the
    /// `BasicHeader` are received it will return the basic header. On subsequent calls it will
    /// do nothing but return the stored header until the input `fragment` returns true from its
    /// [`is_start_fragment`] method.
    ///
    /// [`is_start_fragment`]: L2capFragment::is_start_fragment
    pub(crate) fn process<F, T>(&self, fragment: &mut L2capFragment<T>) -> Result<Option<BasicHeader>, InvalidChannel>
    where
        F: LinkFlavor,
        T: Iterator<Item = u8>,
    {
        if fragment.is_start_fragment() {
            self.length.set(ProcessorLengthState::None);
            self.channel_id.set(ProcessorChannelIdentifier::None);
        }

        loop {
            match (self.length.get(), self.channel_id.get()) {
                (ProcessorLengthState::None, ProcessorChannelIdentifier::None) => {
                    let Some(byte) = fragment.data.next() else {
                        break Ok(None);
                    };

                    self.length.set(ProcessorLengthState::FirstByte(byte))
                }
                (ProcessorLengthState::FirstByte(v), ProcessorChannelIdentifier::None) => {
                    let Some(byte) = fragment.data.next() else {
                        break Ok(None);
                    };

                    self.length
                        .set(ProcessorLengthState::Complete(<u16>::from_le_bytes([v, byte])))
                }
                (ProcessorLengthState::Complete(_), ProcessorChannelIdentifier::None) => {
                    let Some(byte) = fragment.data.next() else {
                        break Ok(None);
                    };

                    self.channel_id.set(ProcessorChannelIdentifier::FirstByte(byte))
                }
                (ProcessorLengthState::Complete(_), ProcessorChannelIdentifier::FirstByte(v)) => {
                    let Some(byte) = fragment.data.next() else {
                        break Ok(None);
                    };

                    let raw_channel = <u16>::from_le_bytes([v, byte]);

                    let channel_id =
                        F::try_channel_from_raw(raw_channel).ok_or_else(|| InvalidChannel::new::<F>(raw_channel))?;

                    self.channel_id.set(ProcessorChannelIdentifier::Complete(channel_id));
                }
                (ProcessorLengthState::Complete(length), ProcessorChannelIdentifier::Complete(channel_id)) => {
                    return Ok(Some(BasicHeader { length, channel_id }))
                }
                _ => unreachable!(),
            }
        }
    }
}

/// Data used by an established credit based channel
#[derive(Debug)]
pub struct CreditBasedChannelData<B> {
    recombine_meta: credit_frame::RecombineMeta,
    peer_channel_id: ChannelDirection,
    maximum_transmission_size: u16,
    maximum_payload_size: u16,
    peer_provided_credits: u16,
    credits_given_to_peer: u16,
    remaining_sdu_bytes: u16,
    sdu_buffer: B,
}

impl<B> CreditBasedChannelData<B> {
    pub(crate) fn get_meta(&mut self) -> &mut credit_frame::RecombineMeta {
        &mut self.recombine_meta
    }
}

impl<S: TryExtend<u8> + Default> CreditBasedChannelData<S> {
    /// Process a PDU, returning a SDU if it has been completely received
    ///
    /// # Error
    /// Returns an error if the buffer cannot be extended by the payload of the credit based frame.
    pub(crate) fn process_pdu<T>(&mut self, pdu: CreditBasedFrame<T>) -> ProcessSduOutput<S, S::Error>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        if self.credits_given_to_peer == 0 {
            return ProcessSduOutput::PeerSentTooManyPdu;
        }

        self.credits_given_to_peer -= 1;

        if let Some(len) = pdu.get_sdu_length() {
            self.recombine_meta.first_pdu_of_sdu = false;

            self.remaining_sdu_bytes = len
        };

        let iter = pdu.into_payload().into_iter();

        let iter_len = iter.len();

        let take_amount = core::cmp::min(iter_len, self.remaining_sdu_bytes.into());

        if let Err(e) = self.sdu_buffer.try_extend(iter.take(take_amount)) {
            return ProcessSduOutput::BufferError(e);
        }

        self.remaining_sdu_bytes = self
            .remaining_sdu_bytes
            .saturating_sub(iter_len.try_into().unwrap_or(<u16>::MAX));

        if self.remaining_sdu_bytes == 0 {
            // now that the SDU is built, reset the first flag
            self.recombine_meta.first_pdu_of_sdu = true;

            if self.credits_given_to_peer == 0 {
                ProcessSduOutput::SduButPeerHasNoMoreCredits(core::mem::take(&mut self.sdu_buffer))
            } else {
                ProcessSduOutput::Sdu(core::mem::take(&mut self.sdu_buffer))
            }
        } else {
            if self.credits_given_to_peer == 0 {
                ProcessSduOutput::NonePeerHasNoMoreCredits
            } else {
                ProcessSduOutput::None
            }
        }
    }

    pub(crate) fn add_peer_credits(&mut self, amount: u16) {
        self.peer_provided_credits = self.peer_provided_credits.saturating_add(amount)
    }
}

pub(crate) enum ProcessSduOutput<S, E> {
    None,
    NonePeerHasNoMoreCredits,
    Sdu(S),
    SduButPeerHasNoMoreCredits(S),
    // errors
    PeerSentTooManyPdu,
    BufferError(E),
}

#[derive(Debug)]
pub enum LeUChannelType<B> {
    Unused,
    Reserved,
    BasicChannel,
    SignallingChannel,
    CreditBasedChannel { data: CreditBasedChannelData<B> },
}

impl<S> LeUChannelType<S> {
    /// Create the recombiner associated with the channel's L2CAP PDU
    ///
    /// # Panic
    /// This cannot be called on an [`Unused`] channel.
    ///
    /// [`Unused`]: LeUChannelType::Unused
    pub(crate) fn new_recombiner<B>(&self, basic_header: &BasicHeader) -> LeUPduRecombine
    where
        B: TryExtend<u8> + Default,
    {
        match self {
            LeUChannelType::Unused
                if match basic_header.channel_id {
                    ChannelIdentifier::Le(LeCid::AttributeProtocol)
                    | ChannelIdentifier::Le(LeCid::LeSignalingChannel)
                    | ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => true,
                    _ => false,
                } =>
            {
                LeUPduRecombine::new_unused(basic_header)
            }
            LeUChannelType::Unused | LeUChannelType::Reserved => LeUPduRecombine::new_dumped(&basic_header),
            LeUChannelType::BasicChannel => {
                let recombine = BasicFrame::<B>::recombine_into_ref(basic_header.length, basic_header.channel_id);

                LeUPduRecombine::BasicChannel(recombine)
            }
            LeUChannelType::SignallingChannel => {
                let recombine = ReceivedLeUSignal::recombine(basic_header.length, basic_header.channel_id, (), ());

                LeUPduRecombine::SignallingChannel(recombine)
            }
            LeUChannelType::CreditBasedChannel { .. } => {
                let recombine = CreditBasedFrame::<B>::recombine_into_ref(basic_header.length, basic_header.channel_id);

                LeUPduRecombine::CreditBasedChannel(recombine)
            }
        }
    }
}

#[derive(Debug)]
pub(crate) enum LeUPduRecombine {
    Dump { pdu_len: usize, received_so_far: usize },
    Unused(unused::LeUUnusedChannelResponseRecombiner),
    BasicChannel(BasicFrameRecombinerIntoRef),
    SignallingChannel(ReceiveLeUSignalRecombineBuilder),
    CreditBasedChannel(CreditBasedFrameRecombinerIntoRef),
    Finished,
}

impl LeUPduRecombine {
    /// Create a `LeUPduRecombine` for dumping data
    pub(crate) fn new_dumped(basic_header: &BasicHeader) -> Self {
        let pdu_len = basic_header.length.into();
        let received_so_far = 0;

        LeUPduRecombine::Dump {
            pdu_len,
            received_so_far,
        }
    }

    /// Convert the recombiner into a dumped recombiner
    pub(crate) fn into_dumped(self) -> Self {
        let (pdu_len, received_so_far) = match self {
            Self::Dump {
                pdu_len,
                received_so_far,
            } => (pdu_len, received_so_far),
            Self::Unused(r) => (r.get_payload_length(), r.get_bytes_received()),
            Self::BasicChannel(r) => (r.get_payload_length(), r.get_byte_count()),
            Self::SignallingChannel(r) => (r.get_payload_length(), r.get_byte_count()),
            Self::CreditBasedChannel(r) => (r.get_payload_length(), r.get_byte_count()),
            Self::Finished => (0, 0),
        };

        Self::Dump {
            pdu_len,
            received_so_far,
        }
    }

    /// Convert the recombiner into a dumped recombiner
    ///
    /// # Panic
    /// The channel ID must be valid for an unused recombiner
    pub(crate) fn into_unused_basic_channel<T>(self, channel_identifier: ChannelIdentifier, received_so_far: T) -> Self
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        match self {
            Self::Unused(r) => Self::Unused(r),
            Self::BasicChannel(r) => match channel_identifier {
                ChannelIdentifier::Le(LeCid::AttributeProtocol) => Self::Unused(
                    LeUUnusedChannelResponseRecombiner::converted_attribute(r.get_payload_length(), received_so_far),
                ),
                ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => Self::Unused(
                    LeUUnusedChannelResponseRecombiner::converted_sm(r.get_payload_length(), received_so_far),
                ),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }

    pub(crate) fn into_unused_signalling_channel(self) -> Self {
        struct BytesReceivedIter<'a>(core::iter::Fuse<core::slice::Iter<'a, u8>>, usize);

        impl Iterator for BytesReceivedIter<'_> {
            type Item = u8;

            fn next(&mut self) -> Option<Self::Item> {
                if let Some(byte) = self.0.next() {
                    Some(*byte)
                } else if self.1 > 0 {
                    self.1 -= 1;
                    Some(0)
                } else {
                    None
                }
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (self.0.len() + self.1, Some(self.0.len() + self.1))
            }
        }

        impl ExactSizeIterator for BytesReceivedIter<'_> {
            fn len(&self) -> usize {
                self.0.len() + self.1
            }
        }

        let Self::SignallingChannel(s) = self else {
            unreachable!()
        };

        let (data, any_more) = s.get_bytes_received();

        Self::Unused(LeUUnusedChannelResponseRecombiner::converted_signal(
            s.get_payload_length(),
            BytesReceivedIter(data.iter().fuse(), any_more),
        ))
    }

    /// create a `LeUPduRecombine` for an unused channel
    pub(crate) fn new_unused(basic_header: &BasicHeader) -> Self {
        let recombine =
            unused::LeUUnusedChannelResponse::recombine(basic_header.length, basic_header.channel_id, (), ());

        LeUPduRecombine::Unused(recombine)
    }

    /// Add more payload bytes to the PDU
    ///
    /// This is just a shadow of the [`add`] method within the inner recombiner type.
    ///
    /// # Panics
    /// This panics if the meta information for the current PDU is required but the `meta` is not
    /// the expected value. For example, if the current PDU is a credit based frame, and `meta` is
    /// [`CurrentMeta::None`], this method will panic as it expects
    /// [`CurrentMeta::CreditBasedFrame].  
    pub(crate) fn add<T, B>(
        &mut self,
        payload_fragment: T,
        buffer: &mut B,
        meta: CurrentMeta,
    ) -> Result<PduRecombineAddOutput<B>, PduRecombineAddError<B>>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
        B: TryExtend<u8> + Default,
    {
        match self {
            LeUPduRecombine::Dump {
                pdu_len,
                received_so_far,
            } => {
                *received_so_far += payload_fragment.into_iter().len();

                if pdu_len > received_so_far {
                    Ok(PduRecombineAddOutput::Ongoing)
                } else {
                    Ok(PduRecombineAddOutput::DumpComplete)
                }
            }
            LeUPduRecombine::Unused(recombiner) => Ok(recombiner
                .add(payload_fragment)
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::UnusedComplete(pdu)
                    })
                    .unwrap_or_default()
                })
                .unwrap_or_else(|_| PduRecombineAddOutput::DumpComplete)),
            LeUPduRecombine::BasicChannel(recombiner) => recombiner
                .add_into_ref(payload_fragment, buffer, meta.get_none().as_mut().unwrap())
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::BasicFrame(pdu)
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| PduRecombineAddError::BasicChannel(e)),
            LeUPduRecombine::SignallingChannel(recombiner) => recombiner
                .add(payload_fragment)
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::ControlFrame(pdu)
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| PduRecombineAddError::SignallingChannel(e)),
            LeUPduRecombine::CreditBasedChannel(recombiner) => recombiner
                .add_into_ref(payload_fragment, buffer, meta.get_credit_based().unwrap())
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::CreditBasedFrame(pdu)
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| PduRecombineAddError::CreditBasedChannel(e)),
            LeUPduRecombine::Finished => Err(PduRecombineAddError::AlreadyFinished),
        }
    }
}

pub(crate) enum CurrentMeta<'a> {
    None,
    CreditBasedFrame(&'a mut credit_frame::RecombineMeta),
}

impl<'a> CurrentMeta<'a> {
    fn get_none(self) -> Option<()> {
        if let CurrentMeta::None = self {
            Some(())
        } else {
            None
        }
    }

    fn get_credit_based(self) -> Option<&'a mut credit_frame::RecombineMeta> {
        if let CurrentMeta::CreditBasedFrame(meta) = self {
            Some(meta)
        } else {
            None
        }
    }
}

#[derive(Default)]
pub(crate) enum PduRecombineAddOutput<B> {
    #[default]
    Ongoing,
    DumpComplete,
    UnusedComplete(unused::LeUUnusedChannelResponse),
    BasicFrame(BasicFrame<B>),
    ControlFrame(ReceivedLeUSignal),
    CreditBasedFrame(CreditBasedFrame<B>),
}

pub(crate) enum PduRecombineAddError<B: TryExtend<u8> + Default> {
    AlreadyFinished,
    BasicChannel(<BasicFrame<B> as RecombineL2capPdu>::RecombineError),
    SignallingChannel(<ReceivedLeUSignal as RecombineL2capPdu>::RecombineError),
    CreditBasedChannel(<CreditBasedFrame<B> as RecombineL2capPdu>::RecombineError),
}

pub(crate) enum DynChannelStateInner {
    ReserveCreditBasedChannel {
        reserved_id: ChannelIdentifier,
        peer_channel_id: ChannelDirection,
        maximum_transmission_size: u16,
        maximum_payload_size: u16,
        credits_given_to_peer: u16,
        peer_provided_credits: u16,
    },
    EstablishedCreditBasedChannel {
        peer_channel_id: ChannelDirection,
        maximum_transmission_size: u16,
        maximum_payload_size: u16,
        credits_given_to_peer: u16,
        peer_provided_credits: u16,
    },
}

pub struct DynChannelState {
    pub(crate) inner: DynChannelStateInner,
}

impl<S> From<DynChannelState> for LeUChannelType<S>
where
    S: Default,
{
    fn from(state: DynChannelState) -> Self {
        match state.inner {
            DynChannelStateInner::ReserveCreditBasedChannel {
                peer_channel_id,
                maximum_transmission_size,
                maximum_payload_size,
                credits_given_to_peer,
                peer_provided_credits,
                ..
            }
            | DynChannelStateInner::EstablishedCreditBasedChannel {
                peer_channel_id,
                maximum_transmission_size,
                maximum_payload_size,
                credits_given_to_peer,
                peer_provided_credits,
            } => {
                let recombine_meta = credit_frame::RecombineMeta { first_pdu_of_sdu: true };

                let remaining_sdu_bytes = 0;

                let credit_data = CreditBasedChannelData {
                    recombine_meta,
                    peer_channel_id,
                    maximum_transmission_size,
                    maximum_payload_size,
                    credits_given_to_peer,
                    peer_provided_credits,
                    remaining_sdu_bytes,
                    sdu_buffer: S::default(),
                };

                LeUChannelType::CreditBasedChannel { data: credit_data }
            }
        }
    }
}

/// Enumeration for dynamic channel source and destination CIDs
#[derive(Debug)]
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

/// Invalid Channel
///
/// This is used to indicate that a channel was invalid for a specific link type.
#[derive(Debug)]
pub struct InvalidChannel(u16, &'static str);

impl InvalidChannel {
    pub(crate) fn new<L: LinkFlavor>(raw_channel: u16) -> Self {
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
/// communication to a connected device.\
#[derive(Debug)]
pub struct BasicFrameChannel<L> {
    channel_id: ChannelIdentifier,
    logical_link: L,
}

impl<L: LogicalLink> BasicFrameChannel<L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: L) -> Self {
        BasicFrameChannel {
            channel_id,
            logical_link,
        }
    }

    /// Get the Channel Identifier (CID)
    pub fn get_cid(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get fragmentation size of L2CAP PDUs
    ///
    /// This returns the maximum payload of the underlying [`PhysicalLink`] of this connection
    /// channel. Every L2CAP PDU is fragmented to this in both sending a receiving of L2CAP data.
    pub fn fragmentation_size(&self) -> usize {
        self.logical_link.get_physical_link().max_transmission_size().into()
    }

    /// Send data through the channel
    ///
    /// The data will be converted into a `BasicFrame<T>` before being sent via the logical link.
    pub async fn send<T>(&mut self, payload: T) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        let b_frame = BasicFrame::new(payload, self.channel_id);

        self.logical_link.get_mut_physical_link().send_pdu(b_frame).await
    }
}

/// Credit Based Channel
///
/// A channel that only communicates with credit based L2CAP PDUs. This channel is used for LE
/// Credit Based Connections and Enhanced Credit Based Connections.
///
/// A `CreditBasedChannel` is created via signalling packets
#[derive(Debug)]
pub struct CreditBasedChannel<L> {
    channel_id: ChannelIdentifier,
    logical_link: L,
}

impl<L: LogicalLink> CreditBasedChannel<L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: L) -> Self {
        CreditBasedChannel {
            channel_id,
            logical_link,
        }
    }

    fn get_channel_data(&self) -> &CreditBasedChannelData<L::SduBuffer> {
        let LeUChannelType::CreditBasedChannel { data } = self.logical_link.get_channel_data() else {
            unreachable!()
        };

        data
    }

    fn get_mut_channel_data(&mut self) -> &mut CreditBasedChannelData<L::SduBuffer> {
        let LeUChannelType::CreditBasedChannel { data } = self.logical_link.get_mut_channel_data() else {
            unreachable!()
        };

        data
    }

    /// Get the source channel identifier for this connection
    ///
    /// The return is the source channel identifier in the initialization request PDU that was used
    /// to create this credit based channel.
    pub fn get_source_channel_id(&self) -> ChannelIdentifier {
        match &self.get_channel_data().peer_channel_id {
            ChannelDirection::Source(c) => *c,
            ChannelDirection::Destination(_) => self.channel_id,
        }
    }

    /// Get the destination channel identifier for this connection
    ///
    /// The return is the destination channel identifier in the initialization response PDU that was
    /// used to create this credit based channel.
    pub fn get_destination_channel_id(&self) -> ChannelIdentifier {
        match &self.get_channel_data().peer_channel_id {
            ChannelDirection::Destination(d) => *d,
            ChannelDirection::Source(_) => self.channel_id,
        }
    }

    /// Get this channel's identifier
    ///
    /// This is the identifier used by this link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by this device then this was the
    /// *source* id within the connection request. If this connection was accepted by this device
    /// then this was the *destination* id within the connection response.
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get the peer's channel identifier
    ///
    /// This is the identifier used by the peer's link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by the peer device then this was the
    /// *source* id within the connection request. If this connection was accepted by the peer
    /// device then this was the *destination* id within the connection response.
    pub fn get_peer_channel_id(&self) -> ChannelIdentifier {
        self.get_channel_data().peer_channel_id.get_channel()
    }

    /// Get the maximum payload size (MPS)
    ///
    /// This is the maximum PDU payload size of a credit based frame for this channel. When a SDU is
    /// transmitted it is fragmented into credit based frames using this size.
    pub fn get_mps(&self) -> u16 {
        self.get_channel_data().maximum_payload_size
    }

    /// Get the maximum transmission unit (MTU)
    ///
    /// This is the maximum size of a SDU.
    pub fn get_mtu(&self) -> u16 {
        self.get_channel_data().maximum_transmission_size
    }

    /// Get the current number of credits available for sending to
    ///
    /// This is not the cumulative
    pub fn get_credits(&self) -> u16 {
        self.get_channel_data().peer_provided_credits
    }

    /// Get the current number of credits that were given to the peer device by this channel
    ///
    /// This is an estimated count for the number of credits the peer device has for sending credit
    /// based frames to this channel.
    ///
    /// It is impossible to get the exact number of credits the peer currently has as this count is
    /// reflective to the number of
    pub fn get_credit_of_peer(&self) -> u16 {
        self.get_channel_data().credits_given_to_peer
    }

    /// Add credits given by the peer
    ///
    /// This forcibly adds peer credits to this channel. After this is called
    pub unsafe fn force_add_peer_credits(&mut self, amount: u16) {
        let peer_credits = &mut self.get_mut_channel_data().peer_provided_credits;

        *peer_credits = if let Some(amount) = peer_credits.checked_add(amount.into()) {
            core::cmp::min(amount, <u16>::MAX.into())
        } else {
            <u16>::MAX.into()
        }
    }

    /// Give the peer device more credits
    ///
    /// This is used for giving credits for this channel to a peer device. The peer device will then
    /// be allowed to send '`amount`' more credit frames to this channel.
    ///
    /// The future returned by this method increases the internal counter of peer credits by input
    /// '`amount`' and sends a *flow control credit indication* over the link's signalling channel
    /// with the number of credits given.
    pub async fn give_credits_to_peer(
        &mut self,
        amount: u16,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        let credits_given = &mut self.get_mut_channel_data().credits_given_to_peer;

        *credits_given = (*credits_given).saturating_add(amount);

        let new_credits = ChannelCredits::new(self.get_channel_id(), amount);

        self.logical_link
            .get_signalling_channel()
            .unwrap()
            .give_credits_to_peer(new_credits)
            .await
    }

    async fn send_k_frame<T>(
        &mut self,
        pdu: CreditBasedFrame<T>,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: Iterator<Item = u8> + ExactSizeIterator,
    {
        self.logical_link.get_mut_physical_link().send_pdu(pdu).await
    }

    /// Send a complete SDU to the linked device
    ///
    /// Sending a SDU needs to be done in accordance with the number of credits provided by the
    /// peer device. this is a greedy send as it will send as many credit based frames as it can.
    /// However, if it runs out of peer issued credits before it can completely send the SDU the
    /// future will complete and return a `CreditServiceData`. Once the peer gives more credits to
    /// this channel the returned `CreditServiceData` can be used to repeat the same process.
    pub async fn send<T>(
        &mut self,
        sdu: T,
    ) -> Result<Option<CreditServiceData<T::IntoIter>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>>
    where
        T: IntoIterator<Item = u8>,
        <T as IntoIterator>::IntoIter: ExactSizeIterator + core::fmt::Debug,
    {
        use crate::pdu::FragmentL2capSdu;

        let sdu = CreditBasedSdu::new(sdu, self.get_peer_channel_id(), self.get_mps());

        let mut packets = sdu.into_packets().map_err(|e| SendSduError::SduPacketError(e))?;

        if packets.get_remaining_count() > self.get_mtu().into() {
            return Err(SendSduError::SduLargerThanMtu);
        }

        while self.get_channel_data().peer_provided_credits != 0 {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better with async)
            let next = packets.next().map(|cfb| cfb.map_to_vec_iter());

            if let Some(pdu) = next {
                self.send_k_frame(pdu).await?;

                self.get_mut_channel_data().peer_provided_credits -= 1;
            } else {
                return Ok(None);
            }
        }

        Ok(Some(CreditServiceData::new(
            self.get_channel_id(),
            self.get_channel_data().peer_channel_id.get_channel(),
            packets,
        )))
    }
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
    SduLargerThanMtu,
}

impl<E> From<E> for SendSduError<E> {
    fn from(e: E) -> Self {
        Self::SendErr(e)
    }
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
            SendSduError::SduLargerThanMtu => {
                f.write_str("the SDU is larger than the maximum transmission unit for this channel")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<E: core::fmt::Debug + core::fmt::Display> std::error::Error for SendSduError<E> {}
