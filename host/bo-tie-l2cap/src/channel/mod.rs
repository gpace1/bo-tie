//! L2CAP Channels
//!
//! This modules defines different types of channels based on the PDU formats and connections
//! defined within the L2CAP Bluetooth Specification.
//!
//! # [`BasicChannel`]
//! This channel is used for a L2CAP channel that exchanges basic frames.
//!
//! # [`SignallingChannel`]
//! This channel is the signalling channel of a logical link. Control frames are passed between the
//! two ends of a signalling channel.
//!
//! # [`CreditBasedChannel`]
//! A credit based channel is created after a L2CAP credit based connection is made between the two
//! linked devices. Both a LE credit based connection and enhanced credit based connection use
//! the `CreditBasedChannel` type to passed credit based data over the link.
//!
//! [flavor]: crate::link_flavor

mod credit_based;
pub mod id;
pub mod signalling;
mod unused;

use crate::channel::id::{ChannelIdentifier, LeCid};
use crate::channel::signalling::ReceivedLeUSignal;
use crate::channel::unused::LeUUnusedChannelResponse;
use crate::link_flavor::LinkFlavor;
use crate::pdu::credit_frame::{self, CreditBasedFrame};
use crate::pdu::{BasicFrame, CreditBasedSdu, PacketsError, RecombinePayloadIncrementally};
use crate::pdu::{RecombineL2capPdu, SduPacketsIterator};
use crate::{pdu::L2capFragment, LogicalLink, PhysicalLink, PhysicalLinkExt};
use bo_tie_core::buffer::TryExtend;
pub(crate) use credit_based::ChannelCredits;
pub use credit_based::CreditServiceData;
pub use signalling::SignallingChannel;

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
pub(crate) struct BasicHeaderProcessor {
    length: core::cell::Cell<ProcessorLengthState>,
    channel_id: core::cell::Cell<ProcessorChannelIdentifier>,
}

impl BasicHeaderProcessor {
    pub(crate) fn init() -> Self {
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

pub enum LeUChannelBuffer<B> {
    Unused,
    Reserved,
    BasicChannel { buffer: B },
    SignallingChannel,
    CreditBasedChannel { data: CreditBasedChannelData<B> },
}

pub struct CreditBasedChannelData<B> {
    recombine_meta: credit_frame::RecombineMeta,
    peer_channel_id: ChannelDirection,
    maximum_transmission_size: u16,
    maximum_payload_size: u16,
    peer_credits: u16,
    remaining_sdu_bytes: u16,
    buffer: B,
}

impl<B: TryExtend<u8> + Default> CreditBasedChannelData<B> {
    /// Process a PDU, returning a SDU if it has been completely received
    ///
    /// # Error
    /// Returns an error if the buffer cannot be extended by the payload of the credit based frame.
    pub(crate) fn process_pdu<T>(&mut self, pdu: CreditBasedFrame<T>) -> Result<Option<B>, B::Error>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        if let Some(len) = pdu.get_sdu_length() {
            self.recombine_meta.first_pdu_of_sdu = false;

            self.remaining_sdu_bytes = len
        };

        let iter = pdu.into_payload().into_iter();

        self.remaining_sdu_bytes = self
            .remaining_sdu_bytes
            .saturating_sub(iter.len().try_into().unwrap_or(<u16>::MAX));

        self.buffer.try_extend(iter.take(self.remaining_sdu_bytes.into()))?;

        if self.remaining_sdu_bytes == 0 {
            // now that the SDU is built, reset the first flag
            self.recombine_meta.first_pdu_of_sdu = true;

            Ok(Some(core::mem::take(&mut self.buffer)))
        } else {
            Ok(None)
        }
    }

    pub(crate) fn add_peer_credits(&mut self, amount: u16) {
        self.peer_credits = self.peer_credits.saturating_add(amount)
    }
}

impl<B> LeUChannelBuffer<B> {
    /// Create the recombiner associated with the channel's L2CAP PDU
    ///
    /// # Panic
    /// This cannot be called on an [`Unused`] channel.
    ///
    /// [`Unused`]: LeUChannelBuffer::Unused
    pub(crate) fn new_recombiner(&mut self, basic_header: &BasicHeader) -> LeUPduRecombine<'_, B>
    where
        B: TryExtend<u8> + Default,
    {
        match self {
            LeUChannelBuffer::Unused => match basic_header.channel_id {
                ChannelIdentifier::Le(LeCid::AttributeProtocol)
                | ChannelIdentifier::Le(LeCid::LeSignalingChannel)
                | ChannelIdentifier::Le(LeCid::SecurityManagerProtocol) => {
                    let recombine = unused::LeUUnusedChannelResponse::recombine(
                        basic_header.length,
                        basic_header.channel_id,
                        (),
                        (),
                    );

                    LeUPduRecombine::Unused(recombine)
                }
                _ => LeUPduRecombine::new_dump_recombiner(&basic_header),
            },
            LeUChannelBuffer::Reserved => LeUPduRecombine::new_dump_recombiner(&basic_header),
            LeUChannelBuffer::BasicChannel { buffer } => {
                let recombine = BasicFrame::recombine(basic_header.length, basic_header.channel_id, buffer, ());

                LeUPduRecombine::BasicChannel(recombine)
            }
            LeUChannelBuffer::SignallingChannel => {
                let recombine = ReceivedLeUSignal::recombine(basic_header.length, basic_header.channel_id, (), ());

                LeUPduRecombine::SignallingChannel(recombine)
            }
            LeUChannelBuffer::CreditBasedChannel { data } => {
                let recombine = CreditBasedFrame::recombine(
                    basic_header.length,
                    basic_header.channel_id,
                    &mut data.buffer,
                    &mut data.recombine_meta,
                );

                LeUPduRecombine::CreditBasedChannel(recombine)
            }
        }
    }
}

pub(crate) enum LeUPduRecombine<'a, B: 'a + TryExtend<u8> + Default> {
    Dump { pdu_len: usize, received_so_far: usize },
    Unused(unused::LeUUnusedChannelResponseRecombiner),
    BasicChannel(<BasicFrame<B> as RecombineL2capPdu>::PayloadRecombiner<'a>),
    SignallingChannel(<ReceivedLeUSignal as RecombineL2capPdu>::PayloadRecombiner<'a>),
    CreditBasedChannel(<CreditBasedFrame<B> as RecombineL2capPdu>::PayloadRecombiner<'a>),
    Finished,
}

impl<'a, B: 'a + TryExtend<u8> + Default> LeUPduRecombine<'a, B> {
    /// Create a recombiner for dumpind data
    pub(crate) fn new_dump_recombiner(basic_header: &BasicHeader) -> Self {
        let pdu_len = basic_header.length.into();
        let received_so_far = 0;

        LeUPduRecombine::Dump {
            pdu_len,
            received_so_far,
        }
    }

    /// Add more payload bytes to the PDU
    ///
    /// This is just a shadow of the [`add`] method within the inner recombiner type.
    pub(crate) fn add<T>(&mut self, payload_fragment: T) -> Result<PduRecombineAddOutput<B>, PduRecombineAddError<B>>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
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
                .add(payload_fragment)
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
                .add(payload_fragment)
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

#[derive(Default)]
pub(crate) enum PduRecombineAddOutput<B> {
    #[default]
    Ongoing,
    DumpComplete,
    UnusedComplete(LeUUnusedChannelResponse),
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
    /// Reserve the channel
    ///
    /// This is used whenever this device is initializing a credit based channel to the peer device.
    /// The channel needs to be reserved until the connection is either established or fails to be.
    /// This must be converted to `EstablishedCreditBasedChannel` once the connection procedure is
    /// complete.
    ReserveCreditBasedChannel,
    EstablishedCreditBasedChannel {
        peer_channel_id: ChannelDirection,
        maximum_transmission_size: u16,
        maximum_payload_size: u16,
        peer_credits: u16,
    },
}

pub struct DynChannelState(DynChannelStateInner);

impl<B> From<DynChannelState> for LeUChannelBuffer<B>
where
    B: Default,
{
    fn from(builder: DynChannelState) -> Self {
        match builder.0 {
            DynChannelStateInner::ReserveCreditBasedChannel => LeUChannelBuffer::Reserved,
            DynChannelStateInner::EstablishedCreditBasedChannel {
                peer_channel_id,
                maximum_transmission_size,
                maximum_payload_size,
                peer_credits,
            } => {
                let recombine_meta = credit_frame::RecombineMeta { first_pdu_of_sdu: true };

                let remaining_sdu_bytes = 0;

                let credit_data = CreditBasedChannelData {
                    recombine_meta,
                    peer_channel_id,
                    maximum_transmission_size,
                    maximum_payload_size,
                    peer_credits,
                    remaining_sdu_bytes,
                    buffer: B::default(),
                };

                LeUChannelBuffer::CreditBasedChannel { data: credit_data }
            }
        }
    }
}

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
/// communication to a connected device.
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

    /// Send a Basic Frame to the lower layers
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    pub async fn send<T>(&mut self, b_frame: BasicFrame<T>) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
        L::Buffer: Default,
    {
        let max_transmission_size = self.logical_link.get_physical_link().max_transmission_size().into();

        self.logical_link
            .get_mut_physical_link()
            .send_pdu(b_frame, max_transmission_size)
            .await
    }
}

/// Credit Based Channel
///
/// A channel that only communicates with credit based L2CAP PDUs. This channel is used for LE
/// Credit Based Connections and Enhanced Credit Based Connections.
///
/// A `CreditBasedChannel` is created via signalling packets
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

    fn get_channel_data(&self) -> &CreditBasedChannelData<L::Buffer> {
        let LeUChannelBuffer::CreditBasedChannel { data } = self.logical_link.get_channel_buffer() else {
            unreachable!()
        };

        data
    }

    fn get_mut_channel_data(&mut self) -> &mut CreditBasedChannelData<L::Buffer> {
        let LeUChannelBuffer::CreditBasedChannel { data } = self.logical_link.get_mut_channel_buffer() else {
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

    /// Get this channel identifier
    ///
    /// This is the identifier used by this link to receive credit based frames for this
    /// `CreditBasedChannel`. If this connection was initiated by this device then this was the
    /// *source* id within the connection request. If this connection was accepted by this device
    /// then this was the *destination* id within the connection response.
    pub fn get_this_channel_id(&self) -> ChannelIdentifier {
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
    /// This is the maximum PDU payload size of a credit based frame. When a SDU is transmitted it
    /// is fragmented into credit based frames using this size.
    pub fn get_mps(&self) -> u16 {
        self.logical_link.get_physical_link().max_transmission_size() as u16
    }

    /// Get the maximum transmission unit (MTU)
    ///
    /// This is the maximum size of a SDU.
    pub fn get_mtu(&self) -> u16 {
        self.get_channel_data().maximum_transmission_size
    }

    /// Get the current number of credits given to this channel by the connected device
    pub fn get_peer_credits(&self) -> u16 {
        self.get_channel_data().peer_credits
    }

    /// Get the current number of credits that were given to the peer device by this channel
    ///
    /// This is the estimated count for the number of credits the peer device has for this channel.
    /// This number may be different from the number of credits for this channel on the connected
    /// device. There may be credit based frames sent by the connected device that have not yet been
    /// received by this channel. This can be because they're either in the lower (than L2CAP)
    /// protocol layers of the connected device or the lower protocol layers of this device.
    pub fn get_credits_given(&self) -> u16 {
        self.get_channel_data().peer_credits
    }

    /// Add credits given by the peer
    ///
    /// This forcibly adds peer credits to this channel. After this is called
    pub unsafe fn force_add_peer_credits(&mut self, amount: u16) {
        let peer_credits = &mut self.get_mut_channel_data().peer_credits;

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
        let new_credits = ChannelCredits::new(self.get_this_channel_id(), amount);

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
        let maximum_payload_size = self.get_channel_data().maximum_payload_size.into();

        self.logical_link
            .get_mut_physical_link()
            .send_pdu(pdu, maximum_payload_size)
            .await
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
        <T as IntoIterator>::IntoIter: ExactSizeIterator,
    {
        use crate::pdu::FragmentL2capSdu;

        let maximum_transmission_size = self.logical_link.get_physical_link().max_transmission_size();

        let sdu = CreditBasedSdu::new(sdu, self.get_peer_channel_id(), maximum_transmission_size);

        let mut packets = sdu.into_packets().map_err(|e| SendSduError::SduPacketError(e))?;

        if packets.get_remaining_count() > maximum_transmission_size.into() {
            return Err(SendSduError::SduLargerThanMtu);
        }

        while self.get_channel_data().peer_credits != 0 {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better with async)
            let next = packets.next().map(|cfb| cfb.map_to_vec_iter());

            if let Some(pdu) = next {
                self.send_k_frame(pdu).await?;

                self.get_mut_channel_data().peer_credits -= 1;
            } else {
                return Ok(None);
            }
        }

        Ok(Some(CreditServiceData::new(
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
impl<E: std::error::Error> std::error::Error for SendSduError<E> {}
