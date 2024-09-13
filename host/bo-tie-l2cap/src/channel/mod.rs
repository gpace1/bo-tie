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
pub(crate) mod shared;
pub mod signalling;

use crate::channel::id::ChannelIdentifier;
use crate::channel::shared::{BasicHeader, BasicHeaderProcessor, MaybeRecvError, ReceiveDataProcessor};
use crate::pdu::control_frame::ControlFrame;
use crate::pdu::credit_frame::CreditBasedFrame;
use crate::pdu::{
    BasicFrame, CreditBasedSdu, FragmentIterator, FragmentL2capPdu, FragmentL2capSdu, PacketsError,
    RecombinePayloadIncrementally,
};
use crate::pdu::{RecombineL2capPdu, SduPacketsIterator};
use crate::{pdu, pdu::L2capFragment, LogicalLink, NextError, PhysicalLink, PhysicalLinkExt};
use bo_tie_core::buffer::TryExtend;
use core::num::NonZeroUsize;
pub(crate) use credit_based::ChannelCredits;
pub use credit_based::CreditServiceData;
pub(crate) use shared::{SharedPhysicalLink, UnusedChannelResponse};
pub use signalling::SignallingChannel;

pub(crate) enum ChannelBuffer<B> {
    Unused,
    AttributeChannel {
        buffer: B,
    },
    SignallingChannel {
        buffer: B,
    },
    CreditBasedChannel {
        peer_channel_id: ChannelDirection,
        maximum_packet_size: u16,
        maximum_transmission_size: u16,
        peer_credits: u16,
        this_credits: u16,
        buffer: B,
    },
}

impl<B> ChannelBuffer<B> {
    /// Create the recombiner associated with the channel's L2CAP PDU
    ///
    /// # Panic
    /// This cannot be called on an [`Unused`] channel.
    ///
    /// [`Unused`]: ChannelBuffer::Unused
    pub(crate) fn new_recombiner(&mut self, basic_header: &BasicHeader) -> PduRecombine<'a, B> {
        match self {
            ChannelBuffer::Unused => unreachable!(),
            ChannelBuffer::AttributeChannel { buffer } => {
                let meta = &mut ();

                let recombiner = BasicFrame::recombine(basic_header.length, basic_header.channel_id, buffer, meta);

                PduRecombine::BasicChannel(recombiner)
            }
            ChannelBuffer::SignallingChannel { buffer } => {
                let meta = &mut ();

                let recombiner = ControlFrame::recombine(basic_header.length, basic_header.channel_id, buffer, meta);

                PduRecombine::SignallingChannel(recombiner)
            }
            ChannelBuffer::CreditBasedChannel { recombine_meta, buffer } => {
                let recombiner =
                    CreditBasedFrame::recombine(basic_header.length, basic_header.channel_id, buffer, recombine_meta);

                PduRecombine::CreditBasedChannel(recombiner)
            }
        }
    }
}

pub(crate) enum PduRecombine<'a, B> {
    Dump { pdu_len: usize, received_so_far: usize },
    BasicChannel(<BasicFrame<&'a mut B> as RecombineL2capPdu>::PayloadRecombiner<'a>),
    SignallingChannel(<ControlFrame<&'a mut B> as RecombineL2capPdu>::PayloadRecombiner<'a>),
    CreditBasedChannel(<CreditBasedFrame<&'a mut B> as RecombineL2capPdu>::PayloadRecombiner<'a>),
    Finished,
}

impl<'a, B> PduRecombine<'a, B> {
    /// Create a recombiner for dumpind data
    pub(crate) fn new_dump_recombiner(basic_header: &BasicHeader) -> Self {
        let pdu_len = basic_header.length.into();
        let received_so_far = 0;

        PduRecombine::Dump {
            pdu_len,
            received_so_far,
        }
    }

    /// Add more payload bytes to the PDU
    ///
    /// This is just a shadow of the [`add`] method within the inner recombiner type.
    pub(crate) fn add<T>(
        &mut self,
        payload_fragment: T,
    ) -> Result<PduRecombineAddOutput<'a, B>, PduRecombineAddError<'a, B>>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        match self {
            PduRecombine::Dump {
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
            PduRecombine::BasicChannel(recombiner) => recombiner
                .add(payload_fragment)
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::BasicFrame(pdu)
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| PduRecombineAddError::BasicChannel(e)),
            PduRecombine::SignallingChannel(recombiner) => recombiner
                .add(payload_fragment)
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::ControlFrame(pdu)
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| PduRecombineAddError::SignallingChannel(e)),
            PduRecombine::CreditBasedChannel(recombiner) => recombiner
                .add(payload_fragment)
                .map(|opt| {
                    opt.map(|pdu| {
                        *self = Self::Finished;

                        PduRecombineAddOutput::CreditBasedFrame(pdu)
                    })
                    .unwrap_or_default()
                })
                .map_err(|e| PduRecombineAddError::CreditBasedChannel(e)),
            PduRecombine::Finished => Err(PduRecombineAddError::AlreadyFinished),
        }
    }
}

#[derive(Default)]
pub(crate) enum PduRecombineAddOutput<'a, B> {
    #[default]
    Ongoing,
    DumpComplete,
    BasicFrame(BasicFrame<&'a mut B>),
    ControlFrame(ControlFrame<&'a mut B>),
    CreditBasedFrame(CreditBasedFrame<&'a mut B>),
}

pub(crate) enum PduRecombineAddError<'a, B> {
    AlreadyFinished,
    BasicChannel(<BasicFrame<B> as RecombineL2capPdu>::RecombineError),
    SignallingChannel(<ControlFrame<B> as RecombineL2capPdu>::RecombineError),
    CreditBasedChannel(<CreditBasedFrame<B> as RecombineL2capPdu>::RecombineError),
}

pub enum ChannelType<L: LogicalLink> {
    BasicFrameChannel(BasicFrameChannel<L::PhysicalLink, L::Buffer>),
    SignallingChannel(SignallingChannel<L>),
    CreditBasedChannel(CreditBasedChannel<P, B>),
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
pub struct BasicFrameChannel<P, D> {
    channel_id: ChannelIdentifier,
    fragmentation_size: usize,
    physical_link: P,
    data: D,
}

impl<P: PhysicalLink, D> BasicFrameChannel<P, D> {
    pub(crate) fn new(channel_id: ChannelIdentifier, fragmentation_size: usize, physical_link: P, data: D) -> Self {
        BasicFrameChannel {
            channel_id,
            fragmentation_size,
            physical_link,
            data,
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
        self.fragmentation_size
    }

    /// Send a Basic Frame to the lower layers
    ///
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device. This method
    /// may be called by protocol at a higher layer than L2CAP.
    pub async fn send<T>(&mut self, b_frame: BasicFrame<T>) -> Result<(), P::SendErr>
    where
        T: IntoIterator<Item = u8>,
        T::IntoIter: ExactSizeIterator,
    {
        self.physical_link.send_pdu(b_frame, self.fragmentation_size).await
    }
}

impl<P, B> BasicFrameChannel<P, Option<&'_ mut B>>
where
    P: PhysicalLink,
    B: Default,
{
    /// Get the last received PDU
    ///
    /// This is intended to be used proceeding the method `receive` of the logical link. The buffer
    /// for this channel will be consumed and replaced with its default.
    ///
    /// # Note
    /// After this is called once, it will return `None`.
    pub fn take_received(self) -> Option<BasicFrame<B>> {
        self.data.map(|b| BasicFrame::new(std::mem::take(b), self.channel_id))
    }
}

/// Credit Based Channel
///
/// A channel that only communicates with credit based L2CAP PDUs. This channel is used for LE
/// Credit Based Connections and Enhanced Credit Based Connections.
///
/// A `CreditBasedChannel` is created via signalling packets
pub struct CreditBasedChannel<P, D> {
    this_channel_id: ChannelDirection,
    peer_channel_id: ChannelDirection,
    physical_link: P,
    data: D,
    maximum_pdu_payload_size: usize,
    maximum_transmission_size: usize,
    peer_credits: usize,
    this_credits: usize,
    received_pdu_count: usize,
    receive_sdu_len: core::cell::Cell<usize>,
    receive_count_so_far: core::cell::Cell<usize>,
}

impl<P, D> CreditBasedChannel<P, D> {
    pub(crate) fn new(
        this_channel_id: ChannelDirection,
        peer_channel_id: ChannelDirection,
        physical_link: P,
        data: D,
        maximum_packet_size: usize,
        maximum_transmission_size: usize,
        initial_peer_credits: usize,
        initial_this_credits: usize,
    ) -> Self {
        let receive_sdu_len = core::cell::Cell::new(0);

        let receive_count_so_far = core::cell::Cell::new(0);

        let received_pdu_count = 0;

        CreditBasedChannel {
            this_channel_id,
            peer_channel_id,
            physical_link,
            data,
            maximum_pdu_payload_size: maximum_packet_size,
            maximum_transmission_size,
            peer_credits: initial_peer_credits,
            this_credits: initial_this_credits,
            received_pdu_count,
            receive_sdu_len,
            receive_count_so_far,
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

    /// Get the current number of credits that were given to the peer device for this channel
    ///
    /// This is the estimated count for the number of credits the peer device has for this channel. This number may be
    /// different then the number of credits for this channel on the connected device. There may be credit based frames
    /// sent by the connected device that have not yet been received by this channel. This can be because they're either
    /// in the lower (than L2CAP) protocol layers of the connected device or the lower protocol layers of this device.
    pub fn get_credits_given(&self) -> u16 {
        self.this_credits as u16
    }

    /// Get the number of PDUs that were received since the last time this method was called
    ///
    /// This returns a counter of the number of credit based frames that were received by this
    /// channel since the last time this method was called.
    ///
    /// # Note
    /// The the receive counter saturates to [`<usize>::MAX`].
    pub fn get_received_pdu_count(&mut self) -> usize {
        core::mem::take(&mut self.received_pdu_count)
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

    /// Give the peer device more credits
    ///
    /// This is used for giving credits for this channel to a peer device. The internal counter of peer credits in
    /// increased by the number of credits input to this method. The returned future is used for giving the credit
    /// indication over the input signalling channel.
    pub async fn give_credits_to_peer(
        &mut self,
        signalling_channel: &mut SignallingChannel<'_, L>,
        amount: u16,
    ) -> Result<(), <L::PhysicalLink as PhysicalLink>::SendErr> {
        self.this_credits = core::cmp::min(self.this_credits.saturating_add(amount as usize), <u16>::MAX as usize);

        let new_credits = ChannelCredits::new(self.get_this_channel_id(), self.this_credits as u16);

        signalling_channel.give_credits_to_peer(new_credits).await
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
    ///
    /// [`get_mps`]: CreditBasedChannel::get_mps
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

        self.logical_link
            .get_shared_link()
            .maybe_send(self.this_channel_id.get_channel(), fragment.take().unwrap())
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
    /// This is used to send a L2CAP Basic Frame PDU from the Host to a linked device.
    ///
    /// ## Output
    /// Output of the future returned by `send` depends on the number of credits this `CreditBasedChannel` has been
    /// given in order to send credit based frames. If the future outputs `None` then the entire `sdu` has been sent
    /// over this `CreditBasedChannel`, but if the future outputs a `CreditServiceData` then this ran out of credits
    /// before it could finish sending.
    ///
    /// ### Out of Credits
    /// This is a very basic and flawed example of how to handle the send future.
    ///
    /// ```
    /// # use tokio::select;
    /// # use bo_tie_l2cap::{CreditBasedChannel, LogicalLink, PhysicalLink, SignallingChannel};
    /// # use bo_tie_l2cap::channel::signalling::ReceivedSignal;
    /// # async fn example<T, L>(sdu: T, mut credit_based_channel: CreditBasedChannel<'_, L>, mut signalling_channel: SignallingChannel<'_, L>)
    /// # -> Result<(), Box<dyn std::error::Error>>
    /// # where
    /// #     T: IntoIterator<Item = u8>,
    /// #     T::IntoIter: ExactSizeIterator,
    /// #     L: LogicalLink + 'static,
    /// #     <<L as LogicalLink>::PhysicalLink as PhysicalLink>::SendErr: std::error::Error + 'static,
    /// #     <<L as LogicalLink>::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error + 'static,
    /// # {
    /// if let Some(mut more_to_send) = credit_based_channel.send(sdu).await? {
    ///     loop {
    ///         let signal = signalling_channel.receive().await?;
    ///
    ///         if let ReceivedSignal::FlowControlCreditIndication(ind) = signal {
    ///            more_to_send = match more_to_send
    ///                .inc_and_send(&mut credit_based_channel, ind.get_credits())
    ///                .await?
    ///            {
    ///                Some(sdu_sender) => sdu_sender,
    ///                None => break,
    ///            };
    ///        }
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    /// This example assumes that the peer device will not send any data on the credit based connection nor are there
    /// any other existing channels besides the obvious signalling channel. A more practical way of doing things is to
    /// select the 'more_to_send' over all the other channels along with the `credit_based_channel`.
    ///
    /// ```
    /// # use tokio::select;
    /// # use bo_tie_l2cap::{CreditBasedChannel, LogicalLink, PhysicalLink, SignallingChannel};
    /// # use bo_tie_l2cap::channel::signalling::ReceivedSignal;
    /// # async fn example<T, L>(sdu: T, mut credit_based_channel: CreditBasedChannel<'_, L>, mut signalling_channel: SignallingChannel<'_, L>)
    /// # -> Result<(), Box<dyn std::error::Error>>
    /// # where
    /// #     T: IntoIterator<Item = u8>,
    /// #     T::IntoIter: ExactSizeIterator,
    /// #     L: LogicalLink + 'static,
    /// #     <<L as LogicalLink>::PhysicalLink as PhysicalLink>::SendErr: std::error::Error + 'static,
    /// #     <<L as LogicalLink>::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error + 'static,
    /// # {
    /// let mut more_to_send = None;
    ///
    /// let mut sdu_buffer = &mut Vec::new();
    ///
    /// loop {
    ///     select! {
    ///         maybe_rx = credit_based_channel.receive(sdu_buffer, false) => /* process received SDU */
    /// # continue,
    ///
    ///         maybe_signal = signalling_channel.receive() => {
    ///             if let ReceivedSignal::FlowControlCreditIndication(ind) = maybe_signal? {
    ///                 let credits = ind.get_credits();
    ///
    ///                 if let Some(more_to_send) = more_to_send {
    ///                     more_to_send = more_to_send
    ///                         .inc_and_send(&mut credit_based_channel, credits)
    ///                         .await?
    ///                 } else {
    ///                     credit_based_channel.add_peer_credit(credits)
    ///                 }
    ///             }
    ///         }
    ///
    ///         /* any other active channels */
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
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

        if packets.get_remaining_count() > self.maximum_transmission_size {
            return Err(SendSduError::SduLargerThanMtu);
        }

        while self.peer_credits != 0 {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better with async)
            let next = packets.next().map(|cfb| cfb.map_to_vec_iter());

            if let Some(pdu) = next {
                self.send_pdu(pdu).await?;

                self.peer_credits -= 1;
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
        buffer: &mut T,
        meta: &mut pdu::credit_frame::RecombineMeta,
    ) -> Result<CreditBasedFrame<T>, ReceiveError<L, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        let basic_headed_fragment = self.receive_fragment().await?;

        if !basic_headed_fragment.is_start_of_data() {
            return Err(ReceiveError::new_expect_first_err());
        }

        let mut first_recombiner = CreditBasedFrame::recombine(
            basic_headed_fragment.get_pdu_length(),
            self.peer_channel_id.get_channel(),
            buffer,
            meta,
        );

        let k_frame = if let Some(first_k_frame) = first_recombiner
            .add(basic_headed_fragment.into_data())
            .map_err(|e| ReceiveError::new_recombine(e))?
        {
            first_k_frame
        } else {
            loop {
                let basic_headed_fragment = self.receive_fragment().await?;

                if basic_headed_fragment.is_start_of_data() {
                    return Err(ReceiveError::new_unexpect_first_err());
                }

                if let Some(k_frame) = first_recombiner
                    .add(basic_headed_fragment.into_data())
                    .map_err(|e| ReceiveError::new_recombine(e))?
                {
                    break k_frame;
                }
            }
        };

        // for subsequent fragments of a k-frame
        meta.first = false;

        self.received_pdu_count = self.received_pdu_count.saturating_add(1);

        Ok(k_frame)
    }

    /// Receive a Credit Based Frame but don't touch the buffer
    ///
    /// Unlike `receive_frame` this returns a `CreditBasedFrame` where the payload is placed within
    /// `sdu_buffer`.
    async fn receive_frame_into<'z, T>(
        &mut self,
        sdu_buffer: &'z mut T,
        meta: &mut pdu::credit_frame::RecombineMeta,
    ) -> Result<CreditBasedFrame<&'z mut T>, ReceiveError<L, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        /// A wrapper that can be taken once
        ///
        /// This 'abuses' the credit frame recombine logic within the bowls of the implementation
        /// of the method `receive_frame_inner`. Within that logic there is a part that occurs once;
        /// the data within the buffer is taken using the method `core::mem::take` and placed within
        /// the output `CreditBasedFrame`. This is used to circumvent this by providing a wrapper
        /// around an `Option` to the reference.
        #[derive(Default)]
        pub(crate) struct TakeOnce<'a, T>(Option<&'a mut T>);

        impl<T: TryExtend<u8>> TryExtend<u8> for TakeOnce<'_, T> {
            type Error = T::Error;

            fn try_extend<I>(&mut self, iter: I) -> Result<(), Self::Error>
            where
                I: IntoIterator<Item = u8>,
            {
                self.0
                    .as_mut()
                    .expect("cannot extend the default TakenOnce")
                    .try_extend(iter)
            }
        }

        let mut buffer = TakeOnce(Some(sdu_buffer));

        let output = self.receive_frame_inner(&mut buffer, meta).await;

        self.logical_link.get_shared_link().clear_owner();

        // map the frame back to a reference
        let output = output.map(|k_frame| match k_frame.get_sdu_length() {
            Some(sdu_size) => {
                CreditBasedFrame::new_first(sdu_size, k_frame.get_channel_id(), k_frame.into_payload().0.unwrap())
            }
            None => CreditBasedFrame::new_subsequent(k_frame.get_channel_id(), k_frame.into_payload().0.unwrap()),
        });

        output
    }

    /// Receive a Service Data Unit (SDU) from this Channel
    ///
    /// This returns a future for awaiting until a complete SDU is received. The future will keep
    /// awaiting receiving credit based frames (k-frames) until either every k-frame that was used to
    /// transport the SDU is received, or the peer has run out of credits issued for this channel.
    ///
    /// ## Buffering
    /// The field `sdu_buffer` is the holding location for k-frames until the entire SDU is received. This allows for
    /// the returned future to be dropped before the full SDU is received as it does not own the buffer. When `receive`
    /// is called on an non-empty buffer, it will calculate where the current state of the to be received SDU based on
    /// the bytes within the buffer.
    ///
    /// `sdu_buffer` must default to an empty buffer as observed by its implementation of `Deref<Target = [u8]>` (The
    /// expression `T::default().is_empty()` must evaluate to true). The purpose of the buffer is to store k-frame
    /// fragments until all frames are received. This allows the future returned by receive to be dropped without
    /// loosing any received data. If the future owns the buffer, it could not be dropped until a SDU was output by it.
    ///
    /// ## Output
    /// The future returned by `receive` will output a SDU when it detects that `sdu_buffer` contains all bytes of the
    /// SDU. The data within `sdu_buffer`` is taken (the reference is replaced with a default `T`) and output by the
    /// future.
    ///
    /// The future can also output `None` if input `check_credits` is true and the channel has determined that the
    /// peer device is out of credits to send k-frames. When `check_credits` is flase, the future never outputs `None`.
    pub async fn receive<T>(
        &mut self,
        sdu_buffer: &mut T,
        check_credits: bool,
    ) -> Result<Option<T>, ReceiveError<L, <CreditBasedFrame<T> as RecombineL2capPdu>::RecombineError>>
    where
        T: TryExtend<u8> + Default + core::ops::Deref<Target = [u8]>,
    {
        let mut meta = if self.receive_sdu_len.get() == 0 {
            if sdu_buffer.len() != 0 {
                return Err(ReceiveError::new_unexpected_length(sdu_buffer.len(), 0));
            }

            if check_credits && self.this_credits == 0 {
                return Ok(None);
            }

            let mut meta = pdu::credit_frame::RecombineMeta {
                first: true,
                mps: self.get_mps(),
            };

            let first_k_frame = self.receive_frame_into::<T>(sdu_buffer, &mut meta).await?;

            self.this_credits = self
                .this_credits
                .checked_sub(1)
                .ok_or(ReceiveError::peer_out_of_credits())?;

            self.receive_sdu_len.set(first_k_frame.get_sdu_length().unwrap().into());

            meta
        } else {
            if sdu_buffer.len() != self.receive_count_so_far.get() {
                return Err(ReceiveError::new_unexpected_length(
                    sdu_buffer.len(),
                    self.receive_count_so_far.get(),
                ));
            }

            pdu::credit_frame::RecombineMeta {
                first: false,
                mps: self.get_mps(),
            }
        };

        if self.receive_sdu_len.get() < sdu_buffer.len() {
            return Err(ReceiveError::new_invalid_sdu_length());
        } else if self.receive_sdu_len.get() > sdu_buffer.len() {
            loop {
                if check_credits && self.this_credits == 0 {
                    return Ok(None);
                }

                self.receive_frame_into(sdu_buffer, &mut meta).await?;

                if self.receive_sdu_len.get() == sdu_buffer.len() {
                    break;
                }

                if self.receive_sdu_len.get() < sdu_buffer.len() {
                    return Err(ReceiveError::new_invalid_sdu_length());
                }

                self.this_credits = self
                    .this_credits
                    .checked_sub(1)
                    .ok_or(ReceiveError::peer_out_of_credits())?;

                self.receive_count_so_far.set(sdu_buffer.len())
            }
        }

        self.receive_sdu_len.set(0);

        self.receive_count_so_far.set(0);

        Ok(Some(core::mem::take(sdu_buffer)))
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
