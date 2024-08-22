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
pub(crate) use credit_based::ChannelCredits;
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
    receiving_pdu_length: core::cell::Cell<usize>,
}

impl<'a, L: LogicalLink> BasicFrameChannel<'a, L> {
    pub(crate) fn new(channel_id: ChannelIdentifier, logical_link: &'a L) -> Self {
        assert!(
            logical_link.get_shared_link().add_channel(channel_id),
            "channel already exists"
        );

        let receiving_pdu_length = core::cell::Cell::new(0);

        BasicFrameChannel {
            channel_id,
            logical_link,
            receiving_pdu_length,
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

        self.logical_link
            .get_shared_link()
            .maybe_send(self.channel_id, fragment.take().unwrap())
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
        buffer: &mut T,
    ) -> Result<BasicFrame<T>, ReceiveError<L, pdu::basic_frame::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        let basic_headed_fragment = self.receive_fragment().await?;

        if self.receiving_pdu_length.get() == 0 && !basic_headed_fragment.is_start_of_data() {
            return Err(ReceiveError::new_expect_first_err());
        }

        let meta = &mut ();

        let mut recombiner = BasicFrame::recombine(
            basic_headed_fragment.get_pdu_length(),
            basic_headed_fragment.get_channel_id(),
            buffer,
            meta,
        );

        let recombine_output = recombiner
            .add(
                basic_headed_fragment
                    .into_data()
                    .into_iter()
                    .inspect(|_| self.receiving_pdu_length.set(self.receiving_pdu_length.get() + 1)),
            )
            .map_err(|e| ReceiveError::new_recombine(e))?;

        if let Some(b_frame) = recombine_output {
            Ok(b_frame)
        } else {
            loop {
                let basic_headed_fragment = self.receive_fragment().await?;

                if basic_headed_fragment.is_start_of_data() {
                    return Err(ReceiveError::new_unexpect_first_err());
                }

                if let Some(b_frame) = recombiner
                    .add(
                        basic_headed_fragment
                            .into_data()
                            .into_iter()
                            .inspect(|_| self.receiving_pdu_length.set(self.receiving_pdu_length.get() + 1)),
                    )
                    .map_err(|e| ReceiveError::new_recombine(e))?
                {
                    return Ok(b_frame);
                }
            }
        }
    }

    /// Receive a Basic Frame
    ///
    /// The `receive` future is used to output the next `BasicFrame` sent to this channel. The input
    /// `buffer` is used to temporarily contain received data until all fragments of a L2CAP PDU are
    /// received.
    ///
    /// The returned `receive` future will poll until a complete L2CAP PDU is received. Internally,
    /// the future polls the physical layer, which only returns fragments of L2CAP PDUs. The PDU
    /// payload within these fragments is stored within `buffer`, stopping once all the fragments
    /// of the L2CAP PDU are received. The data within `buffer` is taken (and is replaced with
    /// `T::default()`) and set as the payload within the output `BasicFrame`.
    pub async fn receive<T>(
        &mut self,
        buffer: &mut T,
    ) -> Result<BasicFrame<T>, ReceiveError<L, pdu::basic_frame::RecombineError>>
    where
        T: TryExtend<u8> + Default,
    {
        let output = self.receive_inner(buffer).await;

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
    this_credits: usize,
    received_pdu_count: usize,
    receive_sdu_len: core::cell::Cell<usize>,
    receive_count_so_far: core::cell::Cell<usize>,
}

impl<'a, L: LogicalLink> CreditBasedChannel<'a, L> {
    pub(crate) fn new(
        this_channel_id: ChannelDirection,
        peer_channel_id: ChannelDirection,
        logical_link: &'a L,
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
            logical_link,
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

/// Errors output by the `receive*` methods of channels
///
/// A receive error is a non-recoverable error. If this error does occur then the logical link (not
/// just the channel) must be closed between the two devices. Afterwards the link can be
/// reestablished.
///
/// These errors are not something that should ever occur. They only occur whenever the this device
/// receives badly formatted L2CAP PDU data or the `receive` future was used incorrectly.
pub struct ReceiveError<L: LogicalLink, C> {
    inner: ReceiveErrorInner<L, C>,
}

impl<L: LogicalLink, C> ReceiveError<L, C> {
    fn new_expect_first_err() -> Self {
        let inner = ReceiveErrorInner::ExpectedPduBeginning;

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

    fn new_unexpected_length(buffer_len: usize, expected_len: usize) -> Self {
        let inner = ReceiveErrorInner::UnexpectedBufferLength(buffer_len, expected_len);

        Self { inner }
    }

    fn peer_out_of_credits() -> Self {
        let inner = ReceiveErrorInner::PeerSentWithNoCredits;

        Self { inner }
    }
}

impl<L, C> From<MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>> for ReceiveError<L, C>
where
    L: LogicalLink,
{
    fn from(maybe: MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>) -> Self {
        let inner = ReceiveErrorInner::Maybe(maybe);

        ReceiveError { inner }
    }
}

impl<L, C> core::fmt::Debug for ReceiveError<L, C>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Debug,
    C: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.inner {
            ReceiveErrorInner::Maybe(MaybeRecvError::Disconnected) => f.write_str("Disconnected"),
            ReceiveErrorInner::Maybe(MaybeRecvError::RecvError(r)) => write!(f, "RecvError({r:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::DumpRecvError(d)) => write!(f, "DumpRecvError({d:?})"),
            ReceiveErrorInner::Maybe(MaybeRecvError::InvalidChannel(c)) => write!(f, "{c:?}"),
            ReceiveErrorInner::Recombine(e) => write!(f, "Recombine({e:?})"),
            ReceiveErrorInner::ExpectedPduBeginning => f.write_str("ExpectedPduBeginning"),
            ReceiveErrorInner::UnexpectedFirstFragment => f.write_str("UnexpectedFirstFragment"),
            ReceiveErrorInner::InvalidSduLength => f.write_str("InvalidSduLength"),
            ReceiveErrorInner::UnexpectedBufferLength(buffer_len, expected_len) => f
                .debug_struct("UnexpectedBufferLength")
                .field("buffer_len", buffer_len)
                .field("expected_len", expected_len)
                .finish(),
            ReceiveErrorInner::PeerSentWithNoCredits => f.write_str("PeerSentWithNoCredits"),
        }
    }
}

impl<L, C> core::fmt::Display for ReceiveError<L, C>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Display,
    C: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.inner {
            ReceiveErrorInner::Maybe(MaybeRecvError::Disconnected) => f.write_str("peer device disconnected"),
            ReceiveErrorInner::Maybe(MaybeRecvError::RecvError(r)) => write!(f, "receive error: {r:}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::DumpRecvError(d)) => write!(f, "receive error (dump): {d:?}"),
            ReceiveErrorInner::Maybe(MaybeRecvError::InvalidChannel(c)) => write!(f, "{c:}"),
            ReceiveErrorInner::Recombine(e) => write!(f, "recombine error: {e:}"),
            ReceiveErrorInner::ExpectedPduBeginning => f.write_str("expected first fragment of PDU"),
            ReceiveErrorInner::UnexpectedFirstFragment => f.write_str("unexpected first fragment of PDU"),
            ReceiveErrorInner::InvalidSduLength => f.write_str("SDU length field does not match SDU size"),
            ReceiveErrorInner::UnexpectedBufferLength(buffer_len, expected_len) => write!(
                f,
                "the buffer length is {}, not the expected length of {}",
                buffer_len, expected_len,
            ),
            ReceiveErrorInner::PeerSentWithNoCredits => {
                f.write_str("linked device sent credit based frame without having credits to send")
            }
        }
    }
}

#[cfg(feature = "std")]
impl<L, C> std::error::Error for ReceiveError<L, C>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        std::error::Error,
    C: std::error::Error,
{
}

enum ReceiveErrorInner<L: LogicalLink, C> {
    Maybe(MaybeRecvError<L::PhysicalLink, L::UnusedChannelResponse>),
    Recombine(C),
    ExpectedPduBeginning,
    UnexpectedFirstFragment,
    InvalidSduLength,
    UnexpectedBufferLength(usize, usize),
    PeerSentWithNoCredits,
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
