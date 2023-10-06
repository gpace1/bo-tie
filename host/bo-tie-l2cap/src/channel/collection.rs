//! Channel Collections
//!
//! When lots of connections are used, it can be easier to put the channels into a collection and
//! send/receive data through it.
//!
//! A collection works by being the await point between all the channels within the collection and
//! the context that is polling them.

use crate::channel::id::ChannelIdentifier;
use crate::channel::shared::ReceiveDataProcessor;
use crate::channel::{ReceiveError, UnusedChannelResponse};
use crate::pdu::credit_frame::CreditBasedFrame;
use crate::pdu::{CreditBasedSdu, RecombineL2capPdu};
use crate::{CreditBasedChannel, LogicalLink, PhysicalLink, SignallingChannel};
use alloc::vec::Vec;
use bo_tie_core::buffer::TryExtend;

macro_rules! send_credit_packets {
    ($channel:expr, $packets:expr, $opt_sdu_packets:expr) => {{
        use crate::pdu::SduPacketsIterator;

        let mut is_next_none = true;

        while $channel.peer_credits != 0 {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better with async)
            let next = $packets.next().map(|cfb| cfb.map_to_vec_iter());

            is_next_none = next.is_none();

            if let Some(pdu) = next {
                $channel
                    .send_pdu(pdu)
                    .await
                    .map_err(|e| SharedCreditError::SduSendError(e))?;
            } else {
                break;
            }
        }

        if is_next_none {
            Ok(true)
        } else {
            *$opt_sdu_packets = Some($packets);

            Ok(false)
        }
    }};
}

struct SharedCreditItem<'a, L: LogicalLink, S: Iterator> {
    channel: CreditBasedChannel<'a, L>,
    to_send_sdu: Option<crate::pdu::credit_frame::PacketsIterator<S>>,
    to_recv_sdu: Vec<CreditBasedFrame<Vec<u8>>>,
    to_recv_required_credits: usize,
}

impl<'a, L: LogicalLink, S: Iterator> SharedCreditItem<'a, L, S> {
    fn new(channel: CreditBasedChannel<'a, L>) -> Self {
        let to_send_sdu = None;
        let to_recv_sdu = alloc::vec::Vec::new();
        let to_recv_given_credits = 0;

        Self {
            channel,
            to_send_sdu,
            to_recv_sdu,
            to_recv_required_credits: to_recv_given_credits,
        }
    }
}

/// A collection of channels that share the credits of this device
///
/// Instead of individually managing credits for each channel, this will manage a set of credits
/// between the
///
/// The collection is made up of `CreditBasedChannels` organized by their channel identifier (which
/// can get retrieved via the [`get_this_channel_id`] method). Adding a channel to the collection
/// consumes that channel, so the `ChannelIdentifier` for the channel will need to be stored before
/// this is done in order to call `send` and `remove`
///
/// [`get_this_channel_id`]: CreditBasedChannel::get_this_channel_id
pub struct SharedCredit<'a, L: LogicalLink, S: Iterator> {
    extra_credits: usize,
    next_to_credit: usize,
    channels: alloc::vec::Vec<SharedCreditItem<'a, L, S>>,
}

impl<'a, L, S> SharedCredit<'a, L, S>
where
    L: LogicalLink,
    S: Iterator<Item = u8> + ExactSizeIterator,
{
    /// Create a new `SharedCreditCollection`
    ///
    /// This creates a new `SharedCreditCollection` with input `shared_credits` as the staring
    /// amount for the total credits given to the peer.
    pub fn new(extra_credits: usize) -> Self {
        let credits = extra_credits;

        let next_to_credit = 0;

        let channels = alloc::vec::Vec::new();

        SharedCredit {
            extra_credits: credits,
            next_to_credit,
            channels,
        }
    }

    /// Increase the credits of this collection
    pub async fn increase_credits(
        &mut self,
        signalling_channel: &mut SignallingChannel<'a, L>,
        mut how_many: usize,
    ) -> Result<(), SharedCreditError<L>> {
        self.extra_credits = self.extra_credits.checked_add(how_many).unwrap_or(<usize>::MAX);

        for index in (self.next_to_credit..self.channels.len()).chain(0..self.next_to_credit) {
            // end when there is no more credits
            if how_many == 0 {
                self.next_to_credit = index;

                return Ok(());
            }

            let item = &mut self.channels[index];

            if !item.to_recv_sdu.is_empty() {
                // the current channel has a pending reception

                let sdu_len: usize = item.to_recv_sdu[0].get_sdu_length().unwrap().into();

                let len_so_far: usize = item.to_recv_sdu.iter().map(|k_frame| k_frame.get_payload().len()).sum();

                let mps: usize = item.channel.get_mps().into();

                // the minimum number of credits required to complete the SDU
                //
                // note: the extra +1 whenever mps is a multiple of the difference is fine as it
                //       just means the channel gets the next baseline credit a little early.
                let min_credit_req = (sdu_len - len_so_far) / mps + 1;

                let given_credits = <u16>::try_from(core::cmp::min(how_many, min_credit_req)).unwrap_or(<u16>::MAX);

                signalling_channel
                    .give_credits_to_peer(&item.channel, given_credits)
                    .await
                    .map_err(|e| SharedCreditError::SendError(e))?;

                how_many -= <usize>::from(given_credits);
            } else {
                signalling_channel
                    .give_credits_to_peer(&item.channel, 1)
                    .await
                    .map_err(|e| SharedCreditError::SendError(e))?;

                how_many -= 1;
            }
        }

        self.extra_credits += how_many;

        Ok(())
    }

    /// A a `CreditBasedChannel` to the collection
    ///
    /// This will add `channel` to this collection and return the channel identifier of `channel`.
    ///
    /// # Note
    /// The current credit count given to the connected peer is unchanged for the added channel.
    /// The credits given to the peer will not be managed by the collection until the credit count
    /// reaches zero.
    pub fn add(&mut self, channel: CreditBasedChannel<'a, L>) -> ChannelIdentifier {
        match self
            .channels
            .binary_search_by(|item| item.channel.get_this_channel_id().cmp(&channel.get_this_channel_id()))
        {
            Ok(_) => unreachable!(),
            Err(index) => {
                let item = SharedCreditItem::new(channel);

                self.channels.insert(index, item);

                self.channels[index].channel.get_this_channel_id()
            }
        }
    }

    /// Remove a `CreditBasedChannel` by its `ChannelIdentifier`
    ///
    /// If there is a `CreditBasedChannel` that has the same channel identifier as input
    /// `identifier` it is removed from the collection and returned.
    ///
    /// # Note
    /// If it is desired to disconnect the channel, call the method [`disconnect`]
    /// 
    /// [`disconnect`]: SharedCredit::disconnect
    pub fn remove(&mut self, identifer: ChannelIdentifier) -> Option<CreditBasedChannel<'a, L>> {
        match self
            .channels
            .binary_search_by(|item| item.channel.get_this_channel_id().cmp(&identifer))
        {
            Ok(index) => self.channels.remove(index).channel.into(),
            Err(_) => None,
        }
    }

    /// Initiation a Disconnect of channel
    ///
    /// If there is a credit based channel for the provided `identifier`, the initiate disconnect
    /// signal will be sent to the peer device. The channel is also removed from the collection and
    /// is output by the returned future.
    ///
    /// # Notes
    /// 1) The disconnect response signal is not awaited for by the returned future.
    /// 2) If the init disconnect signal is received for the channel identified by `identifier`, use
    ///    method [`remove`] to take it from the collection.
    ///
    /// [`remove`]: SharedCredit::remove
    pub async fn disconnect(
        &mut self,
        signalling_channel: &mut SignallingChannel<'a, L>,
        identifier: ChannelIdentifier,
    ) -> Result<CreditBasedChannel<'a, L>, SharedCreditError<L>> {
        let channel = self
            .remove(identifier)
            .ok_or_else(|| SharedCreditError::ChannelDoesNotExist)?;

        signalling_channel
            .request_connection_disconnection(&channel)
            .await
            .map_err(|e| SharedCreditError::SendError(e))?;

        Ok(channel)
    }

    /// Stored sending of a service data unit (SDU).
    ///
    /// This creates a future that will attempt to send the entire SDU over the credit based
    /// connection. However, if there is not enough credits to send the SDU, the remaining data will
    /// be saved by this collection until more credits are given by the connected device.
    ///
    /// The limitation of this method is that only SDU can be saved at a time. Until that SDU is
    /// completely sent to the connected peer, this method cannot be called again. If the returned
    /// future is polled and it detects that there is currently a saved
    ///
    /// # Output
    /// The output boolean to used to indicate that the `sdu` was fully sent. When `true` this
    /// this method can be called again with a new `sdu`.
    pub async fn saved_send<T>(&mut self, sdu: T, id: ChannelIdentifier) -> Result<bool, SharedCreditError<L>>
    where
        T: IntoIterator<Item = u8, IntoIter = S>,
        S: Iterator<Item = u8> + ExactSizeIterator,
    {
        use crate::pdu::FragmentL2capSdu;

        let item = match self
            .channels
            .binary_search_by(|item| item.channel.get_this_channel_id().cmp(&id))
        {
            Ok(channel) => self.channels.get_mut(channel).unwrap(),
            Err(_) => return Err(SharedCreditError::ChannelDoesNotExist),
        };

        let channel = &mut item.channel;

        let opt_sdu_packets = &mut item.to_send_sdu;

        if !opt_sdu_packets.is_none() {
            return Err(SharedCreditError::PendingSdu);
        }

        let sdu_iter = sdu.into_iter();

        let c_sdu = CreditBasedSdu::new(sdu_iter, channel.get_peer_channel_id(), channel.get_mps());

        let mut packets = c_sdu.into_packets().map_err(|e| SharedCreditError::PacketsError(e))?;

        send_credit_packets!(channel, packets, opt_sdu_packets)
    }

    /// Add peer provided credits for sending
    ///
    /// If the channel within the `indication` exists within this collection, it will be given the
    /// credits in the `indication`. If this channel is in the middle of sending a SDU (due to
    /// previously not having any more credits) this method will use the new credits within the
    /// `indication` to continue sending k-frames until either the rest of SDU is sent or all
    /// credits within the indication were used.
    ///
    /// Credits are saved if either there was no pending SDU data to be sent, or there were credits
    /// left over after fully sending a stored SDU.
    ///
    /// # Output
    /// The output is `true` unless the amount of credits given were not enough to finish sending
    /// the currently stored SDU to the channel.
    ///
    /// # Error
    /// An error is output by the returned future if there is no channel within this collection with
    /// the same channel ID as in the input `indication`.
    pub async fn add_peer_credits(
        &mut self,
        indication: crate::signals::packets::FlowControlCreditInd,
    ) -> Result<bool, SharedCreditError<L>> {
        let id = indication.get_cid();

        if let Ok(index) = self
            .channels
            .binary_search_by(|item| item.channel.get_this_channel_id().cmp(&id))
        {
            let item = self.channels.get_mut(index).unwrap();

            item.channel.add_peer_credits(indication.get_credits());

            if let Some(mut packets) = item.to_send_sdu.take() {
                send_credit_packets!(&mut item.channel, packets, &mut item.to_send_sdu)
            } else {
                Ok(true)
            }
        } else {
            Err(SharedCreditError::ChannelDoesNotExist)
        }
    }

    /// Check if a channel has a pending SDU to send
    ///
    /// # Note
    /// `false` is returned if there is no channel with the specified `id` within this collection.
    pub fn pending_send(&self, id: ChannelIdentifier) -> bool {
        match self
            .channels
            .binary_search_by(|item| item.channel.get_this_channel_id().cmp(&id))
        {
            Ok(index) => self.channels[index].to_send_sdu.is_some(),
            Err(_) => false,
        }
    }

    async fn receive_frame_for(
        &mut self,
        index: usize,
    ) -> Result<Option<(ChannelIdentifier, Vec<u8>)>, CollectionReceiveError<L>> {
        let item = &mut self.channels[index];

        let k_frame = item.channel.receive_frame().await?;

        item.to_recv_sdu.push(k_frame);

        let sdu_len = item
            .to_recv_sdu
            .first()
            .unwrap()
            .get_sdu_length()
            .ok_or_else(|| ReceiveError::new_invalid_sdu_length())?;

        let to_recv_sdu_len: usize = item.to_recv_sdu.iter().map(|k_frame| k_frame.get_payload().len()).sum();

        if (sdu_len as usize) == to_recv_sdu_len {
            let data: Vec<u8> = core::mem::take(&mut item.to_recv_sdu)
                .into_iter()
                .map(|k_frame| k_frame.into_payload())
                .flatten()
                .collect();

            Ok(Some((item.channel.get_this_channel_id(), data)))
        } else if (sdu_len as usize) < to_recv_sdu_len {
            Err(ReceiveError::new_invalid_sdu_length().into())
        } else {
            Ok(None)
        }
    }

    /// Set the minimum amount of credits required for the peer to send the full SDU
    fn set_required_credits(&mut self, index: usize) -> usize {
        let item = &mut self.channels[index];

        let channel = &item.channel;

        let frames = &item.to_recv_sdu;

        // this should only be called when the first k-frame is received
        debug_assert_eq!(frames.len(), 1);

        let sdu_len = frames.first().expect("no first").get_sdu_length().expect("no sdu len");

        let mps_len = channel.get_mps();

        let acquired_len = <u16>::try_from(frames.iter().map(|k_frame| k_frame.get_payload().len()).sum::<usize>())
            .expect("frame data exceeded maximum SDU capacity");

        // this should have already been evaluated
        debug_assert!(sdu_len > acquired_len, "invalid current len");

        let remaining_len = sdu_len - acquired_len;

        let required_credits = remaining_len / mps_len + if remaining_len % mps_len != 0 { 1 } else { 0 };

        let given_credits = core::cmp::min(required_credits as usize, self.extra_credits);

        self.extra_credits -= given_credits;

        given_credits
    }

    async fn give_credits_to(&mut self, index: usize, how_many: usize) -> Result<(), CollectionReceiveError<L>> {
        use crate::link_flavor::LinkFlavor;
        use crate::pdu::{FragmentIterator, FragmentL2capPdu, L2capFragment};
        use core::num::NonZeroU8;

        let channel_id = self.channels[index].channel.get_this_channel_id();

        let indication =
            crate::signals::packets::FlowControlCreditInd::new(NonZeroU8::new(1).unwrap(), channel_id, how_many as u16);

        let mut is_first = true;

        let fragmentation_size = self
            .channels
            .first()
            .unwrap()
            .channel
            .logical_link
            .get_shared_link()
            .get_fragmentation_size();

        let mut fragments_iter = indication
            .into_control_frame(L::Flavor::get_signaling_channel().unwrap())
            .into_fragments(fragmentation_size)
            .unwrap();

        while let Some(data) = fragments_iter.next() {
            let mut fragment = Some(L2capFragment::new(is_first, data));

            is_first = false;

            let shared_link = self.channels.first().unwrap().channel.logical_link.get_shared_link();

            core::future::poll_fn(move |_| {
                shared_link.maybe_send(L::Flavor::get_signaling_channel().unwrap(), fragment.take().unwrap())
            })
            .await
            .await
            .map_err(|e| CollectionReceiveError::SendIndicationError(e))?;
        }

        Ok(())
    }

    async fn process_dump_data(&mut self) -> Result<(), CollectionReceiveError<L>> {
        let channel = &mut self.channels.first_mut().unwrap().channel;

        let opt_response = channel.logical_link.get_shared_link().dump_frame().await?;

        if let Some(response) = opt_response {
            channel
                .send_pdu_inner(response)
                .await
                .map_err(|_| ReceiveError::new_disconnected())?;
        }

        Ok(())
    }

    /// Receive a service data unit (SDU) for a channel in the collection
    pub async fn receive(&mut self) -> Result<(ChannelIdentifier, Vec<u8>), CollectionReceiveError<L>> {
        // initially it doesn't matter which channel is used
        // until the receiving channel is actually determined.
        loop {
            match self.channels.first_mut() {
                None => return Err(CollectionReceiveError::CollectionIsEmpty),
                Some(first) => {
                    let opt_index = first
                        .channel
                        .logical_link
                        .get_shared_link()
                        .pre_receive_collection::<L, _, _>(|id| {
                            self.channels
                                .binary_search_by(|item| item.channel.get_this_channel_id().cmp(&id))
                                .ok()
                        })
                        .await?;

                    match opt_index {
                        Some(index) => {
                            if let Some(ret) = self.receive_frame_for(index).await? {
                                self.channels[index].to_recv_sdu.clear();

                                break Ok(ret);
                            } else if self.channels[index].to_recv_sdu.len() == 1 {
                                let credit_count = self.set_required_credits(index);

                                self.channels[index].to_recv_required_credits = credit_count;

                                self.give_credits_to(index, credit_count).await?;
                            } else if self.channels[index].to_recv_required_credits == 0 {
                                // this should only occur when the peer did
                                // not use the full mps for every k-frame.

                                self.channels[index].to_recv_required_credits += 1;

                                self.give_credits_to(index, 1).await?;
                            }

                            self.channels[index].to_recv_required_credits -=
                                self.channels[index].to_recv_required_credits;
                        }
                        None => self.process_dump_data().await?,
                    }
                }
            }
        }
    }
}

/// Error returned by the method `disconnect`
pub enum SharedCreditError<L: LogicalLink> {
    ChannelDoesNotExist,
    PendingSdu,
    SendError(<L::PhysicalLink as crate::PhysicalLink>::SendErr),
    SduSendError(crate::channel::SendSduError<<L::PhysicalLink as crate::PhysicalLink>::SendErr>),
    PacketsError(crate::pdu::PacketsError),
}

impl<L: LogicalLink> core::fmt::Debug for SharedCreditError<L>
where
    <L::PhysicalLink as crate::PhysicalLink>::SendErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SharedCreditError::ChannelDoesNotExist => f.debug_tuple("ChannelDoesNotExist").finish(),
            SharedCreditError::PendingSdu => f.debug_tuple("PendingSdu").finish(),
            SharedCreditError::SendError(e) => f.debug_tuple("SendError").field(e).finish(),
            SharedCreditError::SduSendError(e) => f.debug_tuple("SduSendError").field(e).finish(),
            SharedCreditError::PacketsError(e) => f.debug_tuple("PacketsError").field(e).finish(),
        }
    }
}

impl<L: LogicalLink> core::fmt::Display for SharedCreditError<L>
where
    <L::PhysicalLink as crate::PhysicalLink>::SendErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            SharedCreditError::ChannelDoesNotExist => f.write_str("channel does not exist"),
            SharedCreditError::PendingSdu => {
                f.write_str("there is pending sdu to be sent for the specified credit based channel")
            }
            SharedCreditError::SendError(e) => write!(f, "{e}"),
            SharedCreditError::SduSendError(e) => write!(f, "{e}"),
            SharedCreditError::PacketsError(e) => write!(f, "{e}"),
        }
    }
}

#[cfg(feature = "std")]
impl<L: LogicalLink> std::error::Error for SharedCreditError<L> where
    <L::PhysicalLink as crate::PhysicalLink>::SendErr: core::fmt::Debug + core::fmt::Display
{
}

pub enum CollectionReceiveError<L: LogicalLink> {
    CollectionIsEmpty,
    ChannelNoLongerExistsInCollection,
    ReceiveError(
        ReceiveError<
            L,
            <Vec<u8> as TryExtend<u8>>::Error,
            <CreditBasedFrame<Vec<u8>> as RecombineL2capPdu>::RecombineError,
        >,
    ),
    SendIndicationError(<L::PhysicalLink as PhysicalLink>::SendErr),
}

impl<T, L: LogicalLink> From<T> for CollectionReceiveError<L>
where
    T: Into<
        ReceiveError<
            L,
            <Vec<u8> as TryExtend<u8>>::Error,
            <CreditBasedFrame<Vec<u8>> as RecombineL2capPdu>::RecombineError,
        >,
    >,
{
    fn from(e: T) -> Self {
        CollectionReceiveError::ReceiveError(e.into())
    }
}

impl<L> core::fmt::Debug for CollectionReceiveError<L>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Debug,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Debug,
    <L::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CollectionReceiveError::CollectionIsEmpty => f.debug_tuple("CollectionIsEmpty").finish(),
            CollectionReceiveError::ChannelNoLongerExistsInCollection => {
                f.debug_tuple("ChannelNoLongerExistsInCollection").finish()
            }
            CollectionReceiveError::ReceiveError(e) => f.debug_tuple("ReceiveError").field(e).finish(),
            CollectionReceiveError::SendIndicationError(e) => f.debug_tuple("SendIndicationError").field(e).finish(),
        }
    }
}

impl<L> core::fmt::Display for CollectionReceiveError<L>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: core::fmt::Display,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        core::fmt::Display,
    <L::PhysicalLink as PhysicalLink>::SendErr: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            CollectionReceiveError::CollectionIsEmpty => {
                f.write_str("cannot receive a SDU if the collection has no channels")
            }
            CollectionReceiveError::ChannelNoLongerExistsInCollection => {
                f.write_str("channel no longer exists in collection")
            }
            CollectionReceiveError::ReceiveError(e) => core::fmt::Display::fmt(e, f),
            CollectionReceiveError::SendIndicationError(e) => {
                write!(f, r#"failed to send L2CAP signal "flow control indication", {e}"#)
            }
        }
    }
}

#[cfg(feature = "std")]
impl<L> std::error::Error for CollectionReceiveError<L>
where
    L: LogicalLink,
    <L::PhysicalLink as PhysicalLink>::RecvErr: std::error::Error,
    <<L::UnusedChannelResponse as UnusedChannelResponse>::ReceiveProcessor as ReceiveDataProcessor>::Error:
        std::error::Error,
    <L::PhysicalLink as PhysicalLink>::SendErr: std::error::Error,
{
}
