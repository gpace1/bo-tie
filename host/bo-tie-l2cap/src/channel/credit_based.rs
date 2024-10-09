//! Structures for credit based channels

use crate::channel::id::ChannelIdentifier;
use crate::channel::{CreditBasedChannel, SendSduError};
use crate::pdu::credit_frame::PacketsIterator;
use crate::pdu::SduPacketsIterator;
use crate::{LogicalLink, PhysicalLink};

/// Unsent Credit Frames of a SDU
///
/// When a credit based channel runs out of peer credits it must halt sending of Credit Based Frames
/// (k-frames) until the peer device sends a *L2CAP flow control credit ind* containing one or more
/// credits.
pub struct CreditServiceData<T: Iterator> {
    this_channel: ChannelIdentifier,
    peer_channel: ChannelIdentifier,
    packets_iterator: PacketsIterator<T>,
}

impl<T> CreditServiceData<T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    pub(crate) fn new(
        this_channel: ChannelIdentifier,
        peer_channel: ChannelIdentifier,
        packets_iterator: PacketsIterator<T>,
    ) -> Self {
        Self {
            this_channel,
            peer_channel,
            packets_iterator,
        }
    }

    /// Get the identifier of the channel that is sending this SDU
    pub fn get_this_channel_id(&self) -> ChannelIdentifier {
        self.this_channel
    }

    /// Get the identifier of the device that is receiving this SDU
    pub fn get_peer_channel_id(&self) -> ChannelIdentifier {
        self.peer_channel
    }

    async fn send<L: LogicalLink>(
        &mut self,
        credit_based_channel: &mut CreditBasedChannel<L>,
    ) -> Result<bool, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        while credit_based_channel.get_channel_data().peer_provided_credits != 0 && !self.packets_iterator.is_complete()
        {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better)
            let pdu = self.packets_iterator.next().map(|cfb| cfb.map_to_vec_iter()).unwrap();

            credit_based_channel.send_k_frame(pdu).await?;

            credit_based_channel.get_mut_channel_data().peer_provided_credits -= 1;
        }

        Ok(self.packets_iterator.is_complete())
    }

    /// Increase the peer credit count and send more credit based PDUs
    ///
    /// This first forcibly increases the credit count for the linked device and then starts sending
    /// credit based frames until either the full SDU is sent or the credits have reached zero.
    ///
    /// If all k-frames for the SDU are sent by the returned future will output `None`, otherwise
    /// this is returned if the increased `amount` of credits was not enough to send the SDU.
    ///
    /// Input `amount` should be the number of credits as indicated from a received *L2CAP flow
    /// control credit ind* signal.
    ///
    /// # Unsafe
    /// This does not validate that the peer device sent the credits to increase the credit amount.
    ///
    /// # Error
    /// The `credit_based_channel` must be the same channel that created this `UnsentCreditFrames`.
    ///
    pub async unsafe fn force_inc_and_send<L: LogicalLink>(
        mut self,
        credit_based_channel: &mut CreditBasedChannel<L>,
        amount: u16,
    ) -> Result<Option<CreditServiceData<T>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        if credit_based_channel.get_channel_data().peer_channel_id.get_channel() != self.peer_channel {
            return Err(SendSduError::IncorrectChannel);
        }

        credit_based_channel.force_add_peer_credits(amount);

        self.send(credit_based_channel)
            .await
            .map(|complete| (!complete).then_some(self))
    }

    /// Continue sending the service data unit (SDU)
    ///
    /// This can be used if credits were given directly to the `credit_based_channel`. This method will continue sending
    /// credit based frames until either the SDU was finished sending or the number of credits within the channel is
    /// zero.
    ///
    /// ```
    /// # use std::fmt::{Debug, Display};
    /// # use std::vec::IntoIter;
    /// # use bo_tie_core::buffer::TryExtend;
    /// # use bo_tie_l2cap::{CreditServiceData, LeULogicalLink, LeUNext, SendSduError};
    /// # use bo_tie_l2cap::{CreditBasedChannel, LogicalLink, PhysicalLink};
    /// # use bo_tie_l2cap::cid::{ChannelIdentifier, DynChannelId};
    /// # use bo_tie_l2cap::signals::packets::FlowControlCreditInd;
    /// # async fn example<P: PhysicalLink, B: , S>(
    /// #    mut le_link: LeULogicalLink<P, B, S>)
    /// # -> Result<(), Box<dyn std::error::Error>>
    /// # where
    /// #         P: PhysicalLink + 'static,
    /// #         B: TryExtend<u8> + Default + IntoIterator<Item = u8> + 'static,
    /// #         B::IntoIter: ExactSizeIterator,
    /// #         S: TryExtend<u8> + Default + 'static,
    /// #         P::RecvErr: Debug + Display,
    /// #         P::SendErr: Debug + Display, {
    /// # let channel_id = ChannelIdentifier::Le(DynChannelId::new_le(0x40).unwrap());
    /// # let sdu_data = b"this is the sdu data for this doc example".to_vec();
    /// let mut credit_service_data = le_link.get_credit_based_channel(channel_id)
    ///     .unwrap()
    ///     .send(sdu_data)
    ///     .await?;
    ///
    /// loop {
    ///     if credit_service_data.is_none() { break }
    ///
    ///     match le_link.next().await? {
    ///         LeUNext::CreditIndication { mut channel, .. } => {
    ///             let data_cid = credit_service_data
    ///                 .as_ref()
    ///                 .map(|c| c.get_this_channel_id());
    ///     
    ///             if data_cid == Some(channel.get_channel_id()) {
    ///                 credit_service_data = credit_service_data
    ///                     .unwrap()
    ///                     .continue_sending(&mut channel)
    ///                     .await?;
    ///             }
    ///         }
    ///     
    ///         // ...
    /// #       _ => (),
    ///     }
    /// }
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`add_peer_credits`]: CreditBasedChannel::add_peer_credits
    pub async fn continue_sending<L: LogicalLink>(
        mut self,
        credit_based_channel: &mut CreditBasedChannel<L>,
    ) -> Result<Option<CreditServiceData<T>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        if credit_based_channel.get_channel_data().peer_channel_id.get_channel() != self.peer_channel {
            return Err(SendSduError::IncorrectChannel);
        }

        self.send(credit_based_channel)
            .await
            .map(|complete| (!complete).then_some(self))
    }
}

/// Credits to give for a [`CreditBasedChannel`]
///
/// This is used for giving credits to the other device for a specific credit based channel. See method
/// [`prepare_credits_for_peer`] for how it is created and used.
///
/// [`prepare_credits_for_peer`]: CreditBasedChannel::prepare_credits_for_peer
#[must_use]
pub struct ChannelCredits {
    channel_id: ChannelIdentifier,
    how_many: u16,
}

impl ChannelCredits {
    pub(super) fn new(channel_id: ChannelIdentifier, how_many: u16) -> Self {
        ChannelCredits { channel_id, how_many }
    }

    /// Get the channel identifier of the channel the credits are for
    pub fn get_channel_id(&self) -> ChannelIdentifier {
        self.channel_id
    }

    /// Get the number of credits to be given
    ///
    /// This is the additional number of credits to be given to a linked device.
    pub fn get_credits(&self) -> u16 {
        self.how_many
    }
}
