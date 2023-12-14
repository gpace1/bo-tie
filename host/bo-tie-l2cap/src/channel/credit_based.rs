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
    destination_channel: ChannelIdentifier,
    packets_iterator: PacketsIterator<T>,
}

impl<T> CreditServiceData<T>
where
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    pub(crate) fn new(destination_channel: ChannelIdentifier, packets_iterator: PacketsIterator<T>) -> Self {
        Self {
            destination_channel,
            packets_iterator,
        }
    }

    async fn send<L: LogicalLink>(
        &mut self,
        credit_based_channel: &mut CreditBasedChannel<'_, L>,
    ) -> Result<bool, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        while credit_based_channel.peer_credits != 0 && !self.packets_iterator.is_complete() {
            // todo remove map_to_vec_iter (this is a workaround until rust's borrow check gets better)
            let next_pdu = self.packets_iterator.next().map(|cfb| cfb.map_to_vec_iter()).unwrap();

            credit_based_channel.send_pdu(next_pdu).await?;

            credit_based_channel.peer_credits -= 1;
        }

        Ok(self.packets_iterator.is_complete())
    }

    /// Increase the peer credit count and send more credit based PDUs
    ///
    /// This first increases the credit count for the linked device and then starts sending k-frames
    /// until either the full SDU is sent or the credits have reached zero (again).
    ///
    /// If all k-frames for the SDU are sent by the returned future will output `None`, otherwise
    /// this is returned if the increased `amount` of credits was not enough to send the SDU.
    ///
    /// Input `amount` should be the number of credits as indicated from a received *L2CAP flow
    /// control credit ind* signal.
    ///
    /// # Error
    /// The `credit_based_channel` must be the same channel that created this `UnsentCreditFrames`.
    pub async fn inc_and_send<L: LogicalLink>(
        mut self,
        credit_based_channel: &mut CreditBasedChannel<'_, L>,
        amount: u16,
    ) -> Result<Option<CreditServiceData<T>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        if credit_based_channel.peer_channel_id.get_channel() != self.destination_channel {
            return Err(SendSduError::IncorrectChannel);
        }

        credit_based_channel.add_peer_credits(amount);

        self.send(credit_based_channel)
            .await
            .map(|complete| complete.then_some(self))
    }

    /// Continue sending the service data unit (SDU)
    ///
    /// This can be used if credits were given directly to the `credit_based_channel`. This method will continue sending
    /// credit based frames until either the SDU was finished sending or the number of credits within the channel is
    /// zero. This method is typically called after [`add_peer_credits`].
    ///
    /// ```
    /// # use std::vec::IntoIter;
    /// # use bo_tie_l2cap::channel::{CreditServiceData, SendSduError};
    /// # use bo_tie_l2cap::{CreditBasedChannel, LogicalLink, PhysicalLink};
    /// # use bo_tie_l2cap::signals::packets::FlowControlCreditInd;
    /// # async fn example<L: LogicalLink>(credit_service_data: CreditServiceData<IntoIter<u8>>, mut credit_based_channel: CreditBasedChannel<'_, L>, flow_control_credit_ind: FlowControlCreditInd)
    /// # -> Result<(), SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
    /// credit_based_channel.add_peer_credits(flow_control_credit_ind.get_credits());
    ///
    /// credit_service_data.continue_sending(&mut credit_based_channel).await?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// [`add_peer_credits`]: CreditBasedChannel::add_peer_credits
    pub async fn continue_sending<L: LogicalLink>(
        mut self,
        credit_based_channel: &mut CreditBasedChannel<'_, L>,
    ) -> Result<Option<CreditServiceData<T>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        if credit_based_channel.peer_channel_id.get_channel() != self.destination_channel {
            return Err(SendSduError::IncorrectChannel);
        }

        self.send(credit_based_channel)
            .await
            .map(|complete| complete.then_some(self))
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
