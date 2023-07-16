//! Structures for credit based channels

use crate::channel::{CreditBasedChannel, SendSduError};
use crate::pdu::credit_frame::PacketsIterator;
use crate::pdu::SduPacketsIterator;
use crate::{LogicalLink, PhysicalLink};

/// Unsent Credit Frames of a SDU
///
/// When a credit based channel runs out of peer credits it must halt sending of Credit Based Frames
/// (k-frames) until the peer device sends a *L2CAP flow control credit ind* containing one or more
/// credits.
pub struct UnsentCreditFrames<'a, L, T>
where
    L: LogicalLink,
    T: Iterator,
{
    credit_based_channel: &'a mut CreditBasedChannel<'a, L>,
    packets_iterator: PacketsIterator<T>,
}

impl<'a, L, T> UnsentCreditFrames<'a, L, T>
where
    L: LogicalLink,
    T: Iterator<Item = u8> + ExactSizeIterator,
{
    pub(crate) fn new(
        credit_based_channel: &'a mut CreditBasedChannel<'a, L>,
        packets_iterator: PacketsIterator<T>,
    ) -> Self {
        Self {
            credit_based_channel,
            packets_iterator,
        }
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
    pub async fn inc_and_send(
        mut self,
        amount: u16,
    ) -> Result<Option<UnsentCreditFrames<'a, L, T>>, SendSduError<<L::PhysicalLink as PhysicalLink>::SendErr>> {
        self.credit_based_channel.add_credits(amount);

        while self.credit_based_channel.peer_credits != 0 {
            self.credit_based_channel.peer_credits -= 1;

            if let Some(pdu) = self.packets_iterator.next() {
                self.credit_based_channel.send_pdu(pdu).await?;
            } else {
                return Ok(None);
            }
        }

        Ok(Some(self))
    }
}
