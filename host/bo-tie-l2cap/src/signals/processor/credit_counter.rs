//! Credit Counting
//!
//! Credit based connections require the counting of 'credits' to provide flow control between two
//! connected devices (for a specific L2CAP channel)

use crate::channels::ChannelIdentifier;
use crate::pdu::credit_frame::PacketsIterator;
use crate::pdu::{FragmentL2capSdu, PacketsError};
use crate::signals::packets::LeCreditBasedConnectionResponse;
use crate::{ConnectionChannel, ConnectionChannelExt};
use core::num::NonZeroU8;

/// The kind of crediting to be enabled
///
/// Crediting can be done based on how credits are distributed to all connections. Crediting is
/// styled between all credit based flow control connections. There is no distinction between *LE
/// credit based connections* and regular *credit based connections* in terms of
///
/// # `Owned`
/// Credits are owned by the connections. The value of owned is the initial credit limit established
/// for each connection.
#[derive(Debug, Copy, Clone)]
pub enum CreditKind {
    Owned(u16),
}

impl CreditKind {
    fn get_local(&self) -> u16 {
        match self {
            CreditKind::Owned(val) => *val,
        }
    }

    fn set_local(&mut self, cnt: u16) {
        match self {
            CreditKind::Owned(val) => *val = cnt,
        }
    }
}

/// Credits
pub struct Credits(u16);

/// Connection Information for a L2CAP Credit Based Connection
pub struct CreditBasedConnection {
    channel: ChannelIdentifier,
    signaling_id: NonZeroU8,
    local_credits: CreditKind,
    remote_credits: u16,
    mps: u16,
    mtu: u16,
}

impl CreditBasedConnection {
    pub(crate) fn new_le(response: &LeCreditBasedConnectionResponse, local_credits: CreditKind) -> Self {
        let channel = response.get_destination_cid();

        let signaling_id = response.identifier;

        let remote_credits = response.initial_credits;

        let mps = response.mps;

        let mtu = response.mtu;

        Self {
            channel,
            signaling_id,
            local_credits,
            remote_credits,
            mps,
            mtu,
        }
    }

    /// Get the channel used for this Credit Based Connection
    pub fn channel(&self) -> ChannelIdentifier {
        self.channel
    }

    /// Get the total number of credits currently available by the remote device
    ///
    /// This returns the number of credits that can be "spent" in sending L2CAP credit based PDUs to
    /// the
    pub fn get_remote_credits(&self) -> u16 {
        self.remote_credits
    }

    /// Add credits received from the remote device
    ///
    /// Whenever the remote device sends credits via the *L2CAP flow control credit indication*
    /// signalling command (for this connection). The input type of `credits` comes from a signals
    /// processor in response to processing this signalling command.
    fn add_remote_credits(&mut self, credits: Credits) {
        self.remote_credits = self.remote_credits.checked_add(credits.0).unwrap_or(<u16>::MAX)
    }

    /// Get the local credit count
    pub fn get_local_credits(&self) -> u16 {
        self.local_credits.get_local()
    }

    /// Get the maximum PDU payload size (MPS)
    ///
    /// This is the maximum size of the payload of every PDU used to transfer a SDU
    pub fn get_mps(&self) -> u16 {
        self.mps
    }

    /// Get the maximum transmission unit (MTU)
    ///
    /// This is the maximum size of a SDU
    pub fn get_mtu(&self) -> u16 {
        self.mtu
    }

    /// Add local credits
    ///
    /// Add credits to the local credit count. This will also send a *L2CAP flow control credit
    /// indication* to the remote connected device.
    ///
    /// # Note
    /// If the `amount` plus the current count is larger than the maximum value of a `u16`, then the
    /// local count is set to `<u16>::MAX` and the remote is sent a credit indication signal
    /// containing a credit count equal to difference between the local count and the maximum.
    pub async fn add_local_credits<C>(&mut self, connection_channel: &C, amount: u16) -> Result<(), C::SendErr>
    where
        C: ConnectionChannel,
    {
        use crate::signals::packets::FlowControlCreditInd;

        let amount = match self.local_credits.get_local().checked_add(amount) {
            Some(local_credits) => {
                self.local_credits.set_local(local_credits);

                amount
            }
            None => {
                let amount = <u16>::MAX - self.local_credits.get_local();

                self.local_credits.set_local(<u16>::MAX);

                if amount != 0 {
                    amount
                } else {
                    return Ok(());
                }
            }
        };

        match self.channel {
            ChannelIdentifier::Acl(crate::channels::AclCid::DynamicallyAllocated(dyn_cid)) => {
                let indication = FlowControlCreditInd::new_acl(self.signaling_id, dyn_cid, amount);

                connection_channel
                    .send(indication.as_control_frame::<crate::AclU>())
                    .await
            }
            ChannelIdentifier::Le(crate::channels::LeCid::DynamicallyAllocated(dyn_cid)) => {
                let indication = FlowControlCreditInd::new_le(self.signaling_id, dyn_cid, amount);

                connection_channel
                    .send(indication.as_control_frame::<crate::LeU>())
                    .await
            }
            _ => unreachable!(),
        }
    }

    /// Create a SDU sender
    ///
    /// `SendSdu` used to ensure that k-frames containing the SDU are only sent while there are
    /// credits to send to the remote device.
    pub async fn send_sdu<'a, T>(
        &'a mut self,
        sdu: &'a crate::pdu::credit_frame::CreditBasedSdu<T>,
    ) -> Result<SendSdu<'a, T>, PacketsError>
    where
        T: core::ops::Deref<Target = [u8]>,
    {
        let packets_iter = sdu.as_packets()?.peekable();

        Ok(SendSdu {
            connection: self,
            packets_iter,
        })
    }
}

pub struct SendSdu<'a, T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    connection: &'a mut CreditBasedConnection,
    packets_iter: core::iter::Peekable<PacketsIterator<'a, T>>,
}

impl<'a, T> SendSdu<'a, T>
where
    T: core::ops::Deref<Target = [u8]>,
{
    /// Add remote credits
    ///
    /// As the `CreditBasedConnection` is borrowed by this `SendSdu`, remote credits are added here.
    pub fn add_remote_credits(&mut self, credits: Credits) {
        self.connection.add_remote_credits(credits)
    }

    /// Send `PDU`'s of this SDU to the remote device
    ///
    /// This will send *as many* k-frames to the remote device as there are credits. If all PDUs of
    /// the SDU are sent to the remote device, this will return `None`. If there are PDUs still
    /// waiting to be sent, then this is returned.
    ///
    /// When a `SendSdu` is returned, remote credits must be added via the [`add_remote_credits`]
    /// method before `send_as_many` can be used to send more PDUs
    ///
    /// [`add_remote_credits`]: SendSdu::add_remote_credits
    pub async fn send_as_many<C>(mut self, connection_channel: &C) -> Result<Option<SendSdu<'a, T>>, C::SendErr>
    where
        C: ConnectionChannel,
    {
        while self.connection.remote_credits != 0 {
            self.connection.remote_credits -= 1;

            let Some(packet) = self.packets_iter.next() else {
                return Ok(None)
            };

            connection_channel.send(packet).await?;
        }

        let more = self.packets_iter.peek().is_none();

        if more {
            Ok(Some(self))
        } else {
            Ok(None)
        }
    }
}
