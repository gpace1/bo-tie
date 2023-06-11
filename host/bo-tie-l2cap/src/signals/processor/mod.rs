//! Processing of Received Signals

pub mod credit_counter;

use crate::signals::packets;
use crate::signals::packets::{CommandRejectResponse, LeCreditBasedConnectionResponse};
use crate::{ConnectionChannel, ConnectionChannelExt};
pub use credit_counter::{CreditBasedConnection, CreditKind};

/// The minimum MTU for a credit based frame
const MIN_LE_CREDIT_MTU: u16 = 23;

/// The minimum MPS for a credit based frame
const MIN_LE_CREDIT_MPS: u16 = 23;

/// The maximum MPS for a credit based frame
const MAX_LE_CREDIT_MPS: u16 = 25533;

/// Signals Processor
pub struct SignalsProcessor {
    credits: Option<CreditKind>,
}

macro_rules! invalid_cid_response {
    ($id:expr, $local:expr, $source:expr) => {
        CommandRejectResponse::new_invalid_cid_in_request(
            $id,
            $local.map(|l| l.get()).unwrap_or_default(),
            $source.map(|s| s.get()).unwrap_or_default(),
        )
    };
}

macro_rules! get_identifier {
    ($control_frame:expr) => {
        $control_frame
            .get(6)
            .copied()
            .and_then(|id| core::num::NonZeroU8::new(id))
    };
}

impl SignalsProcessor {
    pub fn builder() -> SignalsProcessorBuilder {
        SignalsProcessorBuilder::new()
    }

    fn get_initial_credits(&self) -> Option<u16> {
        self.credits.map(|kind| match kind {
            CreditKind::Owned(val) => val,
        })
    }

    pub async fn process<C>(
        &mut self,
        connection_channel: &C,
        control_frame: &[u8],
    ) -> Result<SignalProcessOutput, C::SendErr>
    where
        C: ConnectionChannel,
    {
        match control_frame.get(0) {
            Some(&packets::LeCreditBasedConnectionRequest::CODE) => {
                self.process_le_credit_based_connection(connection_channel, control_frame)
                    .await
            }
            Some(_) => self.process_unknown_signal(connection_channel, control_frame).await,
            None => Ok(SignalProcessOutput::Ignore),
        }
    }

    async fn process_unknown_signal<C>(
        &mut self,
        connection_channel: &C,
        control_frame: &[u8],
    ) -> Result<SignalProcessOutput, C::SendErr>
    where
        C: ConnectionChannel,
    {
        if let Some(identifier) = get_identifier!(control_frame) {
            let response = CommandRejectResponse::new_command_not_understood(identifier);

            let pdu = response.as_control_frame::<C::LogicalLinkType>();

            connection_channel.send(pdu).await?;

            Ok(SignalProcessOutput::Rejected(response))
        } else {
            Ok(SignalProcessOutput::Ignore)
        }
    }

    async fn process_le_credit_based_connection<C>(
        &mut self,
        connection_channel: &C,
        control_frame: &[u8],
    ) -> Result<SignalProcessOutput, C::SendErr>
    where
        C: ConnectionChannel,
    {
        let Some(initial_credits) = self.get_initial_credits() else {
            return self.process_unknown_signal(connection_channel, control_frame).await
        };

        match packets::LeCreditBasedConnectionRequest::try_from_control_frame(control_frame) {
            Ok(request) => {
                // If any of these conditions are false, the request is ignored
                if request.mtu >= MIN_LE_CREDIT_MTU
                    && request.mps >= MIN_LE_CREDIT_MPS
                    && request.mps <= MAX_LE_CREDIT_MPS
                {
                    let response = LeCreditBasedConnectionResponse {
                        identifier: request.identifier,
                        destination_dyn_cid: request.source_dyn_cid,
                        mtu: request.mtu,
                        mps: request.mps,
                        initial_credits,
                        result: Ok(()),
                    };

                    let le_credit_connection = CreditBasedConnection::new_le(&response, self.credits.unwrap());

                    connection_channel.send(response.as_control_frame()).await?;

                    Ok(SignalProcessOutput::LeCreditConnection(le_credit_connection))
                } else {
                    Ok(SignalProcessOutput::Ignore)
                }
            }
            Err(crate::pdu::ControlFrameError::InvalidChannelConnectionIds { id, local, source }) => {
                let response = invalid_cid_response!(id, local, source);

                connection_channel
                    .send(response.as_control_frame::<C::LogicalLinkType>())
                    .await?;

                Ok(SignalProcessOutput::Rejected(response))
            }
            _ => Ok(SignalProcessOutput::Ignore),
        }
    }
}

/// The return of method [`process`]
///
/// [`process`]: SignalsProcessor::process
pub enum SignalProcessOutput {
    Ignore,
    Rejected(CommandRejectResponse),
    LeCreditConnection(CreditBasedConnection),
}

/// Builder for a `SignalsProcessor`
///
/// The default configuration of a `SignalsProcessBuilder` is to create a `SignalsProcessor` that
/// returns a *Command not understood Response* for every signal processed by it. Signals must be
/// enabled through the methods of this builder in order to create a `SignalsProcessor` that send
/// back correct responses.
pub struct SignalsProcessorBuilder {
    enable_credits: Option<CreditKind>,
}

impl SignalsProcessorBuilder {
    /// Create a new `SignalsProcessorBuilder`
    pub fn new() -> SignalsProcessorBuilder {
        SignalsProcessorBuilder { enable_credits: None }
    }

    /// Enable credit based connection
    ///
    /// This enables the processing of the signals *LE Credit Based Connection Request* and *Credit
    /// Based Connection* and the creation of credit based L2CAP connections.
    ///
    /// Calling this method with `credit_count` equal to `None` will enable the maximum number of
    /// credits (equivalent to <u16>::MAX).
    ///
    /// # Enables
    /// * LE credit based connections
    /// * Enhanced credit based connections
    pub fn enable_credits<T>(&mut self, credit_count: T) -> &mut Self
    where
        T: Into<Option<CreditKind>>,
    {
        self.enable_credits = credit_count.into();
        self
    }

    pub fn build(self) -> SignalsProcessor {
        SignalsProcessor {
            credits: self.enable_credits,
        }
    }
}
