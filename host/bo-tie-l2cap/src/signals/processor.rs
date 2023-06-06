//! Processing of Received Signals

use crate::pdu::FragmentL2capPdu;
use crate::signals::packets;
use crate::signals::packets::{CommandRejectResponse, LeCreditBasedConnectionResponse};
use crate::ConnectionChannel;
use std::num::NonZeroU8;

/// The minimum MTU for a credit based frame
const MIN_LE_CREDIT_MTU: u16 = 23;

/// The minimum MPS for a credit based frame
const MIN_LE_CREDIT_MPS: u16 = 23;

/// The maximum MPS for a credit based frame
const MAX_LE_CREDIT_MPS: u16 = 25533;

/// Signals Processor
pub struct SignalsProcessor {
    credits: Option<CreditKind>,
    identifier: NonZeroU8,
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
impl SignalsProcessor {
    pub fn builder() -> SignalsProcessorBuilder {
        SignalsProcessorBuilder::new()
    }

    fn send<C, T>(&mut self, connection_channel: &C, signal: T)
    where
        C: ConnectionChannel,
        T: FragmentL2capPdu,
    {
    }

    pub async fn process<C>(
        &mut self,
        connection_channel: &C,
        control_frame: &[u8],
    ) -> Result<SignalProcessResult, C::SendErr>
    where
        C: crate::ConnectionChannel,
    {
        match control_frame.get(0) {
            Some(&packets::LeCreditBasedConnectionRequest::CODE) => {
                self.process_le_credit_based_connection(connection_channel, control_frame)
                    .await
            }
            _ => Ok(SignalProcessResult::Ignore),
        }
    }

    async fn process_le_credit_based_connection<C>(
        &mut self,
        connection_channel: &C,
        control_frame: &[u8],
    ) -> Result<SignalProcessResult, C::SendErr>
    where
        C: crate::ConnectionChannel,
    {
        use crate::ConnectionChannelExt;

        match packets::LeCreditBasedConnectionRequest::try_from_control_frame(control_frame) {
            Ok(request) => {
                // If any of these conditions are false, the request is ignored
                if request.mtu >= MIN_LE_CREDIT_MTU
                    && request.mps >= MIN_LE_CREDIT_MPS
                    && request.mps <= MAX_LE_CREDIT_MPS
                {
                    let response = packets::LeCreditBasedConnectionResponse {
                        identifier: self.identifier,
                        destination_dyn_cid: request.source_dyn_cid,
                        mtu: request.mtu,
                        mps: request.mps,
                        initial_credits: 0,
                        result: Ok(()),
                    };

                    let le_credit_connection = LeCreditConnection::new(&response);

                    connection_channel.send(response.as_control_frame()).await?;

                    Ok(SignalProcessResult::LeCreditConnection(le_credit_connection))
                } else {
                    Ok(SignalProcessResult::Ignore)
                }
            }
            Err(crate::pdu::ControlFrameError::InvalidChannelConnectionIds { id, local, source }) => {
                connection_channel
                    .send(invalid_cid_response!(id, local, source).as_le_control_frame())
                    .await?;

                Ok(SignalProcessResult::Ignore)
            }
            _ => Ok(SignalProcessResult::Ignore),
        }
    }
}

/// The return of method [`process`]
///
/// [`process`]: SignalsProcessor::process
pub enum SignalProcessResult {
    Ignore,
    Rejected(packets::CommandRejectResponse),
    LeCreditConnection(LeCreditConnection),
}

/// Builder for a `SignalsProcessor`
///
/// The default configuration of a `SignalsProcessBuilder` is to create a `SignalsProcessor` that
/// returns *Command Reject Response* for every signal processed by it. Signals must be enabled
/// through the methods of the builder in order for the created `SignalsProcessor` to generate
/// corresponding responses to request signals.
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
    pub fn enable_credits<T>(&mut self, credit_count: T) -> &mut Self
    where
        T: Into<Option<CreditKind>>,
    {
        self.enable_credits = credit_count.into();
        self
    }

    pub fn build(self) -> SignalsProcessor {
        let identifier = NonZeroU8::new(1).unwrap();

        SignalsProcessor {
            credits: self.enable_credits,
            identifier,
        }
    }
}

/// The kind of crediting to be enabled
///
/// Crediting can be done based on how credits are distributed to all connections. Crediting is
/// styled between all credit based flow control connections. There is no distinction between *LE
/// credit based connections* and regular *credit based connections* in terms of
///
/// # `Owned`
/// Credits are owned by the connections. The value of owned is the initial credit limit established
/// for each connection.
pub enum CreditKind {
    Owned(u16),
}

/// A L2CAP LE Credit Based Connection Processor
///
/// A credit based connection needs to monitor
pub struct LeCreditConnection;

impl LeCreditConnection {
    fn new(response: &LeCreditBasedConnectionResponse) -> Self {
        Self
    }
}
