//! Processing of Received Signals

use crate::signals::packets;
use std::num::NonZeroU8;

/// Signals Processor
pub struct SignalsProcessor {
    credits: Option<CreditKind>,
    identifier: NonZeroU8,
}

impl SignalsProcessor {
    pub fn builder() -> SignalsProcessorBuilder {
        SignalsProcessorBuilder::new()
    }

    pub fn process<C>(&mut self, connection_channel: &C, control_frame: &[u8]) -> SignalProcessResult
    where
        C: crate::ConnectionChannel,
    {
        match control_frame.get(0) {
            Some(&packets::LeCreditBasedConnectionRequest::CODE) => {
                self.process_le_credit_based_connection(connection_channel, control_frame)
            }
            _ => SignalProcessResult::Ignore,
        }
    }

    fn process_le_credit_based_connection<C>(
        &mut self,
        connection_channel: &C,
        control_frame: &[u8],
    ) -> SignalProcessResult
    where
        C: crate::ConnectionChannel,
    {
        if let Ok(signal) = packets::LeCreditBasedConnectionRequest::try_from_control_frame(control_frame) {
            let response = packets::LeCreditBasedConnectionResponse {
                identifier: self.identifier,
                destination_dyn_cid: signal.source_dyn_cid,
                mtu: signal.mtu,
                mps: signal.mps,
                initial_credits: 0,
                result: Ok(()),
            };

            todo!();

            SignalProcessResult::Ignore
        } else {
            SignalProcessResult::Ignore
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
