//! Connect Parameter Request Procedure response
//!
//! These are the commands that are used in response to a request from either a master or slave to
//! change the connection parameters.

pub mod remote_connection_parameter_request_reply {

    use crate::hci::common::ConnectionHandle;
    use crate::hci::events::CommandCompleteData;
    use crate::hci::le::common::{ConnectionEventLength, ConnectionInterval, ConnectionLatency, SupervisionTimeout};
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::ReadConnectionParameterRequestReply);

    pub struct CommandParameters {
        /// The handle for the connection
        pub handle: ConnectionHandle,
        /// The minimum connection interval
        pub interval_min: ConnectionInterval,
        /// The maximum connection interval
        pub interval_max: ConnectionInterval,
        /// The slave latency
        pub latency: ConnectionLatency,
        /// The link supervision timeout
        pub timeout: SupervisionTimeout,
        /// The minimum connection event length
        pub ce_len: ConnectionEventLength,
    }

    impl CommandParameter<14> for CommandParameters {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 14] {
            let mut parameter = [0u8; 14];

            parameter[0..2].copy_from_slice(&self.handle.get_raw_handle().to_le_bytes());

            parameter[2..4].copy_from_slice(&self.interval_min.get_raw_val().to_le_bytes());

            parameter[4..6].copy_from_slice(&self.interval_max.get_raw_val().to_le_bytes());

            parameter[6..8].copy_from_slice(&self.latency.get_latency().to_le_bytes());

            parameter[8..10].copy_from_slice(&self.timeout.get_timeout().to_le_bytes());

            parameter[10..12].copy_from_slice(&self.ce_len.minimum.to_le_bytes());

            parameter[12..14].copy_from_slice(&self.ce_len.maximum.to_le_bytes());

            parameter
        }
    }

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let connection_handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|e| CCParameterError::InvalidEventParameter)?;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                completed_packets_cnt,
            })
        }
    }

    impl FlowControlInfo for Return {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    pub async fn send<H: HostGenerics>(
        host: &mut HostInterface<H>,
        parameters: CommandParameters,
    ) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(parameters).await
    }
}

pub mod remote_connection_parameter_request_negative_reply {

    use crate::hci::common::ConnectionHandle;
    use crate::hci::events::CommandCompleteData;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::ReadConnectionParameterRequestNegativeReply);

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let connection_handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|e| CCParameterError::InvalidEventParameter)?;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                completed_packets_cnt,
            })
        }
    }

    impl FlowControlInfo for Return {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    struct Parameter {
        handle: ConnectionHandle,
        reason: error::Error,
    }

    impl CommandParameter<3> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 3] {
            let mut parameter = [0u8; 3];

            parameter[..2].copy_from_slice(&self.handle.get_raw_handle().to_le_bytes());

            parameter[2] = self.reason.into();

            parameter
        }
    }

    /// Send the negative reply to a connection parameter request
    ///
    /// This sends a reason as to why the the request is rejected
    ///
    /// # Panic
    /// The reason cannot be
    /// [`NoError`](crate::hci::error::Error::NoError) nor
    /// [`Message`](crate::hci::error::Error::Message)
    /// as they are translated into the value of 0 on the interface.
    pub async fn send<H: HostGenerics>(
        hci: &mut HostInterface<H>,
        handle: ConnectionHandle,
        reason: error::Error,
    ) -> Result<Return, CommandError<H>> {
        use core::mem::discriminant;

        assert_ne!(
            error::Error::NoError,
            reason,
            "input 'reason' cannot be error 'NoError'"
        );

        assert_ne!(
            discriminant(&error::Error::Message("")),
            discriminant(&reason),
            "input 'reason' cannot be error 'Message'"
        );

        let parameter = Parameter { handle, reason };

        ReturnedFuture(hci.send_command(parameter, CommandEventMatcher::CommandComplete))
    }
}
