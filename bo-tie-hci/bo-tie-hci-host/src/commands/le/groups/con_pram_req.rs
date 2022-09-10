//! Connect Parameter Request Procedure response
//!
//! These are the commands that are used in response to a request from either a master or slave to
//! change the connection parameters.

pub mod remote_connection_parameter_request_reply {

    use crate::commands::le::{ConnectionEventLength, ConnectionInterval, ConnectionLatency, SupervisionTimeout};
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::ReadConnectionParameterRequestReply);

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
        const COMMAND: opcodes::HciCommand = COMMAND;
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
            check_status!(cc.return_parameter);

            let connection_handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|_| CCParameterError::InvalidEventParameter)?;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                completed_packets_cnt,
            })
        }
    }

    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        parameters: CommandParameters,
    ) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(parameters).await
    }
}

/// Send the negative reply to a connection parameter request
///
/// This sends a reason as to why the the request is rejected
///
/// ```
/// # use bo_tie_util::errors::Error;
/// # mod remote_connection_parameter_request_negative_reply {
/// #     use bo_tie_hci_util::ConnectionHandle;
/// #     use bo_tie_util::errors::Error;
/// #     pub async fn send<H>(_h: H, _ch: ConnectionHandle, _r: Error) {}
/// # }
/// # let connection_handle = bo_tie_hci_util::ConnectionHandle::try_from(1).unwrap();
/// # let host = ();
/// # async {
/// let reason = Error::UnacceptableConnectionParameters;
///
/// remote_connection_parameter_request_negative_reply::send(host, connection_handle, reason).await?;
/// # }
/// ```
/// # Note
/// If the value of input `reason` of method [`send`] is either [`NoError`] or [`MissingErrorCode`],
/// then it will be mapped to [`UnspecifiedError`]. The error [`Unknown(_)`] is still accepted even
/// though the error code will probably be unknown to the peer device.
///
/// [`send`]: remote_connection_parameter_request_negative_reply::send
/// [`NoError`]: bo_tie_util::errors::Error::NoError
/// [`MissingErrorCode`]: bo_tie_util::errors::Error::MissingErrorCode
/// [`UnspecifiedError`]: bo_tie_util::errors::Error::UnspecifiedError
pub mod remote_connection_parameter_request_negative_reply {

    use crate::errors::Error;
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::ReadConnectionParameterRequestNegativeReply);

    pub struct Return {
        pub connection_handle: ConnectionHandle,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let connection_handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|_| CCParameterError::InvalidEventParameter)?;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                completed_packets_cnt,
            })
        }
    }

    struct Parameter {
        handle: ConnectionHandle,
        reason: Error,
    }

    impl CommandParameter<3> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 3] {
            let mut parameter = [0u8; 3];

            parameter[..2].copy_from_slice(&self.handle.get_raw_handle().to_le_bytes());

            parameter[2] = Option::<u8>::from(self.reason).unwrap();

            parameter
        }
    }

    /// Method for sending the negative reply
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        handle: ConnectionHandle,
        reason: Error,
    ) -> Result<Return, CommandError<H>> {
        use core::mem::discriminant;

        let reason = match reason {
            Error::NoError | Error::MissingErrorCode => Error::UnspecifiedError,
            _ => reason,
        };

        let parameter = Parameter { handle, reason };

        host.send_command_expect_complete(parameter).await
    }
}
