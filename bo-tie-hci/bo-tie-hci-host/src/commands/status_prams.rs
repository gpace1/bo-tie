//! Status Parameter Commands

pub mod read_rssi {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::StatusParameters(opcodes::StatusParameters::ReadRSSI);

    struct Parameter(ConnectionHandle);

    impl CommandParameter<2> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.0.get_raw_handle().to_le_bytes()
        }
    }

    pub struct RSSIInfo {
        pub handle: ConnectionHandle,
        pub rssi: i8,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for RSSIInfo {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let raw_handle = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let handle = ConnectionHandle::try_from(raw_handle).or(Err(CCParameterError::InvalidEventParameter))?;

            let rssi = *cc
                .return_parameter
                .get(3)
                .ok_or(CCParameterError::InvalidEventParameter)? as i8;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                handle,
                rssi,
                completed_packets_cnt,
            })
        }
    }

    /// Get the RSSI value for a specific connection
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        handle: ConnectionHandle,
    ) -> Result<RSSIInfo, CommandError<H>> {
        host.send_command_expect_complete(Parameter(handle)).await
    }
}
