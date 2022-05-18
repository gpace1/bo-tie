//! Status Parameter Commands

pub mod read_rssi {
    use crate::hci::common::ConnectionHandle;
    use crate::hci::events::CommandCompleteData;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::StatusParameters(opcodes::StatusParameters::ReadRSSI);

    struct Parameter(ConnectionHandle);

    impl CommandParameter<2> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
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
            check_status!(cc.raw_data);

            let raw_handle = <u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let handle = ConnectionHandle::try_from(raw_handle).map_err(CCParameterError::InvalidEventParameter)?;

            let rssi = *cc.raw_data.get(3).ok_or(CCParameterError::InvalidEventParameter)? as i8;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                handle,
                rssi,
                completed_packets_cnt,
            })
        }
    }

    impl FlowControlInfo for RSSIInfo {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    /// Get the RSSI value for a specific connection
    pub async fn send<H: HostGenerics>(
        host: &mut HostInterface<H>,
        handle: ConnectionHandle,
    ) -> Result<RSSIInfo, CommandError<H>> {
        host.send_command_expect_complete(Parameter(handle)).await
    }
}
