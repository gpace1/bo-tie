//! LE Controller transition of scannable advertisements

/// Set the Scan Response Data
///
/// Devices may perform a scan request to an advertising upon receiving either ADV_IND or
/// ADV_SCAN_IND PDU. This command is used to set the scan response data that is returned within
/// the scan response.
pub mod set_scan_response_data {
    use crate::{CommandError, CommandParameter, Host};
    #[cfg(feature = "gap")]
    use bo_tie_gap::assigned::{ConvertError, IntoStruct};
    use bo_tie_hci_util::{opcodes, HostChannelEnds};

    type Payload = [u8; 31];

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::SetScanResponseData);

    /// The scan response data
    ///
    /// This is the data that is returned by an advertising device when another device performs a
    /// scan request.
    #[derive(Default, Debug, Clone, Copy)]
    pub struct ScanResponseData {
        length: usize,
        payload: Payload,
    }

    impl ScanResponseData {
        pub fn new() -> ScanResponseData {
            ScanResponseData {
                length: 0,
                payload: Default::default(),
            }
        }

        /// Add an AD Struct to the scan response data
        ///
        /// # Error
        /// An error is returned if input `data` in its AD structure form was too large for the
        /// remaining free space in the scan response data.
        #[cfg(feature = "gap")]
        pub fn try_push<T>(&mut self, data: T) -> Result<(), ConvertError>
        where
            T: IntoStruct,
        {
            data.convert_into(&mut self.payload[self.length..])
                .map(|ad_struct| self.length += ad_struct.size())
        }

        /// Get the remaining space available within the scan response data
        pub fn remaining_space(&self) -> usize {
            self.payload.len() - self.length as usize
        }
    }

    impl CommandParameter<32> for ScanResponseData {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 32] {
            let mut parameter = [0u8; 32];

            parameter[0] = self.length as u8;

            parameter[1..(self.length + 1)].copy_from_slice(&self.payload[..self.length]);

            parameter
        }
    }

    pub async fn send<H, A>(host: &mut Host<H>, advertising_data: A) -> Result<(), CommandError<H>>
    where
        H: HostChannelEnds,
        A: Into<Option<ScanResponseData>>,
    {
        let parameter = advertising_data.into().unwrap_or_default();

        host.send_command_expect_complete(parameter).await
    }
}
