/// LE Set Scan Parameters command
pub mod set_scan_parameters {

    use crate::commands::le::OwnAddressType;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::SetScanParameters);

    interval!(ScanningInterval, 0x0004, 0x4000, SpecDef, 0x0010, 625);
    interval!(ScanningWindow, 0x0004, 0x4000, SpecDef, 0x0010, 625);

    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum LeScanType {
        /// Under passive scanning, the link layer will not respond to any advertising
        /// packets. This is useful when listening to a device in the broadcast role.
        PassiveScanning,
        /// With Active scanning, the link layer will send packets to the advertiser. These
        /// packets can be for querying for more data.
        ActiveScanning,
    }

    impl From<LeScanType> for u8 {
        fn from(st: LeScanType) -> Self {
            match st {
                LeScanType::PassiveScanning => 0x00,
                LeScanType::ActiveScanning => 0x01,
            }
        }
    }

    impl Default for LeScanType {
        fn default() -> Self {
            LeScanType::PassiveScanning
        }
    }

    /// See the spec on this one (v5.0 | Vol 2, Part E, 7.8.10) to understand what
    /// the enumerations are representing.
    ///
    /// Value mapping
    /// 0x00 => AcceptAll
    /// 0x01 => WhiteListed
    /// 0x02 => AcceptAllExceptIdentityNotAddressed
    /// 0x03 => AcceptAllExceptIdentityNotInWhitelist
    #[derive(Debug, Copy, Clone, Eq, PartialEq)]
    pub enum ScanningFilterPolicy {
        AcceptAll,
        WhiteListed,
        AcceptAllExceptIdentityNotAddressed,
        AcceptAllExceptIdentityNotInWhitelist,
    }

    impl From<ScanningFilterPolicy> for u8 {
        fn from(s: ScanningFilterPolicy) -> Self {
            match s {
                ScanningFilterPolicy::AcceptAll => 0x00,
                ScanningFilterPolicy::WhiteListed => 0x01,
                ScanningFilterPolicy::AcceptAllExceptIdentityNotAddressed => 0x02,
                ScanningFilterPolicy::AcceptAllExceptIdentityNotInWhitelist => 0x03,
            }
        }
    }

    impl Default for ScanningFilterPolicy {
        fn default() -> Self {
            ScanningFilterPolicy::AcceptAll
        }
    }

    pub struct ScanningParameters {
        pub scan_type: LeScanType,
        pub scan_interval: ScanningInterval,
        pub scan_window: ScanningWindow,
        pub own_address_type: OwnAddressType,
        pub scanning_filter_policy: ScanningFilterPolicy,
    }

    impl Default for ScanningParameters {
        fn default() -> Self {
            ScanningParameters {
                scan_type: LeScanType::default(),
                scan_interval: ScanningInterval::default(),
                scan_window: ScanningWindow::default(),
                own_address_type: OwnAddressType::default(),
                scanning_filter_policy: ScanningFilterPolicy::default(),
            }
        }
    }

    impl CommandParameter<7> for ScanningParameters {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 7] {
            let mut parameter = [0u8; 7];

            parameter[0] = self.scan_type.into();

            parameter[1..3].copy_from_slice(&self.scan_interval.get_raw_val().to_le_bytes());

            parameter[3..5].copy_from_slice(&self.scan_window.get_raw_val().to_le_bytes());

            parameter[5] = self.own_address_type.into();

            parameter[6] = self.scanning_filter_policy.into();

            parameter
        }
    }

    /// Send the LE Set Scan Parameters command
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        parameters: ScanningParameters,
    ) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(parameters).await
    }
}

/// LE Set Scan Enable command
pub mod set_scan_enable {

    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::SetScanEnable);

    struct Parameter {
        enable: bool,
        filter_duplicates: bool,
    }

    impl CommandParameter<2> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            [
                if self.enable { 1 } else { 0 },
                if self.filter_duplicates { 1 } else { 0 },
            ]
        }
    }

    /// Send the LE Set Scan Enable command
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        enable: bool,
        filter_duplicates: bool,
    ) -> Result<(), CommandError<H>> {
        let parameter = Parameter {
            enable,
            filter_duplicates,
        };

        host.send_command_expect_complete(parameter).await
    }
}

/// LE Receiver Test command
pub mod receiver_test {

    use crate::commands::le::Frequency;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostInterface, TryFromCommandComplete,
    };

    const COMMAND_V1: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReceiverTest);

    struct ParameterV1 {
        frequency: Frequency,
    }

    impl CommandParameter<1> for ParameterV1 {
        const COMMAND: opcodes::HciCommand = COMMAND_V1;
        fn get_parameter(&self) -> [u8; 1] {
            [self.frequency.get_val()]
        }
    }

    /// Send LE Receiver Test (v1) command
    pub async fn send_v1<H: HostInterface>(host: &mut Host<H>, frequency: Frequency) -> Result<(), CommandError<H>> {
        let parameter = ParameterV1 { frequency };

        host.send_command_expect_complete(parameter).await
    }
}
