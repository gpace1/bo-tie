/// LE Set Scan Parameters command
pub mod set_scan_parameters {

    use crate::hci::le::common::OwnAddressType;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetScanParameters);

    interval!(ScanningInterval, 0x0004, 0x4000, SpecDef, 0x0010, 625);
    interval!(ScanningWindow, 0x0004, 0x4000, SpecDef, 0x0010, 625);

    pub enum LEScanType {
        /// Under passive scanning, the link layer will not respond to any advertising
        /// packets. This is usefull when listening to a device in the broadcast role.
        PassiveScanning,
        /// With Active scanning, the link layer will send packets to the advertisier. These
        /// packets can be for quering for more data.
        ActiveScanning,
    }

    impl LEScanType {
        fn into_val(&self) -> u8 {
            match *self {
                LEScanType::PassiveScanning => 0x00,
                LEScanType::ActiveScanning => 0x01,
            }
        }
    }

    impl Default for LEScanType {
        fn default() -> Self {
            LEScanType::PassiveScanning
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
    pub enum ScanningFilterPolicy {
        AcceptAll,
        WhiteListed,
        AcceptAllExceptIdentityNotAddressed,
        AcceptAllExceptIdentityNotInWhitelist,
    }

    impl ScanningFilterPolicy {
        fn into_val(&self) -> u8 {
            match *self {
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
        pub scan_type: LEScanType,
        pub scan_interval: ScanningInterval,
        pub scan_window: ScanningWindow,
        pub own_address_type: OwnAddressType,
        pub scanning_filter_policy: ScanningFilterPolicy,
    }

    impl Default for ScanningParameters {
        fn default() -> Self {
            ScanningParameters {
                scan_type: LEScanType::default(),
                scan_interval: ScanningInterval::default(),
                scan_window: ScanningWindow::default(),
                own_address_type: OwnAddressType::default(),
                scanning_filter_policy: ScanningFilterPolicy::default(),
            }
        }
    }

    impl CommandParameter<7> for ScanningParameters {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 7] {
            let mut parameter = [0u8; 7];

            parameter[0] = self.scan_type.into_val();

            parameter[1..3].copy_from_slice(&self.scan_interval.get_raw_val().to_le_bytes());

            parameter[3..5].copy_from_slice(&self.scan_window.get_raw_val().to_le_bytes());

            parameter[5] = self.own_address_type.into_val();

            parameter[6] = self.scanning_filter_policy.into_val();

            parameter
        }
    }

    /// Send the LE Set Scan Parameters command
    pub async fn send<H: HostGenerics>(
        host: &mut HostInterface<H>,
        parameters: ScanningParameters,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameters).await;

        r
    }
}

/// LE Set Scan Enable command
pub mod set_scan_enable {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetScanEnable);

    struct Parameter {
        enable: bool,
        filter_duplicates: bool,
    }

    impl CommandParameter<2> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            [
                if self.enable { 1 } else { 0 },
                if self.filter_duplicates { 1 } else { 0 },
            ]
        }
    }

    /// Send the LE Set Scan Enable command
    pub async fn send<H: HostGenerics>(
        host: &mut HostInterface<H>,
        enable: bool,
        filter_duplicates: bool,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = Parameter {
            enable,
            filter_duplicates,
        };

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

/// LE Receiver Test command
pub mod receiver_test {

    use crate::hci::le::common::Frequency;
    use crate::hci::*;

    const COMMAND_V1: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReceiverTest);

    struct ParameterV1 {
        frequency: Frequency,
    }

    impl CommandParameter<1> for ParameterV1 {
        const COMMAND: opcodes::HCICommand = COMMAND_V1;
        fn get_parameter(&self) -> [u8; 1] {
            [self.frequency.get_val()]
        }
    }

    /// Send LE Receiver Test (v1) command
    pub async fn send_v1<H: HostGenerics>(
        host: &mut HostInterface<H>,
        frequency: Frequency,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = ParameterV1 { frequency };

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}
