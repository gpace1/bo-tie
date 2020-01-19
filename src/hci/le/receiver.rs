pub mod receiver_test {

    use crate::hci::*;
    use crate::hci::le::common::Frequency;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReceiverTest);

    impl_status_return!(COMMAND);

    impl CommandParameter for Frequency
    {
        type Parameter = u8;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            self.get_val()
        }
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, frequency: Frequency )
                                 -> impl Future<Output=Result<(), impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(frequency, events::Events::CommandComplete , Duration::from_secs(1) ) )
    }

}

pub mod set_scan_enable {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetScanEnable);

    impl_status_return!(COMMAND);

    #[repr(packed)]
    struct CmdParameter {
        _enable: u8,
        _filter_duplicates: u8,
    }

    struct Parameter {
        enable: bool,
        filter_duplicates: bool,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _enable: if self.enable {1} else {0},
                _filter_duplicates: if self.filter_duplicates {1} else {0},
            }
        }
    }

    /// The command has the ability to enable/disable scanning and filter duplicate
    /// advertisement.
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, enable: bool, filter_duplicates: bool)
                                 -> impl Future<Output=Result<(), impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        let cmd_param = Parameter {
            enable: enable,
            filter_duplicates: filter_duplicates,
        };

        ReturnedFuture( hci.send_command(cmd_param, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

pub mod set_scan_parameters {

    use crate::hci::*;
    use crate::hci::le::common::OwnAddressType;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetScanParameters);

    interval!( ScanningInterval, 0x0004, 0x4000, SpecDef, 0x0010, 625);
    interval!( ScanningWindow, 0x0004, 0x4000, SpecDef, 0x0010, 625);

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
                LEScanType::ActiveScanning  => 0x01,
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

    impl_status_return!(COMMAND);

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _scan_type: u8,
        _scan_interval: u16,
        _scan_window: u16,
        _own_address_type: u8,
        _filter_policy: u8,
    }

    impl CommandParameter for ScanningParameters {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _scan_type:        self.scan_type.into_val(),
                _scan_interval:    self.scan_interval.get_raw_val(),
                _scan_window:      self.scan_window.get_raw_val(),
                _own_address_type: self.own_address_type.into_val(),
                _filter_policy:    self.scanning_filter_policy.into_val(),
            }
        }
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, sp: ScanningParameters )
                                 -> impl Future<Output=Result<(), impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(sp, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}