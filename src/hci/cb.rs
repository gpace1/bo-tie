//! Controller and Baseband Commands

/// Reset the controller
///
/// This will reset the Controller and the appropriate link Layer. For BR/EDR the Link
/// Manager is reset, for LE the Link Layer is reset, and for AMP the PAL is reset.
pub mod reset {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::Reset);

    impl_status_return!(COMMAND);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> ) -> impl Future<Output=Result<(), impl Display + Debug>> + 'a where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

/// Enable events
pub mod set_event_mask {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::SetEventMask);

    #[derive(Debug)]
    enum Error {
        /// Bit position is reserved for future use
        RFU
    }

    impl core::fmt::Display for Error {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "{:?}", self)
        }
    }

    pub enum EventMask {
        /// Not an event mask, this is a marker for the default set of enabled events.
        ///
        /// The default list of enabled events is listed in the Bluetooth Specification v5.0 | Vol
        /// 2, Part E, Section 7.3.1 after table 3.2.
        Default,
        InquiryComplete,
        InquiryResult,
        ConnectionComplete,
        ConnectionRequest,
        DisconnectionComplete,
        AuthenticationComplete,
        RemoteNameRequestComplete,
        EncryptionChange,
        ChangeConnectionLinkKeyComplete,
        MasterLinkKeyComplete,
        ReadRemoteSupportedFeaturesComplete,
        ReadRemoteVersionInformationComplete,
        QoSSetupComplete,
        HardwareError,
        FlushOccurred,
        RoleChange,
        ModeChange,
        ReturnLinkKeys,
        PINCodeRequest,
        LinkKeyRequest,
        LinkKeyNotification,
        LoopbackCommand,
        DataBufferOverflow,
        MaxSlotsChange,
        ReadClockOffsetComplete,
        ConnectionPacketTypeChanged,
        QoSViolation,
        /// deprecated (as per the specification)
        PageScanModeChange,
        PageScanRepetitionModeChange,
        FlowSpecificationComplete,
        InquiryResultWithRSSI,
        ReadRemoteExtendedFeaturesComplete,
        SynchronousConnectionComplete,
        SynchronousConnectionChanged,
        SniffSubrating,
        ExtendedInquiryResult,
        EncryptionKeyRefreshComplete,
        IOCapabilityRequest,
        IOCapabilityResponse,
        UserConfirmationRequest,
        UserPasskeyRequest,
        RemoteOOBDataRequest,
        SimplePairingComplete,
        LinkSupervisionTimeoutChanged,
        EnhancedFlushComplete,
        UserPasskeyNotification,
        KeyPressNotification,
        RemoteHostSupportedFeaturesNotification,
        LEMeta,
    }

    impl EventMask {

        fn to_val(masks: &[Self]) -> u64 {

            masks.iter().fold( 0u64, |val, mask| {
                val | match mask {
                    EventMask::Default => 0x1FFF_FFFF_FFFF,
                    EventMask::InquiryComplete => 1 << 0,
                    EventMask::InquiryResult => 1 << 1,
                    EventMask::ConnectionComplete => 1 << 2,
                    EventMask::ConnectionRequest => 1 << 3,
                    EventMask::DisconnectionComplete => 1 << 4,
                    EventMask::AuthenticationComplete => 1 << 5,
                    EventMask::RemoteNameRequestComplete => 1 << 6,
                    EventMask::EncryptionChange => 1 << 7,
                    EventMask::ChangeConnectionLinkKeyComplete => 1 << 8,
                    EventMask::MasterLinkKeyComplete => 1 << 9,
                    EventMask::ReadRemoteSupportedFeaturesComplete => 1 << 10,
                    EventMask::ReadRemoteVersionInformationComplete => 1 << 11,
                    EventMask::QoSSetupComplete => 1 << 12,
                    EventMask::HardwareError => 1 << 15,
                    EventMask::FlushOccurred => 1 << 16,
                    EventMask::RoleChange => 1 << 17,
                    EventMask::ModeChange => 1 << 19,
                    EventMask::ReturnLinkKeys => 1 << 20,
                    EventMask::PINCodeRequest => 1 << 21,
                    EventMask::LinkKeyRequest => 1 << 22,
                    EventMask::LinkKeyNotification => 1 << 23,
                    EventMask::LoopbackCommand => 1 << 24,
                    EventMask::DataBufferOverflow => 1 << 25,
                    EventMask::MaxSlotsChange => 1 << 26,
                    EventMask::ReadClockOffsetComplete => 1 << 27,
                    EventMask::ConnectionPacketTypeChanged => 1 << 28,
                    EventMask::QoSViolation => 1 << 29,
                    EventMask::PageScanModeChange => 1 << 30,
                    EventMask::PageScanRepetitionModeChange => 1 << 31,
                    EventMask::FlowSpecificationComplete => 1 << 32,
                    EventMask::InquiryResultWithRSSI => 1 << 33,
                    EventMask::ReadRemoteExtendedFeaturesComplete => 1 << 34,
                    EventMask::SynchronousConnectionComplete => 1 << 43,
                    EventMask::SynchronousConnectionChanged => 1 << 44,
                    EventMask::SniffSubrating => 1 << 45,
                    EventMask::ExtendedInquiryResult => 1 << 46,
                    EventMask::EncryptionKeyRefreshComplete => 1 << 47,
                    EventMask::IOCapabilityRequest => 1 << 48,
                    EventMask::IOCapabilityResponse => 1 << 49,
                    EventMask::UserConfirmationRequest => 1 << 50,
                    EventMask::UserPasskeyRequest => 1 << 51,
                    EventMask::RemoteOOBDataRequest => 1 << 52,
                    EventMask::SimplePairingComplete => 1 << 53,
                    EventMask::LinkSupervisionTimeoutChanged => 1 << 55,
                    EventMask::EnhancedFlushComplete => 1 << 56,
                    EventMask::UserPasskeyNotification => 1 << 58,
                    EventMask::KeyPressNotification => 1 << 59,
                    EventMask::RemoteHostSupportedFeaturesNotification => 1 << 60,
                    EventMask::LEMeta => 1 << 61,
                }
            })
        }
    }

    impl_status_return!(COMMAND);

    struct Parameter {
        mask: [u8;8]
    }

    impl CommandParameter for Parameter {
        type Parameter = [u8;8];
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { self.mask }
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, events: &[EventMask] )
    -> impl Future<Output=Result<(), impl Display + Debug>> + 'a where T: HostControllerInterface
    {
        let parameter = Parameter { mask: EventMask::to_val(events).to_le_bytes() };

        ReturnedFuture( hci.send_command(parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }
}

pub mod read_transmit_power_level {
    use crate::hci::*;
    use crate::hci::common::ConnectionHandle;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::ReadTransmitPowerLevel);

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _connection_handle: u16,
        _level_type: u8,
    }

    #[repr(packed)]
    struct CmdReturn {
        status: u8,
        connection_handle: u16,
        power_level: i8,
    }

    /// Transmit power range (from minimum to maximum levels)
    pub struct TransmitPowerLevel {
        pub connection_handle: ConnectionHandle,
        pub power_level: i8,
    }

    impl TransmitPowerLevel {

        fn try_from(packed: CmdReturn) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    // If this panics here the controller returned a bad connection handle
                    connection_handle: ConnectionHandle::try_from(packed.connection_handle).unwrap(),
                    power_level: packed.power_level,
                })
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
            COMMAND,
            CmdReturn,
            TransmitPowerLevel,
            error::Error
        );

    impl_command_data_future!(TransmitPowerLevel, error::Error);

    pub enum TransmitPowerLevelType {
        CurrentPowerLevel,
        MaximumPowerLevel,
    }

    pub struct Parameter {
        pub connection_handle: ConnectionHandle,
        pub level_type: TransmitPowerLevelType,
    }

    impl CommandParameter for Parameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _connection_handle: self.connection_handle.get_raw_handle(),
                _level_type: match self.level_type {
                    TransmitPowerLevelType::CurrentPowerLevel => 0,
                    TransmitPowerLevelType::MaximumPowerLevel => 1,
                }
            }
        }
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, parameter: Parameter )
                                 -> impl Future<Output=Result<TransmitPowerLevel, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }
}