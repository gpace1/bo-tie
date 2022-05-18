//! Controller and Baseband Commands

/// Enable events
pub mod set_event_mask {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::SetEventMask);

    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
    pub enum EventMask {
        /// A marker for the default enabled (upon controller reset) list of events
        #[doc(hidden)]
        _Default,
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
        const DEFAULT_MASK: &'static [Self] = &[Self::_Default];

        const DEFAULT_MASK_LE: &'static [Self] = &[Self::_Default, Self::LEMeta];

        /// Get the default enabled events
        ///
        /// # Note
        /// The returned slice only contains a hidden member of `EventMask`. The hidden member is
        /// used for quickly masking the bits of the command parameter corresponding to the default
        /// events.
        pub fn default() -> &'static [EventMask] {
            Self::DEFAULT_MASK
        }

        /// Get the default enabled events with the `LEMeta` event also enabled.
        ///
        /// The LEMeta event is a mask for all LE events, it must be enabled for any LE event to be
        /// propagate from the controller to the host.
        ///
        /// # Note
        /// The returned slice only contains a hidden member of `EventMask` and the
        /// [`LEMeta`](EventMask::LEMeta) event.
        /// The hidden member is used for quickly masking the bits of the command parameter
        /// corresponding to the default events.
        pub fn default_le() -> &'static [EventMask] {
            Self::DEFAULT_MASK_LE
        }

        pub(crate) fn to_val(masks: &[Self]) -> u64 {
            masks.iter().fold(0u64, |val, mask| {
                val | match mask {
                    EventMask::_Default => 0x1FFF_FFFF_FFFF,
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

    pub struct Parameter {
        mask: [u8; 8],
    }

    impl CommandParameter<8> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 8] {
            self.mask
        }
    }

    /// Send the event mask to the controller
    pub async fn send<H: HostGenerics>(
        host: &mut HostInterface<H>,
        events: &[EventMask],
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = Parameter {
            mask: EventMask::to_val(events).to_le_bytes(),
        };

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

/// Reset the controller
///
/// This will reset the Controller and the appropriate link Layer. For BR/EDR the Link
/// Manager is reset, for LE the Link Layer is reset, and for AMP the PAL is reset.
pub mod reset {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::Reset);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the reset command to the controller
    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<impl FlowControlInfo, CommandError<H>> {
        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(Parameter).await;

        r
    }
}

/// Read the transmit power level
///
/// This reads the transmit power level for a connection specified by its
/// [`ConnectionHandle`](crate::hci::common::ConnectionHandle).
pub mod read_transmit_power_level {
    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::ReadTransmitPowerLevel);

    /// Transmit power range (from minimum to maximum levels)
    pub struct TransmitPowerLevel {
        pub connection_handle: ConnectionHandle,
        pub power_level: i8,
        /// The number of HCI commands that can be sent to the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for TransmitPowerLevel {
        fn try_from(cc: &events::CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let raw_connection_handle = <u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let connection_handle =
                ConnectionHandle::try_from(raw_connection_handle).or(Err(CCParameterError::InvalidEventParameter))?;

            let power_level = *cc.raw_data.get(3).ok_or(CCParameterError::InvalidEventParameter)? as i8;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                connection_handle,
                power_level,
                completed_packets_cnt,
            })
        }
    }

    impl FlowControlInfo for TransmitPowerLevel {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    pub enum TransmitPowerLevelType {
        CurrentPowerLevel,
        MaximumPowerLevel,
    }

    pub struct Parameter {
        pub connection_handle: ConnectionHandle,
        pub level_type: TransmitPowerLevelType,
    }

    impl CommandParameter<3> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 3] {
            let [b0, b1] = self.connection_handle.get_raw_handle().to_le_bytes();

            let b2 = match self.level_type {
                TransmitPowerLevelType::CurrentPowerLevel => 0,
                TransmitPowerLevelType::MaximumPowerLevel => 1,
            };

            [b0, b1, b2]
        }
    }

    /// Send a read transmit power level command to the controller
    ///
    /// This will send the command to the controller and wait for the transmit power level to be returned by it.
    pub async fn send<H: HostGenerics>(
        host: &mut HostInterface<H>,
        parameter: Parameter,
    ) -> Result<TransmitPowerLevel, CommandError<H>> {
        host.send_command_expect_complete(parameter).await
    }
}
