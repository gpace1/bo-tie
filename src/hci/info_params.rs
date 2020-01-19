//! Informational Parameter Commands

/// Read BD_ADDR Command
///
/// For LE this will read the public address of the controller. If the controller doesn't have a
/// public device address then this will return 0 as the address.
pub mod read_bd_addr {

    use crate::BluetoothDeviceAddress;
    use crate::hci::*;
    use core::fmt::{Display, Debug};

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::InformationParameters(opcodes::InformationParameters::ReadBD_ADDR);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        address: BluetoothDeviceAddress,
    }

    struct Return;

    impl Return {
        fn try_from(packed: CmdReturn) -> Result<BluetoothDeviceAddress, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(packed.address)
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
        COMMAND,
        CmdReturn,
        Return,
        BluetoothDeviceAddress,
        error::Error
    );

    impl_command_data_future!(Return, BluetoothDeviceAddress, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    /// Returns the bluetooth device address for the device
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
    -> impl Future<Output=Result<BluetoothDeviceAddress, impl Display + Debug>> + 'a where T: HostControllerInterface
    {
        use events::Events::CommandComplete;

        let cmd_rslt = hci.send_command(Parameter, CommandComplete, Duration::from_secs(1) );

        ReturnedFuture(cmd_rslt)
    }

}

/// Read Local Supported Features Command
///
/// This will return the supported features of the BR/EDR controller
pub mod read_local_supported_features {

    use crate::hci::*;
    use crate::hci::common::EnabledFeaturesIter;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::InformationParameters(opcodes::InformationParameters::ReadLocalSupportedFeatures);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        features: [u8;8],
    }

    impl EnabledFeaturesIter {
        fn try_from(packed: CmdReturn) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(EnabledFeaturesIter::from(packed.features))
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command! (
        COMMAND,
        CmdReturn,
        EnabledFeaturesIter,
        error::Error
    );

    impl_command_data_future!(EnabledFeaturesIter, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
    -> impl Future<Output=Result<EnabledFeaturesIter, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

/// Read Local Version Information Command
///
/// This command will give the version information for the Host Controller Interface (HCI) and Link
/// Manager Protocol (LMP) along with the Bluetooth SIG assigned number of the manufacturer. For
/// AMP, the PAL version information is returned instead of the LMP version (but the information is
/// usually .
pub mod read_local_version_information {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::InformationParameters(opcodes::InformationParameters::ReadLocalSupportedVersionInformation);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        hci_version: u8,
        hci_revision: u16,
        lmp_pal_version: u8,
        manufacturer_name: u16,
        lmp_pal_subversion: u16,
    }

    #[derive(Debug)]
    pub struct VersionInformation {
        pub hci_version: u8,
        pub hci_revision: u16,
        pub lmp_pal_version: u8,
        pub manufacturer_name: u16,
        pub lmp_pal_subversion: u16,
    }

    impl VersionInformation {
        fn try_from(packed: CmdReturn) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    hci_version: packed.hci_version,
                    hci_revision: packed.hci_revision,
                    lmp_pal_version: packed.lmp_pal_version,
                    manufacturer_name: packed.manufacturer_name,
                    lmp_pal_subversion: packed.lmp_pal_subversion,
                })
            } else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
        COMMAND,
        CmdReturn,
        VersionInformation,
        error::Error
    );

    impl_command_data_future!(VersionInformation, error::Error);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    pub fn send<'a, T: 'static>(hci: &'a HostInterface<T>)
                                -> impl Future<Output=Result<VersionInformation, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1)))
    }
}

/// Read Local Supported Commands Command
///
/// This returns the list of Host Controller Interface commands that are implemented by the
/// controller.
pub mod read_local_supported_commands {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::InformationParameters(opcodes::InformationParameters::ReadLocalSupportedCommands);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        supported_commands: [u8;64],
    }

    #[cfg_attr(test,derive(Debug))]
    #[derive(PartialEq)]
    pub enum SupportedCommands {
        Inquiry,
        InquiryCancel,
        PeriodicInquiryMode,
        ExitPeriodicInquiryMode,
        CreateConnection,
        Disconnect,
        /// Depreciated
        AddSCOConnection,
        CreateConnectionCancel,
        AcceptConnectionRequest,
        RejectConnectionRequest,
        LinkKeyRequestReply,
        LinkKeyRequestNegativeReply,
        PINCodeRequestReply,
        PINCodeRequestNegativeReply,
        ChangeConnectionPacketType,
        AuthenticationRequested,
        SetConnectionEncryption,
        ChangeConnectionLinkKey,
        MasterLinkKey,
        RemoteNameRequest,
        RemoteNameRequestCancel,
        ReadRemoteSupportedFeatures,
        ReadRemoteExtendedFeatures,
        ReadRemoteVersionInformation,
        ReadClockOffset,
        ReadLMPHandle,
        HoldMode,
        SniffMode,
        ExitSniffMode,
        QosSetup,
        RoleDiscovery,
        SwitchRole,
        ReadLinkPolicySettings,
        WriteLinkPolicySettings,
        ReadDefaultLinkPolicySettings,
        WriteDefaultLinkPolicySettings,
        FlowSpecification,
        SetEventMask,
        Reset,
        SetEVentFilter,
        Flush,
        ReadPINType,
        WritePINType,
        CreateNewUnitKey,
        ReadStoredLinkKey,
        WriteStoredLinkKey,
        DeleteStoredLinkKey,
        WriteLocalName,
        ReadLocalName,
        ReadConnectionAcceptedTimeout,
        WriteConnectionAcceptedTimeout,
        ReadPageTimeout,
        WritePageTimeout,
        ReadScanEnable,
        WriteScanEnable,
        ReadPageScanActivity,
        WritePageScanActivity,
        ReadInquiryScanActivity,
        WriteInquiryScanActivity,
        ReadAuthenticationEnable,
        WriteAuthenticationEnable,
        ///Depreciated
        ReadEncryptionMode,
        ///Depreciated
        WriteEncryptionMode,
        ReadClassOfDevice,
        WriteClassOfDevice,
        REadVoiceSetting,
        WriteVoiceSetting,
        ReadAutomaticFlushTimeout,
        WriteAutomaticFlushTimeout,
        ReadNumBroadcastRetransmission,
        WriteNumBroadcastRetransmissions,
        ReadHoldModeActivity,
        WriteHoldModeActiviy,
        ReadTransmitPowerLevel,
        ReadSynchronousFlowControlEnable,
        WriteSynchronousFlowControlEnable,
        SetConrollerToHostFlowControl,
        HostBufferSize,
        HostNumberOfCompletedPackets,
        ReadLinkSupervisionTimeout,
        WriteLinkSupervisionTimeout,
        ReadNumberOfSupportedIAC,
        ReadCurrentIACLAP,
        WriteCurrentIACLAP,
        /// Depreciated
        ReadPageScanModePeriod,
        /// Depreciated
        WritePageScanModePeriod,
        /// Depreciated
        ReadPageScanMode,
        /// Depreciated
        WritePageSanMode,
        SetAFHHostChannel,
        ReadInquiryScanType,
        WriteInquirySCanType,
        ReadInquiryMode,
        WriteInquiryMode,
        ReadPageScanType,
        WritePageScanType,
        ReadAFHChannelAssessmentMode,
        WriteAFHChannelAssessmentMode,
        ReadLocalVersionInformation,
        ReadLocalSupportedFeatures,
        ReadLocalExtendedFeatures,
        ReadBufferSize,
        /// Depreciated
        ReadCountryCode,
        ReadBDADDR,
        ReadFAiledContactCounter,
        ResetFailedContactCounter,
        ReadLinkQuality,
        ReadRSSI,
        ReadAFHChannelMap,
        ReadClock,
        ReadLoopbackMode,
        WriteLoopbackMode,
        EnableDeviceUnderTestMode,
        SetupSynchronousConnectionRequest,
        AcceptSynchronousConnectionRequest,
        RejectSynchronousConnectionRequest,
        ReadExtendedInquiryResponse,
        WriteExtendedInquiryResponse,
        RefreshEncryptionKey,
        SniffSubrating,
        ReadSimplePairingMode,
        WriteSimplePairingMode,
        ReadLocalOOBData,
        ReadInquiryResponseTransmitPowerLevel,
        WriteInquiryTransmitPowerLevel,
        ReadDefaultErroneousDataReporting,
        WriteDefaultErroneousDataReporting,
        IOCapabilityRequestReply,
        UserConfirmationRequestReply,
        UserConfirmationRequestNegativeReply,
        UserPasskeyRequestReply,
        UserPasskeyRequestNegativeReply,
        RemoteOOBDataRequestReply,
        WriteSimplePairingDebugMode,
        EnhancedFlush,
        RemoteOOBDataRequestNagativeReply,
        SendKeypressNotification,
        IOCapabilityRequestNegativeReply,
        ReadEncryptionKeySize,
        CreatePhysicalLink,
        AcceptPhysicalLink,
        DisconnectPhysicalLink,
        CreateLogicalLink,
        AcceptLogicalLink,
        DisconnectLogicalLink,
        LogicalLinkCancel,
        FlowSpecModify,
        ReadLogicalLinkAcceptTimeout,
        WriteLogicalLinkAcceptTimeout,
        SetEventMaskPage2,
        ReadLocationData,
        WRiteLocationData,
        ReadLocalAMPInfo,
        ReadLocalAMPASSOC,
        WriteRemoteAMPASSOC,
        READFlowControlMode,
        WriteFlowControlMode,
        ReadDataBlockSize,
        EnableAMPReceiverReports,
        AMPTestEnd,
        AmPTest,
        ReadEnhancedTransmitPowerLevel,
        ReadBestEffortFlushTimeout,
        WriteBestEffortFlushTimeout,
        ShortRangeMode,
        ReadLEHostSupport,
        WriteLEHostSupport,
        LESetEventMask,
        LEReadBufferSize,
        LEReadLocalSupportedFeatures,
        LESetRandomAddress,
        LESetAdvertisingParameters,
        LEReadAdvertisingChannelTXPower,
        LESetAdvertisingData,
        LESetScanResponseData,
        LESetAdvertisingEnable,
        LESetScanParameters,
        LESetScanEnable,
        LECreateConnection,
        LECreateConnectionCancel,
        LEReadWhiteListSize,
        LEClearWhiteList,
        LEAddDeviceToWhiteList,
        LERemoveDeviceFromWhiteList,
        LEConnectionUpdate,
        LESetHostChannelClassification,
        LEReadChannelMap,
        LEReadRemoteFeatures,
        LEEncrypt,
        LERand,
        LEStartEncryption,
        LELongTermKeyRequestReply,
        LELongTermKeyRequestNegativeReply,
        LEReadSupportedStates,
        LEReceiverTest,
        LETransmitterTest,
        LETestEnd,
        EnhancedSetupSynchronousConnection,
        EnhancedAcceptSynchronousConnection,
        ReadLocalSupportedCondecs,
        SetMWSChannelParameters,
        SetExternalFrameConfiguration,
        SetMWSSignaling,
        SetMWSTransportLayer,
        SetMWSScanFrequencyTable,
        GetMWSTransportLayerConfiguration,
        SetMWSPATTERNConfiguration,
        SetTriggeredClockCapture,
        TruncatedPage,
        TruncatedPageCancel,
        SetConnectionlessSlaveBroadcast,
        SetConnectionlessSlaveBroadcastReceive,
        StartSynchronizationTrain,
        ReceiveSynchronizationTrain,
        SetReservedLTADDR,
        DeleteReservedLTADDR,
        SetConnectionlessSlaveBroadcastData,
        ReadSynchronizationTrainParameters,
        WriteSynchronizationTrainParameters,
        RemoteOOBExtendedDataRequestReply,
        ReadSecureConnectionsHostSupport,
        WriteSecureConnectionsHostSupport,
        ReadAuthenticatedPayloadTimeout,
        WriteAuthenticatedPayloadTimeout,
        ReadLocalOOBExtendedData,
        WriteSecureConnectionsTestMode,
        ReadExtendedPageTimeout,
        WriteExtendedPageTimeout,
        ReadExtendedInquiryLength,
        WriteExtendedInquiryLengh,
        LERemoteConnectionParameterRequestReply,
        LERemoteConnectionParameterREquestNegativeReply,
        LESetDataLength,
        LEReadSuggestedDefaultDataLength,
        LEWriteSuggestedDefaultDataLength,
        LEReadLocalP256PublicKey,
        LEGenerateDHKey,
        LEAddDeviceToResolvingList,
        LERemoveDeviceFromResolvingList,
        LEClearResolvingList,
        LEReadResolvingListSize,
        LEReadPeerResolvableAddress,
        LEReadLocalResolvableAddress,
        LESetAddressResolutionEnable,
        LESetResolvablePrivateAddressTimeout,
        LEReadMaximumDataLength,
        LEReadPHYCommand,
        LESetDefaultPHYCommand,
        LESetPHYCommand,
        LEEnhancedReceiverTestCommand,
        LEEnhancedTransmitterTestCommand,
        LESetAdvertisingSetRandomAddressCommand,
        LESetExtendedAdvertisingParametersCommand,
        LESetExtendedAdvertisingDataCommand,
        LESetExtendedScanResponseDataCommand,
        LESetExtendedAdvertisingEnableCommand,
        LEReadMaximumAdvertisingDataLengthCommand,
        LEReadNumberOfSupportedAdvertisingSetCommand,
        LERemoveAdvertisingSetCommand,
        LEClearAdvertisingSetsCommand,
        LESetPeriodicAdvertisingParametersCommand,
        LESetPeriodicAdvertisingDataCommand,
        LESetPeriodicAdvertisingEnableCommand,
        LESetExtendedScanParametersCommand,
        LESetExtendedScanEnableCommand,
        LEExtendedCreateConnectionCommand,
        LEPeriodicAdvertisingCreateSyncCommand,
        LEPeriodicAdvertisingCreateSyncCancelCommand,
        LEPeriodicAdvertisingTerminateSyncCommand,
        LEAddDeviceToPeriodicAdvertiserListCommand,
        LERemoveDeviceFromPeriodicAdvertiserListCommand,
        LEClearPeriodicAdvertiserListCommand,
        LEReadPeriodicAdvertiserListSizeCommand,
        LEReadTransmitPowerCommand,
        LEReadRFPathCompensationCommand,
        LEWriteRFPathCompensationCommand,
        LESetPrivacyMode,
    }

    impl SupportedCommands {

        fn from_bit_pos( pos: (usize, usize) ) -> Option<SupportedCommands> {
            use self::SupportedCommands::*;

            match pos {
                (0,0)  => Some(Inquiry),
                (0,1)  => Some(InquiryCancel),
                (0,2)  => Some(PeriodicInquiryMode),
                (0,3)  => Some(ExitPeriodicInquiryMode),
                (0,4)  => Some(CreateConnection),
                (0,5)  => Some(Disconnect),
                (0,6)  => Some(AddSCOConnection),
                (0,7)  => Some(CreateConnectionCancel),
                (1,0)  => Some(AcceptConnectionRequest),
                (1,1)  => Some(RejectConnectionRequest),
                (1,2)  => Some(LinkKeyRequestReply),
                (1,3)  => Some(LinkKeyRequestNegativeReply),
                (1,4)  => Some(PINCodeRequestReply),
                (1,5)  => Some(PINCodeRequestNegativeReply),
                (1,6)  => Some(ChangeConnectionPacketType),
                (1,7)  => Some(AuthenticationRequested),
                (2,0)  => Some(SetConnectionEncryption),
                (2,1)  => Some(ChangeConnectionLinkKey),
                (2,2)  => Some(MasterLinkKey),
                (2,3)  => Some(RemoteNameRequest),
                (2,4)  => Some(RemoteNameRequestCancel),
                (2,5)  => Some(ReadRemoteSupportedFeatures),
                (2,6)  => Some(ReadRemoteExtendedFeatures),
                (2,7)  => Some(ReadRemoteVersionInformation),
                (3,0)  => Some(ReadClockOffset),
                (3,1)  => Some(ReadLMPHandle),
                (4,1)  => Some(HoldMode),
                (4,2)  => Some(SniffMode),
                (4,3)  => Some(ExitSniffMode),
                (4,6)  => Some(QosSetup),
                (4,7)  => Some(RoleDiscovery),
                (5,0)  => Some(SwitchRole),
                (5,1)  => Some(ReadLinkPolicySettings),
                (5,2)  => Some(WriteLinkPolicySettings),
                (5,3)  => Some(ReadDefaultLinkPolicySettings),
                (5,4)  => Some(WriteDefaultLinkPolicySettings),
                (5,5)  => Some(FlowSpecification),
                (5,6)  => Some(SetEventMask),
                (5,7)  => Some(Reset),
                (6,0)  => Some(SetEVentFilter),
                (6,1)  => Some(Flush),
                (6,2)  => Some(ReadPINType),
                (6,3)  => Some(WritePINType),
                (6,4)  => Some(CreateNewUnitKey),
                (6,5)  => Some(ReadStoredLinkKey),
                (6,6)  => Some(WriteStoredLinkKey),
                (6,7)  => Some(DeleteStoredLinkKey),
                (7,0)  => Some(WriteLocalName),
                (7,1)  => Some(ReadLocalName),
                (7,2)  => Some(ReadConnectionAcceptedTimeout),
                (7,3)  => Some(WriteConnectionAcceptedTimeout),
                (7,4)  => Some(ReadPageTimeout),
                (7,5)  => Some(WritePageTimeout),
                (7,6)  => Some(ReadScanEnable),
                (7,7)  => Some(WriteScanEnable),
                (8,0)  => Some(ReadPageScanActivity),
                (8,1)  => Some(WritePageScanActivity),
                (8,2)  => Some(ReadInquiryScanActivity),
                (8,3)  => Some(WriteInquiryScanActivity),
                (8,4)  => Some(ReadAuthenticationEnable),
                (8,5)  => Some(WriteAuthenticationEnable),
                (8,6)  => Some(ReadEncryptionMode),
                (8,7)  => Some(WriteEncryptionMode),
                (9,0)  => Some(ReadClassOfDevice),
                (9,1)  => Some(WriteClassOfDevice),
                (9,2)  => Some(REadVoiceSetting),
                (9,3)  => Some(WriteVoiceSetting),
                (9,4)  => Some(ReadAutomaticFlushTimeout),
                (9,5)  => Some(WriteAutomaticFlushTimeout),
                (9,6)  => Some(ReadNumBroadcastRetransmission),
                (9,7)  => Some(WriteNumBroadcastRetransmissions),
                (10,0) => Some(ReadHoldModeActivity),
                (10,1) => Some(WriteHoldModeActiviy),
                (10,2) => Some(ReadTransmitPowerLevel),
                (10,3) => Some(ReadSynchronousFlowControlEnable),
                (10,4) => Some(WriteSynchronousFlowControlEnable),
                (10,5) => Some(SetConrollerToHostFlowControl),
                (10,6) => Some(HostBufferSize),
                (10,7) => Some(HostNumberOfCompletedPackets),
                (11,0) => Some(ReadLinkSupervisionTimeout),
                (11,1) => Some(WriteLinkSupervisionTimeout),
                (11,2) => Some(ReadNumberOfSupportedIAC),
                (11,3) => Some(ReadCurrentIACLAP),
                (11,4) => Some(WriteCurrentIACLAP),
                (11,5) => Some(ReadPageScanModePeriod),
                (11,6) => Some(WritePageScanModePeriod),
                (11,7) => Some(ReadPageScanMode),
                (12,0) => Some(WritePageSanMode),
                (12,1) => Some(SetAFHHostChannel),
                (12,4) => Some(ReadInquiryScanType),
                (12,5) => Some(WriteInquirySCanType),
                (12,6) => Some(ReadInquiryMode),
                (12,7) => Some(WriteInquiryMode),
                (13,0) => Some(ReadPageScanType),
                (13,1) => Some(WritePageScanType),
                (13,2) => Some(ReadAFHChannelAssessmentMode),
                (13,3) => Some(WriteAFHChannelAssessmentMode),
                (14,3) => Some(ReadLocalVersionInformation),
                (14,5) => Some(ReadLocalSupportedFeatures),
                (14,6) => Some(ReadLocalExtendedFeatures),
                (14,7) => Some(ReadBufferSize),
                (15,0) => Some(ReadCountryCode),
                (15,1) => Some(ReadBDADDR),
                (15,2) => Some(ReadFAiledContactCounter),
                (15,3) => Some(ResetFailedContactCounter),
                (15,4) => Some(ReadLinkQuality),
                (15,5) => Some(ReadRSSI),
                (15,6) => Some(ReadAFHChannelMap),
                (15,7) => Some(ReadClock),
                (16,0) => Some(ReadLoopbackMode),
                (16,1) => Some(WriteLoopbackMode),
                (16,2) => Some(EnableDeviceUnderTestMode),
                (16,3) => Some(SetupSynchronousConnectionRequest),
                (16,4) => Some(AcceptSynchronousConnectionRequest),
                (16,5) => Some(RejectSynchronousConnectionRequest),
                (17,0) => Some(ReadExtendedInquiryResponse),
                (17,1) => Some(WriteExtendedInquiryResponse),
                (17,2) => Some(RefreshEncryptionKey),
                (17,4) => Some(SniffSubrating),
                (17,5) => Some(ReadSimplePairingMode),
                (17,6) => Some(WriteSimplePairingMode),
                (17,7) => Some(ReadLocalOOBData),
                (18,0) => Some(ReadInquiryResponseTransmitPowerLevel),
                (18,1) => Some(WriteInquiryTransmitPowerLevel),
                (18,2) => Some(ReadDefaultErroneousDataReporting),
                (18,3) => Some(WriteDefaultErroneousDataReporting),
                (18,7) => Some(IOCapabilityRequestReply),
                (19,0) => Some(UserConfirmationRequestReply),
                (19,1) => Some(UserConfirmationRequestNegativeReply),
                (19,2) => Some(UserPasskeyRequestReply),
                (19,3) => Some(UserPasskeyRequestNegativeReply),
                (19,4) => Some(RemoteOOBDataRequestReply),
                (19,5) => Some(WriteSimplePairingDebugMode),
                (19,6) => Some(EnhancedFlush),
                (19,7) => Some(RemoteOOBDataRequestNagativeReply),
                (20,2) => Some(SendKeypressNotification),
                (20,3) => Some(IOCapabilityRequestNegativeReply),
                (20,4) => Some(ReadEncryptionKeySize),
                (21,0) => Some(CreatePhysicalLink),
                (21,1) => Some(AcceptPhysicalLink),
                (21,2) => Some(DisconnectPhysicalLink),
                (21,3) => Some(CreateLogicalLink),
                (21,4) => Some(AcceptLogicalLink),
                (21,5) => Some(DisconnectLogicalLink),
                (21,6) => Some(LogicalLinkCancel),
                (21,7) => Some(FlowSpecModify),
                (22,0) => Some(ReadLogicalLinkAcceptTimeout),
                (22,1) => Some(WriteLogicalLinkAcceptTimeout),
                (22,2) => Some(SetEventMaskPage2),
                (22,3) => Some(ReadLocationData),
                (22,4) => Some(WRiteLocationData),
                (22,5) => Some(ReadLocalAMPInfo),
                (22,6) => Some(ReadLocalAMPASSOC),
                (22,7) => Some(WriteRemoteAMPASSOC),
                (23,0) => Some(READFlowControlMode),
                (23,1) => Some(WriteFlowControlMode),
                (23,2) => Some(ReadDataBlockSize),
                (23,5) => Some(EnableAMPReceiverReports),
                (23,6) => Some(AMPTestEnd),
                (23,7) => Some(AmPTest),
                (24,0) => Some(ReadEnhancedTransmitPowerLevel),
                (24,2) => Some(ReadBestEffortFlushTimeout),
                (24,3) => Some(WriteBestEffortFlushTimeout),
                (24,4) => Some(ShortRangeMode),
                (24,5) => Some(ReadLEHostSupport),
                (24,6) => Some(WriteLEHostSupport),
                (25,0) => Some(LESetEventMask),
                (25,1) => Some(LEReadBufferSize),
                (25,2) => Some(LEReadLocalSupportedFeatures),
                (25,4) => Some(LESetRandomAddress),
                (25,5) => Some(LESetAdvertisingParameters),
                (25,6) => Some(LEReadAdvertisingChannelTXPower),
                (25,7) => Some(LESetAdvertisingData),
                (26,0) => Some(LESetScanResponseData),
                (26,1) => Some(LESetAdvertisingEnable),
                (26,2) => Some(LESetScanParameters),
                (26,3) => Some(LESetScanEnable),
                (26,4) => Some(LECreateConnection),
                (26,5) => Some(LECreateConnectionCancel),
                (26,6) => Some(LEReadWhiteListSize),
                (26,7) => Some(LEClearWhiteList),
                (27,0) => Some(LEAddDeviceToWhiteList),
                (27,1) => Some(LERemoveDeviceFromWhiteList),
                (27,2) => Some(LEConnectionUpdate),
                (27,3) => Some(LESetHostChannelClassification),
                (27,4) => Some(LEReadChannelMap),
                (27,5) => Some(LEReadRemoteFeatures),
                (27,6) => Some(LEEncrypt),
                (27,7) => Some(LERand),
                (28,0) => Some(LEStartEncryption),
                (28,1) => Some(LELongTermKeyRequestReply),
                (28,2) => Some(LELongTermKeyRequestNegativeReply),
                (28,3) => Some(LEReadSupportedStates),
                (28,4) => Some(LEReceiverTest),
                (28,5) => Some(LETransmitterTest),
                (28,6) => Some(LETestEnd),
                (29,3) => Some(EnhancedSetupSynchronousConnection),
                (29,4) => Some(EnhancedAcceptSynchronousConnection),
                (29,5) => Some(ReadLocalSupportedCondecs),
                (29,6) => Some(SetMWSChannelParameters),
                (29,7) => Some(SetExternalFrameConfiguration),
                (30,0) => Some(SetMWSSignaling),
                (30,1) => Some(SetMWSTransportLayer),
                (30,2) => Some(SetMWSScanFrequencyTable),
                (30,3) => Some(GetMWSTransportLayerConfiguration),
                (30,4) => Some(SetMWSPATTERNConfiguration),
                (30,5) => Some(SetTriggeredClockCapture),
                (30,6) => Some(TruncatedPage),
                (30,7) => Some(TruncatedPageCancel),
                (31,0) => Some(SetConnectionlessSlaveBroadcast),
                (31,1) => Some(SetConnectionlessSlaveBroadcastReceive),
                (31,2) => Some(StartSynchronizationTrain),
                (31,3) => Some(ReceiveSynchronizationTrain),
                (31,4) => Some(SetReservedLTADDR),
                (31,5) => Some(DeleteReservedLTADDR),
                (31,6) => Some(SetConnectionlessSlaveBroadcastData),
                (31,7) => Some(ReadSynchronizationTrainParameters),
                (32,0) => Some(WriteSynchronizationTrainParameters),
                (32,1) => Some(RemoteOOBExtendedDataRequestReply),
                (32,2) => Some(ReadSecureConnectionsHostSupport),
                (32,3) => Some(WriteSecureConnectionsHostSupport),
                (32,4) => Some(ReadAuthenticatedPayloadTimeout),
                (32,5) => Some(WriteAuthenticatedPayloadTimeout),
                (32,6) => Some(ReadLocalOOBExtendedData),
                (32,7) => Some(WriteSecureConnectionsTestMode),
                (33,0) => Some(ReadExtendedPageTimeout),
                (33,1) => Some(WriteExtendedPageTimeout),
                (33,2) => Some(ReadExtendedInquiryLength),
                (33,3) => Some(WriteExtendedInquiryLengh),
                (33,4) => Some(LERemoteConnectionParameterRequestReply),
                (33,5) => Some(LERemoteConnectionParameterREquestNegativeReply),
                (33,6) => Some(LESetDataLength),
                (33,7) => Some(LEReadSuggestedDefaultDataLength),
                (34,0) => Some(LEWriteSuggestedDefaultDataLength),
                (34,1) => Some(LEReadLocalP256PublicKey),
                (34,2) => Some(LEGenerateDHKey),
                (34,3) => Some(LEAddDeviceToResolvingList),
                (34,4) => Some(LERemoveDeviceFromResolvingList),
                (34,5) => Some(LEClearResolvingList),
                (34,6) => Some(LEReadResolvingListSize),
                (34,7) => Some(LEReadPeerResolvableAddress),
                (35,0) => Some(LEReadLocalResolvableAddress),
                (35,1) => Some(LESetAddressResolutionEnable),
                (35,2) => Some(LESetResolvablePrivateAddressTimeout),
                (35,3) => Some(LEReadMaximumDataLength),
                (35,4) => Some(LEReadPHYCommand),
                (35,5) => Some(LESetDefaultPHYCommand),
                (35,6) => Some(LESetPHYCommand),
                (35,7) => Some(LEEnhancedReceiverTestCommand),
                (36,0) => Some(LEEnhancedTransmitterTestCommand),
                (36,1) => Some(LESetAdvertisingSetRandomAddressCommand),
                (36,2) => Some(LESetExtendedAdvertisingParametersCommand),
                (36,3) => Some(LESetExtendedAdvertisingDataCommand),
                (36,4) => Some(LESetExtendedScanResponseDataCommand),
                (36,5) => Some(LESetExtendedAdvertisingEnableCommand),
                (36,6) => Some(LEReadMaximumAdvertisingDataLengthCommand),
                (36,7) => Some(LEReadNumberOfSupportedAdvertisingSetCommand),
                (37,0) => Some(LERemoveAdvertisingSetCommand),
                (37,1) => Some(LEClearAdvertisingSetsCommand),
                (37,2) => Some(LESetPeriodicAdvertisingParametersCommand),
                (37,3) => Some(LESetPeriodicAdvertisingDataCommand),
                (37,4) => Some(LESetPeriodicAdvertisingEnableCommand),
                (37,5) => Some(LESetExtendedScanParametersCommand),
                (37,6) => Some(LESetExtendedScanEnableCommand),
                (37,7) => Some(LEExtendedCreateConnectionCommand),
                (38,0) => Some(LEPeriodicAdvertisingCreateSyncCommand),
                (38,1) => Some(LEPeriodicAdvertisingCreateSyncCancelCommand),
                (38,2) => Some(LEPeriodicAdvertisingTerminateSyncCommand),
                (38,3) => Some(LEAddDeviceToPeriodicAdvertiserListCommand),
                (38,4) => Some(LERemoveDeviceFromPeriodicAdvertiserListCommand),
                (38,5) => Some(LEClearPeriodicAdvertiserListCommand),
                (38,6) => Some(LEReadPeriodicAdvertiserListSizeCommand),
                (38,7) => Some(LEReadTransmitPowerCommand),
                (39,0) => Some(LEReadRFPathCompensationCommand),
                (39,1) => Some(LEWriteRFPathCompensationCommand),
                (39,2) => Some(LESetPrivacyMode),
                _      => None
            }
        }

        pub(crate) fn try_from( packed: CmdReturn ) -> Result<alloc::vec::Vec<Self>, error::Error> {

            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {

                let mut sup_commands =alloc::vec::Vec::new();

                let raw = &packed.supported_commands;

                for indx in 0..raw.len() {
                    for bit in 0..8 {
                        if 0 != raw[indx] & (1 << bit) {
                            if let Some(command) = Self::from_bit_pos((indx,bit)) {
                                sup_commands.push(command);
                            }
                        }
                    }
                }

                Ok(sup_commands)
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
        COMMAND,
        CmdReturn,
        SupportedCommands,
       alloc::vec::Vec<SupportedCommands>,
        error::Error
    );

    impl_command_data_future!(SupportedCommands,alloc::vec::Vec<SupportedCommands>, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
                                 -> impl Future<Output=Result<alloc::vec::Vec<SupportedCommands>, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }
}
