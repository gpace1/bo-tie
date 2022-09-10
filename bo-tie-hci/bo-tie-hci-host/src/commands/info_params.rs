//! Informational Parameter Commands

/// Read Local Version Information Command
///
/// This command will give the version information for the Host Controller Interface (HCI) and Link
/// Manager Protocol (LMP) along with the Bluetooth SIG assigned number of the manufacturer. For
/// AMP, the PAL version information is returned instead of the LMP version (but the information is
/// usually .
pub mod read_local_version_information {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::InformationParameters(
        opcodes::InformationParameters::ReadLocalSupportedVersionInformation,
    );

    #[derive(Debug)]
    pub struct VersionInformation {
        pub hci_version: u8,
        pub hci_revision: u16,
        pub lmp_pal_version: u8,
        pub manufacturer_name: u16,
        pub lmp_pal_subversion: u16,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for VersionInformation {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let hci_version = *cc
                .return_parameter
                .get(1)
                .ok_or(CCParameterError::InvalidEventParameter)?;

            let hci_revision = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(3)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let lmp_pal_version = *cc
                .return_parameter
                .get(4)
                .ok_or(CCParameterError::InvalidEventParameter)?;

            let manufacturer_name = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(5)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(6)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let lmp_pal_subversion = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(7)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(8)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                hci_version,
                hci_revision,
                lmp_pal_version,
                manufacturer_name,
                lmp_pal_subversion,
                completed_packets_cnt,
            })
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Get the version information from the Controller
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<VersionInformation, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// Read Local Supported Commands Command
///
/// This returns the list of Host Controller Interface commands that are implemented by the
/// controller.
pub mod read_local_supported_commands {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::InformationParameters(opcodes::InformationParameters::ReadLocalSupportedCommands);

    #[derive(Debug, Clone, Copy, PartialEq, Ord, PartialOrd, Eq)]
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
        /// The last byte containing command masks
        ///
        /// Instead of iterating into the bytes that have no masks, the `LAST_BYTE` is used to mark
        /// wherever the last byte is used. This value will need to be updated when more commands
        /// are added to the HCI in new editions of the Bluetooth Specification.
        const LAST_BYTE: usize = 39;

        fn from_bit_pos(pos: (usize, usize)) -> Option<SupportedCommands> {
            use self::SupportedCommands::*;

            match pos {
                (0, 0) => Some(Inquiry),
                (0, 1) => Some(InquiryCancel),
                (0, 2) => Some(PeriodicInquiryMode),
                (0, 3) => Some(ExitPeriodicInquiryMode),
                (0, 4) => Some(CreateConnection),
                (0, 5) => Some(Disconnect),
                (0, 6) => Some(AddSCOConnection),
                (0, 7) => Some(CreateConnectionCancel),
                (1, 0) => Some(AcceptConnectionRequest),
                (1, 1) => Some(RejectConnectionRequest),
                (1, 2) => Some(LinkKeyRequestReply),
                (1, 3) => Some(LinkKeyRequestNegativeReply),
                (1, 4) => Some(PINCodeRequestReply),
                (1, 5) => Some(PINCodeRequestNegativeReply),
                (1, 6) => Some(ChangeConnectionPacketType),
                (1, 7) => Some(AuthenticationRequested),
                (2, 0) => Some(SetConnectionEncryption),
                (2, 1) => Some(ChangeConnectionLinkKey),
                (2, 2) => Some(MasterLinkKey),
                (2, 3) => Some(RemoteNameRequest),
                (2, 4) => Some(RemoteNameRequestCancel),
                (2, 5) => Some(ReadRemoteSupportedFeatures),
                (2, 6) => Some(ReadRemoteExtendedFeatures),
                (2, 7) => Some(ReadRemoteVersionInformation),
                (3, 0) => Some(ReadClockOffset),
                (3, 1) => Some(ReadLMPHandle),
                (4, 1) => Some(HoldMode),
                (4, 2) => Some(SniffMode),
                (4, 3) => Some(ExitSniffMode),
                (4, 6) => Some(QosSetup),
                (4, 7) => Some(RoleDiscovery),
                (5, 0) => Some(SwitchRole),
                (5, 1) => Some(ReadLinkPolicySettings),
                (5, 2) => Some(WriteLinkPolicySettings),
                (5, 3) => Some(ReadDefaultLinkPolicySettings),
                (5, 4) => Some(WriteDefaultLinkPolicySettings),
                (5, 5) => Some(FlowSpecification),
                (5, 6) => Some(SetEventMask),
                (5, 7) => Some(Reset),
                (6, 0) => Some(SetEVentFilter),
                (6, 1) => Some(Flush),
                (6, 2) => Some(ReadPINType),
                (6, 3) => Some(WritePINType),
                (6, 4) => Some(CreateNewUnitKey),
                (6, 5) => Some(ReadStoredLinkKey),
                (6, 6) => Some(WriteStoredLinkKey),
                (6, 7) => Some(DeleteStoredLinkKey),
                (7, 0) => Some(WriteLocalName),
                (7, 1) => Some(ReadLocalName),
                (7, 2) => Some(ReadConnectionAcceptedTimeout),
                (7, 3) => Some(WriteConnectionAcceptedTimeout),
                (7, 4) => Some(ReadPageTimeout),
                (7, 5) => Some(WritePageTimeout),
                (7, 6) => Some(ReadScanEnable),
                (7, 7) => Some(WriteScanEnable),
                (8, 0) => Some(ReadPageScanActivity),
                (8, 1) => Some(WritePageScanActivity),
                (8, 2) => Some(ReadInquiryScanActivity),
                (8, 3) => Some(WriteInquiryScanActivity),
                (8, 4) => Some(ReadAuthenticationEnable),
                (8, 5) => Some(WriteAuthenticationEnable),
                (8, 6) => Some(ReadEncryptionMode),
                (8, 7) => Some(WriteEncryptionMode),
                (9, 0) => Some(ReadClassOfDevice),
                (9, 1) => Some(WriteClassOfDevice),
                (9, 2) => Some(REadVoiceSetting),
                (9, 3) => Some(WriteVoiceSetting),
                (9, 4) => Some(ReadAutomaticFlushTimeout),
                (9, 5) => Some(WriteAutomaticFlushTimeout),
                (9, 6) => Some(ReadNumBroadcastRetransmission),
                (9, 7) => Some(WriteNumBroadcastRetransmissions),
                (10, 0) => Some(ReadHoldModeActivity),
                (10, 1) => Some(WriteHoldModeActiviy),
                (10, 2) => Some(ReadTransmitPowerLevel),
                (10, 3) => Some(ReadSynchronousFlowControlEnable),
                (10, 4) => Some(WriteSynchronousFlowControlEnable),
                (10, 5) => Some(SetConrollerToHostFlowControl),
                (10, 6) => Some(HostBufferSize),
                (10, 7) => Some(HostNumberOfCompletedPackets),
                (11, 0) => Some(ReadLinkSupervisionTimeout),
                (11, 1) => Some(WriteLinkSupervisionTimeout),
                (11, 2) => Some(ReadNumberOfSupportedIAC),
                (11, 3) => Some(ReadCurrentIACLAP),
                (11, 4) => Some(WriteCurrentIACLAP),
                (11, 5) => Some(ReadPageScanModePeriod),
                (11, 6) => Some(WritePageScanModePeriod),
                (11, 7) => Some(ReadPageScanMode),
                (12, 0) => Some(WritePageSanMode),
                (12, 1) => Some(SetAFHHostChannel),
                (12, 4) => Some(ReadInquiryScanType),
                (12, 5) => Some(WriteInquirySCanType),
                (12, 6) => Some(ReadInquiryMode),
                (12, 7) => Some(WriteInquiryMode),
                (13, 0) => Some(ReadPageScanType),
                (13, 1) => Some(WritePageScanType),
                (13, 2) => Some(ReadAFHChannelAssessmentMode),
                (13, 3) => Some(WriteAFHChannelAssessmentMode),
                (14, 3) => Some(ReadLocalVersionInformation),
                (14, 5) => Some(ReadLocalSupportedFeatures),
                (14, 6) => Some(ReadLocalExtendedFeatures),
                (14, 7) => Some(ReadBufferSize),
                (15, 0) => Some(ReadCountryCode),
                (15, 1) => Some(ReadBDADDR),
                (15, 2) => Some(ReadFAiledContactCounter),
                (15, 3) => Some(ResetFailedContactCounter),
                (15, 4) => Some(ReadLinkQuality),
                (15, 5) => Some(ReadRSSI),
                (15, 6) => Some(ReadAFHChannelMap),
                (15, 7) => Some(ReadClock),
                (16, 0) => Some(ReadLoopbackMode),
                (16, 1) => Some(WriteLoopbackMode),
                (16, 2) => Some(EnableDeviceUnderTestMode),
                (16, 3) => Some(SetupSynchronousConnectionRequest),
                (16, 4) => Some(AcceptSynchronousConnectionRequest),
                (16, 5) => Some(RejectSynchronousConnectionRequest),
                (17, 0) => Some(ReadExtendedInquiryResponse),
                (17, 1) => Some(WriteExtendedInquiryResponse),
                (17, 2) => Some(RefreshEncryptionKey),
                (17, 4) => Some(SniffSubrating),
                (17, 5) => Some(ReadSimplePairingMode),
                (17, 6) => Some(WriteSimplePairingMode),
                (17, 7) => Some(ReadLocalOOBData),
                (18, 0) => Some(ReadInquiryResponseTransmitPowerLevel),
                (18, 1) => Some(WriteInquiryTransmitPowerLevel),
                (18, 2) => Some(ReadDefaultErroneousDataReporting),
                (18, 3) => Some(WriteDefaultErroneousDataReporting),
                (18, 7) => Some(IOCapabilityRequestReply),
                (19, 0) => Some(UserConfirmationRequestReply),
                (19, 1) => Some(UserConfirmationRequestNegativeReply),
                (19, 2) => Some(UserPasskeyRequestReply),
                (19, 3) => Some(UserPasskeyRequestNegativeReply),
                (19, 4) => Some(RemoteOOBDataRequestReply),
                (19, 5) => Some(WriteSimplePairingDebugMode),
                (19, 6) => Some(EnhancedFlush),
                (19, 7) => Some(RemoteOOBDataRequestNagativeReply),
                (20, 2) => Some(SendKeypressNotification),
                (20, 3) => Some(IOCapabilityRequestNegativeReply),
                (20, 4) => Some(ReadEncryptionKeySize),
                (21, 0) => Some(CreatePhysicalLink),
                (21, 1) => Some(AcceptPhysicalLink),
                (21, 2) => Some(DisconnectPhysicalLink),
                (21, 3) => Some(CreateLogicalLink),
                (21, 4) => Some(AcceptLogicalLink),
                (21, 5) => Some(DisconnectLogicalLink),
                (21, 6) => Some(LogicalLinkCancel),
                (21, 7) => Some(FlowSpecModify),
                (22, 0) => Some(ReadLogicalLinkAcceptTimeout),
                (22, 1) => Some(WriteLogicalLinkAcceptTimeout),
                (22, 2) => Some(SetEventMaskPage2),
                (22, 3) => Some(ReadLocationData),
                (22, 4) => Some(WRiteLocationData),
                (22, 5) => Some(ReadLocalAMPInfo),
                (22, 6) => Some(ReadLocalAMPASSOC),
                (22, 7) => Some(WriteRemoteAMPASSOC),
                (23, 0) => Some(READFlowControlMode),
                (23, 1) => Some(WriteFlowControlMode),
                (23, 2) => Some(ReadDataBlockSize),
                (23, 5) => Some(EnableAMPReceiverReports),
                (23, 6) => Some(AMPTestEnd),
                (23, 7) => Some(AmPTest),
                (24, 0) => Some(ReadEnhancedTransmitPowerLevel),
                (24, 2) => Some(ReadBestEffortFlushTimeout),
                (24, 3) => Some(WriteBestEffortFlushTimeout),
                (24, 4) => Some(ShortRangeMode),
                (24, 5) => Some(ReadLEHostSupport),
                (24, 6) => Some(WriteLEHostSupport),
                (25, 0) => Some(LESetEventMask),
                (25, 1) => Some(LEReadBufferSize),
                (25, 2) => Some(LEReadLocalSupportedFeatures),
                (25, 4) => Some(LESetRandomAddress),
                (25, 5) => Some(LESetAdvertisingParameters),
                (25, 6) => Some(LEReadAdvertisingChannelTXPower),
                (25, 7) => Some(LESetAdvertisingData),
                (26, 0) => Some(LESetScanResponseData),
                (26, 1) => Some(LESetAdvertisingEnable),
                (26, 2) => Some(LESetScanParameters),
                (26, 3) => Some(LESetScanEnable),
                (26, 4) => Some(LECreateConnection),
                (26, 5) => Some(LECreateConnectionCancel),
                (26, 6) => Some(LEReadWhiteListSize),
                (26, 7) => Some(LEClearWhiteList),
                (27, 0) => Some(LEAddDeviceToWhiteList),
                (27, 1) => Some(LERemoveDeviceFromWhiteList),
                (27, 2) => Some(LEConnectionUpdate),
                (27, 3) => Some(LESetHostChannelClassification),
                (27, 4) => Some(LEReadChannelMap),
                (27, 5) => Some(LEReadRemoteFeatures),
                (27, 6) => Some(LEEncrypt),
                (27, 7) => Some(LERand),
                (28, 0) => Some(LEStartEncryption),
                (28, 1) => Some(LELongTermKeyRequestReply),
                (28, 2) => Some(LELongTermKeyRequestNegativeReply),
                (28, 3) => Some(LEReadSupportedStates),
                (28, 4) => Some(LEReceiverTest),
                (28, 5) => Some(LETransmitterTest),
                (28, 6) => Some(LETestEnd),
                (29, 3) => Some(EnhancedSetupSynchronousConnection),
                (29, 4) => Some(EnhancedAcceptSynchronousConnection),
                (29, 5) => Some(ReadLocalSupportedCondecs),
                (29, 6) => Some(SetMWSChannelParameters),
                (29, 7) => Some(SetExternalFrameConfiguration),
                (30, 0) => Some(SetMWSSignaling),
                (30, 1) => Some(SetMWSTransportLayer),
                (30, 2) => Some(SetMWSScanFrequencyTable),
                (30, 3) => Some(GetMWSTransportLayerConfiguration),
                (30, 4) => Some(SetMWSPATTERNConfiguration),
                (30, 5) => Some(SetTriggeredClockCapture),
                (30, 6) => Some(TruncatedPage),
                (30, 7) => Some(TruncatedPageCancel),
                (31, 0) => Some(SetConnectionlessSlaveBroadcast),
                (31, 1) => Some(SetConnectionlessSlaveBroadcastReceive),
                (31, 2) => Some(StartSynchronizationTrain),
                (31, 3) => Some(ReceiveSynchronizationTrain),
                (31, 4) => Some(SetReservedLTADDR),
                (31, 5) => Some(DeleteReservedLTADDR),
                (31, 6) => Some(SetConnectionlessSlaveBroadcastData),
                (31, 7) => Some(ReadSynchronizationTrainParameters),
                (32, 0) => Some(WriteSynchronizationTrainParameters),
                (32, 1) => Some(RemoteOOBExtendedDataRequestReply),
                (32, 2) => Some(ReadSecureConnectionsHostSupport),
                (32, 3) => Some(WriteSecureConnectionsHostSupport),
                (32, 4) => Some(ReadAuthenticatedPayloadTimeout),
                (32, 5) => Some(WriteAuthenticatedPayloadTimeout),
                (32, 6) => Some(ReadLocalOOBExtendedData),
                (32, 7) => Some(WriteSecureConnectionsTestMode),
                (33, 0) => Some(ReadExtendedPageTimeout),
                (33, 1) => Some(WriteExtendedPageTimeout),
                (33, 2) => Some(ReadExtendedInquiryLength),
                (33, 3) => Some(WriteExtendedInquiryLengh),
                (33, 4) => Some(LERemoteConnectionParameterRequestReply),
                (33, 5) => Some(LERemoteConnectionParameterREquestNegativeReply),
                (33, 6) => Some(LESetDataLength),
                (33, 7) => Some(LEReadSuggestedDefaultDataLength),
                (34, 0) => Some(LEWriteSuggestedDefaultDataLength),
                (34, 1) => Some(LEReadLocalP256PublicKey),
                (34, 2) => Some(LEGenerateDHKey),
                (34, 3) => Some(LEAddDeviceToResolvingList),
                (34, 4) => Some(LERemoveDeviceFromResolvingList),
                (34, 5) => Some(LEClearResolvingList),
                (34, 6) => Some(LEReadResolvingListSize),
                (34, 7) => Some(LEReadPeerResolvableAddress),
                (35, 0) => Some(LEReadLocalResolvableAddress),
                (35, 1) => Some(LESetAddressResolutionEnable),
                (35, 2) => Some(LESetResolvablePrivateAddressTimeout),
                (35, 3) => Some(LEReadMaximumDataLength),
                (35, 4) => Some(LEReadPHYCommand),
                (35, 5) => Some(LESetDefaultPHYCommand),
                (35, 6) => Some(LESetPHYCommand),
                (35, 7) => Some(LEEnhancedReceiverTestCommand),
                (36, 0) => Some(LEEnhancedTransmitterTestCommand),
                (36, 1) => Some(LESetAdvertisingSetRandomAddressCommand),
                (36, 2) => Some(LESetExtendedAdvertisingParametersCommand),
                (36, 3) => Some(LESetExtendedAdvertisingDataCommand),
                (36, 4) => Some(LESetExtendedScanResponseDataCommand),
                (36, 5) => Some(LESetExtendedAdvertisingEnableCommand),
                (36, 6) => Some(LEReadMaximumAdvertisingDataLengthCommand),
                (36, 7) => Some(LEReadNumberOfSupportedAdvertisingSetCommand),
                (37, 0) => Some(LERemoveAdvertisingSetCommand),
                (37, 1) => Some(LEClearAdvertisingSetsCommand),
                (37, 2) => Some(LESetPeriodicAdvertisingParametersCommand),
                (37, 3) => Some(LESetPeriodicAdvertisingDataCommand),
                (37, 4) => Some(LESetPeriodicAdvertisingEnableCommand),
                (37, 5) => Some(LESetExtendedScanParametersCommand),
                (37, 6) => Some(LESetExtendedScanEnableCommand),
                (37, 7) => Some(LEExtendedCreateConnectionCommand),
                (38, 0) => Some(LEPeriodicAdvertisingCreateSyncCommand),
                (38, 1) => Some(LEPeriodicAdvertisingCreateSyncCancelCommand),
                (38, 2) => Some(LEPeriodicAdvertisingTerminateSyncCommand),
                (38, 3) => Some(LEAddDeviceToPeriodicAdvertiserListCommand),
                (38, 4) => Some(LERemoveDeviceFromPeriodicAdvertiserListCommand),
                (38, 5) => Some(LEClearPeriodicAdvertiserListCommand),
                (38, 6) => Some(LEReadPeriodicAdvertiserListSizeCommand),
                (38, 7) => Some(LEReadTransmitPowerCommand),
                (Self::LAST_BYTE, 0) => Some(LEReadRFPathCompensationCommand),
                (Self::LAST_BYTE, 1) => Some(LEWriteRFPathCompensationCommand),
                (Self::LAST_BYTE, 2) => Some(LESetPrivacyMode),
                _ => None,
            }
        }
        /// Get the position of the command within the bit mask
        ///
        /// The return is the byte followed by the bit within the byte.
        fn get_pos(&self) -> (usize, usize) {
            use self::SupportedCommands::*;

            match self {
                Inquiry => (0, 0),
                InquiryCancel => (0, 1),
                PeriodicInquiryMode => (0, 2),
                ExitPeriodicInquiryMode => (0, 3),
                CreateConnection => (0, 4),
                Disconnect => (0, 5),
                AddSCOConnection => (0, 6),
                CreateConnectionCancel => (0, 7),
                AcceptConnectionRequest => (1, 0),
                RejectConnectionRequest => (1, 1),
                LinkKeyRequestReply => (1, 2),
                LinkKeyRequestNegativeReply => (1, 3),
                PINCodeRequestReply => (1, 4),
                PINCodeRequestNegativeReply => (1, 5),
                ChangeConnectionPacketType => (1, 6),
                AuthenticationRequested => (1, 7),
                SetConnectionEncryption => (2, 0),
                ChangeConnectionLinkKey => (2, 1),
                MasterLinkKey => (2, 2),
                RemoteNameRequest => (2, 3),
                RemoteNameRequestCancel => (2, 4),
                ReadRemoteSupportedFeatures => (2, 5),
                ReadRemoteExtendedFeatures => (2, 6),
                ReadRemoteVersionInformation => (2, 7),
                ReadClockOffset => (3, 0),
                ReadLMPHandle => (3, 1),
                HoldMode => (4, 1),
                SniffMode => (4, 2),
                ExitSniffMode => (4, 3),
                QosSetup => (4, 6),
                RoleDiscovery => (4, 7),
                SwitchRole => (5, 0),
                ReadLinkPolicySettings => (5, 1),
                WriteLinkPolicySettings => (5, 2),
                ReadDefaultLinkPolicySettings => (5, 3),
                WriteDefaultLinkPolicySettings => (5, 4),
                FlowSpecification => (5, 5),
                SetEventMask => (5, 6),
                Reset => (5, 7),
                SetEVentFilter => (6, 0),
                Flush => (6, 1),
                ReadPINType => (6, 2),
                WritePINType => (6, 3),
                CreateNewUnitKey => (6, 4),
                ReadStoredLinkKey => (6, 5),
                WriteStoredLinkKey => (6, 6),
                DeleteStoredLinkKey => (6, 7),
                WriteLocalName => (7, 0),
                ReadLocalName => (7, 1),
                ReadConnectionAcceptedTimeout => (7, 2),
                WriteConnectionAcceptedTimeout => (7, 3),
                ReadPageTimeout => (7, 4),
                WritePageTimeout => (7, 5),
                ReadScanEnable => (7, 6),
                WriteScanEnable => (7, 7),
                ReadPageScanActivity => (8, 0),
                WritePageScanActivity => (8, 1),
                ReadInquiryScanActivity => (8, 2),
                WriteInquiryScanActivity => (8, 3),
                ReadAuthenticationEnable => (8, 4),
                WriteAuthenticationEnable => (8, 5),
                ReadEncryptionMode => (8, 6),
                WriteEncryptionMode => (8, 7),
                ReadClassOfDevice => (9, 0),
                WriteClassOfDevice => (9, 1),
                REadVoiceSetting => (9, 2),
                WriteVoiceSetting => (9, 3),
                ReadAutomaticFlushTimeout => (9, 4),
                WriteAutomaticFlushTimeout => (9, 5),
                ReadNumBroadcastRetransmission => (9, 6),
                WriteNumBroadcastRetransmissions => (9, 7),
                ReadHoldModeActivity => (10, 0),
                WriteHoldModeActiviy => (10, 1),
                ReadTransmitPowerLevel => (10, 2),
                ReadSynchronousFlowControlEnable => (10, 3),
                WriteSynchronousFlowControlEnable => (10, 4),
                SetConrollerToHostFlowControl => (10, 5),
                HostBufferSize => (10, 6),
                HostNumberOfCompletedPackets => (10, 7),
                ReadLinkSupervisionTimeout => (11, 0),
                WriteLinkSupervisionTimeout => (11, 1),
                ReadNumberOfSupportedIAC => (11, 2),
                ReadCurrentIACLAP => (11, 3),
                WriteCurrentIACLAP => (11, 4),
                ReadPageScanModePeriod => (11, 5),
                WritePageScanModePeriod => (11, 6),
                ReadPageScanMode => (11, 7),
                WritePageSanMode => (12, 0),
                SetAFHHostChannel => (12, 1),
                ReadInquiryScanType => (12, 4),
                WriteInquirySCanType => (12, 5),
                ReadInquiryMode => (12, 6),
                WriteInquiryMode => (12, 7),
                ReadPageScanType => (13, 0),
                WritePageScanType => (13, 1),
                ReadAFHChannelAssessmentMode => (13, 2),
                WriteAFHChannelAssessmentMode => (13, 3),
                ReadLocalVersionInformation => (14, 3),
                ReadLocalSupportedFeatures => (14, 5),
                ReadLocalExtendedFeatures => (14, 6),
                ReadBufferSize => (14, 7),
                ReadCountryCode => (15, 0),
                ReadBDADDR => (15, 1),
                ReadFAiledContactCounter => (15, 2),
                ResetFailedContactCounter => (15, 3),
                ReadLinkQuality => (15, 4),
                ReadRSSI => (15, 5),
                ReadAFHChannelMap => (15, 6),
                ReadClock => (15, 7),
                ReadLoopbackMode => (16, 0),
                WriteLoopbackMode => (16, 1),
                EnableDeviceUnderTestMode => (16, 2),
                SetupSynchronousConnectionRequest => (16, 3),
                AcceptSynchronousConnectionRequest => (16, 4),
                RejectSynchronousConnectionRequest => (16, 5),
                ReadExtendedInquiryResponse => (17, 0),
                WriteExtendedInquiryResponse => (17, 1),
                RefreshEncryptionKey => (17, 2),
                SniffSubrating => (17, 4),
                ReadSimplePairingMode => (17, 5),
                WriteSimplePairingMode => (17, 6),
                ReadLocalOOBData => (17, 7),
                ReadInquiryResponseTransmitPowerLevel => (18, 0),
                WriteInquiryTransmitPowerLevel => (18, 1),
                ReadDefaultErroneousDataReporting => (18, 2),
                WriteDefaultErroneousDataReporting => (18, 3),
                IOCapabilityRequestReply => (18, 7),
                UserConfirmationRequestReply => (19, 0),
                UserConfirmationRequestNegativeReply => (19, 1),
                UserPasskeyRequestReply => (19, 2),
                UserPasskeyRequestNegativeReply => (19, 3),
                RemoteOOBDataRequestReply => (19, 4),
                WriteSimplePairingDebugMode => (19, 5),
                EnhancedFlush => (19, 6),
                RemoteOOBDataRequestNagativeReply => (19, 7),
                SendKeypressNotification => (20, 2),
                IOCapabilityRequestNegativeReply => (20, 3),
                ReadEncryptionKeySize => (20, 4),
                CreatePhysicalLink => (21, 0),
                AcceptPhysicalLink => (21, 1),
                DisconnectPhysicalLink => (21, 2),
                CreateLogicalLink => (21, 3),
                AcceptLogicalLink => (21, 4),
                DisconnectLogicalLink => (21, 5),
                LogicalLinkCancel => (21, 6),
                FlowSpecModify => (21, 7),
                ReadLogicalLinkAcceptTimeout => (22, 0),
                WriteLogicalLinkAcceptTimeout => (22, 1),
                SetEventMaskPage2 => (22, 2),
                ReadLocationData => (22, 3),
                WRiteLocationData => (22, 4),
                ReadLocalAMPInfo => (22, 5),
                ReadLocalAMPASSOC => (22, 6),
                WriteRemoteAMPASSOC => (22, 7),
                READFlowControlMode => (23, 0),
                WriteFlowControlMode => (23, 1),
                ReadDataBlockSize => (23, 2),
                EnableAMPReceiverReports => (23, 5),
                AMPTestEnd => (23, 6),
                AmPTest => (23, 7),
                ReadEnhancedTransmitPowerLevel => (24, 0),
                ReadBestEffortFlushTimeout => (24, 2),
                WriteBestEffortFlushTimeout => (24, 3),
                ShortRangeMode => (24, 4),
                ReadLEHostSupport => (24, 5),
                WriteLEHostSupport => (24, 6),
                LESetEventMask => (25, 0),
                LEReadBufferSize => (25, 1),
                LEReadLocalSupportedFeatures => (25, 2),
                LESetRandomAddress => (25, 4),
                LESetAdvertisingParameters => (25, 5),
                LEReadAdvertisingChannelTXPower => (25, 6),
                LESetAdvertisingData => (25, 7),
                LESetScanResponseData => (26, 0),
                LESetAdvertisingEnable => (26, 1),
                LESetScanParameters => (26, 2),
                LESetScanEnable => (26, 3),
                LECreateConnection => (26, 4),
                LECreateConnectionCancel => (26, 5),
                LEReadWhiteListSize => (26, 6),
                LEClearWhiteList => (26, 7),
                LEAddDeviceToWhiteList => (27, 0),
                LERemoveDeviceFromWhiteList => (27, 1),
                LEConnectionUpdate => (27, 2),
                LESetHostChannelClassification => (27, 3),
                LEReadChannelMap => (27, 4),
                LEReadRemoteFeatures => (27, 5),
                LEEncrypt => (27, 6),
                LERand => (27, 7),
                LEStartEncryption => (28, 0),
                LELongTermKeyRequestReply => (28, 1),
                LELongTermKeyRequestNegativeReply => (28, 2),
                LEReadSupportedStates => (28, 3),
                LEReceiverTest => (28, 4),
                LETransmitterTest => (28, 5),
                LETestEnd => (28, 6),
                EnhancedSetupSynchronousConnection => (29, 3),
                EnhancedAcceptSynchronousConnection => (29, 4),
                ReadLocalSupportedCondecs => (29, 5),
                SetMWSChannelParameters => (29, 6),
                SetExternalFrameConfiguration => (29, 7),
                SetMWSSignaling => (30, 0),
                SetMWSTransportLayer => (30, 1),
                SetMWSScanFrequencyTable => (30, 2),
                GetMWSTransportLayerConfiguration => (30, 3),
                SetMWSPATTERNConfiguration => (30, 4),
                SetTriggeredClockCapture => (30, 5),
                TruncatedPage => (30, 6),
                TruncatedPageCancel => (30, 7),
                SetConnectionlessSlaveBroadcast => (31, 0),
                SetConnectionlessSlaveBroadcastReceive => (31, 1),
                StartSynchronizationTrain => (31, 2),
                ReceiveSynchronizationTrain => (31, 3),
                SetReservedLTADDR => (31, 4),
                DeleteReservedLTADDR => (31, 5),
                SetConnectionlessSlaveBroadcastData => (31, 6),
                ReadSynchronizationTrainParameters => (31, 7),
                WriteSynchronizationTrainParameters => (32, 0),
                RemoteOOBExtendedDataRequestReply => (32, 1),
                ReadSecureConnectionsHostSupport => (32, 2),
                WriteSecureConnectionsHostSupport => (32, 3),
                ReadAuthenticatedPayloadTimeout => (32, 4),
                WriteAuthenticatedPayloadTimeout => (32, 5),
                ReadLocalOOBExtendedData => (32, 6),
                WriteSecureConnectionsTestMode => (32, 7),
                ReadExtendedPageTimeout => (33, 0),
                WriteExtendedPageTimeout => (33, 1),
                ReadExtendedInquiryLength => (33, 2),
                WriteExtendedInquiryLengh => (33, 3),
                LERemoteConnectionParameterRequestReply => (33, 4),
                LERemoteConnectionParameterREquestNegativeReply => (33, 5),
                LESetDataLength => (33, 6),
                LEReadSuggestedDefaultDataLength => (33, 7),
                LEWriteSuggestedDefaultDataLength => (34, 0),
                LEReadLocalP256PublicKey => (34, 1),
                LEGenerateDHKey => (34, 2),
                LEAddDeviceToResolvingList => (34, 3),
                LERemoveDeviceFromResolvingList => (34, 4),
                LEClearResolvingList => (34, 5),
                LEReadResolvingListSize => (34, 6),
                LEReadPeerResolvableAddress => (34, 7),
                LEReadLocalResolvableAddress => (35, 0),
                LESetAddressResolutionEnable => (35, 1),
                LESetResolvablePrivateAddressTimeout => (35, 2),
                LEReadMaximumDataLength => (35, 3),
                LEReadPHYCommand => (35, 4),
                LESetDefaultPHYCommand => (35, 5),
                LESetPHYCommand => (35, 6),
                LEEnhancedReceiverTestCommand => (35, 7),
                LEEnhancedTransmitterTestCommand => (36, 0),
                LESetAdvertisingSetRandomAddressCommand => (36, 1),
                LESetExtendedAdvertisingParametersCommand => (36, 2),
                LESetExtendedAdvertisingDataCommand => (36, 3),
                LESetExtendedScanResponseDataCommand => (36, 4),
                LESetExtendedAdvertisingEnableCommand => (36, 5),
                LEReadMaximumAdvertisingDataLengthCommand => (36, 6),
                LEReadNumberOfSupportedAdvertisingSetCommand => (36, 7),
                LERemoveAdvertisingSetCommand => (37, 0),
                LEClearAdvertisingSetsCommand => (37, 1),
                LESetPeriodicAdvertisingParametersCommand => (37, 2),
                LESetPeriodicAdvertisingDataCommand => (37, 3),
                LESetPeriodicAdvertisingEnableCommand => (37, 4),
                LESetExtendedScanParametersCommand => (37, 5),
                LESetExtendedScanEnableCommand => (37, 6),
                LEExtendedCreateConnectionCommand => (37, 7),
                LEPeriodicAdvertisingCreateSyncCommand => (38, 0),
                LEPeriodicAdvertisingCreateSyncCancelCommand => (38, 1),
                LEPeriodicAdvertisingTerminateSyncCommand => (38, 2),
                LEAddDeviceToPeriodicAdvertiserListCommand => (38, 3),
                LERemoveDeviceFromPeriodicAdvertiserListCommand => (38, 4),
                LEClearPeriodicAdvertiserListCommand => (38, 5),
                LEReadPeriodicAdvertiserListSizeCommand => (38, 6),
                LEReadTransmitPowerCommand => (38, 7),
                LEReadRFPathCompensationCommand => (Self::LAST_BYTE, 0),
                LEWriteRFPathCompensationCommand => (Self::LAST_BYTE, 1),
                LESetPrivacyMode => (Self::LAST_BYTE, 2),
            }
        }
    }

    /// An iterator over the supported commands
    ///
    /// The controller returns a bit mask of the commands within
    pub struct SuppCmdIter<'a> {
        supported_commands: &'a [u8; 64],
        byte: usize,
        bit: usize,
    }

    impl<'a> SuppCmdIter<'a> {
        fn new(supported_commands: &'a [u8; 64]) -> Self {
            Self {
                supported_commands,
                byte: 0,
                bit: 0,
            }
        }

        fn next_pos(&mut self) {
            if (self.bit + 1) / 8 == 1 {
                self.bit += 1
            } else {
                self.bit = 0;
                self.byte += 1;
            }
        }
    }

    impl Iterator for SuppCmdIter<'_> {
        type Item = SupportedCommands;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                if let Some(command) = SupportedCommands::from_bit_pos((self.byte, self.bit)) {
                    if (self.supported_commands[self.byte] & (1 << self.bit)) != 0 {
                        self.next_pos();

                        break Some(command);
                    }
                } else {
                    if self.byte > SupportedCommands::LAST_BYTE {
                        break None;
                    }
                }

                self.next_pos()
            }
        }
    }

    /// The supported commands of the controller
    pub struct Return {
        supported_commands: [u8; 64],
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl Return {
        /// Check if the command is enabled
        pub fn is_enabled(&self, command: SupportedCommands) -> bool {
            let (byte, bit) = command.get_pos();

            self.supported_commands[byte] & (1 << bit) != 0
        }

        /// Iterate over the enabled commands
        ///
        /// # Note
        /// Only the commands listed within [`SupportedCommands`](SupportedCommands) are iterated
        /// over, any masked custom commands are not returned.
        pub fn iter(&self) -> SuppCmdIter<'_> {
            SuppCmdIter::new(&self.supported_commands)
        }

        /// Get the raw bit mask
        pub fn get_raw_mask(&self) -> &[u8; 64] {
            &self.supported_commands
        }
    }

    impl<'a> IntoIterator for &'a Return {
        type Item = SupportedCommands;
        type IntoIter = SuppCmdIter<'a>;

        fn into_iter(self) -> Self::IntoIter {
            Return::iter(self)
        }
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == 64 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut supported_commands = [0u8; 64];

                supported_commands.copy_from_slice(&cc.return_parameter[1..]);

                Ok(Self {
                    supported_commands,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Get the bit mask of enabled commands from the Controller
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// Read Local Supported Features Command
///
/// This will return the supported features of the BR/EDR controller
pub mod read_local_supported_features {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };
    use bo_tie_util::{DeviceFeatures, Features, FeaturesIter};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::InformationParameters(opcodes::InformationParameters::ReadLocalSupportedFeatures);

    pub struct EnabledFeatures {
        device_features: DeviceFeatures,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl EnabledFeatures {
        /// Iterator over the enabled features
        fn iter(&self) -> FeaturesIter<'_> {
            self.device_features.iter()
        }
    }

    impl TryFromCommandComplete for EnabledFeatures {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == 8 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let device_features = DeviceFeatures::new(0, &cc.return_parameter[1..])
                    .map_err(|_| CCParameterError::InvalidEventParameter)?;

                Ok(Self {
                    device_features,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    impl<'a> IntoIterator for &'a EnabledFeatures {
        type Item = Features;
        type IntoIter = FeaturesIter<'a>;

        fn into_iter(self) -> Self::IntoIter {
            self.device_features.iter()
        }
    }

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Request the features of the Link Manager Protocol on the controller
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<EnabledFeatures, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// Read BD_ADDR Command
///
/// For LE this will read the public address of the controller. If the controller doesn't have a
/// public device address then this will return 0 as the address.
pub mod read_bd_addr {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };
    use bo_tie_util::BluetoothDeviceAddress;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::InformationParameters(opcodes::InformationParameters::ReadBD_ADDR);

    pub struct Return {
        address: BluetoothDeviceAddress,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == 6 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut address = BluetoothDeviceAddress::zeroed();

                address.copy_from_slice(&cc.return_parameter[1..]);

                Ok(Return {
                    address,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    impl core::ops::Deref for Return {
        type Target = BluetoothDeviceAddress;

        fn deref(&self) -> &Self::Target {
            &self.address
        }
    }

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Get the public Bluetooth device address
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// Read the size of the BR/EDR HCI data buffer
pub mod read_buffer_size {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::InformationParameters(opcodes::InformationParameters::ReadBufferSize);

    pub struct Return {
        pub hc_acl_data_packet_len: usize,
        pub hc_synchronous_data_packet_len: usize,
        pub hc_total_num_acl_data_packets: usize,
        pub hc_total_num_synchronous_data_packets: usize,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let hc_acl_data_packet_len = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ])
            .into();

            let hc_synchronous_data_packet_len = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(3)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(4)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ])
            .into();

            let hc_total_num_acl_data_packets = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(5)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(6)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ])
            .into();

            let hc_total_num_synchronous_data_packets = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(7)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(8)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ])
            .into();

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                hc_acl_data_packet_len,
                hc_synchronous_data_packet_len,
                hc_total_num_acl_data_packets,
                hc_total_num_synchronous_data_packets,
                completed_packets_cnt,
            })
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}
