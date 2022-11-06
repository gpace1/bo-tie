//! LE connection related commands

/// LE Connection Update command
pub mod connection_update {
    use crate::commands::le::{ConnectionEventLength, ConnectionIntervalBounds, SupervisionTimeout};
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ConnectionUpdate);

    pub struct ConnectionUpdate {
        pub handle: ConnectionHandle,
        pub interval: ConnectionIntervalBounds,
        pub latency: u16,
        pub supervision_timeout: SupervisionTimeout,
        pub connection_event_len: ConnectionEventLength,
    }

    impl CommandParameter<14> for ConnectionUpdate {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 14] {
            let mut parameter = [0u8; 14];

            parameter[0..2].copy_from_slice(&self.handle.get_raw_handle().to_le_bytes());

            parameter[2..4].copy_from_slice(&self.interval.get_min().get_raw_val().to_le_bytes());

            parameter[4..6].copy_from_slice(&self.interval.get_max().get_raw_val().to_le_bytes());

            parameter[6..8].copy_from_slice(&self.latency.to_le_bytes());

            parameter[8..10].copy_from_slice(&self.supervision_timeout.get_timeout().to_le_bytes());

            parameter[10..12].copy_from_slice(&self.connection_event_len.minimum.to_le_bytes());

            parameter[12..14].copy_from_slice(&self.connection_event_len.maximum.to_le_bytes());

            parameter
        }
    }

    /// Send the LE Connection Update command
    ///
    /// This sends the LE Connection Update command and awaits for the controller to send back the
    /// Command Status event. If the LE
    /// [`ConnectionUpdateComplete`] event is enabled, the controller will send this event to the
    /// host when the connection is updated.
    ///
    /// [`ConnectionUpdateComplete`]: bo_tie_hci_util::events::LeMeta::ConnectionUpdateComplete
    pub async fn send<H: HostChannelEnds>(
        host: &mut Host<H>,
        parameter: ConnectionUpdate,
    ) -> Result<(), CommandError<H>> {
        host.send_command_expect_status(parameter).await
    }
}

/// Send the LE Create Connection Cancel command
pub mod create_connection_cancel {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::CreateConnectionCancel);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the LE Create Connection Cancel command
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// LE Create Connection command
pub mod create_connection {
    use crate::commands::le::{
        AddressType, ConnectionEventLength, ConnectionIntervalBounds, ConnectionLatency, OwnAddressType,
        SupervisionTimeout,
    };
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use bo_tie_util::BluetoothDeviceAddress;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::CreateConnection);

    bo_tie_hci_util::interval!(ScanningInterval, 0x0004, 0x4000, SpecDef, 0x0010, 625);
    bo_tie_hci_util::interval!(ScanningWindow, 0x0004, 0x4000, SpecDef, 0x0010, 625);

    pub enum InitiatorFilterPolicy {
        DoNotUseWhiteList,
        UseWhiteList,
    }

    impl InitiatorFilterPolicy {
        fn val(&self) -> u8 {
            match *self {
                InitiatorFilterPolicy::DoNotUseWhiteList => 0x00,
                InitiatorFilterPolicy::UseWhiteList => 0x01,
            }
        }
    }

    pub struct ConnectionParameters {
        scan_interval: ScanningInterval,
        scan_window: ScanningWindow,
        initiator_filter_policy: InitiatorFilterPolicy,
        peer_address_type: AddressType,
        peer_address: bo_tie_util::BluetoothDeviceAddress,
        own_address_type: OwnAddressType,
        connection_interval: ConnectionIntervalBounds,
        connection_latency: ConnectionLatency,
        supervision_timeout: SupervisionTimeout,
        connection_event_len: ConnectionEventLength,
    }

    impl CommandParameter<25> for ConnectionParameters {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 25] {
            let mut parameter = [0u8; 25];

            parameter[0..2].copy_from_slice(&self.scan_interval.get_raw_val().to_le_bytes());

            parameter[2..4].copy_from_slice(&self.scan_window.get_raw_val().to_le_bytes());

            parameter[4] = self.initiator_filter_policy.val();

            parameter[5] = self.peer_address_type.get_raw_val();

            parameter[6..12].copy_from_slice(&self.peer_address);

            parameter[12] = self.own_address_type.into();

            parameter[13..15].copy_from_slice(&self.connection_interval.get_min().get_raw_val().to_le_bytes());

            parameter[15..17].copy_from_slice(&self.connection_interval.get_max().get_raw_val().to_le_bytes());

            parameter[17..19].copy_from_slice(&self.connection_latency.get_latency().to_le_bytes());

            parameter[19..21].copy_from_slice(&self.supervision_timeout.get_timeout().to_le_bytes());

            parameter[21..23].copy_from_slice(&self.connection_event_len.minimum.to_le_bytes());

            parameter[23..25].copy_from_slice(&self.connection_event_len.maximum.to_le_bytes());

            parameter
        }
    }

    impl ConnectionParameters {
        /// Command Parameters for connecting without the white list
        pub fn new_without_whitelist(
            scan_interval: ScanningInterval,
            scan_window: ScanningWindow,
            peer_address_type: AddressType,
            peer_address: BluetoothDeviceAddress,
            own_address_type: OwnAddressType,
            connection_interval: ConnectionIntervalBounds,
            connection_latency: ConnectionLatency,
            supervision_timeout: SupervisionTimeout,
            connection_event_len: ConnectionEventLength,
        ) -> Self {
            Self {
                scan_interval,
                scan_window,
                initiator_filter_policy: InitiatorFilterPolicy::DoNotUseWhiteList,
                peer_address_type,
                peer_address,
                own_address_type,
                connection_interval,
                connection_latency,
                supervision_timeout,
                connection_event_len,
            }
        }

        /// Command parameters for connecting with the white list
        pub fn new_with_whitelist(
            scan_interval: ScanningInterval,
            scan_window: ScanningWindow,
            own_address_type: OwnAddressType,
            connection_interval: ConnectionIntervalBounds,
            connection_latency: ConnectionLatency,
            supervision_timeout: SupervisionTimeout,
            connection_event_len: ConnectionEventLength,
        ) -> Self {
            Self {
                scan_interval,
                scan_window,
                initiator_filter_policy: InitiatorFilterPolicy::UseWhiteList,
                peer_address_type: AddressType::PublicDeviceAddress, // This is not used (see spec)
                peer_address: BluetoothDeviceAddress::zeroed(),      // This is not used (see spec)
                own_address_type,
                connection_interval,
                connection_latency,
                supervision_timeout,
                connection_event_len,
            }
        }
    }

    /// Send the LE Create Connection command
    ///
    /// This sends the LE Create Connection command to the controller and awaits for the controller
    /// to send back the [`CommandStatus`] event. If the LE event [`ConnectionComplete`] or
    /// [`EnhancedConnectionComplete`] is unmasked, the controller will send the event (with
    /// `EnhancedConnectionComplete` having precedence over `ConnectionComplete` if they are both
    /// unmasked) to the host after a connection is made.
    ///
    /// [`CommandStatus`]: bo_tie_hci_util::events::Events::CommandStatus
    /// [`ConnectionComplete`]: bo_tie_hci_util::events::LeMeta::ConnectionComplete
    /// [`EnhancedConnectionComplete`]: bo_tie_hci_util::events::LeMeta::EnhancedConnectionComplete
    pub async fn send<H: HostChannelEnds>(
        host: &mut Host<H>,
        parameters: ConnectionParameters,
    ) -> Result<(), CommandError<H>> {
        host.send_command_expect_status(parameters).await
    }
}

/// LE Set Host Channel Classification command
pub mod set_host_channel_classification {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::SetHostChannelClassification);

    struct CmdParameter {
        channel_map: [u8; 5],
    }

    impl CmdParameter {
        fn new<I>(channels: I) -> Self
        where
            I: IntoIterator<Item = usize>,
        {
            let mut channel_map = [0u8; 5];

            for channel in channels {
                let byte = channel / 8;
                let bit = channel % 8;

                channel_map[byte] |= 1 << bit;
            }

            CmdParameter { channel_map }
        }
    }

    impl CommandParameter<5> for CmdParameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 5] {
            self.channel_map
        }
    }

    /// Send the LE Set Host Channel Classification command
    pub async fn send<H, I>(host: &mut Host<H>, channels: I) -> Result<(), CommandError<H>>
    where
        H: HostChannelEnds,
        I: IntoIterator<Item = usize>,
    {
        let parameter = CmdParameter::new(channels);

        host.send_command_expect_complete(parameter).await
    }
}

/// LE Read Channel Map command
pub mod read_channel_map {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadChannelMap);

    pub struct ChannelMapInfo {
        pub handle: ConnectionHandle,
        /// This is the list of channels (from 0 through 36)
        pub channel_map_bit_mask: [u8; 5],
    }

    impl TryFromCommandComplete for ChannelMapInfo {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|_| CCParameterError::InvalidEventParameter)?;

            if cc.return_parameter[3..].len() == 5 {
                let channel_map_bit_mask = [0u8; 5];

                Ok(Self {
                    handle,
                    channel_map_bit_mask,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    /// An iterator over the enabled channels
    pub struct ChannelMapIter {
        bit_mask: [u8; 5],
        channel: usize,
    }

    impl Iterator for ChannelMapIter {
        type Item = usize;

        fn next(&mut self) -> Option<Self::Item> {
            // channels are from 0 -> 36
            while self.channel < 37 {
                let byte = self.channel / 8;
                let bit_offset = self.channel % 8;

                if self.bit_mask[byte] & (1 << bit_offset) != 0 {
                    let channel = self.channel;

                    self.channel += 1;

                    return Some(channel);
                } else {
                    self.channel += 1;
                }
            }

            None
        }
    }

    struct CmdParameter {
        connection_handle: ConnectionHandle,
    }

    impl CommandParameter<2> for CmdParameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.connection_handle.get_raw_handle().to_le_bytes()
        }
    }

    /// Send the LE Read Channel Map command
    pub async fn send<H: HostChannelEnds>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) -> Result<ChannelMapInfo, CommandError<H>> {
        let parameter = CmdParameter { connection_handle };

        host.send_command_expect_complete(parameter).await
    }
}

pub mod read_remote_features {

    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadRemoteFeatures);

    struct CmdParameter {
        connection_handle: ConnectionHandle,
    }

    impl CommandParameter<2> for CmdParameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.connection_handle.get_raw_handle().to_le_bytes()
        }
    }

    /// Send the LE Read Remote Features command
    ///
    /// This sends the LE Read Remote Features command to the controller and awaits for the
    /// controller to send back the [`CommandStatus`] event. If the LE event
    /// [`ReadRemoteFeaturesComplete`] is unmasked, the controller will send the event to the host
    /// containing the LE features of the connected device.
    ///
    /// [`CommandStatus`]: bo_tie_hci_util::events::Events::CommandStatus
    /// [`ReadRemoteFeaturesComplete`]: bo_tie_hci_util::events::LeMeta::ReadRemoteFeaturesComplete
    pub async fn send<H: HostChannelEnds>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) -> Result<(), CommandError<H>> {
        let parameter = CmdParameter { connection_handle };

        host.send_command_expect_status(parameter).await
    }
}
