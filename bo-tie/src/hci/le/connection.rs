use crate::hci::le::common::ConnectionInterval;
pub use crate::hci::link_control::disconnect;

/// ConnectionUpdateInterval contains the minimum and maximum connection intervals for
/// the le connection update
pub struct ConnectionIntervalBounds {
    min: ConnectionInterval,
    max: ConnectionInterval,
}

impl ConnectionIntervalBounds {
    /// Create a ConnectionUpdateInterval
    ///
    /// # Errors
    /// An error is returned if the minimum is greater then the maximum
    pub fn try_from(min: ConnectionInterval, max: ConnectionInterval) -> Result<Self, &'static str> {
        if min.get_raw_val() <= max.get_raw_val() {
            Ok(Self { min, max })
        } else {
            Err("'min' is greater than 'max'")
        }
    }
}

/// LE Connection Update command
pub mod connection_update {
    use super::ConnectionIntervalBounds;
    use crate::hci::common::ConnectionHandle;
    use crate::hci::le::common::{ConnectionEventLength, SupervisionTimeout};
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ConnectionUpdate);

    pub struct ConnectionUpdate {
        pub handle: ConnectionHandle,
        pub interval: ConnectionIntervalBounds,
        pub latency: u16,
        pub supervision_timeout: SupervisionTimeout,
        pub connection_event_len: ConnectionEventLength,
    }

    impl CommandParameter<14> for ConnectionUpdate {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 14] {
            let mut parameter = [0u8; 14];

            parameter[0..2].copy_from_slice(&self.handle.get_raw_handle().to_le_bytes());

            parameter[2..4].copy_from_slice(&self.interval.min.get_raw_val().to_le_bytes());

            parameter[4..6].copy_from_slice(&self.interval.max.get_raw_val().to_le_bytes());

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
    /// [`ConnectionUpdateComplete`](events::LeMeta::ConnectionUpdateComplete) event is enabled, the
    /// controller will send this event to the host when the connection is updated.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        parameter: ConnectionUpdate,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        host.send_command_expect_status(parameter).await
    }
}

/// Send the LE Create Connection Cancel command
pub mod create_connection_cancel {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::CreateConnectionCancel);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the LE Create Connection Cancel command
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<impl FlowControlInfo, CommandError<H>> {
        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(Parameter).await;

        r
    }
}

/// LE Create Connection command
pub mod create_connection {

    use super::ConnectionIntervalBounds;
    use crate::hci::le::common::{
        AddressType, ConnectionEventLength, ConnectionLatency, OwnAddressType, SupervisionTimeout,
    };
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::CreateConnection);

    interval!(ScanningInterval, 0x0004, 0x4000, SpecDef, 0x0010, 625);
    interval!(ScanningWindow, 0x0004, 0x4000, SpecDef, 0x0010, 625);

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
        peer_address: crate::BluetoothDeviceAddress,
        own_address_type: OwnAddressType,
        connection_interval: ConnectionIntervalBounds,
        connection_latency: ConnectionLatency,
        supervision_timeout: SupervisionTimeout,
        connection_event_len: ConnectionEventLength,
    }

    impl CommandParameter<25> for ConnectionParameters {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 25] {
            let mut parameter = [0u8; 25];

            parameter[0..2].copy_from_slice(&self.scan_interval.get_raw_val().to_le_bytes());

            parameter[2..4].copy_from_slice(&self.scan_window.get_raw_val().to_le_bytes());

            parameter[4] = self.initiator_filter_policy.val();

            parameter[5] = self.peer_address_type.into_raw();

            parameter[6..12].copy_from_slice(&self.peer_address);

            parameter[12] = self.own_address_type.into_val();

            parameter[13..15].copy_from_slice(&self.connection_interval.min.get_raw_val().to_le_bytes());

            parameter[15..17].copy_from_slice(&self.connection_interval.max.get_raw_val().to_le_bytes());

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
            peer_address: crate::BluetoothDeviceAddress,
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
                peer_address: [0u8; 6],                              // This is not used (see spec)
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
    /// to send back the [`CommandStatus`](events::Events::CommandStatus) event. If the LE event
    /// [`ConnectionComplete`](events::LeMeta::ConnectionComplete) or
    /// [`EnhancedConnectionComplete`](events::LeMeta::EnhancedConnectionComplete) is unmasked, the
    /// controller will send the event (with `EnhancedConnectionComplete` having precedence over
    /// `ConnectionComplete` if they are both unmasked) to the host after a connection is made.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        parameters: ConnectionParameters,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        host.send_command_expect_status(parameters).await
    }
}

/// LE Set Host Channel Classification command
pub mod set_host_channel_classification {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::SetHostChannelClassification);

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
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 5] {
            self.channel_map
        }
    }

    /// Send the LE Set Host Channel Classification command
    pub async fn send<H, I>(host: &mut Host<H>, channels: I) -> Result<impl FlowControlInfo, CommandError<H>>
    where
        H: HostInterface,
        I: IntoIterator<Item = usize>,
    {
        let parameter = CmdParameter::new(channels);

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

/// LE Read Channel Map command
pub mod read_channel_map {

    use crate::hci::common::ConnectionHandle;
    use crate::hci::events::CommandCompleteData;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadChannelMap);

    pub struct ChannelMapInfo {
        pub handle: ConnectionHandle,
        /// This is the list of channels (from 0 through 36)
        pub channel_map_bit_mask: [u8; 5],
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for ChannelMapInfo {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            use core::convert::TryFrom;

            check_status!(cc.raw_data);

            let handle = ConnectionHandle::try_from(<u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
            ]))
            .map_err(|_| CCParameterError::InvalidEventParameter)?;

            if cc.raw_data[3..].len() == 5 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut channel_map_bit_mask = [0u8; 5];

                channel_map_bit_mask.copy_from_slice(&cc.raw_data[3..]);

                Ok(Self {
                    handle,
                    channel_map_bit_mask,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    impl FlowControlInfo for ChannelMapInfo {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
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
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.connection_handle.get_raw_handle().to_le_bytes()
        }
    }

    /// Send the LE Read Channel Map command
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) -> Result<ChannelMapInfo, CommandError<H>> {
        let parameter = CmdParameter { connection_handle };

        host.send_command_expect_complete(parameter).await
    }
}

pub mod read_remote_features {

    use crate::hci::common::ConnectionHandle;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadRemoteFeatures);

    struct CmdParameter {
        connection_handle: ConnectionHandle,
    }

    impl CommandParameter<2> for CmdParameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 2] {
            self.connection_handle.get_raw_handle().to_le_bytes()
        }
    }

    /// Send the LE Read Remote Features command
    ///
    /// This sends the LE Read Remote Features command to the controller and awaits for the
    /// controller to send back the [`CommandStatus`](events::Events::CommandStatus) event. If the
    /// LE event [`ReadRemoteFeaturesComplete`](events::LeMeta::ReadRemoteFeaturesComplete) is
    /// unmasked, the controller will send the event to the host containing the LE features of the
    /// connected device.
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        connection_handle: ConnectionHandle,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = CmdParameter { connection_handle };

        host.send_command_expect_status(parameter).await
    }
}

pub use super::super::cb::read_transmit_power_level;
pub use super::super::link_control::read_remote_version_information;
pub use super::super::status_prams::read_rssi;
