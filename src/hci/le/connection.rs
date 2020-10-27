pub use crate::hci::link_control::disconnect;

interval!( #[derive(Clone, Copy)] ConnectionInterval, 0x0006, 0x0C80, ApiDef, 0x0006, 1250);

/// ConnectionUpdateInterval contaings the minimum and maximum connection intervals for
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
    pub fn try_from(min: ConnectionInterval, max: ConnectionInterval)
                    -> Result<Self,&'static str>
    {
        if min.get_raw_val() <= max.get_raw_val() {
            Ok( Self {
                min,
                max,
            })
        }
        else {
            Err("'min' is greater than 'max'")
        }
    }
}

/// LE Connection Update Command
pub mod connection_update {
    use crate::hci::*;
    use crate::hci::common::{
        ConnectionHandle,
        SupervisionTimeout,
    };
    use crate::hci::le::common::ConnectionEventLength;
    use super::ConnectionIntervalBounds;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ConnectionUpdate);

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _handle: u16,
        _conn_interval_min: u16,
        _conn_interval_max: u16,
        _conn_latency: u16,
        _supervision_timeout: u16,
        _minimum_ce_length: u16,
        _maximum_ce_length: u16,
    }

    pub struct ConnectionUpdate {
        pub handle: ConnectionHandle,
        pub interval: ConnectionIntervalBounds,
        pub latency: u16,
        pub supervision_timeout: SupervisionTimeout,
        pub connection_event_len: ConnectionEventLength,
    }


    impl CommandParameter for ConnectionUpdate {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _handle:              self.handle.get_raw_handle(),
                _conn_interval_min:   self.interval.min.get_raw_val(),
                _conn_interval_max:   self.interval.max.get_raw_val(),
                _conn_latency:        self.latency,
                _supervision_timeout: self.supervision_timeout.get_timeout(),
                _minimum_ce_length:   self.connection_event_len.minimum,
                _maximum_ce_length:   self.connection_event_len.maximum,
             }
        }
    }

    impl_command_status_future!();

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, cu: ConnectionUpdate)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(cu, events::Events::CommandStatus ) )
    }

}

pub mod create_connection_cancel {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::CreateConnectionCancel);

    impl_status_return!(COMMAND);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>)
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command( Parameter, events::Events::CommandComplete ) )
    }

}

pub mod create_connection {

    use super::ConnectionIntervalBounds;
    use crate::hci::*;
    use crate::hci::common::{
        ConnectionLatency,
        LEAddressType,
        SupervisionTimeout,
    };
    use crate::hci::le::common::{OwnAddressType, ConnectionEventLength};

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
        scan_interval : ScanningInterval,
        scan_window : ScanningWindow,
        initiator_filter_policy: InitiatorFilterPolicy,
        peer_address_type: LEAddressType,
        peer_address: crate::BluetoothDeviceAddress,
        own_address_type: OwnAddressType,
        connection_interval: ConnectionIntervalBounds,
        connection_latency: ConnectionLatency,
        supervision_timeout: SupervisionTimeout,
        connection_event_len: ConnectionEventLength,
    }

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _scan_interval: u16,
        _scan_window: u16,
        _initiator_filter_policy: u8,
        _peer_address_type: u8,
        _peer_address: crate::BluetoothDeviceAddress,
        _own_address_type: u8,
        _conn_interval_min: u16,
        _conn_interval_max: u16,
        _conn_latency: u16,
        _supervision_timeout: u16,
        _minimum_ce_length: u16,
        _maximum_ce_length: u16,
    }

    impl CommandParameter for ConnectionParameters {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _scan_interval:           self.scan_interval.get_raw_val(),
                _scan_window:             self.scan_window.get_raw_val(),
                _initiator_filter_policy: self.initiator_filter_policy.val(),
                _peer_address_type:       self.peer_address_type.into_raw(),
                _peer_address:            self.peer_address,
                _own_address_type:        self.own_address_type.into_val(),
                _conn_interval_min:       self.connection_interval.min.get_raw_val(),
                _conn_interval_max:       self.connection_interval.max.get_raw_val(),
                _conn_latency:            self.connection_latency.get_latency(),
                _supervision_timeout:     self.supervision_timeout.get_timeout(),
                _minimum_ce_length:       self.connection_event_len.minimum,
                _maximum_ce_length:       self.connection_event_len.maximum,
            }
        }
    }

    impl ConnectionParameters {

        /// Command Parameters for connecting without the white list
        pub fn new_without_whitelist(
            scan_interval : ScanningInterval,
            scan_window : ScanningWindow,
            peer_address_type: LEAddressType,
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
            scan_interval : ScanningInterval,
            scan_window : ScanningWindow,
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
                peer_address_type : LEAddressType::PublicDeviceAddress, // This is not used (see spec)
                peer_address : [0u8;6], // This is not used (see spec)
                own_address_type,
                connection_interval,
                connection_latency,
                supervision_timeout,
                connection_event_len,
            }
        }

    }

    impl_command_status_future!();

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, cp: ConnectionParameters )
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(cp, events::Events::CommandStatus ) )
    }

}
pub mod read_channel_map {

    use crate::hci::*;
    use crate::hci::common::ConnectionHandle;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadChannelMap);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        connection_handle: u16,
        channel_map: [u8;5]
    }

    pub struct ChannelMapInfo {
        pub handle: ConnectionHandle,
        /// This is the list of channels (from 0 through 36)
        pub channel_map: ::alloc::boxed::Box<[usize]>,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl ChannelMapInfo {
        fn try_from((packed, cnt): (CmdReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {

                // 37 is the number of channels (as of bluetooth 5.0)
                let channel_count = 37;

                let mut count = 0;

                let mut mapped_channels =alloc::vec::Vec::with_capacity(channel_count);

                'outer: for byte in packed.channel_map.iter() {
                    for bit in 0..8 {
                        if count < channel_count {
                            if 0 != (byte & (1 << bit)) {
                                mapped_channels.push(count);
                                count += 1;
                            }
                        }
                        else {
                            break 'outer;
                        }
                    }
                }

                Ok( Self {
                    handle: ConnectionHandle::try_from(packed.connection_handle).unwrap(),
                    channel_map: mapped_channels.into_boxed_slice(),
                    completed_packets_cnt: cnt.into()
                })
            }
            else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for ChannelMapInfo {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    #[repr(packed)]
    #[derive( Clone, Copy)]
    struct CmdParameter {
        _connection_handle: u16
    }

    impl CommandParameter for CmdParameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    impl_get_data_for_command!(
            COMMAND,
            CmdReturn,
            ChannelMapInfo,
            error::Error
        );

    impl_command_complete_future!(ChannelMapInfo, error::Error);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, handle: ConnectionHandle )
    -> impl Future<Output=Result<ChannelMapInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {

        let parameter = CmdParameter {
            _connection_handle: handle.get_raw_handle()
        };

        ReturnedFuture( hci.send_command(parameter, events::Events::CommandComplete ) )
    }

}

pub mod read_remote_features {

    use crate::hci::*;
    use crate::hci::common::ConnectionHandle;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadRemoteFeatures);

    #[repr(packed)]
    #[derive( Clone, Copy)]
    struct CmdParameter {
        _connection_handle: u16
    }

    impl CommandParameter for CmdParameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    impl_command_status_future!();

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, handle: ConnectionHandle )
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {

        let parameter = CmdParameter {
            _connection_handle: handle.get_raw_handle(),
        };

        ReturnedFuture( hci.send_command(parameter, events::Events::CommandStatus ) )
    }

}

pub mod set_host_channel_classification {
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetHostChannelClassification);

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParemeter {
        _channel_map: [u8;5]
    }

    const CHANNEL_MAP_MAX: usize = 37;

    pub struct ChannelMap {
        channels: [bool;CHANNEL_MAP_MAX]
    }

    impl ChannelMap {
        pub const MAX: usize = 37;

        /// try to create a Channel Map
        ///
        /// This will form a channel map so long as every value in slice referenced by
        /// channels is less then CHANNEL_MAP_MAX
        ///
        /// # Error
        /// A value in the parameter was found to be larger then CHANNEL_MAP_MAX
        pub fn try_from<'a>(channels: &'a[usize]) -> Result<Self, usize> {

            let mut channel_flags = [false;CHANNEL_MAP_MAX];

            for val in channels {
                if *val < CHANNEL_MAP_MAX {
                    channel_flags[*val] = true;
                }
                else {
                    return Err(*val);
                }
            }

            Ok( Self {
                channels: channel_flags
            })
        }
    }

    impl CommandParameter for ChannelMap {
        type Parameter = CmdParemeter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {

            let mut raw = [0u8;5];

            for val in 0..CHANNEL_MAP_MAX {
                if self.channels[val] {
                    raw[val / 8] |= 1 << (val % 8)
                }
            }

            CmdParemeter {
                _channel_map : raw
            }
        }
    }

    impl_status_return!(COMMAND);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds= "'static")]
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>, map: ChannelMap )
    -> impl Future<Output=Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command( map, events::Events::CommandComplete ) )
    }
}

pub use super::super::cb::read_transmit_power_level;
pub use super::super::status_prams::read_rssi;
pub use super::super::link_control::read_remote_version_information;
