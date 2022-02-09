pub mod read_advertising_channel_tx_power {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::ReadAdvertisingChannelTxPower);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        tx_power_level: i8,
    }

    /// The LE Read Advertising Channel Tx Power Command returns dBm, a unit of power
    /// provided to the radio antenna.
    #[derive(Debug)]
    pub struct TxPower {
        pub power: i8,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TxPower {
        fn try_from((packed, cnt): (CmdReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(TxPower {
                    power: packed.tx_power_level,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }

        pub fn as_milli_watts(&self) -> f32 {
            use core::f32;
            10f32.powf(self.power as f32 / 10f32)
        }
    }

    impl crate::hci::FlowControlInfo for TxPower {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CmdReturn, TxPower, error::Error);

    impl_command_complete_future!(TxPower, error::Error);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
    ) -> impl Future<Output = Result<TxPower, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

pub mod transmitter_test {

    use crate::hci::common::le::Frequency;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::TransmitterTest);

    #[repr(packed)]
    #[derive(Clone, Copy)]
    struct CmdParameter {
        _tx_channel: u8,
        _lenght_of_test_data: u8,
        _packet_payload: u8,
    }

    #[cfg_attr(test, derive(Debug))]
    pub enum TestPayload {
        PRBS9Sequence,
        Repeat11110000,
        Repeat10101010,
        PRBS15Sequence,
        Repeat11111111,
        Repeat00000000,
        Repeat00001111,
        Repeat01010101,
    }

    impl TestPayload {
        fn into_val(&self) -> u8 {
            use self::TestPayload::*;
            match *self {
                PRBS9Sequence => 0x00u8,
                Repeat11110000 => 0x01u8,
                Repeat10101010 => 0x02u8,
                PRBS15Sequence => 0x03u8,
                Repeat11111111 => 0x04u8,
                Repeat00000000 => 0x05u8,
                Repeat00001111 => 0x06u8,
                Repeat01010101 => 0x07u8,
            }
        }
    }

    impl_status_return!(COMMAND);

    impl CommandParameter for CmdParameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        channel: Frequency,
        payload: TestPayload,
        payload_length: u8,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        let parameters = CmdParameter {
            _tx_channel: channel.get_val(),
            _lenght_of_test_data: payload_length,
            _packet_payload: payload.into_val(),
        };

        ReturnedFuture(hci.send_command(parameters, events::Events::CommandComplete))
    }
}

pub mod set_advertising_data {

    use crate::gap::assigned::{DataTooLargeError, IntoStruct};
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetAdvertisingData);

    type Payload = [u8; 31];

    #[repr(packed)]
    #[doc(hidden)]
    pub struct CmdParameter {
        _length: u8,
        _data: [u8; 31],
    }

    /// Advertising data
    ///
    /// The Advertising data is made up of AD Structs. The maximum amount of bytes a
    /// regular advertising broadcast can send is 30 bytes (look at extended
    /// advertising for a larger payload). The total payload is 1 byte for the length,
    /// and 30 bytes for the AD structures. The data can consist of as many AD structs
    /// that can fit in it, but it must consist of at least one AD struct (unless
    /// early termination is desired).
    #[derive(Debug, Clone, Copy)]
    pub struct AdvertisingData {
        length: usize,
        payload: Payload,
    }

    impl AdvertisingData {
        /// Create an empty advertising data
        pub fn new() -> Self {
            AdvertisingData {
                length: 0,
                payload: Payload::default(),
            }
        }

        /// Add an ADStruct to the advertising data
        ///
        /// Returns self if the data was added to the advertising data
        ///
        /// # Error
        /// 'data' in its transmission form was too large for remaining free space in
        /// the advertising data.
        pub fn try_push<T>(&mut self, data: T) -> Result<(), DataTooLargeError>
        where
            T: IntoStruct,
        {
            let payload_len = self.payload.len();

            match data.convert_into(&mut self.payload[self.length..]) {
                Some(ad_struct) => {
                    self.length = payload_len - ad_struct.size();
                    Ok(())
                }
                None => Err(DataTooLargeError {
                    overflow: payload_len + data.data_len().unwrap_or_default() - self.length,
                    remaining: payload_len - self.length,
                }),
            }
        }

        /// Get the remaining amount of space available for ADStructures
        ///
        /// Use this to get the remaining space that can be sent in an advertising
        /// packet.
        pub fn remaining_space(&self) -> usize {
            self.payload.len() - self.length as usize
        }
    }

    impl CommandParameter for AdvertisingData {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            CmdParameter {
                _length: self.length as u8,
                _data: self.payload,
            }
        }
    }

    impl_status_return!(COMMAND);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static, A>(
        hci: &'a HostInterface<T>,
        adv_data: A,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
        A: Into<Option<AdvertisingData>>,
    {
        if let Some(data) = adv_data.into() {
            ReturnedFuture(hci.send_command(data, events::Events::CommandComplete))
        } else {
            let data = AdvertisingData::new();

            ReturnedFuture(hci.send_command(data, events::Events::CommandComplete))
        }
    }
}

pub mod set_advertising_enable {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetAdvertisingEnable);

    impl_status_return!(COMMAND);

    #[derive(Clone, Copy)]
    #[repr(packed)]
    struct Parameter {
        enable: bool,
    }

    impl CommandParameter for Parameter {
        type Parameter = u8;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            if self.enable {
                1u8
            } else {
                0u8
            }
        }
    }

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        enable: bool,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter { enable }, events::Events::CommandComplete))
    }
}

pub mod set_advertising_parameters {

    use crate::hci::common::le::OwnAddressType;
    use crate::hci::*;
    use core::default::Default;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::SetAdvertisingParameters);

    interval!(AdvertisingInterval, 0x0020, 0x4000, SpecDef, 0x0800, 625);

    /// Advertising Type
    ///
    /// Enumeration for the 'Advertising Type' advertising parameter.
    #[cfg_attr(test, derive(Debug))]
    pub enum AdvertisingType {
        ConnectableAndScannableUndirectedAdvertising,
        ConnectableHighDucyCycleDirectedAdvertising,
        ScannableUndirectedAdvertising,
        NonConnectableUndirectedAdvertising,
        ConnectableLowDutyCycleDirectedAdvertising,
    }

    impl AdvertisingType {
        fn into_val(&self) -> u8 {
            match *self {
                AdvertisingType::ConnectableAndScannableUndirectedAdvertising => 0x00,
                AdvertisingType::ConnectableHighDucyCycleDirectedAdvertising => 0x01,
                AdvertisingType::ScannableUndirectedAdvertising => 0x02,
                AdvertisingType::NonConnectableUndirectedAdvertising => 0x03,
                AdvertisingType::ConnectableLowDutyCycleDirectedAdvertising => 0x04,
            }
        }
    }

    impl Default for AdvertisingType {
        fn default() -> Self {
            AdvertisingType::ConnectableAndScannableUndirectedAdvertising
        }
    }

    /// Peer address type
    ///
    /// # Notes (from core 5.0 specification)
    /// - PublicAddress -> Public Device Address (default) or Public Identity Address
    /// - RandomAddress -> Random Device Address or Random (static) Identity Address
    #[cfg_attr(test, derive(Debug))]
    pub enum PeerAddressType {
        PublicAddress,
        RandomAddress,
    }

    impl PeerAddressType {
        fn into_val(&self) -> u8 {
            match *self {
                PeerAddressType::PublicAddress => 0x00,
                PeerAddressType::RandomAddress => 0x01,
            }
        }
    }

    impl Default for PeerAddressType {
        fn default() -> Self {
            PeerAddressType::PublicAddress
        }
    }

    /// Advertising channels
    #[cfg_attr(test, derive(Debug))]
    pub enum AdvertisingChannel {
        Channel37,
        Channel38,
        Channel39,
    }

    impl AdvertisingChannel {
        fn into_val(&self) -> u8 {
            match *self {
                AdvertisingChannel::Channel37 => 0x01,
                AdvertisingChannel::Channel38 => 0x02,
                AdvertisingChannel::Channel39 => 0x04,
            }
        }

        pub fn default_channels() -> &'static [AdvertisingChannel] {
            &[
                AdvertisingChannel::Channel37,
                AdvertisingChannel::Channel38,
                AdvertisingChannel::Channel39,
            ]
        }
    }

    #[cfg_attr(test, derive(Debug))]
    pub enum AdvertisingFilterPolicy {
        AllDevices,
        AllConnectionRequestsWhitlistedDeviceScanRequests,
        AllScanRequestsWhitlistedDeviceConnectionRequests,
        WhitelistedDevices,
    }

    impl AdvertisingFilterPolicy {
        fn into_val(&self) -> u8 {
            match *self {
                AdvertisingFilterPolicy::AllDevices => 0x00,
                AdvertisingFilterPolicy::AllConnectionRequestsWhitlistedDeviceScanRequests => 0x01,
                AdvertisingFilterPolicy::AllScanRequestsWhitlistedDeviceConnectionRequests => 0x02,
                AdvertisingFilterPolicy::WhitelistedDevices => 0x03,
            }
        }
    }

    impl Default for AdvertisingFilterPolicy {
        fn default() -> Self {
            AdvertisingFilterPolicy::AllDevices
        }
    }

    /// All the parameters required for advertising
    ///
    /// For the advertising_channel_map, provide a slice containing every channels
    /// desired to be advertised on.
    ///
    /// While most members are public, the only way to set the minimum and maximum
    /// advertising interval is through method calls.
    #[cfg_attr(test, derive(Debug))]
    pub struct AdvertisingParameters<'a> {
        pub minimum_advertising_interval: AdvertisingInterval,
        pub maximum_advertising_interval: AdvertisingInterval,
        pub advertising_type: AdvertisingType,
        pub own_address_type: OwnAddressType,
        pub peer_address_type: PeerAddressType,
        pub peer_address: crate::BluetoothDeviceAddress,
        pub advertising_channel_map: &'a [AdvertisingChannel],
        pub advertising_filter_policy: AdvertisingFilterPolicy,
    }

    impl<'a> Default for AdvertisingParameters<'a> {
        /// Create an AdvertisingParameters object with the default parameters (except
        /// for the peer_address member).
        ///
        /// The default parameter values are from the bluetooth core 5.0 specification,
        /// however there is no default value for the peer_address. This function sets
        /// the peer_address to zero, so it must be set after if a connection to a
        /// specific peer device is desired.
        fn default() -> Self {
            AdvertisingParameters {
                minimum_advertising_interval: AdvertisingInterval::default(),
                maximum_advertising_interval: AdvertisingInterval::default(),
                advertising_type: AdvertisingType::default(),
                own_address_type: OwnAddressType::default(),
                peer_address_type: PeerAddressType::default(),
                peer_address: [0u8; 6].into(),
                advertising_channel_map: AdvertisingChannel::default_channels(),
                advertising_filter_policy: AdvertisingFilterPolicy::default(),
            }
        }
    }

    impl<'a> AdvertisingParameters<'a> {
        /// Create the default parameters except use the specified bluetooth device
        /// address for the peer_address member
        pub fn default_with_peer_address(addr: &'a crate::BluetoothDeviceAddress) -> AdvertisingParameters {
            let mut ap = AdvertisingParameters::default();

            ap.peer_address = *addr;

            ap
        }
    }

    #[repr(packed)]
    #[derive(Clone, Copy)]
    struct CmdParameter {
        _advertising_interval_min: u16,
        _advertising_interval_max: u16,
        _advertising_type: u8,
        _own_address_type: u8,
        _peer_address_type: u8,
        _peer_address: crate::BluetoothDeviceAddress,
        _advertising_channel_map: u8,
        _advertising_filter_policy: u8,
    }

    impl CommandParameter for CmdParameter {
        type Parameter = CmdParameter;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    impl_status_return!(COMMAND);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        params: AdvertisingParameters,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        let parameter = CmdParameter {
            _advertising_interval_min: params.minimum_advertising_interval.get_raw_val(),

            _advertising_interval_max: params.maximum_advertising_interval.get_raw_val(),

            _advertising_type: params.advertising_type.into_val(),

            _own_address_type: params.own_address_type.into_val(),

            _peer_address_type: params.peer_address_type.into_val(),

            _peer_address: params.peer_address.into(),

            _advertising_channel_map: params.advertising_channel_map.iter().fold(0u8, |v, x| v | x.into_val()),

            _advertising_filter_policy: params.advertising_filter_policy.into_val(),
        };

        ReturnedFuture(hci.send_command(parameter, events::Events::CommandComplete))
    }
}

pub mod set_random_address {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetRandomAddress);

    impl_status_return!(COMMAND);

    #[repr(packed)]
    #[derive(Clone)]
    struct Parameter {
        _rand_address: crate::BluetoothDeviceAddress,
    }

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            self.clone()
        }
    }

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
        rand_addr: crate::BluetoothDeviceAddress,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        let parameter = Parameter {
            _rand_address: rand_addr,
        };

        ReturnedFuture(hci.send_command(parameter, events::Events::CommandComplete))
    }
}
