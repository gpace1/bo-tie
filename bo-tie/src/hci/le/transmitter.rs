/// LE Read Advertising Physical Channel Tx Power command
pub mod read_advertising_channel_tx_power {

    use crate::hci::events::CommandCompleteData;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::ReadAdvertisingChannelTxPower);

    /// The LE Read Advertising Channel Tx Power Command returns dBm, a unit of power
    /// provided to the radio antenna.
    #[derive(Debug)]
    pub struct TxPower {
        pub power: i8,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for TxPower {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let power = *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)? as i8;

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                power,
                completed_packets_cnt,
            })
        }
    }

    impl TxPower {
        pub fn as_milli_watts(&self) -> f32 {
            use core::f32;
            10f32.powf(self.power as f32 / 10f32)
        }
    }

    impl FlowControlInfo for TxPower {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the LE Read Advertising Physical Channel Tx Power command
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<TxPower, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// LE Set Advertising Enable command
pub mod set_advertising_parameters {

    use crate::hci::le::common::OwnAddressType;
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

    impl CommandParameter<15> for AdvertisingParameters<'_> {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 15] {
            let mut parameter = [0u8; 15];

            parameter[..2].copy_from_slice(&self.minimum_advertising_interval.get_raw_val().to_le_bytes());

            parameter[2..4].copy_from_slice(&self.maximum_advertising_interval.get_raw_val().to_le_bytes());

            parameter[4] = self.advertising_type.into_val();

            parameter[5] = self.own_address_type.into_val();

            parameter[6] = self.peer_address_type.into_val();

            parameter[7..13].copy_from_slice(&self.peer_address);

            parameter[13] = self.advertising_channel_map.iter().fold(0u8, |v, x| v | x.into_val());

            parameter[14] = self.advertising_filter_policy.into_val();

            parameter
        }
    }

    /// Send the LE Set Advertising Enable command
    pub async fn send<'a, H: HostInterface>(
        host: &mut Host<H>,
        parameters: AdvertisingParameters<'a>,
    ) -> Result<impl FlowControlInfo + 'a, CommandError<H>> {
        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameters).await;

        r
    }
}

/// LE Set Advertising Data command
pub mod set_advertising_data {

    use crate::gap::assigned::{DataTooLargeError, IntoStruct};
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetAdvertisingData);

    type Payload = [u8; 31];

    /// Advertising data
    ///
    /// The Advertising data is made up of AD Structs. The maximum amount of bytes a
    /// regular advertising broadcast can send is 30 bytes (look at extended
    /// advertising for a larger payload). The total payload is 1 byte for the length,
    /// and 30 bytes for the AD structures. The data can consist of as many AD structs
    /// that can fit in it, but it must consist of at least one AD struct (unless
    /// early termination is desired).
    #[derive(Default, Debug, Clone, Copy)]
    pub struct AdvertisingData {
        length: usize,
        payload: Payload,
    }

    impl AdvertisingData {
        /// Create an empty advertising data
        pub fn new() -> Self {
            AdvertisingData::default()
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

    impl CommandParameter<32> for AdvertisingData {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 32] {
            let mut parameter = [0u8; 32];

            parameter[0] = self.length as u8;

            parameter[1..(self.length + 1)].copy_from_slice(&self.payload);

            parameter
        }
    }

    pub async fn send<H, A>(host: &mut Host<H>, advertising_data: A) -> Result<impl FlowControlInfo, CommandError<H>>
    where
        H: HostInterface,
        A: Into<Option<AdvertisingData>>,
    {
        let parameter = advertising_data.into().unwrap_or_default();

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

/// LE Set Advertising Enable command
pub mod set_advertising_enable {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetAdvertisingEnable);

    struct Parameter {
        enable: bool,
    }

    impl CommandParameter<1> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 1] {
            [if self.enable { 1u8 } else { 0u8 }]
        }
    }

    /// Send the LE Set Advertising Enable command
    pub async fn send<H: HostInterface>(
        host: &mut Host<H>,
        enable: bool,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = Parameter { enable };

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

pub mod set_random_address {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetRandomAddress);

    #[derive(Clone)]
    struct Parameter {
        rand_address: crate::BluetoothDeviceAddress,
    }

    impl CommandParameter<6> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 6] {
            self.rand_address
        }
    }

    pub async fn send<'a, H: HostInterface>(
        host: &mut Host<H>,
        address: crate::BluetoothDeviceAddress,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = Parameter { rand_address: address };

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

/// LE Transmitter Test command
pub mod transmitter_test {

    use crate::hci::le::common::Frequency;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::TransmitterTest);

    struct ParameterV1 {
        tx_channel: u8,
        length_of_test_data: u8,
        packet_payload: u8,
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

    impl CommandParameter<3> for ParameterV1 {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 3] {
            [self.tx_channel, self.length_of_test_data, self.packet_payload]
        }
    }

    /// Send the LE Transmitter Test (v1) command
    pub async fn send_v1<H: HostInterface>(
        host: &mut Host<H>,
        channel: Frequency,
        payload: TestPayload,
        payload_length: u8,
    ) -> Result<impl FlowControlInfo, CommandError<H>> {
        let parameter = ParameterV1 {
            tx_channel: channel.get_val(),
            length_of_test_data: payload_length,
            packet_payload: payload.into_val(),
        };

        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}
