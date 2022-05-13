//! Mandatory commands for a device that implements lE
//!
//! Some of these functions are not specific to Bluetooth LE, but they are re-exported here to be
//! noted that they are associated with LE.
//!
//! Vol2 Part E 3.1 of the Bluetooth spec

pub use super::super::cb::reset;
pub use super::super::cb::set_event_mask as cb_set_event_mask;
pub use super::super::info_params::read_bd_addr;
pub use super::super::info_params::read_local_supported_commands;
pub use super::super::info_params::read_local_supported_features as info_params_read_local_supported_features;
pub use super::super::info_params::read_local_version_information;

/// Set the [`LeMeta`](crate::hci::events::LEMeta) event mask
pub mod set_event_mask {

    use crate::hci::events::LEMeta;
    use crate::hci::*;
    use crate::hci::cb::set_event_mask::EventMask::LEMeta;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetEventMask);

    impl LEMeta {
        fn bit_offset(&self) -> usize {
            match *self {
                LEMeta::ConnectionComplete => 0,
                LEMeta::AdvertisingReport => 1,
                LEMeta::ConnectionUpdateComplete => 2,
                LEMeta::ReadRemoteFeaturesComplete => 3,
                LEMeta::LongTermKeyRequest => 4,
                LEMeta::RemoteConnectionParameterRequest => 5,
                LEMeta::DataLengthChange => 6,
                LEMeta::ReadLocalP256PublicKeyComplete => 7,
                LEMeta::GenerateDHKeyComplete => 8,
                LEMeta::EnhancedConnectionComplete => 9,
                LEMeta::DirectedAdvertisingReport => 10,
                LEMeta::PHYUpdateComplete => 11,
                LEMeta::ExtendedAdvertisingReport => 12,
                LEMeta::PeriodicAdvertisingSyncEstablished => 13,
                LEMeta::PeriodicAdvertisingReport => 14,
                LEMeta::PeriodicAdvertisingSyncLost => 15,
                LEMeta::ScanTimeout => 16,
                LEMeta::AdvertisingSetTerminated => 17,
                LEMeta::ScanRequestReceived => 18,
                LEMeta::ChannelSelectionAlgorithm => 19,
            }
        }

        fn build_mask(events: &[Self]) -> [u8; 8] {
            let mut mask = <[u8; 8]>::default();

            for event in events.iter() {
                let bit = event.bit_offset();
                let byte = bit / 8;

                mask[byte] |= 1 << (bit % 8);
            }

            mask
        }
    }

    struct CmdParameter {
        mask: [u8; 8],
    }

    impl CommandParameter<8> for CmdParameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8;8] {
            self.mask
        }
    }

    /// Set the enabled events on a device
    ///
    /// ```rust
    /// # use bo_tie::hci::{PlatformInterface, CommandParameter, events, EventMatcher};
    /// # use std::task::Waker;
    /// # use std::time::Duration;
    /// # use std::pin::Pin;
    /// # use std::sync::Arc;
    /// #
    /// # #[derive(Default)]
    /// # pub struct StubHi;
    /// #
    /// # #[derive(Debug)]
    /// # pub struct ReceiveError;
    /// #
    /// # impl core::fmt::Display for ReceiveError {
    /// #     fn fmt(&self,f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result
    /// #     {
    /// #          unimplemented!()
    /// #     }
    /// # }
    /// #
    /// # impl PlatformInterface for StubHi {
    /// #     type SendCommandError = &'static str;
    /// #     type ReceiveEventError = ReceiveError;
    /// #
    /// #     fn send_command<D, W>(&self, _: &D, _: W)
    /// #     -> Result<bool, Self::SendCommandError>
    /// #     where D: CommandParameter,
    /// #           W: Into<Option<Waker>>,
    /// #     {
    /// #         Ok(true)
    /// #     }
    /// #
    /// #     fn receive_event<P>(&self, _: Option<events::Events>, _: &Waker, _: Pin<Arc<P>> )
    /// #     -> Option<Result<events::EventsData, Self::ReceiveEventError>>
    /// #     where P: EventMatcher + Send + Sync + 'static,
    /// #     {
    /// #         None
    /// #     }
    /// # }
    /// #
    /// # let host_interface = bo_tie::hci::HostInterface::<StubHi>::default();
    ///
    /// use bo_tie::hci::le::mandatory::set_event_mask::{self, send};
    /// use bo_tie::hci::events::LEMeta;
    /// use serde::export::Formatter;
    ///
    ///
    /// let events = vec!(LEMeta::ConnectionComplete,LEMeta::AdvertisingReport);
    ///
    /// // This will enable the LE Connection Complete Event and LE Advertising Report Event
    /// send(&host_interface, &events);
    /// ```
    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>, enabled_events: &[LEMeta]) -> Result<impl FlowControlInfo, CommandError<H>> {
        let mask = LEMeta::build_mask(enabled_events);

        let parameter = CmdParameter { mask };

        let r : Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

        r
    }
}

/// Read the size of the LE HCI data buffer
pub mod read_buffer_size {

    use crate::hci::events::CommandCompleteData;
    use crate::hci::*;
    use crate::hci::opcodes::HCICommand;

    const COMMAND_V1: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadBufferSizeV1);
    const COMMAND_V2: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::)

    struct ParameterV1;

    impl CommandParameter<0> for ParameterV1 {
        const COMMAND: opcodes::HCICommand = COMMAND_V1;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    struct ParameterV2;

    impl CommandParameter<0> for ParameterV2 {
        const COMMAND: HCICommand = COMMAND_V2;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Buffer Size (version 1)
    ///
    /// This type consists of the ACL packet data length and total number of ACL data
    /// packets the Bluetooth device (controller portion) can store.
    ///
    /// If either member of BufferSize is None (they are either both None or both Some),
    /// then the Read Buffer Size (v5 | vol2, part E, sec 7.4.5) command should be used
    /// instead.
    #[derive(Debug)]
    pub struct BufferSizeV1 {
        /// The maximum size of each ACL packet
        pub packet_len: Option<u16>,
        /// The maximum number of ACL packets that the controller can hold
        pub packet_cnt: Option<u8>,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for BufferSizeV1 {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let raw_packet_len = <u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let raw_packet_cnt = *cc.raw_data.get(3).ok_or(CCParameterError::InvalidEventParameter)?;

            let packet_len = (raw_packet_len != 0).then(|| raw_packet_len);

            let packet_cnt = (raw_packet_cnt != 0).then(|| raw_packet_cnt);

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                packet_len,
                packet_cnt,
                completed_packets_cnt,
            })
        }
    }

    impl FlowControlInfo for BufferSizeV1 {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    #[derive(Debug)]
    pub struct BufferSizeV2 {
        /// The maximum size of each ACL packet
        pub acl_packet_len: Option<u16>,
        /// The maximum number of ACL packets that the controller can hold
        pub acl_packet_cnt: Option<u8>,
        /// The maximum size of each ISO packet
        pub iso_packet_len: Option<u16>,
        /// The maximum number of ISO packets that the controller can hold
        pub iso_packet_cnt: Option<u8>,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for BufferSizeV2 {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let raw_acl_packet_len = <u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let raw_acl_packet_cnt = *cc.raw_data.get(3).ok_or(CCParameterError::InvalidEventParameter)?;

            let raw_iso_packet_len = <u16>::from_le_bytes([
                *cc.raw_data.get(3).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(4).ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let raw_iso_packet_cnt = *cc.raw_data.get(5).ok_or(CCParameterError::InvalidEventParameter)?;

            let acl_packet_len = (raw_acl_packet_len != 0).then(|| raw_acl_packet_len);

            let acl_packet_cnt = (raw_acl_packet_cnt != 0).then(|| raw_acl_packet_cnt);

            let iso_packet_len = (raw_iso_packet_len != 0).then(|| raw_iso_packet_len);

            let iso_packet_cnt = (raw_iso_packet_cnt != 0).then(|| raw_iso_packet_cnt);

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                acl_packet_len,
                acl_packet_cnt,
                iso_packet_len,
                iso_packet_cnt,
                completed_packets_cnt
            })
        }
    }

    /// Request information on the LE data buffers (version 1)
    ///
    /// This only returns the buffer information for LE ACL data packets.
    pub async fn send_v1<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<BufferSizeV1, CommandError<H>> {
        host.send_command_expect_complete(ParameterV1).await
    }

    /// Request information on the LE data buffers (version 2)
    ///
    /// This returns the buffer information for the LE ACL and LE ISO data packets.
    pub async fn send_v2<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<BufferSizeV2, CommandError<H>> {
        host.send_command_expect_complete(ParameterV2).await
    }
}

pub mod read_local_supported_features {

    use crate::hci::le::common::EnabledLeFeaturesItr;
    use crate::hci::*;
    use crate::hci::events::CommandCompleteData;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::ReadLocalSupportedFeatures);

    pub struct EnabledLeFeatures {
        features_mask: [u8;8],
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl EnabledLeFeatures {
        pub fn iter(&self) -> EnabledLEFeaturesItr {
            EnabledLeFeaturesItr::from(self.features_mask)
        }
    }

    impl IntoIterator for EnabledLeFeatures {
        type Item = EnabledLeFeaturesItr::Item;
        type IntoIter = EnabledLeFeaturesItr;

        fn into_iter(self) -> Self::IntoIter {
            EnabledLeFeaturesItr::from(self.features_mask)
        }
    }

    impl TryFromCommandComplete for EnabledLeFeatures {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            if cc.raw_data[1..].len() == 8 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut features_mask = [0u8; 8];

                features_mask.copy_from_slice(&cc.raw_data[1..]);

                Ok(Self {
                    features_mask,
                    completed_packets_cnt
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    impl FlowControlInfo for EnabledLeFeatures {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8;0] {
            []
        }
    }

    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<EnabledLeFeatures, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

pub mod read_white_list_size {

    use crate::hci::*;
    use crate::hci::events::CommandCompleteData;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadWhiteListSize);

    pub struct WhiteListSize {
        pub list_size: usize,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for WhiteListSize {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let list_size = cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?.into();

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                list_size,
                completed_packets_cnt
            })
        }
    }

    impl core::ops::Deref for WhiteListSize {
        type Target = usize;

        fn deref(&self) -> &Self::Target {
            &self.list_size
        }
    }

    impl FlowControlInfo for WhiteListSize {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8;0] {
            []
        }
    }

    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<WhiteListSize, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

pub mod clear_white_list {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ClearWhiteList);

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the command to clear the white list
    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<impl FlowControlInfo, CommandError<H>> {
        let r: Result<OnlyStatus, _> = host.send_command_expect_complete(Parameter).await;

        r
    }
}

macro_rules! add_remove_white_list_setup {
    ( $command: ident ) => {
        use crate::hci::events::CommandCompleteData;
        use crate::BluetoothDeviceAddress,
        use crate::hci::*;

        struct CommandPrameter {
            address_type: u8,
            address: BluetoothDeviceAddress,
        }

        impl CommandParameter<7> for CommandPrameter {
            const COMMAND: opcodes::HCICommand = $command;
            fn get_parameter(&self) -> [u8; 7] {
                let mut parameter = [0u8; 7];

                parameter[0] = self.address_type;

                parameter[1..].copy_from_slice(&self.address);

                parameter
            }
        }

        pub async fn send<H: HostGenerics>(
            host: &mut HostInterface<H>,
            address_type: crate::hci::le::common::WhiteListedAddressType,
            address: crate::BluetoothDeviceAddress,
        ) -> Result<impl FlowControlInfo, CommandError<H>> {
            let parameter = CommandParameter {
                address_type,
                address
            }

            let r: Result<OnlyStatus, _> = host.send_command_expect_complete(parameter).await;

            r
        }
    };
}

pub mod add_device_to_white_list {
    const COMMAND: crate::hci::opcodes::HCICommand =
        crate::hci::opcodes::HCICommand::LEController(crate::hci::opcodes::LEController::AddDeviceToWhiteList);

    add_remove_white_list_setup!(COMMAND);
}

pub mod remove_device_from_white_list {

    const COMMAND: crate::hci::opcodes::HCICommand =
        crate::hci::opcodes::HCICommand::LEController(crate::hci::opcodes::LEController::RemoveDeviceFromWhiteList);

    add_remove_white_list_setup!(COMMAND);
}


pub mod read_supported_states {

    use crate::hci::*;
    use core::mem::size_of_val;
    use crate::hci::events::CommandCompleteData;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadSupportedStates);

    /// All possible states/roles a controller can be in
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub enum StatesAndRoles {
        ScannableAdvertisingState,
        ConnectableAdvertisingState,
        NonConnectableAdvertisingState,
        HighDutyCyleDirectedAdvertisingState,
        LowDutyCycleDirectedAdvertisingState,
        ActiveScanningState,
        PassiveScanningState,
        InitiatingState,
        ConnectionStateMasterRole,
        ConnectionStateSlaveRole,
    }

    impl StatesAndRoles {
        /// Returns the total number of states and roles
        const NUMBER_OF_STATES_AND_ROLES: usize = 10;

        /// Returns the total possible bit options
        ///
        /// See Bluetooth v5 vol 2 part E 7.8.27
        fn get_bit_count() -> usize {
            41
        }

        /// This function doesn't return all available states and roles of a device
        /// (since devices can set multiple of these bits indicating the available
        /// roles) so it doesn't return the special type name.
        fn get_states_for_bit_val(bit_val: usize) -> &'static [Self] {
            use self::StatesAndRoles::*;

            match bit_val {
                0 => &[NonConnectableAdvertisingState],
                1 => &[ScannableAdvertisingState],
                2 => &[ConnectableAdvertisingState],
                3 => &[HighDutyCyleDirectedAdvertisingState],
                4 => &[PassiveScanningState],
                5 => &[ActiveScanningState],
                6 => &[InitiatingState],
                7 => &[ConnectionStateSlaveRole],
                8 => &[NonConnectableAdvertisingState, PassiveScanningState],
                9 => &[ScannableAdvertisingState, PassiveScanningState],
                10 => &[ConnectableAdvertisingState, PassiveScanningState],
                11 => &[HighDutyCyleDirectedAdvertisingState, PassiveScanningState],
                12 => &[NonConnectableAdvertisingState, ActiveScanningState],
                13 => &[ScannableAdvertisingState, ActiveScanningState],
                14 => &[ConnectableAdvertisingState, ActiveScanningState],
                15 => &[HighDutyCyleDirectedAdvertisingState, ActiveScanningState],
                16 => &[NonConnectableAdvertisingState, InitiatingState],
                17 => &[ScannableAdvertisingState, InitiatingState],
                18 => &[NonConnectableAdvertisingState, ConnectionStateMasterRole],
                19 => &[ScannableAdvertisingState, ConnectionStateMasterRole],
                20 => &[NonConnectableAdvertisingState, ConnectionStateSlaveRole],
                21 => &[ScannableAdvertisingState, ConnectionStateSlaveRole],
                22 => &[PassiveScanningState, InitiatingState],
                23 => &[ActiveScanningState, InitiatingState],
                24 => &[PassiveScanningState, ConnectionStateMasterRole],
                25 => &[ActiveScanningState, ConnectionStateMasterRole],
                26 => &[PassiveScanningState, ConnectionStateSlaveRole],
                27 => &[ActiveScanningState, ConnectionStateSlaveRole],
                28 => &[InitiatingState, ConnectionStateMasterRole],
                29 => &[LowDutyCycleDirectedAdvertisingState],
                30 => &[LowDutyCycleDirectedAdvertisingState, PassiveScanningState],
                31 => &[LowDutyCycleDirectedAdvertisingState, ActiveScanningState],
                32 => &[ConnectableAdvertisingState, InitiatingState],
                33 => &[HighDutyCyleDirectedAdvertisingState, InitiatingState],
                34 => &[LowDutyCycleDirectedAdvertisingState, InitiatingState],
                35 => &[ConnectableAdvertisingState, ConnectionStateMasterRole],
                36 => &[HighDutyCyleDirectedAdvertisingState, ConnectionStateMasterRole],
                37 => &[LowDutyCycleDirectedAdvertisingState, ConnectionStateMasterRole],
                38 => &[ConnectableAdvertisingState, ConnectionStateSlaveRole],
                39 => &[HighDutyCyleDirectedAdvertisingState, ConnectionStateSlaveRole],
                40 => &[LowDutyCycleDirectedAdvertisingState, ConnectionStateSlaveRole],
                41 => &[InitiatingState, ConnectionStateSlaveRole],
                _ => &[],
            }
        }
    }

    pub struct CurrentStatesAndRoles {
        states_and_roles_mask: [u8; 8],
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl CurrentStatesAndRoles {

        /// Iterate over the supported LE states and roles
        ///
        /// # Note
        /// Because bit flags can correspond to multiple states and roles, this iterator can often
        /// return the same [`StatesAndRoles`] multiple times.
        pub fn iter(&self) -> StatesAndRolesIter<'_> {
            StatesAndRolesIter::new(&self.states_and_roles_mask)
        }
    }

    impl TryFromCommandComplete for CurrentStatesAndRoles {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            if cc.raw_data[1..].len() == 8 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut states_and_roles_mask = [0u8; 8];

                states_and_roles_mask.copy_from_slice(&cc.raw_data[1..]);

                Ok(Self {
                    states_and_roles_mask,
                    completed_packets_cnt
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    impl FlowControlInfo for CurrentStatesAndRoles {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    pub struct StatesAndRolesIter<'a> {
        mask: &'a [u8; 8],
        current: &'static [StatesAndRoles],
        byte: usize,
        bit: usize,
    }

    impl<'a> StatesAndRolesIter<'a> {
        fn new(mask: &'a [u8; 8]) -> Self {
            Self {
                mask,
                current: &[],
                byte: 0,
                bit: 0,
            }
        }

        fn next_current(&mut self) -> Option<StatesAndRoles> {
            let (next, current) = self.current.split_first()?;

            self.current = current;

            Some(*next)
        }

        fn next_bit(&mut self) {
            if (self.bit + 1) / 8 == 1 {
                self.byte += 1;
                self.bit = 0;
            } else {
                self.bit += 1;
            }
        }

        fn get_bit_val(&self) -> usize {
            self.byte * 8 + self.bit
        }
    }

    impl Iterator for StatesAndRolesIter<'_> {
        type Item = StatesAndRoles;

        fn next(&mut self) -> Option<Self::Item> {
            match self.next_current() {
                None => {
                    self.next_bit();

                    let states = StatesAndRoles::get_states_for_bit_val(self.get_bit_val());

                    if states.is_empty() {
                        None
                    } else {
                        self.current = states;

                        self.next_current()
                    }
                }
                next => next,
            }
        }
    }
    
    impl<'a> IntoIterator for &'a CurrentStatesAndRoles {
        type Item = StatesAndRoles;
        type IntoIter = StatesAndRolesIter<'a>;

        fn into_iter(self) -> Self::IntoIter {
            self.iter()
        }
    }
    
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<CurrentStatesAndRoles, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }    
}

/// LE test end command
pub mod test_end {

    use crate::hci::*;
    use crate::hci::events::CommandCompleteData;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::TestEnd);

    pub struct Return {
        pub number_of_packets: u16,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.raw_data);

            let number_of_packets = <u16>::from_le_bytes([
                *cc.raw_data.get(1).ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.raw_data.get(2).ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                number_of_packets,
                completed_packets_cnt,
            })
        }
    }
    impl FlowControlInfo for Return {
        fn command_count(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> [u8;0] {
            []
        }
    }

    /// Send the command
    pub async fn send<H: HostGenerics>(host: &mut HostInterface<H>) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}
