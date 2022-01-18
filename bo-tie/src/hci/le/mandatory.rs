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

macro_rules! add_remove_white_list_setup {
    ( $command: ident ) => {
        use crate::hci::events::Events;
        use crate::hci::le::common::AddressType;
        use crate::hci::*;

        /// Command parameter data for both add and remove whitelist commands.
        #[repr(packed)]
        #[derive(Clone, Copy)]
        struct CommandPrameter {
            _address_type: u8,
            _address: [u8; 6],
        }

        impl_status_return!($command);

        #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
        pub fn send<'a, T: 'static>(
            hci: &'a HostInterface<T>,
            at: AddressType,
            addr: crate::BluetoothDeviceAddress,
        ) -> impl core::future::Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
        where
            T: HostControllerInterface,
        {
            let parameter = CommandPrameter {
                _address_type: at.to_value(),
                _address: addr,
            };

            ReturnedFuture(hci.send_command(parameter, Events::CommandComplete))
        }

        impl CommandParameter for CommandPrameter {
            type Parameter = Self;
            const COMMAND: opcodes::HCICommand = $command;
            fn get_parameter(&self) -> Self::Parameter {
                *self
            }
        }
    };
}

pub mod add_device_to_white_list {
    const COMMAND: crate::hci::opcodes::HCICommand =
        crate::hci::opcodes::HCICommand::LEController(crate::hci::opcodes::LEController::AddDeviceToWhiteList);

    add_remove_white_list_setup!(COMMAND);
}

pub mod clear_white_list {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ClearWhiteList);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    impl_status_return!(COMMAND);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

/// Read the size of the LE HCI data buffer
pub mod read_buffer_size {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadBufferSize);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        packet_length: u16,
        maximum_packet_cnt: u8,
    }

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    /// This type consists of the ACL packet data length and total number of ACL data
    /// packets the Bluetooth device (controller portion) can store.
    ///
    /// If either member of BufferSize is None (they are either both None or both Some),
    /// then the Read Buffer Size (v5 | vol2, part E, sec 7.4.5) command should be used
    /// instead.
    #[derive(Debug)]
    pub struct BufferSize {
        /// The maximum size of each packet
        pub packet_len: Option<u16>,
        /// The maximum number of packets that the controller can hold
        pub packet_cnt: Option<u8>,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl BufferSize {
        fn try_from((packed, buf_cnt): (CmdReturn, u8)) -> Result<Self, error::Error> {
            let err_val = error::Error::from(packed.status);

            match err_val {
                error::Error::NoError => {
                    let len = if packed.packet_length != 0 {
                        Some(<u16>::from_le(packed.packet_length))
                    } else {
                        None
                    };

                    let cnt = if packed.maximum_packet_cnt != 0 {
                        Some(packed.maximum_packet_cnt)
                    } else {
                        None
                    };

                    Ok(BufferSize {
                        packet_len: len,
                        packet_cnt: cnt,
                        completed_packets_cnt: buf_cnt.into(),
                    })
                }
                _ => Err(err_val),
            }
        }
    }

    impl crate::hci::FlowControlInfo for BufferSize {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CmdReturn, BufferSize, error::Error);

    impl_command_complete_future!(BufferSize, error::Error);

    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
    ) -> impl Future<Output = Result<BufferSize, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

pub mod read_local_supported_features {

    use crate::hci::common::EnabledLeFeaturesItr;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand =
        opcodes::HCICommand::LEController(opcodes::LEController::ReadLocalSupportedFeatures);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        features: [u8; 8],
    }

    pub struct ReturnedEnabledLeFeaturesItr {
        itr: EnabledLeFeaturesItr,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl core::ops::Deref for ReturnedEnabledLeFeaturesItr {
        type Target = EnabledLeFeaturesItr;

        fn deref(&self) -> &Self::Target {
            &self.itr
        }
    }

    impl ReturnedEnabledLeFeaturesItr {
        fn try_from((packed, cnt): (CmdReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                let itr = EnabledLeFeaturesItr::from(packed.features);

                Ok(Self {
                    itr,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl crate::hci::FlowControlInfo for ReturnedEnabledLeFeaturesItr {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CmdReturn, ReturnedEnabledLeFeaturesItr, error::Error);

    impl_command_complete_future!(ReturnedEnabledLeFeaturesItr, error::Error);

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
    ) -> impl Future<Output = Result<ReturnedEnabledLeFeaturesItr, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

pub mod read_supported_states {

    use crate::hci::*;
    use core::mem::size_of_val;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadSupportedStates);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        states: [u8; 8],
    }

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

        /// This function will return all the supported states
        ///
        /// The returned supported states will be ordered per the derived implementation of `ord`.
        fn get_supported_states(rss: &CmdReturn) -> alloc::vec::Vec<Self> {
            let mut set = Vec::with_capacity(Self::NUMBER_OF_STATES_AND_ROLES);

            let count = StatesAndRoles::get_bit_count();

            for byte in 0..size_of_val(&rss.states) {
                for bit in 0..8 {
                    if (byte * 8 + bit) < count {
                        if 0 != rss.states[byte] & (1 << bit) {
                            for state_or_role in StatesAndRoles::get_states_for_bit_val(bit) {
                                if let Err(indx) = set.binary_search(state_or_role) {
                                    set.insert(indx, *state_or_role);
                                }
                            }
                        }
                    } else {
                        return set;
                    }
                }
            }

            set
        }

        fn try_from(packed: CmdReturn) -> Result<alloc::vec::Vec<Self>, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(StatesAndRoles::get_supported_states(&packed))
            } else {
                Err(status)
            }
        }
    }

    pub struct CurrentStatesAndRoles {
        states_and_roles: Vec<StatesAndRoles>,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl CurrentStatesAndRoles {
        fn try_from((packed, cnt): (CmdReturn, u8)) -> Result<Self, error::Error> {
            let states_and_roles = StatesAndRoles::try_from(packed)?;

            Ok(Self {
                states_and_roles,
                completed_packets_cnt: cnt.into(),
            })
        }
    }

    impl crate::hci::FlowControlInfo for CurrentStatesAndRoles {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl core::ops::Deref for CurrentStatesAndRoles {
        type Target = [StatesAndRoles];

        fn deref(&self) -> &Self::Target {
            &self.states_and_roles
        }
    }

    impl_get_data_for_command!(COMMAND, CmdReturn, CurrentStatesAndRoles, error::Error);

    impl_command_complete_future!(CurrentStatesAndRoles, error::Error);

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
    ) -> impl Future<Output = Result<CurrentStatesAndRoles, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

pub mod read_white_list_size {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadWhiteListSize);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        size: u8,
    }

    pub struct WhiteListSize {
        pub list_size: usize,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl WhiteListSize {
        fn try_from((packed, cnt): (CmdReturn, u8)) -> Result<Self, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    list_size: packed.size.into(),
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl core::ops::Deref for WhiteListSize {
        type Target = usize;

        fn deref(&self) -> &Self::Target {
            &self.list_size
        }
    }

    impl crate::hci::FlowControlInfo for WhiteListSize {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl_get_data_for_command!(COMMAND, CmdReturn, WhiteListSize, error::Error);

    impl_command_complete_future!(WhiteListSize, error::Error);

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
    ) -> impl Future<Output = Result<WhiteListSize, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}

pub mod remove_device_from_white_list {

    const COMMAND: crate::hci::opcodes::HCICommand =
        crate::hci::opcodes::HCICommand::LEController(crate::hci::opcodes::LEController::RemoveDeviceFromWhiteList);

    add_remove_white_list_setup!(COMMAND);
}

pub mod set_event_mask {

    use crate::hci::events::LEMeta;
    use crate::hci::*;

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

    impl_status_return!(COMMAND);

    #[repr(packed)]
    #[derive(Clone, Copy)]
    struct CmdParameter {
        _mask: [u8; 8],
    }

    impl CommandParameter for CmdParameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    /// Set the enabled events on a device
    ///
    /// ```rust
    /// # use bo_tie::hci::{HostControllerInterface, CommandParameter, events, EventMatcher};
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
    /// # impl HostControllerInterface for StubHi {
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
    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hi: &'a HostInterface<T>,
        enabled_events: &[LEMeta],
    ) -> impl Future<Output = Result<impl crate::hci::FlowControlInfo, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        let command_pram = CmdParameter {
            _mask: LEMeta::build_mask(enabled_events),
        };

        ReturnedFuture(hi.send_command(command_pram, events::Events::CommandComplete))
    }
}

pub mod test_end {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::TestEnd);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        number_of_packets: u16,
    }

    pub struct Return {
        pub number_of_packets: u16,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl crate::hci::FlowControlInfo for Return {
        fn packet_space(&self) -> usize {
            self.completed_packets_cnt
        }
    }

    impl Return {
        fn try_from((packed, cnt): (CmdReturn, u8)) -> Result<Return, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(Self {
                    number_of_packets: packed.number_of_packets,
                    completed_packets_cnt: cnt.into(),
                })
            } else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(COMMAND, CmdReturn, Return, error::Error);

    impl_command_complete_future!(Return, error::Error);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {
            *self
        }
    }

    /// This will return a future with its type 'Output' being the number of packets
    /// received during what ever tests was done
    #[bo_tie_macros::host_interface(flow_ctrl_bounds = "'static")]
    pub fn send<'a, T: 'static>(
        hci: &'a HostInterface<T>,
    ) -> impl Future<Output = Result<Return, impl Display + Debug>> + 'a
    where
        T: HostControllerInterface,
    {
        ReturnedFuture(hci.send_command(Parameter, events::Events::CommandComplete))
    }
}
