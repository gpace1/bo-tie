//! Mandatory commands for a device that implements lE
//!
//! Some of these functions are not specific to Bluetooth LE, but they are re-exported here to be
//! noted that they are associated with LE.
//!
//! Vol2 Part E 3.1 of the Bluetooth spec

pub use super::super::info_params::read_bd_addr;
pub use super::super::info_params::read_local_supported_features as info_params_read_local_supported_features;
pub use super::super::info_params::read_local_version_information;
pub use super::super::info_params::read_local_supported_commands;
pub use super::super::cb::reset;
pub use super::super::cb::set_event_mask as cb_set_event_mask;

macro_rules! add_remove_white_list_setup {
    ( $command: ident ) => {
        use crate::hci::*;
        use crate::hci::events::Events;
        use crate::hci::le::common::AddressType;

        /// Command parameter data for both add and remove whitelist commands.
        ///
        /// Not using bluez becasue there are different parameter structs for the
        /// two commands even though they are the same in structure.
        #[repr(packed)]
        #[derive(Clone, Copy)]
        struct CommandPrameter {
            _address_type: u8,
            _address: [u8;6],
        }

        impl_status_return!( $command );

        pub fn send<'a, T: 'static>( hci: &'a HostInterface<T>,
            at: AddressType,
            addr: crate::BluetoothDeviceAddress )
        -> impl core::future::Future<Output=Result<(), impl Display + Debug>> + 'a
        where T: HostControllerInterface
        {
            let parameter = CommandPrameter {
                _address_type: at.to_value(),
                _address: addr,
            };

            ReturnedFuture( hci.send_command(parameter, Events::CommandComplete, Duration::from_secs(1) ) )
        }

        impl CommandParameter for CommandPrameter {
            type Parameter = Self;
            const COMMAND: opcodes::HCICommand = $command;
            fn get_parameter(&self) -> Self::Parameter { *self }
        }
    };
}

pub mod add_device_to_white_list {
    const COMMAND: crate::hci::opcodes::HCICommand = crate::hci::opcodes::HCICommand::LEController(crate::hci::opcodes::LEController::AddDeviceToWhiteList);

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
        fn get_parameter(&self) -> Self::Parameter { *self }
    }

    impl_status_return!(COMMAND);

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> ) -> impl Future<Output=Result<(), impl Display + Debug>> + 'a where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }
}

pub mod read_buffer_size {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadBufferSize);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        packet_length: u16,
        maximum_packet_cnt: u8,
    }

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter { *self }
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
    }

    impl BufferSize {
        fn try_from(packed: CmdReturn) -> Result<Self, error::Error >{
            let err_val = error::Error::from(packed.status);

            match err_val {
                error::Error::NoError => {
                    let len = if packed.packet_length != 0 {
                        Some(packed.packet_length)
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
                    })
                },
                _ => Err(err_val),
            }
        }
    }

    impl_get_data_for_command!(
        COMMAND,
        CmdReturn,
        BufferSize,
        error::Error);

    impl_command_data_future!(BufferSize, error::Error);

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> ) -> impl Future<Output=Result<BufferSize,impl Display + Debug>> + 'a where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

pub mod read_local_supported_features {

    use crate::hci::common::EnabledLEFeaturesItr;
    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadLocalSupportedFeatures);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        features: [u8;8]
    }

    impl EnabledLEFeaturesItr {
        fn try_from( packed: CmdReturn ) -> Result<Self,error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(EnabledLEFeaturesItr::from(packed.features))
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
        COMMAND,
        CmdReturn,
        EnabledLEFeaturesItr,
        error::Error
    );

    impl_command_data_future!(EnabledLEFeaturesItr, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
                                 -> impl Future<Output=Result<EnabledLEFeaturesItr, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

pub mod read_supported_states {

    use crate::hci::*;
    use alloc::collections::BTreeSet;
    use core::mem::size_of_val;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::ReadSupportedStates);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        states: [u8;8],
    }

    /// All possible states/roles a controller can be in
    #[derive(PartialEq,Eq,PartialOrd,Ord,Debug)]
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
        ConnectionStateSlaveRole
    }

    impl StatesAndRoles {

        /// Returns the total number of states and roles
        fn get_count() -> usize { 10 }

        /// Returns the total possible bit options
        ///
        /// See Bluetooth v5 vol 2 part E 7.8.27
        fn get_bit_count() -> usize { 41 }

        /// This function doesn't return all available states and roles of a device
        /// (since devices can set multiple of these bits indicating the available
        /// roles) so it doesn't return the special type name.
        fn get_states_for_bit_val( bit_val: usize) ->alloc::vec::Vec<Self> {
            use self::StatesAndRoles::*;

            match bit_val {
                0  => alloc::vec![ NonConnectableAdvertisingState],
                1  => alloc::vec![ ScannableAdvertisingState],
                2  => alloc::vec![ ConnectableAdvertisingState],
                3  => alloc::vec![ HighDutyCyleDirectedAdvertisingState],
                4  => alloc::vec![ PassiveScanningState],
                5  => alloc::vec![ ActiveScanningState],
                6  => alloc::vec![ InitiatingState],
                7  => alloc::vec![ ConnectionStateSlaveRole],
                8  => alloc::vec![ NonConnectableAdvertisingState,
                            PassiveScanningState],
                9  => alloc::vec![ ScannableAdvertisingState,
                            PassiveScanningState],
                10 => alloc::vec![ ConnectableAdvertisingState,
                            PassiveScanningState],
                11 => alloc::vec![ HighDutyCyleDirectedAdvertisingState,
                            PassiveScanningState],
                12 => alloc::vec![ NonConnectableAdvertisingState,
                            ActiveScanningState],
                13 => alloc::vec![ ScannableAdvertisingState,
                            ActiveScanningState],
                14 => alloc::vec![ ConnectableAdvertisingState,
                            ActiveScanningState],
                15 => alloc::vec![ HighDutyCyleDirectedAdvertisingState,
                            ActiveScanningState],
                16 => alloc::vec![ NonConnectableAdvertisingState,
                            InitiatingState],
                17 => alloc::vec![ ScannableAdvertisingState,
                            InitiatingState],
                18 => alloc::vec![ NonConnectableAdvertisingState,
                            ConnectionStateMasterRole],
                19 => alloc::vec![ ScannableAdvertisingState,
                            ConnectionStateMasterRole],
                20 => alloc::vec![ NonConnectableAdvertisingState,
                            ConnectionStateSlaveRole],
                21 => alloc::vec![ ScannableAdvertisingState,
                            ConnectionStateSlaveRole],
                22 => alloc::vec![ PassiveScanningState,
                            InitiatingState],
                23 => alloc::vec![ ActiveScanningState,
                            InitiatingState],
                24 => alloc::vec![ PassiveScanningState,
                            ConnectionStateMasterRole],
                25 => alloc::vec![ ActiveScanningState,
                            ConnectionStateMasterRole],
                26 => alloc::vec![ PassiveScanningState,
                            ConnectionStateSlaveRole],
                27 => alloc::vec![ ActiveScanningState,
                            ConnectionStateSlaveRole],
                28 => alloc::vec![ InitiatingState,
                            ConnectionStateMasterRole],
                29 => alloc::vec![ LowDutyCycleDirectedAdvertisingState ],
                30 => alloc::vec![ LowDutyCycleDirectedAdvertisingState,
                            PassiveScanningState],
                31 => alloc::vec![ LowDutyCycleDirectedAdvertisingState,
                            ActiveScanningState],
                32 => alloc::vec![ ConnectableAdvertisingState,
                            InitiatingState],
                33 => alloc::vec![ HighDutyCyleDirectedAdvertisingState,
                            InitiatingState],
                34 => alloc::vec![ LowDutyCycleDirectedAdvertisingState,
                            InitiatingState],
                35 => alloc::vec![ ConnectableAdvertisingState,
                            ConnectionStateMasterRole],
                36 => alloc::vec![ HighDutyCyleDirectedAdvertisingState,
                            ConnectionStateMasterRole],
                37 => alloc::vec![ LowDutyCycleDirectedAdvertisingState,
                            ConnectionStateMasterRole],
                38 => alloc::vec![ ConnectableAdvertisingState,
                            ConnectionStateSlaveRole],
                39 => alloc::vec![ HighDutyCyleDirectedAdvertisingState,
                            ConnectionStateSlaveRole],
                40 => alloc::vec![ LowDutyCycleDirectedAdvertisingState,
                            ConnectionStateSlaveRole],
                41 => alloc::vec![ InitiatingState,
                            ConnectionStateSlaveRole],
                _  => alloc::vec![],
            }
        }

        fn collect_to_vec( bts: BTreeSet<StatesAndRoles> ) ->alloc::vec::Vec<Self> {
            let mut retval =alloc::vec::Vec::<Self>::with_capacity(
                StatesAndRoles::get_count()
            );

            for state_or_role in bts {
                retval.push(state_or_role)
            }

            retval
        }

        /// This function will return all the supported states
        fn get_supported_states( rss: &CmdReturn) ->alloc::vec::Vec<Self> {

            let mut set = BTreeSet::new();

            let count = StatesAndRoles::get_bit_count();

            for byte in 0..size_of_val(&rss.states) {
                for bit in 0..8 {
                    if (byte * 8 + bit) < count {
                        if 0 != rss.states[byte] & ( 1 << bit ) {
                            for state_or_role in StatesAndRoles::get_states_for_bit_val( bit ) {
                                set.insert(state_or_role);
                            }
                        }
                    }
                    else {
                        return StatesAndRoles::collect_to_vec(set);
                    }
                }
            }
            StatesAndRoles::collect_to_vec(set)
        }

        fn try_from(packed: CmdReturn) -> Result<alloc::vec::Vec<Self>, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(StatesAndRoles::get_supported_states(&packed))
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command!(
        COMMAND,
        CmdReturn,
        StatesAndRoles,
       alloc::vec::Vec<StatesAndRoles>,
        error::Error
    );

    impl_command_data_future!(StatesAndRoles,alloc::vec::Vec<StatesAndRoles>, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
                                 -> impl Future<Output=Result<alloc::vec::Vec<StatesAndRoles>, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
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

    pub struct Return;

    impl Return {
        fn try_from( packed: CmdReturn) -> Result<usize, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(packed.size as usize)
            }
            else {
                Err(status)
            }
        }
    }

    impl_get_data_for_command! (
        COMMAND,
        CmdReturn,
        Return,
        usize,
        error::Error
    );

    impl_command_data_future!(Return, usize, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
                                 -> impl Future<Output=Result<usize, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

pub mod remove_device_from_white_list {

    const COMMAND: crate::hci::opcodes::HCICommand = crate::hci::opcodes::HCICommand::LEController(crate::hci::opcodes::LEController::RemoveDeviceFromWhiteList);

    add_remove_white_list_setup!(COMMAND);

}

pub mod set_event_mask {

    use crate::hci::*;
    use crate::hci::events::LEMeta;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::SetEventMask);

    impl LEMeta {

        fn bit_offset(&self) -> usize{
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

        fn build_mask( events: &[Self]) -> [u8;8] {
            let mut mask = <[u8;8]>::default();

            for event in events.iter() {
                let bit = event.bit_offset();
                let byte = bit/8;

                mask[byte] |= 1 << (bit % 8);
            }

            mask
        }
    }

    impl_status_return!(COMMAND);

    #[repr(packed)]
    #[derive( Clone, Copy)]
    struct CmdParameter {
        _mask: [u8;8]
    }

    impl CommandParameter for CmdParameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
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
    /// # impl HostControllerInterface for StubHi {
    /// #     type SendCommandError = &'static str;
    /// #     type ReceiveEventError = &'static str;
    /// #
    /// #     fn send_command<D, W>(&self, _: &D, _: W)
    /// #     -> Result<bool, Self::SendCommandError>
    /// #     where D: CommandParameter,
    /// #           W: Into<Option<Waker>>,
    /// #     {
    /// #         Ok(true)
    /// #     }
    /// #
    /// #     fn receive_event<P>(&self, _: events::Events, _: &Waker, _: Pin<Arc<P>>, _: Option<Duration>)
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
    ///
    ///
    /// let events = vec!(LEMeta::ConnectionComplete,LEMeta::AdvertisingReport);
    ///
    /// // This will enable the LE Connection Complete Event and LE Advertising Report Event
    /// send(&host_interface, &events);
    /// ```
    pub fn send<'a, T: 'static>( hi: &'a HostInterface<T>, enabled_events: &[LEMeta] )
    -> impl Future<Output=Result<(), impl Display + Debug>> + 'a
    where T: HostControllerInterface
    {

        let command_pram = CmdParameter {
            _mask: LEMeta::build_mask(enabled_events),
        };

        ReturnedFuture( hi.send_command(command_pram, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}

pub mod test_end {

    use crate::hci::*;

    const COMMAND: opcodes::HCICommand = opcodes::HCICommand::LEController(opcodes::LEController::TestEnd);

    #[repr(packed)]
    pub(crate) struct CmdReturn {
        status: u8,
        number_of_packets: u16
    }

    pub struct Return;

    impl Return {
        fn try_from(packed: CmdReturn) -> Result<usize, error::Error> {
            let status = error::Error::from(packed.status);

            if let error::Error::NoError = status {
                Ok(packed.number_of_packets as usize)
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
        usize,
        error::Error
    );

    impl_command_data_future!(Return, usize, error::Error);

    #[derive(Clone,Copy)]
    struct Parameter;

    impl CommandParameter for Parameter {
        type Parameter = Self;
        const COMMAND: opcodes::HCICommand = COMMAND;
        fn get_parameter(&self) -> Self::Parameter {*self}
    }

    /// This will return a future with its type 'Output' being the number of packets
    /// received during what ever test was done
    pub fn send<'a, T: 'static>( hci: &'a HostInterface<T> )
                                 -> impl Future<Output=Result<usize, impl Display + Debug>> + 'a
        where T: HostControllerInterface
    {
        ReturnedFuture( hci.send_command(Parameter, events::Events::CommandComplete, Duration::from_secs(1) ) )
    }

}