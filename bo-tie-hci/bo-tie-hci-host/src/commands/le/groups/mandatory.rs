//! Mandatory commands for a device that implements lE
//!
//! Some of these functions are not specific to Bluetooth LE, but they are re-exported here to be
//! noted that they are associated with LE.
//!
//! Vol2 Part E 3.1 of the Bluetooth spec

/// Set the [`LeMeta`](crate::hci::events::LeMeta) event mask
///
/// LE events are unmasked by passing a list of LE events to the controller via the LE set event
/// mask command. The method [`send`] takes the list of LE events and converts them into the command
/// that is sent to the controller.
///
/// ```
/// # mod le {
/// # pub mod set_event_mask {
/// #     use bo_tie_hci_host::commands::cb::set_event_mask_page_2;
/// #     use bo_tie_hci_util::events::Events;
/// #     pub async fn send<H, E, I>(_h: H, _e: E)
/// #        where
/// #             E: Into<set_event_mask_page_2::EventMask<I>>,
/// #             I: Iterator<Item = Events>
/// #     {}
/// # }
/// # }
/// # use bo_tie_hci_util::events::LeMeta;
/// # let host = ();
/// # async {
///     le::set_event_mask::send(host, [LeMeta::ConnectionComplete, LeMeta::LongTermKeyRequest]).await
/// # }
/// ```
///
/// # Note
/// There is a global mask for LE events unmasked by the set event mask command within the
/// Controller and Baseband commands group. In order for any LE event to be sent from the
/// Controller, the bit for the global mask must be set and the specific mask bit for the event must
/// be set.
///
/// [`send`]: self::send
pub mod set_event_mask {
    use crate::events::LeMeta;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };
    use core::borrow::Borrow;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::SetEventMask);

    fn bit_offset(le_meta: &LeMeta) -> usize {
        match *le_meta {
            LeMeta::ConnectionComplete => 0,
            LeMeta::AdvertisingReport => 1,
            LeMeta::ConnectionUpdateComplete => 2,
            LeMeta::ReadRemoteFeaturesComplete => 3,
            LeMeta::LongTermKeyRequest => 4,
            LeMeta::RemoteConnectionParameterRequest => 5,
            LeMeta::DataLengthChange => 6,
            LeMeta::ReadLocalP256PublicKeyComplete => 7,
            LeMeta::GenerateDhKeyComplete => 8,
            LeMeta::EnhancedConnectionComplete => 9,
            LeMeta::DirectedAdvertisingReport => 10,
            LeMeta::PhyUpdateComplete => 11,
            LeMeta::ExtendedAdvertisingReport => 12,
            LeMeta::PeriodicAdvertisingSyncEstablished => 13,
            LeMeta::PeriodicAdvertisingReport => 14,
            LeMeta::PeriodicAdvertisingSyncLost => 15,
            LeMeta::ScanTimeout => 16,
            LeMeta::AdvertisingSetTerminated => 17,
            LeMeta::ScanRequestReceived => 18,
            LeMeta::ChannelSelectionAlgorithm => 19,
        }
    }

    /// The event mask
    ///
    /// This is the type used for creating an event mask to send to the Controller. Anything that
    /// implements [`IntoIterator`] where the `Item` type can be '[borrowed]' as an [`Events`] is
    /// able to be converted into an `EventMask`.
    ///
    /// ```
    /// # use bo_tie_hci_host::commands::le::set_event_mask::EventMask;
    /// # use bo_tie_hci_util::events::LeMeta;
    ///
    /// let e_mask: EventMask<_> = [LeMeta::ConnectionComplete, LeMeta::RemoteConnectionParameterRequest].into();
    /// # let _ignored = e_mask;
    /// ```
    ///
    /// # Default mask
    /// The default mask for the page 2 is equivalent to disabling all events for page 2, but it can
    /// still be creating by using a default `EventMask` (`EventMask::default()`).
    ///
    /// [`Event`]:bo_tie_hci_util::events::Events
    /// [borrowed]: core::borrow::Borrow
    pub struct EventMask<I> {
        mask: I,
    }

    impl<I, T> EventMask<I>
    where
        I: Iterator<Item = T>,
        T: Borrow<LeMeta>,
    {
        /// Create a new `EventMask`
        pub fn new(t: I) -> Self {
            EventMask { mask: t }
        }
    }

    impl EventMask<AllUnmasked> {
        /// Create a new `EventMask` with all events disabled
        ///
        /// This event mask will disable all events that are able to be enabled by the *Set Event
        /// Mask* command.
        pub fn disable_all() -> EventMask<AllUnmasked> {
            EventMask { mask: AllUnmasked }
        }
    }

    impl Default for EventMask<DefaultMask> {
        fn default() -> Self {
            EventMask { mask: DefaultMask }
        }
    }

    impl<I, T> From<I> for EventMask<I::IntoIter>
    where
        I: IntoIterator<Item = T>,
        T: Borrow<LeMeta>,
    {
        fn from(t: I) -> Self {
            Self::new(t.into_iter())
        }
    }

    impl From<DefaultMask> for EventMask<DefaultMask> {
        fn from(_: DefaultMask) -> Self {
            Self::default()
        }
    }

    impl From<AllUnmasked> for EventMask<AllUnmasked> {
        fn from(_: AllUnmasked) -> Self {
            Self::disable_all()
        }
    }

    /// A marker for the default event mask
    ///
    /// This is normally used with the implementation of `Default` for [`EventMask`]
    pub struct DefaultMask;

    /// A marker for disabling all events
    ///
    /// This is the type used whenever an `EventMask` is created with [`disable_all`].
    ///
    /// [`disable_all`]: EventMask::disable_all
    pub struct AllUnmasked;

    struct CmdParameter {
        mask: [u8; 8],
    }

    impl<I, T> TryFrom<EventMask<I>> for CmdParameter
    where
        I: Iterator<Item = T>,
        T: Borrow<LeMeta>,
    {
        type Error = ();

        fn try_from(em: EventMask<I>) -> Result<Self, Self::Error> {
            let mut filtered = em.mask.filter(|e| event_to_mask_bit(e.borrow()) != 0).peekable();

            match filtered.peek() {
                None => Err(()),
                Some(_) => {
                    let mask = em
                        .mask
                        .fold(0u64, |mask, e| mask | event_to_mask_bit(e.borrow()))
                        .to_le_bytes();

                    Ok(CmdParameter { mask })
                }
            }
        }
    }

    impl TryFrom<EventMask<DefaultMask>> for CmdParameter {
        type Error = core::convert::Infallible;

        fn try_from(_: EventMask<DefaultMask>) -> Result<Self, Self::Error> {
            let mask = 0.to_le_bytes();

            Ok(CmdParameter { mask })
        }
    }

    impl TryFrom<EventMask<AllUnmasked>> for CmdParameter {
        type Error = core::convert::Infallible;

        fn try_from(_: EventMask<AllUnmasked>) -> Result<Self, Self::Error> {
            let mask = [0; 8];

            Ok(CmdParameter { mask })
        }
    }

    impl CommandParameter<8> for CmdParameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 8] {
            self.mask
        }
    }

    /// Send the command
    ///
    /// ```
    /// # mod le {
    /// # pub mod set_event_mask {
    /// #     use bo_tie_hci_host::commands::cb::set_event_mask_page_2;
    /// #     use bo_tie_hci_util::events::Events;
    /// #     pub async fn send<H, E, I>(_h: H, _e: E)
    /// #        where
    /// #             E: Into<set_event_mask_page_2::EventMask<I>>,
    /// #             I: Iterator<Item = Events>
    /// #     {}
    /// # }
    /// # }
    /// # use bo_tie_hci_util::events::LeMeta;
    /// # let host = ();
    /// # async {
    ///     le::set_event_mask::send(host, [LeMeta::ConnectionComplete, LeMeta::LongTermKeyRequest]).await
    /// # }
    /// ```
    pub async fn send<H: HostInterface, E, I>(host: &mut Host<H>, events: E) -> Result<(), CommandError<H>>
    where
        E: Into<EventMask<I>>,
        E: Iterator<Item = LeMeta>,
    {
        let parameter = CommandParameter::from(events.into());

        host.send_command_expect_complete(parameter).await
    }
}

/// Read the size of the LE HCI data buffer
pub mod read_buffer_size {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };

    const COMMAND_V1: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadBufferSizeV1);
    const COMMAND_V2: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadBufferSizeV2);

    struct ParameterV1;

    impl CommandParameter<0> for ParameterV1 {
        const COMMAND: opcodes::HciCommand = COMMAND_V1;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    struct ParameterV2;

    impl CommandParameter<0> for ParameterV2 {
        const COMMAND: opcodes::HciCommand = COMMAND_V2;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Buffer size information
    ///
    /// This is the information about a specific buffer in the Controller. The field `len` is the
    /// maximum size of a HCI packet's payload that can be stored in the buffer, and field `cnt` is
    /// the number of HCI packets that can be stored within the buffer.
    #[derive(Debug)]
    pub struct BufferSize {
        pub len: u16,
        pub cnt: u8,
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
        /// Information on the LE ACL buffer
        pub acl: BufferSize,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Option<BufferSizeV1> {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let raw_packet_len = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let raw_packet_cnt = *cc
                .return_parameter
                .get(3)
                .ok_or(CCParameterError::InvalidEventParameter)?;

            let len = match (raw_packet_len != 0).then(|| raw_packet_len) {
                Some(packet_len) => packet_len,
                None => return Ok(None),
            };

            let cnt = match (raw_packet_cnt != 0).then(|| raw_packet_cnt) {
                Some(packet_cnt) => packet_cnt,
                None => {
                    log::info!(
                        "within the return parameters for the LE read buffer size (v1) \
                        command, the packet count is unexpectedly zero as the packet length was \
                        not zero"
                    );

                    return Ok(None);
                }
            };

            let acl = BufferSize { len, cnt };

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Some(BufferSizeV1 {
                acl,
                completed_packets_cnt,
            }))
        }
    }

    #[derive(Debug)]
    pub struct BufferSizeV2 {
        /// Information on the LE ACL buffer
        pub acl: Option<BufferSize>,
        /// Information on the LE ISO buffer
        pub iso: Option<BufferSize>,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for BufferSizeV2 {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let raw_acl_packet_len = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let raw_acl_packet_cnt = *cc
                .return_parameter
                .get(3)
                .ok_or(CCParameterError::InvalidEventParameter)?;

            let raw_iso_packet_len = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(3)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(4)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let raw_iso_packet_cnt = *cc
                .return_parameter
                .get(5)
                .ok_or(CCParameterError::InvalidEventParameter)?;

            let acl = (raw_acl_packet_len != 0)
                .then_some(raw_acl_packet_len)
                .and_then(|len| {
                    if raw_acl_packet_cnt != 0 {
                        Some((len, raw_acl_packet_cnt))
                    } else {
                        log::info!(
                            "within the return parameters for the LE read buffer size (v2) \
                        command, the ACL packet count is unexpectedly zero as the ACL packet \
                        length was not zero"
                        );

                        None
                    }
                })
                .map(|(len, cnt)| BufferSize { len, cnt });

            let iso = (raw_iso_packet_len != 0)
                .then_some(raw_iso_packet_len)
                .and_then(|len| {
                    if raw_iso_packet_cnt != 0 {
                        Some((len, raw_iso_packet_cnt))
                    } else {
                        log::info!(
                            "within the return parameters for the LE read buffer size (v2) \
                        command, the ISO packet count is unexpectedly zero as the ISO packet \
                        length was not zero"
                        );

                        None
                    }
                })
                .map(|(len, cnt)| BufferSize { len, cnt });

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                acl,
                iso,
                completed_packets_cnt,
            })
        }
    }

    /// Request information on the LE data buffers (version 1)
    ///
    /// This only returns the buffer information for LE ACL data packets.
    ///
    /// `send_v1` will return `Ok(None)` when there is no dedicated LE buffer. The information
    /// parameters command *read buffer size* ([`bo_tie::hci::info_params::read_buffer_size`]) should
    /// be used instead to get the buffer information for LE.
    pub async fn send_v1<H: HostInterface>(host: &mut Host<H>) -> Result<Option<BufferSizeV1>, CommandError<H>> {
        host.send_command_expect_complete(ParameterV1).await
    }

    /// Request information on the LE data buffers (version 2)
    ///
    /// This returns the buffer information for the LE ACL and LE ISO data packets.
    ///
    /// `send_v1` will return `Ok(None)` when there is no dedicated LE buffer. The information
    /// parameters command *read buffer size* ([`bo_tie::hci::info_params::read_buffer_size`]) should
    /// be used instead to get the buffer information for LE.
    pub async fn send_v2<H: HostInterface>(host: &mut Host<H>) -> Result<BufferSizeV2, CommandError<H>> {
        host.send_command_expect_complete(ParameterV2).await
    }
}

/// Read the LE features supported by the Controller.
pub mod read_local_supported_features {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };
    use bo_tie_util::{LeDeviceFeatures, LeFeaturesItr};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::ReadLocalSupportedFeatures);

    pub struct EnabledLeFeatures {
        features: LeDeviceFeatures,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl EnabledLeFeatures {
        pub fn iter(&self) -> LeFeaturesItr<'_> {
            self.features.iter()
        }
    }

    impl TryFromCommandComplete for EnabledLeFeatures {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == 8 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let features = LeDeviceFeatures::new(&cc.return_parameter[1..])
                    .map_err(|_| CCParameterError::InvalidEventParameter)?;

                Ok(Self {
                    features,
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

    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<EnabledLeFeatures, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

pub mod read_white_list_size {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadWhiteListSize);

    pub struct WhiteListSize {
        pub list_size: usize,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for WhiteListSize {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let list_size = cc
                .return_parameter
                .get(1)
                .copied()
                .ok_or(CCParameterError::InvalidEventParameter)?
                .into();

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                list_size,
                completed_packets_cnt,
            })
        }
    }

    impl core::ops::Deref for WhiteListSize {
        type Target = usize;

        fn deref(&self) -> &Self::Target {
            &self.list_size
        }
    }

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<WhiteListSize, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

pub mod clear_white_list {

    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ClearWhiteList);

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the command to clear the white list
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

macro_rules! add_remove_white_list_setup {
    ( $command: ident ) => {
        use crate::commands::le::WhiteListedAddressType;
        use crate::{
            opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface,
            OnlyStatus, TryFromCommandComplete,
        };
        use bo_tie_util::BluetoothDeviceAddress;

        struct CommandPrameter {
            address_type: u8,
            address: BluetoothDeviceAddress,
        }

        impl CommandParameter<7> for CommandPrameter {
            const COMMAND: opcodes::HciCommand = $command;
            fn get_parameter(&self) -> [u8; 7] {
                let mut parameter = [0u8; 7];

                parameter[0] = self.address_type;

                parameter[1..].copy_from_slice(&self.address);

                parameter
            }
        }

        pub async fn send<H: HostInterface>(
            host: &mut Host<H>,
            address_type: WhiteListedAddressType,
            address: BluetoothDeviceAddress,
        ) -> Result<(), CommandError<H>> {
            let parameter = CommandPrameter {
                address_type: address_type.into(),
                address,
            };

            host.send_command_expect_complete(parameter).await
        }
    };
}

pub mod add_device_to_white_list {
    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::AddDeviceToWhiteList);

    add_remove_white_list_setup!(COMMAND);
}

pub mod remove_device_from_white_list {

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::RemoveDeviceFromWhiteList);

    add_remove_white_list_setup!(COMMAND);
}

pub mod read_supported_states {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadSupportedStates);

    /// All possible states/roles a controller can be in
    #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
    pub enum StatesAndRoles {
        ScannableAdvertisingState,
        ConnectableAdvertisingState,
        NonConnectableAdvertisingState,
        HighDutyCycleDirectedAdvertisingState,
        LowDutyCycleDirectedAdvertisingState,
        ActiveScanningState,
        PassiveScanningState,
        InitiatingState,
        ConnectionStateMasterRole,
        ConnectionStateSlaveRole,
    }

    impl StatesAndRoles {
        /// This function doesn't return all available states and roles of a device
        /// (since devices can set multiple of these bits indicating the available
        /// roles) so it doesn't return the special type name.
        fn get_states_for_bit_val(bit_val: usize) -> &'static [Self] {
            use self::StatesAndRoles::*;

            match bit_val {
                0 => &[NonConnectableAdvertisingState],
                1 => &[ScannableAdvertisingState],
                2 => &[ConnectableAdvertisingState],
                3 => &[HighDutyCycleDirectedAdvertisingState],
                4 => &[PassiveScanningState],
                5 => &[ActiveScanningState],
                6 => &[InitiatingState],
                7 => &[ConnectionStateSlaveRole],
                8 => &[NonConnectableAdvertisingState, PassiveScanningState],
                9 => &[ScannableAdvertisingState, PassiveScanningState],
                10 => &[ConnectableAdvertisingState, PassiveScanningState],
                11 => &[HighDutyCycleDirectedAdvertisingState, PassiveScanningState],
                12 => &[NonConnectableAdvertisingState, ActiveScanningState],
                13 => &[ScannableAdvertisingState, ActiveScanningState],
                14 => &[ConnectableAdvertisingState, ActiveScanningState],
                15 => &[HighDutyCycleDirectedAdvertisingState, ActiveScanningState],
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
                33 => &[HighDutyCycleDirectedAdvertisingState, InitiatingState],
                34 => &[LowDutyCycleDirectedAdvertisingState, InitiatingState],
                35 => &[ConnectableAdvertisingState, ConnectionStateMasterRole],
                36 => &[HighDutyCycleDirectedAdvertisingState, ConnectionStateMasterRole],
                37 => &[LowDutyCycleDirectedAdvertisingState, ConnectionStateMasterRole],
                38 => &[ConnectableAdvertisingState, ConnectionStateSlaveRole],
                39 => &[HighDutyCycleDirectedAdvertisingState, ConnectionStateSlaveRole],
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
            check_status!(cc.return_parameter);

            if cc.return_parameter[1..].len() == 8 {
                let completed_packets_cnt = cc.number_of_hci_command_packets.into();

                let mut states_and_roles_mask = [0u8; 8];

                states_and_roles_mask.copy_from_slice(&cc.return_parameter[1..]);

                Ok(Self {
                    states_and_roles_mask,
                    completed_packets_cnt,
                })
            } else {
                Err(CCParameterError::InvalidEventParameter)
            }
        }
    }

    /// An iterator over the states and roles
    ///
    /// This is returned by the method [`iter`](CurrentStatesAndRoles::iter) of
    /// `CurrentStatesAndRoles`
    pub struct StatesAndRolesIter<'a> {
        mask_iter: core::slice::Iter<'a, u8>,
        current_mask: core::slice::Iter<'static, StatesAndRoles>,
        byte: &'a u8,
        bit: usize,
    }

    impl<'a> StatesAndRolesIter<'a> {
        fn new(mask: &'a [u8; 8]) -> Self {
            let mut mask_iter = mask.iter();

            let current_mask = [].iter();

            let byte = mask_iter.next().unwrap();

            let bit = 0;

            Self {
                mask_iter,
                current_mask,
                byte,
                bit,
            }
        }

        fn next_mask(&mut self) -> Option<usize> {
            loop {
                let next_bit = (self.bit + 1) % 8;

                if next_bit == 0 {
                    self.byte = self.mask_iter.next()?;
                }

                self.bit += 1;

                if self.byte & (1 << next_bit) != 0 {
                    break Some(self.bit);
                }
            }
        }
    }

    impl Iterator for StatesAndRolesIter<'_> {
        type Item = StatesAndRoles;

        fn next(&mut self) -> Option<Self::Item> {
            loop {
                match self.current_mask.next().copied() {
                    s @ Some(_) => break s,
                    None => {
                        let bit_val = self.next_mask()?;

                        self.current_mask = StatesAndRoles::get_states_for_bit_val(bit_val).iter();
                    }
                }
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
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<CurrentStatesAndRoles, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// LE test end command
pub mod test_end {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, FlowControlInfo, Host, HostInterface, OnlyStatus,
        TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::TestEnd);

    pub struct Return {
        pub number_of_packets: u16,
        /// The number of HCI command packets completed by the controller
        completed_packets_cnt: usize,
    }

    impl TryFromCommandComplete for Return {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let number_of_packets = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let completed_packets_cnt = cc.number_of_hci_command_packets.into();

            Ok(Self {
                number_of_packets,
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

    /// Send the command
    pub async fn send<H: HostInterface>(host: &mut Host<H>) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}
