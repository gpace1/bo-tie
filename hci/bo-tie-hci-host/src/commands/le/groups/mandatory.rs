//! Mandatory commands for a device that implements lE
//!
//! Some of these functions are not specific to Bluetooth LE, but they are re-exported here to be
//! noted that they are associated with LE.
//!
//! Vol2 Part E 3.1 of the Bluetooth spec

/// Set the event mask for LE events
///
/// LE events are unmasked by passing a list of LE events to the controller via the LE Set Event
/// Mask command. The method [`send`] takes the list of LE events and converts them into the command
/// that is sent to the controller.
///
/// # Note
/// There is a global mask for LE events unmasked by the set event mask command within the
/// Controller and Baseband commands group. In order for any LE event to be sent from the
/// Controller, the bit for the global mask must be set and the specific mask bit for the event must
/// be set.
///
/// [`send`]: set_event_mask::send
pub mod set_event_mask {
    use crate::events::{Events, LeMeta};
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use core::borrow::Borrow;

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::SetEventMask);

    pub(crate) fn event_to_mask_bit(le_meta: &LeMeta) -> u64 {
        match *le_meta {
            LeMeta::ConnectionComplete => 1 << 0,
            LeMeta::AdvertisingReport => 1 << 1,
            LeMeta::ConnectionUpdateComplete => 1 << 2,
            LeMeta::ReadRemoteFeaturesComplete => 1 << 3,
            LeMeta::LongTermKeyRequest => 1 << 4,
            LeMeta::RemoteConnectionParameterRequest => 1 << 5,
            LeMeta::DataLengthChange => 1 << 6,
            LeMeta::ReadLocalP256PublicKeyComplete => 1 << 7,
            LeMeta::GenerateDhKeyComplete => 1 << 8,
            LeMeta::EnhancedConnectionComplete => 1 << 9,
            LeMeta::DirectedAdvertisingReport => 1 << 10,
            LeMeta::PhyUpdateComplete => 1 << 11,
            LeMeta::ExtendedAdvertisingReport => 1 << 12,
            LeMeta::PeriodicAdvertisingSyncEstablished => 1 << 13,
            LeMeta::PeriodicAdvertisingReport => 1 << 14,
            LeMeta::PeriodicAdvertisingSyncLost => 1 << 15,
            LeMeta::ScanTimeout => 1 << 16,
            LeMeta::AdvertisingSetTerminated => 1 << 17,
            LeMeta::ScanRequestReceived => 1 << 18,
            LeMeta::ChannelSelectionAlgorithm => 1 << 19,
        }
    }

    const MASKED_EVENTS: &'static [Events] = &[
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::LeMeta(LeMeta::AdvertisingReport),
        Events::LeMeta(LeMeta::ConnectionUpdateComplete),
        Events::LeMeta(LeMeta::ReadRemoteFeaturesComplete),
        Events::LeMeta(LeMeta::LongTermKeyRequest),
        Events::LeMeta(LeMeta::RemoteConnectionParameterRequest),
        Events::LeMeta(LeMeta::DataLengthChange),
        Events::LeMeta(LeMeta::ReadLocalP256PublicKeyComplete),
        Events::LeMeta(LeMeta::GenerateDhKeyComplete),
        Events::LeMeta(LeMeta::EnhancedConnectionComplete),
        Events::LeMeta(LeMeta::DirectedAdvertisingReport),
        Events::LeMeta(LeMeta::PhyUpdateComplete),
        Events::LeMeta(LeMeta::ExtendedAdvertisingReport),
        Events::LeMeta(LeMeta::PeriodicAdvertisingSyncEstablished),
        Events::LeMeta(LeMeta::PeriodicAdvertisingReport),
        Events::LeMeta(LeMeta::PeriodicAdvertisingSyncLost),
        Events::LeMeta(LeMeta::ScanTimeout),
        Events::LeMeta(LeMeta::AdvertisingSetTerminated),
        Events::LeMeta(LeMeta::ScanRequestReceived),
        Events::LeMeta(LeMeta::ChannelSelectionAlgorithm),
    ];

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
    /// [`Events`]: bo_tie_hci_util::events::Events
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

    impl DefaultMask {
        const DEFAULT_MASK: u64 = 0x1F;

        const DEFAULT_EVENTS: &'static [Events] = &[
            Events::LeMeta(LeMeta::ConnectionComplete),
            Events::LeMeta(LeMeta::AdvertisingReport),
            Events::LeMeta(LeMeta::ConnectionUpdateComplete),
            Events::LeMeta(LeMeta::ReadRemoteFeaturesComplete),
            Events::LeMeta(LeMeta::LongTermKeyRequest),
        ];

        /// Iterate over the events that make up the default mask
        pub const fn iter() -> impl Iterator<Item = LeMeta> {
            struct DefaultMaskIter(usize, u64);

            impl Iterator for DefaultMaskIter {
                type Item = LeMeta;

                fn next(&mut self) -> Option<Self::Item> {
                    let bit = 1 << self.0;

                    if self.1 & bit != 0 {
                        self.0 += 1;

                        Some(LeMeta::from_depth(self.0))
                    } else {
                        None
                    }
                }
            }

            DefaultMaskIter(0, Self::DEFAULT_MASK)
        }
    }

    /// A marker for disabling all events
    ///
    /// This is the type used whenever an `EventMask` is created with [`disable_all`].
    ///
    /// [`disable_all`]: EventMask::disable_all
    pub struct AllUnmasked;

    struct Parameter {
        mask: [u8; 8],
    }

    impl<I, T> From<EventMask<I>> for Parameter
    where
        I: Iterator<Item = T>,
        T: Borrow<LeMeta>,
    {
        fn from(em: EventMask<I>) -> Self {
            let mask = em
                .mask
                .filter_map(|event| {
                    let bit = event_to_mask_bit(event.borrow());

                    (bit != 0).then_some(bit)
                })
                .fold(0u64, |mut mask, bit| {
                    mask |= bit;
                    mask
                })
                .to_le_bytes();

            Parameter { mask }
        }
    }

    impl<H, I, T> From<(&mut Host<H>, EventMask<I>)> for Parameter
    where
        H: HostChannelEnds,
        I: Iterator<Item = T>,
        T: Borrow<LeMeta>,
    {
        fn from((host, em): (&mut Host<H>, EventMask<I>)) -> Self {
            host.masked_events.clear_events(MASKED_EVENTS, false);

            let mask = em
                .mask
                .filter_map(|event| {
                    let bit = event_to_mask_bit(event.borrow());

                    if bit != 0 {
                        host.masked_events.set_event(Events::LeMeta(*event.borrow()));

                        Some(bit)
                    } else {
                        None
                    }
                })
                .fold(0u64, |mut mask, bit| {
                    mask |= bit;
                    mask
                })
                .to_le_bytes();

            Parameter { mask }
        }
    }

    impl From<EventMask<DefaultMask>> for Parameter {
        fn from(_: EventMask<DefaultMask>) -> Self {
            let mask = DefaultMask::DEFAULT_MASK.to_le_bytes();

            Parameter { mask }
        }
    }

    impl<H: HostChannelEnds> From<(&mut Host<H>, EventMask<DefaultMask>)> for Parameter {
        fn from((host, _): (&mut Host<H>, EventMask<DefaultMask>)) -> Self {
            let mask = DefaultMask::DEFAULT_MASK.to_le_bytes();

            host.masked_events.clear_events(MASKED_EVENTS, false);

            host.masked_events.set_events(DefaultMask::DEFAULT_EVENTS);

            Parameter { mask }
        }
    }

    impl From<EventMask<AllUnmasked>> for Parameter {
        fn from(_: EventMask<AllUnmasked>) -> Self {
            let mask = [0; 8];

            Parameter { mask }
        }
    }

    impl<H: HostChannelEnds> From<(&mut Host<H>, EventMask<AllUnmasked>)> for Parameter {
        fn from((host, _): (&mut Host<H>, EventMask<AllUnmasked>)) -> Self {
            let mask = [0; 8];

            host.masked_events.clear_events(MASKED_EVENTS, false);

            Parameter { mask }
        }
    }

    impl CommandParameter<8> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 8] {
            self.mask
        }
    }

    /// Same as method `send` except it does not effect the host's `EventMask`
    pub async fn send_command<H: HostChannelEnds, M, I, E>(host: &mut Host<H>, events: M) -> Result<(), CommandError<H>>
    where
        M: Into<EventMask<I>>,
        I: Iterator<Item = E>,
        E: Borrow<LeMeta>,
    {
        host.send_command_expect_complete(Parameter::from(events.into())).await
    }

    /// Send the command
    ///
    /// This will send the *LE Set Event Mask* command to the controller and await the command
    /// response. See the [module] level documentation for how events are masked.
    /// ```
    /// # use bo_tie_hci_util::events::LeMeta;
    /// # let (_channel_ends, host_ends) = bo_tie_hci_util::channel::tokio_unbounded();
    /// # async {
    /// # let mut host = bo_tie_hci_host::Host::init(host_ends).await?;
    /// # use bo_tie_hci_host::commands;
    /// use commands::le::set_event_mask;
    ///
    /// set_event_mask::send(&mut host, [LeMeta::ConnectionComplete, LeMeta::LongTermKeyRequest]).await
    /// # };
    /// ```
    ///
    /// [module]: self
    pub async fn send<H: HostChannelEnds, M, I, E>(host: &mut Host<H>, events: M) -> Result<(), CommandError<H>>
    where
        M: Into<EventMask<I>>,
        I: Iterator<Item = E>,
        E: Borrow<LeMeta>,
    {
        let parameter = Parameter::from((&mut *host, events.into()));

        host.send_command_expect_complete(parameter).await
    }
}

/// Read the size of the LE HCI data buffer
pub mod read_buffer_size {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
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
                        "(HCI) within the return parameters for the LE read buffer size (v1) \
                        command, the packet count is unexpectedly zero as the packet length was \
                        not zero"
                    );

                    return Ok(None);
                }
            };

            let acl = BufferSize { len, cnt };

            Ok(Some(BufferSizeV1 { acl }))
        }
    }

    #[derive(Debug)]
    pub struct BufferSizeV2 {
        /// Information on the LE ACL buffer
        pub acl: Option<BufferSize>,
        /// Information on the LE ISO buffer
        pub iso: Option<BufferSize>,
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
                            "(HCI) within the return parameters for the LE read buffer size (v2) \
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
                            "(HCI) within the return parameters for the LE read buffer size (v2) \
                            command, the ISO packet count is unexpectedly zero as the ISO packet \
                            length was not zero"
                        );

                        None
                    }
                })
                .map(|(len, cnt)| BufferSize { len, cnt });

            Ok(Self { acl, iso })
        }
    }

    /// Request information on the LE data buffers (version 1)
    ///
    /// This only returns the buffer information for LE ACL data packets.
    ///
    /// `send_v1` will return `Ok(None)` when there is no dedicated LE buffer. The information
    /// parameters command [*read buffer size*] should be used instead to get the buffer information
    /// for LE.
    ///
    /// [*read buffer size*]: crate::commands::info_params::read_buffer_size
    pub async fn send_v1<H: HostChannelEnds>(host: &mut Host<H>) -> Result<Option<BufferSizeV1>, CommandError<H>> {
        host.send_command_expect_complete(ParameterV1).await
    }

    /// Request information on the LE data buffers (version 2)
    ///
    /// This returns the buffer information for the LE ACL and LE ISO data packets.
    ///
    /// `send_v1` will return `Ok(None)` when there is no dedicated LE buffer. The information
    /// parameters command [*read buffer size*] should be used instead to get the buffer information
    /// for LE.
    ///
    /// [*read buffer size*]: crate::commands::info_params::read_buffer_size
    pub async fn send_v2<H: HostChannelEnds>(host: &mut Host<H>) -> Result<BufferSizeV2, CommandError<H>> {
        host.send_command_expect_complete(ParameterV2).await
    }
}

/// Read the LE features supported by the Controller.
pub mod read_local_supported_features {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
    };
    use bo_tie_util::{LeDeviceFeatures, LeFeaturesItr};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::LEController(opcodes::LEController::ReadLocalSupportedFeatures);

    pub struct EnabledLeFeatures {
        features: LeDeviceFeatures,
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
                let features = LeDeviceFeatures::new(&cc.return_parameter[1..])
                    .map_err(|_| CCParameterError::InvalidEventParameter)?;

                Ok(Self { features })
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

    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<EnabledLeFeatures, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

pub mod read_white_list_size {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ReadWhiteListSize);

    pub struct WhiteListSize {
        pub list_size: usize,
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

            Ok(Self { list_size })
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

    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<WhiteListSize, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

pub mod clear_white_list {

    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::ClearWhiteList);

    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the command to clear the white list
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

macro_rules! add_remove_white_list_setup {
    ( $command: ident ) => {
        use crate::commands::le::WhiteListedAddressType;
        use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
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

        pub async fn send<H: HostChannelEnds>(
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
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
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
                let mut states_and_roles_mask = [0u8; 8];

                states_and_roles_mask.copy_from_slice(&cc.return_parameter[1..]);

                Ok(Self { states_and_roles_mask })
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

    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<CurrentStatesAndRoles, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// LE test end command
pub mod test_end {

    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
    };

    const COMMAND: opcodes::HciCommand = opcodes::HciCommand::LEController(opcodes::LEController::TestEnd);

    pub struct Return {
        pub number_of_packets: u16,
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

            Ok(Self { number_of_packets })
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
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<Return, CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}
