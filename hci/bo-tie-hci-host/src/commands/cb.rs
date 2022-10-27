//! Controller and Baseband Commands

/// Set the event mask on the controller
///
/// This command sends a mask to the Controller to enable the selected events. Afterward the
/// Controller will only send the selected events to the Host with some
/// [*exceptions*](#Events-Not-Masked).
///
/// # Default
/// The default list of events can be created by using `EventMask::default()`. These are the events
/// that are enabled upon reset of the Controller.
///
/// # LE Events
/// This command has a 'global' flag for enabling or disabling all LE events. Any time a
/// [`LeMeta`] is within the list of events to enable it will enable this flag. However, the
/// specific LE event contained within the `LeMeta` is not enabled by this function. To deliberately
/// enable a LE event the global flag must be set by this command and the individual mask for the
/// event must be set using the command [*LE Set Event Mask*].
///
/// # Events Masked by Page 2
/// * [*Triggered Clock Capture*]
/// * [*Synchronization Train Complete*]
/// * [*Synchronization Train Received*]
/// * [*Connectionless Peripheral Broadcast Receive*]
/// * [*Connectionless Peripheral Broadcast Timeout*]
/// * [*Truncated Page Complete*]
/// * [*Peripheral Page Response Timeout*]
/// * [*Connectionless Slave Broadcast Channel Map Change*]
/// * [*Inquiry Response Notification*]
/// * [*Authenticated Payload Timeout Expired*]
/// * [*Sam Status Change*]
/// * [*Encryption Change \[v2\]*]
///
/// These events can be masked, but they must be masked by the *Set Event Mask Page 2* command.
///
/// # Events Never Masked
/// Not all events can be enabled by this command. Some events are on the next mask "page" and they
/// can be enabled through the [*Set Event Mask Page 2*] command. LE events need to be *further*
/// masked through the *LE Set Event Mask* command. Finally some events cannot be masked at all.
///
/// Whenever an event is not masked by this command, but is included within the input to the method
/// `set_event_mask` it is simply ignored.
///
/// ## Command Events
/// * [*Command Complete*](bo_tie_hci_util::events::Events::CommandComplete)
/// * [*Command Status*](bo_tie_hci_util::events::Events::CommandStatus)
///
/// These events are sent from the controller in response to a HCI command. These are processed
/// by the `Host` object as part of the await process whenever a command is sent (by this library).
/// Essentially all the futures created by the send functions for HCI commands within this library
/// await until one of these two events are sent from the controller before polling to completion.
///
/// ## Flow Control Events
/// * [*Number of Completed Packets*](bo_tie_hci_util::events::Events::NumberOfCompletedPackets)
/// * [*Number of Completed Data Blocks*](bo_tie_hci_util::events::Events::NumberOfCompletedDataBlocks)
///
/// These events concern the buffers for data sent to the controller. This information is processed
/// within the interface async task so that flow control with the connection async tasks to the
/// controller can be maintained.
///
/// [*Authenticated Payload Timeout Expired*]: bo_tie_hci_util::events::Events::AuthenticatedPayloadTimeoutExpired
/// [*Command Complete*]: bo_tie_hci_util::events::Events::CommandComplete
/// [*Command Status*]: bo_tie_hci_util::events::Events::CommandStatus   
/// [*Connectionless Peripheral Broadcast Receive*]: bo_tie_hci_util::events::Events::ConnectionlessPeripheralBroadcastReceive
/// [*Connectionless Peripheral Broadcast Timeout*]: bo_tie_hci_util::events::Events::ConnectionlessPeripheralBroadcastTimeout
/// [*Encryption Change \[v2\]*]: bo_tie_hci_util::events::Events::EncryptionChangeV2
/// [*Inquiry Response Notification*]: bo_tie_hci_util::events::Events::InquiryResponseNotification
/// [`LeMeta`]: bo_tie_hci_util::events::Events::LeMeta
/// [*Number of Completed Data Blocks*]: bo_tie_hci_util::events::Events::NumberOfCompletedDataBlocks      
/// [*Number of Completed Packets*]: bo_tie_hci_util::events::Events::NumberOfCompletedPackets        
/// [*Peripheral Page Response Timeout*]: bo_tie_hci_util::events::Events::PeripheralPageResponseTimeout
/// [*Sam Status Change*]: bo_tie_hci_util::events::Events::SamStatusChange
/// [*Set Event Mask Page 2*]: crate::commands::cb::set_event_mask_page_2
/// [*Synchronization Train Complete*]: bo_tie_hci_util::events::Events::SynchronizationTrainComplete
/// [*Synchronization Train Received*]: bo_tie_hci_util::events::Events::SynchronizationTrainReceived
/// [*Triggered Clock Capture*]: bo_tie_hci_util::events::Events::TriggeredClockCapture
/// [*Truncated Page Complete*]: bo_tie_hci_util::events::Events::TruncatedPageComplete
pub mod set_event_mask {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use bo_tie_hci_util::events::Events;
    use core::borrow::Borrow;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::SetEventMask);

    /// Get the mask bit for an event
    ///
    /// # Note
    /// Zero is returned if an event is not maskable is returned or it is on page 2.
    pub(crate) fn event_to_mask_bit(event: &Events) -> u64 {
        match *event {
            Events::InquiryComplete => 1 << 0,
            Events::InquiryResult => 1 << 1,
            Events::ConnectionComplete => 1 << 2,
            Events::ConnectionRequest => 1 << 3,
            Events::DisconnectionComplete => 1 << 4,
            Events::AuthenticationComplete => 1 << 5,
            Events::RemoteNameRequestComplete => 1 << 6,
            Events::EncryptionChangeV1 => 1 << 7,
            Events::ChangeConnectionLinkKeyComplete => 1 << 8,
            Events::LinkKeyTypeChanged => 1 << 9,
            Events::ReadRemoteSupportedFeaturesComplete => 1 << 10,
            Events::ReadRemoteVersionInformationComplete => 1 << 11,
            Events::QosSetupComplete => 1 << 12,
            Events::HardwareError => 1 << 15,
            Events::FlushOccurred => 1 << 16,
            Events::RoleChange => 1 << 17,
            Events::ModeChange => 1 << 19,
            Events::ReturnLinkKeys => 1 << 20,
            Events::PinCodeRequest => 1 << 21,
            Events::LinkKeyRequest => 1 << 22,
            Events::LinkKeyNotification => 1 << 23,
            Events::LoopbackCommand => 1 << 24,
            Events::DataBufferOverflow => 1 << 25,
            Events::MaxSlotsChange => 1 << 26,
            Events::ReadClockOffsetComplete => 1 << 27,
            Events::ConnectionPacketTypeChanged => 1 << 28,
            Events::QosViolation => 1 << 29,
            Events::PageScanRepetitionModeChange => 1 << 31,
            Events::FlowSpecificationComplete => 1 << 32,
            Events::InquiryResultWithRssi => 1 << 33,
            Events::ReadRemoteExtendedFeaturesComplete => 1 << 34,
            Events::SynchronousConnectionComplete => 1 << 43,
            Events::SynchronousConnectionChanged => 1 << 44,
            Events::SniffSubrating => 1 << 45,
            Events::ExtendedInquiryResult => 1 << 46,
            Events::EncryptionKeyRefreshComplete => 1 << 47,
            Events::IoCapabilityRequest => 1 << 48,
            Events::IoCapabilityResponse => 1 << 49,
            Events::UserConfirmationRequest => 1 << 50,
            Events::UserPasskeyRequest => 1 << 51,
            Events::RemoteOobDataRequest => 1 << 52,
            Events::SimplePairingComplete => 1 << 53,
            Events::LinkSupervisionTimeoutChanged => 1 << 55,
            Events::EnhancedFlushComplete => 1 << 56,
            Events::UserPasskeyNotification => 1 << 58,
            Events::KeypressNotification => 1 << 59,
            Events::RemoteHostSupportedFeaturesNotification => 1 << 60,
            Events::LeMeta(_) => 1 << 61,
            // Non maskable
            Events::CommandComplete
            | Events::CommandStatus
            | Events::NumberOfCompletedPackets
            | Events::NumberOfCompletedDataBlocks => 0,
            // maskable on page 2
            Events::TriggeredClockCapture
            | Events::SynchronizationTrainComplete
            | Events::SynchronizationTrainReceived
            | Events::ConnectionlessPeripheralBroadcastReceive
            | Events::ConnectionlessPeripheralBroadcastTimeout
            | Events::TruncatedPageComplete
            | Events::PeripheralPageResponseTimeout
            | Events::ConnectionlessSlaveBroadcastChannelMapChange
            | Events::InquiryResponseNotification
            | Events::AuthenticatedPayloadTimeoutExpired
            | Events::SamStatusChange
            | Events::EncryptionChangeV2 => 0,
        }
    }

    const MASKED_EVENTS: &'static [Events] = &[
        Events::InquiryComplete,
        Events::InquiryResult,
        Events::ConnectionComplete,
        Events::ConnectionRequest,
        Events::DisconnectionComplete,
        Events::AuthenticationComplete,
        Events::RemoteNameRequestComplete,
        Events::EncryptionChangeV1,
        Events::ChangeConnectionLinkKeyComplete,
        Events::LinkKeyTypeChanged,
        Events::ReadRemoteSupportedFeaturesComplete,
        Events::ReadRemoteVersionInformationComplete,
        Events::QosSetupComplete,
        Events::HardwareError,
        Events::FlushOccurred,
        Events::RoleChange,
        Events::ModeChange,
        Events::ReturnLinkKeys,
        Events::PinCodeRequest,
        Events::LinkKeyRequest,
        Events::LinkKeyNotification,
        Events::LoopbackCommand,
        Events::DataBufferOverflow,
        Events::MaxSlotsChange,
        Events::ReadClockOffsetComplete,
        Events::ConnectionPacketTypeChanged,
        Events::QosViolation,
        Events::PageScanRepetitionModeChange,
        Events::FlowSpecificationComplete,
        Events::InquiryResultWithRssi,
        Events::ReadRemoteExtendedFeaturesComplete,
        Events::SynchronousConnectionComplete,
        Events::SynchronousConnectionChanged,
        Events::SniffSubrating,
        Events::ExtendedInquiryResult,
        Events::EncryptionKeyRefreshComplete,
        Events::IoCapabilityRequest,
        Events::IoCapabilityResponse,
        Events::UserConfirmationRequest,
        Events::UserPasskeyRequest,
        Events::RemoteOobDataRequest,
        Events::SimplePairingComplete,
        Events::LinkSupervisionTimeoutChanged,
        Events::EnhancedFlushComplete,
        Events::UserPasskeyNotification,
        Events::KeypressNotification,
        Events::RemoteHostSupportedFeaturesNotification,
    ];

    /// The event mask
    ///
    /// This is the type used for creating an event mask to send to the Controller. Anything that
    /// implements [`IntoIterator`] where the `Item` type can be '[borrowed]' as an [`Events`] is
    /// able to be converted into an `EventMask`.
    ///
    /// ```
    /// # use bo_tie_hci_host::commands::cb::set_event_mask::EventMask;
    /// # use bo_tie_hci_util::events::Events;
    ///
    /// let e_mask: EventMask<_> = [Events::ConnectionComplete, Events::DisconnectionComplete].into();
    /// # let _ignored = e_mask;
    /// ```
    ///
    /// # Default Mask
    /// The default mask can be created by creating a default `EventMask` (`EventMask::default()`).
    /// This mask is equivalent to the event mask set upon reset of the Controller.
    ///
    /// [borrowed]: core::borrow::Borrow
    /// [`Events`]: bo_tie_hci_util::events::Events
    pub struct EventMask<T> {
        mask: T,
        le_is_masked: bool,
    }

    impl<I, T> EventMask<I>
    where
        I: Iterator<Item = T>,
        T: Borrow<Events>,
    {
        /// Create a new `EventMask`
        ///
        /// This creates a new `EventMask` from the iterable type `t` and a boolean indicating if
        /// LE events are to be enabled.
        pub fn new(t: I, le_mask: bool) -> Self {
            EventMask {
                mask: t,
                le_is_masked: le_mask,
            }
        }
    }

    impl EventMask<AllUnmasked> {
        /// Create a new `EventMask` with all events disabled
        ///
        /// This event mask will disable all events that are able to be enabled by the *Set Event
        /// Mask* command.
        pub fn disable_all() -> EventMask<AllUnmasked> {
            EventMask {
                mask: AllUnmasked,
                le_is_masked: false,
            }
        }
    }

    impl Default for EventMask<DefaultMask> {
        fn default() -> Self {
            EventMask {
                mask: DefaultMask,
                le_is_masked: false,
            }
        }
    }

    impl<I, T> From<I> for EventMask<I::IntoIter>
    where
        I: IntoIterator<Item = T>,
        T: Borrow<Events>,
    {
        fn from(t: I) -> Self {
            Self::new(t.into_iter(), false)
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
        const DEFAULT_MASK: u64 = 0x1FFF_FFFF_FFFFu64;

        const ENABLED_EVENTS: &'static [Events] = &[
            Events::InquiryComplete,
            Events::InquiryResult,
            Events::ConnectionComplete,
            Events::ConnectionRequest,
            Events::DisconnectionComplete,
            Events::AuthenticationComplete,
            Events::RemoteNameRequestComplete,
            Events::EncryptionChangeV1,
            Events::ChangeConnectionLinkKeyComplete,
            Events::LinkKeyTypeChanged,
            Events::ReadRemoteSupportedFeaturesComplete,
            Events::ReadRemoteVersionInformationComplete,
            Events::QosSetupComplete,
            Events::HardwareError,
            Events::FlushOccurred,
            Events::RoleChange,
            Events::ModeChange,
            Events::ReturnLinkKeys,
            Events::PinCodeRequest,
            Events::LinkKeyRequest,
            Events::LinkKeyNotification,
            Events::LoopbackCommand,
            Events::DataBufferOverflow,
            Events::MaxSlotsChange,
            Events::ReadClockOffsetComplete,
            Events::ConnectionPacketTypeChanged,
            Events::QosViolation,
            Events::PageScanRepetitionModeChange,
            Events::FlowSpecificationComplete,
            Events::InquiryResultWithRssi,
            Events::ReadRemoteExtendedFeaturesComplete,
            Events::SynchronousConnectionComplete,
            Events::SynchronousConnectionChanged,
        ];

        /// Iterate over the events that make up the default mask
        pub const fn iter() -> impl Iterator<Item = Events> {
            struct DefaultMaskIter(usize, u64);

            impl Iterator for DefaultMaskIter {
                type Item = Events;

                fn next(&mut self) -> Option<Self::Item> {
                    let bit = 1 << self.0;

                    if self.1 & bit != 0 {
                        self.0 += 1;

                        Some(Events::from_depth(self.0))
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

    #[derive(Copy, Clone)]
    pub struct Parameter {
        mask: [u8; 8],
    }

    impl<I, T> From<EventMask<I>> for Parameter
    where
        I: IntoIterator<Item = T>,
        T: Borrow<Events>,
    {
        fn from(em: EventMask<I>) -> Self {
            let mask = em
                .mask
                .into_iter()
                .filter_map(|item| {
                    let bit = event_to_mask_bit(item.borrow());

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
        I: IntoIterator<Item = T>,
        T: Borrow<Events>,
    {
        fn from((host, em): (&mut Host<H>, EventMask<I>)) -> Self {
            host.masked_events.clear_events(MASKED_EVENTS, true);

            let mask = em
                .mask
                .into_iter()
                .filter_map(|item| {
                    let event = item.borrow();

                    let bit = event_to_mask_bit(item.borrow());

                    if bit != 0 {
                        host.masked_events.set_event(*event);

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

            host.masked_events.set_le_mask(em.le_is_masked);

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
        fn from((host, _): (&mut Host<H>, EventMask<DefaultMask>)) -> Parameter {
            let mask = DefaultMask::DEFAULT_MASK.to_le_bytes();

            host.masked_events.clear_events(MASKED_EVENTS, true);

            host.masked_events.set_events(DefaultMask::ENABLED_EVENTS);

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

            host.masked_events.clear_events(MASKED_EVENTS, true);

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
    pub(crate) async fn send_command<H: HostChannelEnds, M, I, E>(
        host: &mut Host<H>,
        events: M,
    ) -> Result<(), CommandError<H>>
    where
        M: Into<EventMask<I>>,
        I: Iterator<Item = E>,
        E: Borrow<Events>,
    {
        host.send_command_expect_complete(Parameter::from(events.into())).await
    }

    /// Send the command
    ///
    /// This will send the *Set Event Mask* command to the controller and await for the command
    /// complete event from the controller. See the [module] level documentation for how events are
    /// masked.
    /// ```
    /// # use bo_tie_hci_util::events::Events;
    /// # let (_channel_ends, host_ends) = bo_tie_hci_util::channel::tokio_unbounded(0, 0);
    /// # async {
    /// # let mut host = bo_tie_hci_host::Host::init(host_ends).await?;
    /// # use bo_tie_hci_host::commands;
    /// use commands::cb::set_event_mask;
    ///
    /// set_event_mask::send(&mut host, [Events::ConnectionComplete, Events::DisconnectionComplete]).await
    /// # };
    /// ```
    ///
    /// # LE events
    /// In addition to their individual mask, all LE events must also be further unmasked by a mask
    /// bit within this page of event masks. This flag is set if there is a LE event output by the
    /// iteration of `I` or during the creating of an `EventMask` the boolean for the LE mask is
    /// set to true.
    ///
    /// ```
    /// # use bo_tie_hci_util::events::{Events, LeMeta};
    /// # let (_channel_ends, host_ends) = bo_tie_hci_util::channel::tokio_unbounded(0, 0);
    /// # async {
    /// # let mut host = bo_tie_hci_host::Host::init(host_ends).await?;
    /// # use bo_tie_hci_host::commands;
    /// use bo_tie_hci_host::commands::cb::set_event_mask::EventMask;
    /// use commands::cb::set_event_mask;
    ///
    /// // This will set the masks for the 'Encryption
    /// // Change (v1)' event and the global mask for LE
    /// // events. This will not set the individual mask
    /// // for the LE connection complete event, the field
    /// // for Events::LeMeta(_) is treated as arbitrary.
    /// set_event_mask::send(&mut host, [Events::EncryptionChangeV1, Events::LeMeta(LeMeta::ConnectionComplete)]).await?;
    ///
    /// // The second input of method `new` is for
    /// // setting/unsetting the global LE mask.
    /// let event_mask = EventMask::new([Events::ConnectionComplete, Events::DisconnectionComplete], true);
    ///
    /// set_event_mask::send(&mut host, event_mask).await?;
    /// # };
    /// ```
    ///
    /// [module]: self
    pub async fn send<H: HostChannelEnds, M, I, E>(host: &mut Host<H>, events: M) -> Result<(), CommandError<H>>
    where
        M: Into<EventMask<I>>,
        I: Iterator<Item = E>,
        E: Borrow<Events>,
    {
        let parameter = Parameter::from((&mut *host, events.into()));

        host.send_command_expect_complete(parameter).await
    }
}

/// Reset the controller
///
/// This will reset the Controller and the appropriate link Layer. For BR/EDR the Link
/// Manager is reset, for LE the Link Layer is reset, and for AMP the PAL is reset.
pub mod reset {

    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::Reset);

    #[derive(Clone, Copy)]
    struct Parameter;

    impl CommandParameter<0> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 0] {
            []
        }
    }

    /// Send the reset command to the controller
    pub async fn send<H: HostChannelEnds>(host: &mut Host<H>) -> Result<(), CommandError<H>> {
        host.send_command_expect_complete(Parameter).await
    }
}

/// Read the transmit power level
///
/// This reads the transmit power level for a connection specified by its
/// [`ConnectionHandle`](bo_tie_hci_util::ConnectionHandle).
pub mod read_transmit_power_level {
    use crate::events::parameters::CommandCompleteData;
    use crate::{
        opcodes, CCParameterError, CommandError, CommandParameter, Host, HostChannelEnds, TryFromCommandComplete,
    };
    use bo_tie_hci_util::ConnectionHandle;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::ReadTransmitPowerLevel);

    /// Transmit power range (from minimum to maximum levels)
    pub struct TransmitPowerLevel {
        pub connection_handle: ConnectionHandle,
        pub power_level: i8,
    }

    impl TryFromCommandComplete for TransmitPowerLevel {
        fn try_from(cc: &CommandCompleteData) -> Result<Self, CCParameterError> {
            check_status!(cc.return_parameter);

            let raw_connection_handle = <u16>::from_le_bytes([
                *cc.return_parameter
                    .get(1)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
                *cc.return_parameter
                    .get(2)
                    .ok_or(CCParameterError::InvalidEventParameter)?,
            ]);

            let connection_handle =
                ConnectionHandle::try_from(raw_connection_handle).or(Err(CCParameterError::InvalidEventParameter))?;

            let power_level = *cc
                .return_parameter
                .get(3)
                .ok_or(CCParameterError::InvalidEventParameter)? as i8;

            Ok(Self {
                connection_handle,
                power_level,
            })
        }
    }

    pub enum TransmitPowerLevelType {
        CurrentPowerLevel,
        MaximumPowerLevel,
    }

    pub struct Parameter {
        pub connection_handle: ConnectionHandle,
        pub level_type: TransmitPowerLevelType,
    }

    impl CommandParameter<3> for Parameter {
        const COMMAND: opcodes::HciCommand = COMMAND;
        fn get_parameter(&self) -> [u8; 3] {
            let [b0, b1] = self.connection_handle.get_raw_handle().to_le_bytes();

            let b2 = match self.level_type {
                TransmitPowerLevelType::CurrentPowerLevel => 0,
                TransmitPowerLevelType::MaximumPowerLevel => 1,
            };

            [b0, b1, b2]
        }
    }

    /// Send a read transmit power level command to the controller
    ///
    /// This will send the command to the controller and wait for the transmit power level to be returned by it.
    pub async fn send<H: HostChannelEnds>(
        host: &mut Host<H>,
        parameter: Parameter,
    ) -> Result<TransmitPowerLevel, CommandError<H>> {
        host.send_command_expect_complete(parameter).await
    }
}

/// Set event mask page 2
///
/// This is the command for sending page two of the event mask. Most of the explanation on how to
/// use this command is the same as [`set_event_mask`].
///
/// # Encryption Change
/// When used with this command, this [`Events`] will enable the second version of the event.
///
/// [`Events`]: bo_tie_hci_util::events::Events
pub mod set_event_mask_page_2 {
    use crate::{opcodes, CommandError, CommandParameter, Host, HostChannelEnds};
    use bo_tie_hci_util::events::Events;
    use core::borrow::Borrow;

    const COMMAND: opcodes::HciCommand =
        opcodes::HciCommand::ControllerAndBaseband(opcodes::ControllerAndBaseband::SetEventMask);

    /// Get the mask bit for an event
    ///
    /// # Note
    /// Zero is returned if an event is not maskable is returned or it is on page 2.
    pub(crate) fn event_to_mask_bit(event: &Events) -> u64 {
        match *event {
            // Page 1 maskable
            Events::InquiryComplete
            | Events::InquiryResult
            | Events::ConnectionComplete
            | Events::ConnectionRequest
            | Events::DisconnectionComplete
            | Events::AuthenticationComplete
            | Events::RemoteNameRequestComplete
            | Events::EncryptionChangeV1
            | Events::ChangeConnectionLinkKeyComplete
            | Events::LinkKeyTypeChanged
            | Events::ReadRemoteSupportedFeaturesComplete
            | Events::ReadRemoteVersionInformationComplete
            | Events::QosSetupComplete
            | Events::HardwareError
            | Events::FlushOccurred
            | Events::RoleChange
            | Events::ModeChange
            | Events::ReturnLinkKeys
            | Events::PinCodeRequest
            | Events::LinkKeyRequest
            | Events::LinkKeyNotification
            | Events::LoopbackCommand
            | Events::DataBufferOverflow
            | Events::MaxSlotsChange
            | Events::ReadClockOffsetComplete
            | Events::ConnectionPacketTypeChanged
            | Events::QosViolation
            | Events::PageScanRepetitionModeChange
            | Events::FlowSpecificationComplete
            | Events::InquiryResultWithRssi
            | Events::ReadRemoteExtendedFeaturesComplete
            | Events::SynchronousConnectionComplete
            | Events::SynchronousConnectionChanged
            | Events::SniffSubrating
            | Events::ExtendedInquiryResult
            | Events::EncryptionKeyRefreshComplete
            | Events::IoCapabilityRequest
            | Events::IoCapabilityResponse
            | Events::UserConfirmationRequest
            | Events::UserPasskeyRequest
            | Events::RemoteOobDataRequest
            | Events::SimplePairingComplete
            | Events::LinkSupervisionTimeoutChanged
            | Events::EnhancedFlushComplete
            | Events::UserPasskeyNotification
            | Events::KeypressNotification
            | Events::RemoteHostSupportedFeaturesNotification
            | Events::LeMeta(_) => 0,
            // Not maskable
            Events::CommandComplete
            | Events::CommandStatus
            | Events::NumberOfCompletedPackets
            | Events::NumberOfCompletedDataBlocks => 0,
            // maskable events on page 2
            Events::TriggeredClockCapture => 1 << 8,
            Events::SynchronizationTrainComplete => 1 << 14,
            Events::SynchronizationTrainReceived => 1 << 15,
            Events::ConnectionlessPeripheralBroadcastReceive => 1 << 17,
            Events::ConnectionlessPeripheralBroadcastTimeout => 1 << 18,
            Events::TruncatedPageComplete => 1 << 19,
            Events::PeripheralPageResponseTimeout => 1 << 20,
            Events::ConnectionlessSlaveBroadcastChannelMapChange => 1 << 21,
            Events::InquiryResponseNotification => 1 << 22,
            Events::AuthenticatedPayloadTimeoutExpired => 1 << 23,
            Events::SamStatusChange => 1 << 24,
            Events::EncryptionChangeV2 => 1 << 25,
        }
    }

    const MASKED_EVENTS: &'static [Events] = &[
        Events::TriggeredClockCapture,
        Events::SynchronizationTrainComplete,
        Events::SynchronizationTrainReceived,
        Events::ConnectionlessPeripheralBroadcastReceive,
        Events::ConnectionlessPeripheralBroadcastTimeout,
        Events::TruncatedPageComplete,
        Events::PeripheralPageResponseTimeout,
        Events::ConnectionlessSlaveBroadcastChannelMapChange,
        Events::InquiryResponseNotification,
        Events::AuthenticatedPayloadTimeoutExpired,
        Events::SamStatusChange,
        Events::EncryptionChangeV2,
    ];

    /// The event mask
    ///
    /// This is the type used for creating an event mask to send to the Controller. Anything that
    /// implements [`IntoIterator`] where the `Item` type can be '[borrowed]' as an [`Events`] is
    /// able to be converted into an `EventMask`.
    ///
    /// ```
    /// # use bo_tie_hci_host::commands::cb::set_event_mask_page_2::EventMask;
    /// # use bo_tie_hci_util::events::Events;
    ///
    /// let e_mask: EventMask<_> = [Events::TriggeredClockCapture, Events::EncryptionChangeV2].into();
    /// # let _ignored = e_mask;
    /// ```
    ///
    /// # Default mask
    /// The default mask for the page 2 is equivalent to disabling all events for page 2, but it can
    /// still be creating by using a default `EventMask` (`EventMask::default()`).
    ///
    /// [`Event`]:bo_tie_hci_util::events::Events
    /// [borrowed]: core::borrow::Borrow
    pub struct EventMask<T> {
        mask: T,
    }

    impl<I, T> EventMask<I>
    where
        I: Iterator<Item = T>,
        T: Borrow<Events>,
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
        T: Borrow<Events>,
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
        const DEFAULT_MASK: u64 = 0;

        /// Iterate over the events that make up the default mask
        pub const fn iter() -> impl Iterator<Item = Events> {
            struct DefaultMaskIter(usize, u64);

            impl Iterator for DefaultMaskIter {
                type Item = Events;

                fn next(&mut self) -> Option<Self::Item> {
                    None
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

    pub struct Parameter {
        mask: [u8; 8],
    }

    impl<I, T> From<EventMask<I>> for Parameter
    where
        I: IntoIterator<Item = T>,
        T: Borrow<Events>,
    {
        fn from(em: EventMask<I>) -> Self {
            let mask = em
                .mask
                .into_iter()
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
        I: IntoIterator<Item = T>,
        T: Borrow<Events>,
    {
        fn from((host, em): (&mut Host<H>, EventMask<I>)) -> Self {
            host.masked_events.clear_events(MASKED_EVENTS, false);

            let mask = em
                .mask
                .into_iter()
                .filter_map(|event| {
                    let bit = event_to_mask_bit(event.borrow());

                    if bit != 0 {
                        host.masked_events.set_event(*event.borrow());

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
            let mask = [0; 8];

            Parameter { mask }
        }
    }

    impl<H: HostChannelEnds> From<(&mut Host<H>, EventMask<DefaultMask>)> for Parameter {
        fn from((host, _): (&mut Host<H>, EventMask<DefaultMask>)) -> Self {
            let mask = [0; 8];

            host.masked_events.clear_events(MASKED_EVENTS, false);

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
    pub(crate) async fn send_command<H: HostChannelEnds, M, I, E>(
        host: &mut Host<H>,
        events: M,
    ) -> Result<(), CommandError<H>>
    where
        M: Into<EventMask<I>>,
        I: Iterator<Item = E>,
        E: Borrow<Events>,
    {
        host.send_command_expect_complete(Parameter::from(events.into())).await
    }

    /// Send the command
    ///
    /// This will send the *Set Event Mask* command to the controller and await for the command
    /// complete event from the controller. See the [module] level documentation for how events are
    /// masked.
    /// ```
    /// # use bo_tie_hci_util::events::Events;
    /// # let (_channel_ends, host_ends) = bo_tie_hci_util::channel::tokio_unbounded();
    /// # async {
    /// # let mut host = bo_tie_hci_host::Host::init(host_ends).await?;
    /// # use bo_tie_hci_host::commands;
    /// use commands::cb::set_event_mask_page_2;
    ///
    /// set_event_mask_page_2::send(&mut host, [Events::EncryptionChangeV2]).await
    /// # };
    /// ```
    ///
    /// [module]: self
    pub async fn send<H: HostChannelEnds, M, I, E>(host: &mut Host<H>, events: M) -> Result<(), CommandError<H>>
    where
        M: Into<EventMask<I>>,
        I: Iterator<Item = E>,
        E: Borrow<Events>,
    {
        let parameter = Parameter::from((&mut *host, events.into()));

        host.send_command_expect_complete(parameter).await
    }
}
