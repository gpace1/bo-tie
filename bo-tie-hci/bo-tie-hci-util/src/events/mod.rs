//! Host Controller Interface Events
//!
//! This is the implementations of the events within the Host Controller Interface Specification.
//!

macro_rules! make_u16 {
    ( $packet:ident, $start:expr ) => {
        u16::from_le($packet[$start] as u16 | ($packet[$start + 1] as u16) << 8)
    };
}

macro_rules! make_u32 {
    ( $packet:ident, $start:expr) => {
        u32::from_le(
            ($packet[$start] as u32)
                | ($packet[$start + 1] as u32) << 8
                | ($packet[$start + 2] as u32) << 16
                | ($packet[$start + 3] as u32) << 24,
        )
    };
}

macro_rules! make_u64 {
    ( $packet:ident, $start:expr) => {
        u64::from_le(
            ($packet[$start] as u64)
                | ($packet[$start + 1] as u64) << 8
                | ($packet[$start + 2] as u64) << 16
                | ($packet[$start + 3] as u64) << 24
                | ($packet[$start + 4] as u64) << 32
                | ($packet[$start + 5] as u64) << 40
                | ($packet[$start + 6] as u64) << 48
                | ($packet[$start + 7] as u64) << 56,
        )
    };
}

macro_rules! make_baddr {
    ( $packet:ident, $start:expr ) => {{
        let mut address = [0u8; 6];
        address.copy_from_slice(&$packet[$start..($start + 6)]);
        BluetoothDeviceAddress::from(address)
    }};
}

macro_rules! make_handle {
    ( $packet:ident, $start:expr ) => {
        ConnectionHandle::try_from(make_u16!($packet, $start)).unwrap()
    };
}

/// Create from implementation for $name
///
/// The parameter name for the from method is "raw" and its type is &[u8].
/// $inner is the contents of the from method.
macro_rules! impl_try_from_for_raw_packet {
    ( $name:ty, $param:tt, $inner:block ) => {
        #[allow(unused_assignments)]
        #[allow(unused_mut)]
        impl core::convert::TryFrom<&[u8]> for $name {
            type Error = alloc::string::String;
            fn try_from(mut $param: &[u8]) -> Result<Self, Self::Error> {
                $inner
            }
        }
    };
}

/// "chews-off" and returns a slice of size $size from the beginning of $packet.
///
/// Invoking this with only one parameter returns an u8, otherwise a reference to a slice is
/// returned.
macro_rules! chew {
    ( $packet:ident, $start:expr, $size:expr) => {{
        let chewed = &$packet[$start..($size as usize)];
        $packet = &$packet[($start as usize) + ($size as usize)..];
        chewed
    }};
    ( $packet:ident, $size:expr ) => {
        chew!($packet, 0, $size)
    };
    ( $packet:ident ) => {{
        let chewed_byte = $packet[0];
        $packet = &$packet[1..];
        chewed_byte
    }};
}

macro_rules! chew_u16 {
    ($packet:ident, $start:expr) => {{
        let chewed = make_u16!($packet, $start as usize);
        $packet = &$packet[$start as usize + 2..];
        chewed
    }};
    ($packet:ident) => {
        chew_u16!($packet, 0)
    };
}

macro_rules! chew_u32 {
    ($packet:ident, $start:expr) => {{
        let chewed = make_u32!($packet, $start as usize);
        $packet = &$packet[$start as usize + 4..];
        chewed
    }};
    ($packet:ident) => {
        chew_u32!($packet, 0)
    };
}

macro_rules! chew_u64 {
    ($packet:ident, $start:expr) => {{
        let chewed = make_u64!($packet, $start as usize);
        $packet = &$packet[$start as usize + 8..];
        chewed
    }};
    ($packet:ident) => {
        chew_u64!($packet, 0)
    };
}

macro_rules! chew_baddr {
    ($packet:ident, $start:expr ) => {{
        let chewed = make_baddr!($packet, $start as usize);
        $packet = &$packet[$start as usize + 6..];
        chewed
    }};
    ($packet:ident) => {
        chew_baddr!($packet, 0)
    };
}

macro_rules! chew_handle {
    ($packet:ident, $start:expr) => {{
        let chewed = make_handle!($packet, $start as usize);
        $packet = &$packet[$start as usize + 2..];
        chewed
    }};
    ($packet:ident) => {
        chew_handle!($packet, 0)
    };
}

pub mod parameters;

use parameters::{
    AuthenticatedPayloadTimeoutExpiredData, AuthenticationCompleteData, ChangeConnectionLinkKeyCompleteData,
    CommandCompleteData, CommandStatusData, ConnectionCompleteData, ConnectionPacketTypeChangedData,
    ConnectionRequestData, ConnectionlessSlaveBroadcastChannelMapChangeData, ConnectionlessSlaveBroadcastReceiveData,
    ConnectionlessSlaveBroadcastTimeoutData, DataBufferOverflowData, DisconnectionCompleteData, EncryptionChangeData,
    EncryptionKeyRefreshCompleteData, EnhancedFlushCompleteData, ExtendedInquiryResultData,
    FlowSpecificationCompleteData, FlushOccuredData, HardwareErrorData, IOCapabilityRequestData,
    IOCapabilityResponseData, InquiryCompleteData, InquiryResponseNotificationData, InquiryResultData,
    InquiryResultWithRSSIData, KeypressNotificationData, LEAdvertisingReportData, LEAdvertisingSetTerminatedData,
    LEChannelSelectionAlgorithmData, LEConnectionCompleteData, LEConnectionUpdateCompleteData, LEDataLengthChangeData,
    LEDirectedAdvertisingReportData, LEEnhancedConnectionCompleteData, LEExtendedAdvertisingReportData,
    LEGenerateDHKeyCompleteData, LELongTermKeyRequestData, LEPHYUpdateCompleteData, LEPeriodicAdvertisingReportData,
    LEPeriodicAdvertisingSyncEstablishedData, LEPeriodicAdvertisingSyncLostData, LEReadLocalP256PublicKeyCompleteData,
    LEReadRemoteFeaturesCompleteData, LERemoteConnectionParameterRequestData, LEScanRequestReceivedData,
    LinkKeyNotificationData, LinkKeyRequestData, LinkSupervisionTimeoutChangedData, LoopbackCommandData,
    MasterLinkKeyCompleteData, MaxSlotsChangeData, ModeChangeData, Multiple, NumberOfCompletedDataBlocksData,
    NumberOfCompletedPacketsData, PINCodeRequestData, PageScanRepetitionModeChangeData, QoSViolationData,
    QosSetupCompleteData, ReadClockOffsetCompleteData, ReadRemoteExtendedFeaturesCompleteData,
    ReadRemoteSupportedFeaturesCompleteData, ReadRemoteVersionInformationCompleteData,
    RemoteHostSupportedFeaturesNotificationData, RemoteNameRequestCompleteData, RemoteOOBDataRequestData,
    ReturnLinkKeysData, RoleChangeData, SAMStatusChangeData, SimplePairingCompleteData, SlavePageResponseTimeoutData,
    SniffSubratingData, SynchronizationTrainCompleteData, SynchronizationTrainReceivedData,
    SynchronousConnectionChangedData, SynchronousConnectionCompleteData, TriggeredClockCaptureData,
    TruncatedPageCompleteData, UserConfirmationRequestData, UserPasskeyNotificationData, UserPasskeyRequestData,
};

/// Used for splitting up the enumeration - one for without data and one with the data
macro_rules! enumerate_split {
    ( $( #[ $attrs_1:meta ] )* pub enum $EnumName:tt ( $( #[ $attrs_2:meta ] )* enum $EnumDataName:tt ) {
        $( $name:tt $(( $($val:tt),* ))* $({ $( $data:ident $(< $($type:ty),* >)* ),* })*, )*
    } ) => {

        $( #[$attrs_1] )*
        pub enum $EnumName {
            $( $name $(( $($val),* ))* ),*
        }

        $( #[$attrs_2] )*
        pub enum $EnumDataName {
            $( $name $(( $( $data $(< $($type),* >)* ),* )),*),*
        }
    }
}

enumerate_split! {
    #[derive(Debug,Hash,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
    pub enum LeMeta ( #[derive(Debug,Clone)] enum LeMetaData ) {
        ConnectionComplete{LEConnectionCompleteData},
        AdvertisingReport{Multiple<Result<LEAdvertisingReportData, alloc::string::String>>},
        ConnectionUpdateComplete{LEConnectionUpdateCompleteData},
        ReadRemoteFeaturesComplete{LEReadRemoteFeaturesCompleteData},
        LongTermKeyRequest{LELongTermKeyRequestData},
        RemoteConnectionParameterRequest{LERemoteConnectionParameterRequestData},
        DataLengthChange{LEDataLengthChangeData},
        ReadLocalP256PublicKeyComplete{LEReadLocalP256PublicKeyCompleteData},
        GenerateDHKeyComplete{LEGenerateDHKeyCompleteData},
        EnhancedConnectionComplete{LEEnhancedConnectionCompleteData},
        DirectedAdvertisingReport{Multiple<Result<LEDirectedAdvertisingReportData, alloc::string::String>>},
        PHYUpdateComplete{LEPHYUpdateCompleteData},
        ExtendedAdvertisingReport{Multiple<Result<LEExtendedAdvertisingReportData, alloc::string::String>>},
        PeriodicAdvertisingSyncEstablished{LEPeriodicAdvertisingSyncEstablishedData},
        PeriodicAdvertisingReport{LEPeriodicAdvertisingReportData},
        PeriodicAdvertisingSyncLost{LEPeriodicAdvertisingSyncLostData},
        ScanTimeout,
        AdvertisingSetTerminated{LEAdvertisingSetTerminatedData},
        ScanRequestReceived{LEScanRequestReceivedData},
        ChannelSelectionAlgorithm{LEChannelSelectionAlgorithmData},
    }
}

impl LeMeta {
    pub fn try_from(raw: u8) -> Result<LeMeta, alloc::string::String> {
        match raw {
            0x01 => Ok(LeMeta::ConnectionComplete),
            0x02 => Ok(LeMeta::AdvertisingReport),
            0x03 => Ok(LeMeta::ConnectionUpdateComplete),
            0x04 => Ok(LeMeta::ReadRemoteFeaturesComplete),
            0x05 => Ok(LeMeta::LongTermKeyRequest),
            0x06 => Ok(LeMeta::RemoteConnectionParameterRequest),
            0x07 => Ok(LeMeta::DataLengthChange),
            0x08 => Ok(LeMeta::ReadLocalP256PublicKeyComplete),
            0x09 => Ok(LeMeta::GenerateDHKeyComplete),
            0x0A => Ok(LeMeta::EnhancedConnectionComplete),
            0x0B => Ok(LeMeta::DirectedAdvertisingReport),
            0x0C => Ok(LeMeta::PHYUpdateComplete),
            0x0D => Ok(LeMeta::ExtendedAdvertisingReport),
            0x0E => Ok(LeMeta::PeriodicAdvertisingSyncEstablished),
            0x0F => Ok(LeMeta::PeriodicAdvertisingReport),
            0x10 => Ok(LeMeta::PeriodicAdvertisingSyncLost),
            0x11 => Ok(LeMeta::ScanTimeout),
            0x12 => Ok(LeMeta::AdvertisingSetTerminated),
            0x13 => Ok(LeMeta::ScanRequestReceived),
            0x14 => Ok(LeMeta::ChannelSelectionAlgorithm),
            _ => Err(alloc::format!("Unknown LE Meta: {}", raw)),
        }
    }
}

impl core::fmt::Display for LeMeta {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            LeMeta::ConnectionComplete => f.write_str(bo_tie_macros::display_hci_event!(ConnectionComplete)),
            LeMeta::AdvertisingReport => f.write_str(bo_tie_macros::display_hci_event!(AdvertisingReport)),
            LeMeta::ConnectionUpdateComplete => {
                f.write_str(bo_tie_macros::display_hci_event!(ConnectionUpdateComplete))
            }
            LeMeta::ReadRemoteFeaturesComplete => {
                f.write_str(bo_tie_macros::display_hci_event!(ReadRemoteFeaturesComplete))
            }
            LeMeta::LongTermKeyRequest => f.write_str(bo_tie_macros::display_hci_event!(LongTermKeyRequest)),
            LeMeta::RemoteConnectionParameterRequest => {
                f.write_str(bo_tie_macros::display_hci_event!(RemoteConnectionParameterRequest))
            }
            LeMeta::DataLengthChange => f.write_str(bo_tie_macros::display_hci_event!(DataLengthChange)),
            LeMeta::ReadLocalP256PublicKeyComplete => {
                f.write_str(bo_tie_macros::display_hci_event!(ReadLocalP256PublicKeyComplete))
            }
            LeMeta::GenerateDHKeyComplete => f.write_str(bo_tie_macros::display_hci_event!(GenerateDHKeyComplete)),
            LeMeta::EnhancedConnectionComplete => {
                f.write_str(bo_tie_macros::display_hci_event!(EnhancedConnectionComplete))
            }
            LeMeta::DirectedAdvertisingReport => {
                f.write_str(bo_tie_macros::display_hci_event!(DirectedAdvertisingReport))
            }
            LeMeta::PHYUpdateComplete => f.write_str(bo_tie_macros::display_hci_event!(PHYUpdateComplete)),
            LeMeta::ExtendedAdvertisingReport => {
                f.write_str(bo_tie_macros::display_hci_event!(ExtendedAdvertisingReport))
            }
            LeMeta::PeriodicAdvertisingSyncEstablished => {
                f.write_str(bo_tie_macros::display_hci_event!(PeriodicAdvertisingSyncEstablished))
            }
            LeMeta::PeriodicAdvertisingReport => {
                f.write_str(bo_tie_macros::display_hci_event!(PeriodicAdvertisingReport))
            }
            LeMeta::PeriodicAdvertisingSyncLost => {
                f.write_str(bo_tie_macros::display_hci_event!(PeriodicAdvertisingSyncLost))
            }
            LeMeta::ScanTimeout => f.write_str(bo_tie_macros::display_hci_event!(ScanTimeout)),
            LeMeta::AdvertisingSetTerminated => {
                f.write_str(bo_tie_macros::display_hci_event!(AdvertisingSetTerminated))
            }
            LeMeta::ScanRequestReceived => f.write_str(bo_tie_macros::display_hci_event!(ScanRequestReceived)),
            LeMeta::ChannelSelectionAlgorithm => {
                f.write_str(bo_tie_macros::display_hci_event!(ChannelSelectionAlgorithm))
            }
        }
    }
}

impl LeMetaData {
    fn into_simple(&self) -> LeMeta {
        match *self {
            LeMetaData::ConnectionComplete(_) => LeMeta::ConnectionComplete,
            LeMetaData::AdvertisingReport(_) => LeMeta::AdvertisingReport,
            LeMetaData::ConnectionUpdateComplete(_) => LeMeta::ConnectionUpdateComplete,
            LeMetaData::ReadRemoteFeaturesComplete(_) => LeMeta::ReadRemoteFeaturesComplete,
            LeMetaData::LongTermKeyRequest(_) => LeMeta::LongTermKeyRequest,
            LeMetaData::RemoteConnectionParameterRequest(_) => LeMeta::RemoteConnectionParameterRequest,
            LeMetaData::DataLengthChange(_) => LeMeta::DataLengthChange,
            LeMetaData::ReadLocalP256PublicKeyComplete(_) => LeMeta::ReadLocalP256PublicKeyComplete,
            LeMetaData::GenerateDHKeyComplete(_) => LeMeta::GenerateDHKeyComplete,
            LeMetaData::EnhancedConnectionComplete(_) => LeMeta::EnhancedConnectionComplete,
            LeMetaData::DirectedAdvertisingReport(_) => LeMeta::DirectedAdvertisingReport,
            LeMetaData::PHYUpdateComplete(_) => LeMeta::PHYUpdateComplete,
            LeMetaData::ExtendedAdvertisingReport(_) => LeMeta::ExtendedAdvertisingReport,
            LeMetaData::PeriodicAdvertisingSyncEstablished(_) => LeMeta::PeriodicAdvertisingSyncEstablished,
            LeMetaData::PeriodicAdvertisingReport(_) => LeMeta::PeriodicAdvertisingReport,
            LeMetaData::PeriodicAdvertisingSyncLost(_) => LeMeta::PeriodicAdvertisingSyncLost,
            LeMetaData::ScanTimeout => LeMeta::ScanTimeout,
            LeMetaData::AdvertisingSetTerminated(_) => LeMeta::AdvertisingSetTerminated,
            LeMetaData::ScanRequestReceived(_) => LeMeta::ScanRequestReceived,
            LeMetaData::ChannelSelectionAlgorithm(_) => LeMeta::ChannelSelectionAlgorithm,
        }
    }
}

impl_try_from_for_raw_packet! {
    LeMetaData,
    packet,
    {
        match chew!(packet) {
            0x01 => Ok(LeMetaData::ConnectionComplete(LEConnectionCompleteData::try_from(packet)?)),
            0x02 => Ok(LeMetaData::AdvertisingReport(LEAdvertisingReportData::buf_from(packet))),
            0x03 => Ok(LeMetaData::ConnectionUpdateComplete(LEConnectionUpdateCompleteData::try_from(packet)?)),
            0x04 => Ok(LeMetaData::ReadRemoteFeaturesComplete(LEReadRemoteFeaturesCompleteData::try_from(packet)?)),
            0x05 => Ok(LeMetaData::LongTermKeyRequest(LELongTermKeyRequestData::from(packet))),
            0x06 => Ok(LeMetaData::RemoteConnectionParameterRequest(LERemoteConnectionParameterRequestData::try_from(packet)?)),
            0x07 => Ok(LeMetaData::DataLengthChange(LEDataLengthChangeData::try_from(packet)?)),
            0x08 => Ok(LeMetaData::ReadLocalP256PublicKeyComplete(LEReadLocalP256PublicKeyCompleteData::from(packet))),
            0x09 => Ok(LeMetaData::GenerateDHKeyComplete(LEGenerateDHKeyCompleteData::from(packet))),
            0x0A => Ok(LeMetaData::EnhancedConnectionComplete(LEEnhancedConnectionCompleteData::try_from(packet)?)),
            0x0B => Ok(LeMetaData::DirectedAdvertisingReport(LEDirectedAdvertisingReportData::buf_from(packet))),
            0x0C => Ok(LeMetaData::PHYUpdateComplete(LEPHYUpdateCompleteData::try_from(packet)?)),
            0x0D => Ok(LeMetaData::ExtendedAdvertisingReport(LEExtendedAdvertisingReportData::buf_from(packet))),
            0x0E => Ok(LeMetaData::PeriodicAdvertisingSyncEstablished(LEPeriodicAdvertisingSyncEstablishedData::try_from(packet)?)),
            0x0F => Ok(LeMetaData::PeriodicAdvertisingReport(LEPeriodicAdvertisingReportData::try_from(packet)?)),
            0x10 => Ok(LeMetaData::PeriodicAdvertisingSyncLost(LEPeriodicAdvertisingSyncLostData::from(packet))),
            0x11 => Ok(LeMetaData::ScanTimeout),
            0x12 => Ok(LeMetaData::AdvertisingSetTerminated(LEAdvertisingSetTerminatedData::from(packet))),
            0x13 => Ok(LeMetaData::ScanRequestReceived(LEScanRequestReceivedData::try_from(packet)?)),
            0x14 => Ok(LeMetaData::ChannelSelectionAlgorithm(LEChannelSelectionAlgorithmData::try_from(packet)?)),
            _    => Err(alloc::format!("Unknown LE meta event ID: {}", packet[0])),
        }
    }
}

impl From<LeMeta> for Events {
    fn from(meta: LeMeta) -> Events {
        Events::LeMeta(meta)
    }
}

macro_rules! put_ {
    ( $t:tt ) => {
        _
    };
}

macro_rules! data_into_simple {
    ($unused_rpt:tt, $data_var:expr) => {
        $data_var.into_simple()
    };
}

macro_rules! events_markup {
    ( pub enum $EnumName:tt ( $EnumDataName:tt ) {
        $( $name:tt $(( $($enum_val:tt),* ))* {$data:ident $(< $type:ty >)*} -> $val:expr, )*
    } ) => (

        enumerate_split! {
            #[derive(Debug,Hash,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
            pub enum $EnumName ( #[derive(Debug,Clone)] enum $EnumDataName ){
                $( $name $(( $($enum_val),* ))* {$data $(< $type >)*}, )*
            }
        }

        impl $EnumName {
            /// Return the event code
            ///
            /// # Note
            /// This does not return the sub event code for a [`LeMeta`](Events::LeMeta) event
            pub fn get_event_code( &self ) -> u8 {
                match *self {
                    $($EnumName::$name $(( $(put_!($enum_val))* ))* => $val,)*
                }
            }

            /// Try to create an event from an event code.
            ///
            /// The first input of this method is for the event code and the second is the LE Meta
            /// sub event code. When the first input matches [`LeMeta`](Events::LeMeta) the second
            /// input is used to determine the LeMeta sub event otherwise input `sub_event` is
            /// ignored.
            pub fn try_from_event_codes<S>(event: u8, sub_event: S)
            -> core::result::Result<crate::events::$EnumName, EventError>
            where
                S: Into<Option<u8>>
            {
                match event {
                    $( $val => Ok( $EnumName::$name $(( $($enum_val::try_from(sub_event.into().unwrap())?)* ))* ), )*
                    _ => Err(EventCodeError::new(event, sub_event.into().unwrap_or_default()).into()),
                }
            }
        }

        impl core::fmt::Display for $EnumName {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                #![allow(non_snake_case)]

                match self {
                    $( $EnumName::$name $(($( $enum_val )*))* => {
                        f.write_str(bo_tie_macros::display_hci_event!($name))?;

                        $($(
                            f.write_str(" with sub event ")?;
                            core::fmt::Display::fmt($enum_val, f)?;
                        )*)*

                        Ok(())
                    } ),*
                }
            }
        }

        impl crate::events::$EnumDataName {

            pub fn get_event_name(&self) -> $EnumName {
                #[cfg(not(test))]
                match *self {
                    $( $EnumDataName::$name(ref _data) =>
                        $EnumName::$name $(( $(data_into_simple!($enum_val, _data)),* ))*, )*
                }

                #[cfg(test)]
                match *self {
                    $( $EnumDataName::$name(ref _data) =>
                        $EnumName::$name $(( $(data_into_simple!($enum_val, _data)),* ))*, )*
                }
            }

            /// Make an event from a raw HCI event packet
            ///
            /// The input `data` should contain *only* the data that is part of the HCI Event
            /// Packet as specified in the Bluetooth core specification (vol 4, Part E).
            /// Do not include the *HCI packet indicator* as that will (most likely) cause this
            /// method to panic.
            pub fn try_from_packet( data: &[u8] ) -> Result<Self, EventError> {

                use core::convert::TryFrom;

                debug_assert!( data.len() > 1 ,
                    "Error occurred in macro invocation of hci::events::events_markup");

                let mut packet = data;

                // packet[2] is the LeMeta specific sub event code if the event is LeMeta
                let event_code = crate::hci::events::$EnumName::try_from_event_codes(chew!(packet), packet[2])?;

                // Get the length of the packet and convert it into a usize
                let event_len = chew!(packet).into();

                match event_code {
                    $( crate::events::$EnumName::$name $( ( $(put_!($enum_val)),* ) )* =>
                        Ok(crate::hci::events::$EnumDataName::$name(
                            crate::hci::events::$data::<$( $type ),*>::try_from( &packet[..event_len] )?)),
                    )*
                }
            }
        }
    )
}

events_markup! {
    pub enum Events(EventsData) {
        InquiryComplete{InquiryCompleteData} -> 0x01,
        InquiryResult{Multiple<Result<InquiryResultData,alloc::string::String>>} -> 0x02,
        ConnectionComplete{ConnectionCompleteData} -> 0x03,
        ConnectionRequest{ConnectionRequestData} -> 0x04,
        DisconnectionComplete{DisconnectionCompleteData} -> 0x05,
        AuthenticationComplete{AuthenticationCompleteData} -> 0x06,
        RemoteNameRequestComplete{RemoteNameRequestCompleteData} -> 0x07,
        EncryptionChange{EncryptionChangeData} -> 0x08,
        ChangeConnectionLinkKeyComplete{ChangeConnectionLinkKeyCompleteData} -> 0x09,
        MasterLinkKeyComplete{MasterLinkKeyCompleteData} -> 0x0A,
        ReadRemoteSupportedFeaturesComplete{ReadRemoteSupportedFeaturesCompleteData} -> 0x0B,
        ReadRemoteVersionInformationComplete{ReadRemoteVersionInformationCompleteData} -> 0x0C,
        QosSetupComplete{QosSetupCompleteData} -> 0x0D,
        CommandComplete{CommandCompleteData} -> 0x0E,
        CommandStatus{CommandStatusData} -> 0x0F,
        HardwareError{HardwareErrorData} -> 0x10,
        FlushOccured{FlushOccuredData} -> 0x11,
        RoleChange{RoleChangeData} -> 0x12,
        NumberOfCompletedPackets{Multiple<NumberOfCompletedPacketsData>} -> 0x13,
        ModeChange{ModeChangeData} -> 0x14,
        ReturnLinkKeys{Multiple<ReturnLinkKeysData>} -> 0x15,
        PINCodeRequest{PINCodeRequestData} -> 0x16,
        LinkKeyRequest{LinkKeyRequestData} -> 0x17,
        LinkKeyNotification{LinkKeyNotificationData} -> 0x18,
        LoopbackCommand{LoopbackCommandData} -> 0x19,
        DataBufferOverflow{DataBufferOverflowData} -> 0x1A,
        MaxSlotsChange{MaxSlotsChangeData} -> 0x1B,
        ReadClockOffsetComplete{ReadClockOffsetCompleteData} -> 0x1C,
        ConnectionPacketTypeChanged{ConnectionPacketTypeChangedData} -> 0x1D,
        QoSViolation{QoSViolationData} -> 0x1E,
        PageScanRepetitionModeChange{PageScanRepetitionModeChangeData} -> 0x20,
        FlowSpecificationComplete{FlowSpecificationCompleteData} -> 0x21,
        InquiryResultWithRSSI{Multiple<Result<InquiryResultWithRSSIData,alloc::string::String>>} -> 0x22,
        ReadRemoteExtendedFeaturesComplete{ReadRemoteExtendedFeaturesCompleteData} -> 0x23,
        SynchronousConnectionComplete{SynchronousConnectionCompleteData} -> 0x2C,
        SynchronousConnectionChanged{SynchronousConnectionChangedData} -> 0x2D,
        SniffSubrating{SniffSubratingData} -> 0x2E,
        ExtendedInquiryResult{ExtendedInquiryResultData} -> 0x2F,
        EncryptionKeyRefreshComplete{EncryptionKeyRefreshCompleteData} -> 0x30,
        IOCapabilityRequest{IOCapabilityRequestData} -> 0x31,
        IOCapabilityResponse{IOCapabilityResponseData} -> 0x32,
        UserConfirmationRequest{UserConfirmationRequestData} -> 0x33,
        UserPasskeyRequest{UserPasskeyRequestData} -> 0x34,
        RemoteOOBDataRequest{RemoteOOBDataRequestData} -> 0x35,
        SimplePairingComplete{SimplePairingCompleteData} -> 0x36,
        LinkSupervisionTimeoutChanged{LinkSupervisionTimeoutChangedData} -> 0x38,
        EnhancedFlushComplete{EnhancedFlushCompleteData} -> 0x39,
        UserPasskeyNotification{UserPasskeyNotificationData} -> 0x3B,
        KeypressNotification{KeypressNotificationData} -> 0x3C,
        RemoteHostSupportedFeaturesNotification{RemoteHostSupportedFeaturesNotificationData} -> 0x3D,
        NumberOfCompletedDataBlocks{NumberOfCompletedDataBlocksData} -> 0x48,
        LeMeta(LeMeta){LeMetaData} -> 0x3E,
        TriggeredClockCapture{TriggeredClockCaptureData} -> 0x4E,
        SynchronizationTrainComplete{SynchronizationTrainCompleteData} -> 0x4F,
        SynchronizationTrainReceived{SynchronizationTrainReceivedData} -> 0x50,
        ConnectionlessSlaveBroadcastReceive{ConnectionlessSlaveBroadcastReceiveData} -> 0x51,
        ConnectionlessSlaveBroadcastTimeout{ConnectionlessSlaveBroadcastTimeoutData} -> 0x52,
        TruncatedPageComplete{TruncatedPageCompleteData} -> 0x53,
        SlavePageResponseTimeout{SlavePageResponseTimeoutData} -> 0x54,
        ConnectionlessSlaveBroadcastChannelMapChange{ConnectionlessSlaveBroadcastChannelMapChangeData} -> 0x55,
        InquiryResponseNotification{InquiryResponseNotificationData} -> 0x56,
        AuthenticatedPayloadTimeoutExpired{AuthenticatedPayloadTimeoutExpiredData} -> 0x57,
        SAMStatusChange{SAMStatusChangeData} -> 0x58,
    }
}

impl Events {
    /// Check if an event can be masked
    ///
    /// This function checks that an event is maskable by the
    /// [set event mask](crate::hci::cb::set_event_mask),
    /// [set event mask page 2](crate::hci::cb::set_event_mask_page_2), or
    /// [LE set event mask](crate::hci::le::mandatory::set_event_mask) HCI commands. This method
    /// will return true for every event
    /// except for
    /// [`CommandComplete`](Events::CommandComplete),
    /// [`CommandStatus`](Events::CommandStatus), and
    /// [`NumberOfCompletedPackets`](Events::NumberOfCompletedPackets).
    pub fn is_maskable(&self) -> bool {
        match self {
            Events::CommandComplete => false,
            Events::CommandStatus => false,
            Events::NumberOfCompletedPackets => false,
            _ => true,
        }
    }
}

/// Generic error for trying to convert raw data into an event
#[derive(Debug)]
pub struct EventError {
    for_event: Option<Events>,
    reason: EventErrorReason,
}

impl core::fmt::Display for EventError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Display::fmt(&self.reason, f)?;

        if let Some(ref event) = self.for_event {
            f.write_str(r#" for event ""#)?;
            core::fmt::Display::fmt(event, f)?;
            f.write_str(r#"""#)?;
        }

        Ok(())
    }
}

impl From<EventCodeError> for EventError {
    fn from(ec: EventCodeError) -> EventError {
        EventError {
            for_event: None,
            reason: EventErrorReason::EventCode(ec),
        }
    }
}

impl From<alloc::string::String> for EventError {
    fn from(s: alloc::string::String) -> EventError {
        EventError {
            for_event: None,
            reason: EventErrorReason::Error(s),
        }
    }
}

#[derive(Debug)]
enum EventErrorReason {
    // TODO: Temporary error message until strings are no longer used for event errors
    Error(alloc::string::String),
    EventCode(EventCodeError),
}

impl core::fmt::Display for EventErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            EventErrorReason::Error(reason) => core::fmt::Display::fmt(reason, f),
            EventErrorReason::EventCode(code) => core::fmt::Display::fmt(code, f),
        }
    }
}

/// Error returned when trying to convert event codes into an `Events`
#[derive(Debug)]
pub struct EventCodeError {
    code: u8,
    sub_code: Option<u8>,
}

impl EventCodeError {
    fn new(code: u8, sub_code: u8) -> Self {
        const IRRELEVANT: LeMeta = LeMeta::ConnectionComplete;

        if code == Events::LeMeta(IRRELEVANT).get_event_code() {
            EventCodeError {
                code,
                sub_code: Some(sub_code),
            }
        } else {
            EventCodeError { code, sub_code: None }
        }
    }
}

impl core::fmt::Display for EventCodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Some(ref sub_code) = self.sub_code {
            write!(f, "unknown LE sub event code: {}", sub_code)
        } else {
            write!(f, "unknown event code: {}", self.code)
        }
    }
}
