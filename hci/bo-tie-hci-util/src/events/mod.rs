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
        BluetoothDeviceAddress(address)
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

use crate::ConnectionHandle;
use parameters::{
    AuthenticatedPayloadTimeoutExpiredData, AuthenticationCompleteData, ChangeConnectionLinkKeyCompleteData,
    CommandCompleteData, CommandStatusData, ConnectionCompleteData, ConnectionPacketTypeChangedData,
    ConnectionRequestData, ConnectionlessSlaveBroadcastChannelMapChangeData, ConnectionlessSlaveBroadcastReceiveData,
    ConnectionlessSlaveBroadcastTimeoutData, DataBufferOverflowData, DisconnectionCompleteData, EncryptionChangeV1Data,
    EncryptionChangeV2Data, EncryptionKeyRefreshCompleteData, EnhancedFlushCompleteData, ExtendedInquiryResultData,
    FlowSpecificationCompleteData, FlushOccurredData, HardwareErrorData, InquiryCompleteData,
    InquiryResponseNotificationData, InquiryResultData, InquiryResultWithRssiData, IoCapabilityRequestData,
    IoCapabilityResponseData, KeypressNotificationData, LeAdvertisingReportData, LeAdvertisingSetTerminatedData,
    LeChannelSelectionAlgorithmData, LeConnectionCompleteData, LeConnectionUpdateCompleteData, LeDataLengthChangeData,
    LeDirectedAdvertisingReportData, LeEnhancedConnectionCompleteData, LeExtendedAdvertisingReportData,
    LeGenerateDhKeyCompleteData, LeLongTermKeyRequestData, LePeriodicAdvertisingReportData,
    LePeriodicAdvertisingSyncEstablishedData, LePeriodicAdvertisingSyncLostData, LePhyUpdateCompleteData,
    LeReadLocalP256PublicKeyCompleteData, LeReadRemoteFeaturesCompleteData, LeRemoteConnectionParameterRequestData,
    LeScanRequestReceivedData, LinkKeyNotificationData, LinkKeyRequestData, LinkKeyTypeChangedData,
    LinkSupervisionTimeoutChangedData, LoopbackCommandData, MaxSlotsChangeData, ModeChangeData, Multiple,
    NumberOfCompletedDataBlocksData, NumberOfCompletedPacketsData, PageScanRepetitionModeChangeData,
    PeripheralPageResponseTimeoutData, PinCodeRequestData, QosSetupCompleteData, QosViolationData,
    ReadClockOffsetCompleteData, ReadRemoteExtendedFeaturesCompleteData, ReadRemoteSupportedFeaturesCompleteData,
    ReadRemoteVersionInformationCompleteData, RemoteHostSupportedFeaturesNotificationData,
    RemoteNameRequestCompleteData, RemoteOobDataRequestData, ReturnLinkKeysData, RoleChangeData, SamStatusChangeData,
    SimplePairingCompleteData, SniffSubratingData, SynchronizationTrainCompleteData, SynchronizationTrainReceivedData,
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
    #[derive(Debug,Hash,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,bo_tie_macros::DepthCount)]
    pub enum LeMeta ( #[derive(Debug,Clone)] enum LeMetaData ) {
        ConnectionComplete{LeConnectionCompleteData},
        AdvertisingReport{Multiple<Result<LeAdvertisingReportData, alloc::string::String>>},
        ConnectionUpdateComplete{LeConnectionUpdateCompleteData},
        ReadRemoteFeaturesComplete{LeReadRemoteFeaturesCompleteData},
        LongTermKeyRequest{LeLongTermKeyRequestData},
        RemoteConnectionParameterRequest{LeRemoteConnectionParameterRequestData},
        DataLengthChange{LeDataLengthChangeData},
        ReadLocalP256PublicKeyComplete{LeReadLocalP256PublicKeyCompleteData},
        GenerateDhKeyComplete{LeGenerateDhKeyCompleteData},
        EnhancedConnectionComplete{LeEnhancedConnectionCompleteData},
        DirectedAdvertisingReport{Multiple<Result<LeDirectedAdvertisingReportData, alloc::string::String>>},
        PhyUpdateComplete{LePhyUpdateCompleteData},
        ExtendedAdvertisingReport{Multiple<Result<LeExtendedAdvertisingReportData, alloc::string::String>>},
        PeriodicAdvertisingSyncEstablished{LePeriodicAdvertisingSyncEstablishedData},
        PeriodicAdvertisingReport{LePeriodicAdvertisingReportData},
        PeriodicAdvertisingSyncLost{LePeriodicAdvertisingSyncLostData},
        ScanTimeout,
        AdvertisingSetTerminated{LeAdvertisingSetTerminatedData},
        ScanRequestReceived{LeScanRequestReceivedData},
        ChannelSelectionAlgorithm{LeChannelSelectionAlgorithmData},
    }
}

impl LeMeta {
    /// Get the sub event code for the `LeMeta` event
    pub fn get_sub_code(&self) -> u8 {
        match *self {
            LeMeta::ConnectionComplete => 0x01,
            LeMeta::AdvertisingReport => 0x02,
            LeMeta::ConnectionUpdateComplete => 0x03,
            LeMeta::ReadRemoteFeaturesComplete => 0x04,
            LeMeta::LongTermKeyRequest => 0x05,
            LeMeta::RemoteConnectionParameterRequest => 0x06,
            LeMeta::DataLengthChange => 0x07,
            LeMeta::ReadLocalP256PublicKeyComplete => 0x08,
            LeMeta::GenerateDhKeyComplete => 0x09,
            LeMeta::EnhancedConnectionComplete => 0x0A,
            LeMeta::DirectedAdvertisingReport => 0x0B,
            LeMeta::PhyUpdateComplete => 0x0C,
            LeMeta::ExtendedAdvertisingReport => 0x0D,
            LeMeta::PeriodicAdvertisingSyncEstablished => 0x0E,
            LeMeta::PeriodicAdvertisingReport => 0x0F,
            LeMeta::PeriodicAdvertisingSyncLost => 0x10,
            LeMeta::ScanTimeout => 0x11,
            LeMeta::AdvertisingSetTerminated => 0x12,
            LeMeta::ScanRequestReceived => 0x13,
            LeMeta::ChannelSelectionAlgorithm => 0x14,
        }
    }

    /// Try to create a `LeMeta` event from its sub event code
    pub fn try_from_sub_code(sub_event_code: u8) -> Result<Self, InvalidLeMetaCode> {
        match sub_event_code {
            0x01 => Ok(LeMeta::ConnectionComplete),
            0x02 => Ok(LeMeta::AdvertisingReport),
            0x03 => Ok(LeMeta::ConnectionUpdateComplete),
            0x04 => Ok(LeMeta::ReadRemoteFeaturesComplete),
            0x05 => Ok(LeMeta::LongTermKeyRequest),
            0x06 => Ok(LeMeta::RemoteConnectionParameterRequest),
            0x07 => Ok(LeMeta::DataLengthChange),
            0x08 => Ok(LeMeta::ReadLocalP256PublicKeyComplete),
            0x09 => Ok(LeMeta::GenerateDhKeyComplete),
            0x0A => Ok(LeMeta::EnhancedConnectionComplete),
            0x0B => Ok(LeMeta::DirectedAdvertisingReport),
            0x0C => Ok(LeMeta::PhyUpdateComplete),
            0x0D => Ok(LeMeta::ExtendedAdvertisingReport),
            0x0E => Ok(LeMeta::PeriodicAdvertisingSyncEstablished),
            0x0F => Ok(LeMeta::PeriodicAdvertisingReport),
            0x10 => Ok(LeMeta::PeriodicAdvertisingSyncLost),
            0x11 => Ok(LeMeta::ScanTimeout),
            0x12 => Ok(LeMeta::AdvertisingSetTerminated),
            0x13 => Ok(LeMeta::ScanRequestReceived),
            0x14 => Ok(LeMeta::ChannelSelectionAlgorithm),
            _ => Err(InvalidLeMetaCode(sub_event_code)),
        }
    }
}

impl TryFrom<u8> for LeMeta {
    type Error = InvalidLeMetaCode;

    fn try_from(sub_event_code: u8) -> Result<LeMeta, Self::Error> {
        Self::try_from_sub_code(sub_event_code)
    }
}

impl From<LeMeta> for u8 {
    fn from(le_meta: LeMeta) -> Self {
        le_meta.get_sub_code()
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
            LeMeta::GenerateDhKeyComplete => f.write_str(bo_tie_macros::display_hci_event!(GenerateDhKeyComplete)),
            LeMeta::EnhancedConnectionComplete => {
                f.write_str(bo_tie_macros::display_hci_event!(EnhancedConnectionComplete))
            }
            LeMeta::DirectedAdvertisingReport => {
                f.write_str(bo_tie_macros::display_hci_event!(DirectedAdvertisingReport))
            }
            LeMeta::PhyUpdateComplete => f.write_str(bo_tie_macros::display_hci_event!(PhyUpdateComplete)),
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
    /// Get the [`LeMeta`] enumeration for this `LeMetaData`
    fn get_le_event_name(&self) -> LeMeta {
        match *self {
            LeMetaData::ConnectionComplete(_) => LeMeta::ConnectionComplete,
            LeMetaData::AdvertisingReport(_) => LeMeta::AdvertisingReport,
            LeMetaData::ConnectionUpdateComplete(_) => LeMeta::ConnectionUpdateComplete,
            LeMetaData::ReadRemoteFeaturesComplete(_) => LeMeta::ReadRemoteFeaturesComplete,
            LeMetaData::LongTermKeyRequest(_) => LeMeta::LongTermKeyRequest,
            LeMetaData::RemoteConnectionParameterRequest(_) => LeMeta::RemoteConnectionParameterRequest,
            LeMetaData::DataLengthChange(_) => LeMeta::DataLengthChange,
            LeMetaData::ReadLocalP256PublicKeyComplete(_) => LeMeta::ReadLocalP256PublicKeyComplete,
            LeMetaData::GenerateDhKeyComplete(_) => LeMeta::GenerateDhKeyComplete,
            LeMetaData::EnhancedConnectionComplete(_) => LeMeta::EnhancedConnectionComplete,
            LeMetaData::DirectedAdvertisingReport(_) => LeMeta::DirectedAdvertisingReport,
            LeMetaData::PhyUpdateComplete(_) => LeMeta::PhyUpdateComplete,
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
            0x01 => Ok(LeMetaData::ConnectionComplete(LeConnectionCompleteData::try_from(packet)?)),
            0x02 => Ok(LeMetaData::AdvertisingReport(Multiple::<Result<LeAdvertisingReportData, alloc::string::String>>::try_from(packet)?)),
            0x03 => Ok(LeMetaData::ConnectionUpdateComplete(LeConnectionUpdateCompleteData::try_from(packet)?)),
            0x04 => Ok(LeMetaData::ReadRemoteFeaturesComplete(LeReadRemoteFeaturesCompleteData::try_from(packet)?)),
            0x05 => Ok(LeMetaData::LongTermKeyRequest(LeLongTermKeyRequestData::try_from(packet)?)),
            0x06 => Ok(LeMetaData::RemoteConnectionParameterRequest(LeRemoteConnectionParameterRequestData::try_from(packet)?)),
            0x07 => Ok(LeMetaData::DataLengthChange(LeDataLengthChangeData::try_from(packet)?)),
            0x08 => Ok(LeMetaData::ReadLocalP256PublicKeyComplete(LeReadLocalP256PublicKeyCompleteData::try_from(packet)?)),
            0x09 => Ok(LeMetaData::GenerateDhKeyComplete(LeGenerateDhKeyCompleteData::try_from(packet)?)),
            0x0A => Ok(LeMetaData::EnhancedConnectionComplete(LeEnhancedConnectionCompleteData::try_from(packet)?)),
            0x0B => Ok(LeMetaData::DirectedAdvertisingReport(Multiple::<Result<LeDirectedAdvertisingReportData, alloc::string::String>>::try_from(packet)?)),
            0x0C => Ok(LeMetaData::PhyUpdateComplete(LePhyUpdateCompleteData::try_from(packet)?)),
            0x0D => Ok(LeMetaData::ExtendedAdvertisingReport(Multiple::<Result<LeExtendedAdvertisingReportData, alloc::string::String>>::try_from(packet)?)),
            0x0E => Ok(LeMetaData::PeriodicAdvertisingSyncEstablished(LePeriodicAdvertisingSyncEstablishedData::try_from(packet)?)),
            0x0F => Ok(LeMetaData::PeriodicAdvertisingReport(LePeriodicAdvertisingReportData::try_from(packet)?)),
            0x10 => Ok(LeMetaData::PeriodicAdvertisingSyncLost(LePeriodicAdvertisingSyncLostData::try_from(packet)?)),
            0x11 => Ok(LeMetaData::ScanTimeout),
            0x12 => Ok(LeMetaData::AdvertisingSetTerminated(LeAdvertisingSetTerminatedData::try_from(packet)?)),
            0x13 => Ok(LeMetaData::ScanRequestReceived(LeScanRequestReceivedData::try_from(packet)?)),
            0x14 => Ok(LeMetaData::ChannelSelectionAlgorithm(LeChannelSelectionAlgorithmData::try_from(packet)?)),
            _    => Err(alloc::format!("Unknown LE meta event ID: {}", packet[0])),
        }
    }
}

#[derive(Debug)]
pub struct InvalidLeMetaCode(u8);

impl From<InvalidLeMetaCode> for EventError {
    fn from(i: InvalidLeMetaCode) -> Self {
        let event_code_error = EventCodeError::new(0x3E, i.0);

        EventError::from(event_code_error)
    }
}

impl core::fmt::Display for InvalidLeMetaCode {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "invalid le meta code {:#x}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidLeMetaCode {}

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
        $data_var.get_le_event_name()
    };
}

macro_rules! events_markup {
    ( pub enum $EnumName:tt ( $EnumDataName:tt ) {
        $( $name:tt $(( $($enum_val:tt),* ))* {$data:ident $(< $type:ty >)*} -> $val:expr, )*
    } ) => (

        enumerate_split! {
            #[derive(Debug,Hash,Clone,Copy,PartialEq,Eq,PartialOrd,Ord,bo_tie_macros::DepthCount)]
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
            -> core::result::Result<$crate::events::$EnumName, EventError>
            where
                S: Into<Option<u8>>
            {
                match event {
                    $( $val => Ok( $EnumName::$name $(( $(
                        $enum_val::try_from(sub_event.into().ok_or(EventError {
                            for_event: None,
                            reason: EventErrorReason::MissingSubEventCode,
                        })?)?
                    )* ))* ), )*
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

        impl $crate::events::$EnumDataName {

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

                if packet[0] == 0xFF {
                    let e = VendorSpecificEvent::new(packet);

                    return Err(EventError {
                        for_event: None,
                        reason: EventErrorReason::VendorSpecificEvent(e)
                    })
                }

                // packet[2] is the LeMeta specific sub event code (if the event is LeMeta)
                let event_code = $crate::events::$EnumName::try_from_event_codes(
                    chew!(packet), // chew "removes" the first byte from packet
                    packet.get(1).cloned().unwrap_or_default()
                )?;

                // Get the length of the packet and convert it into a usize
                let event_len = chew!(packet).into();

                match event_code {
                    $( $crate::events::$EnumName::$name $( ( $(put_!($enum_val)),* ) )* =>
                        Ok(crate::events::$EnumDataName::$name(
                            $crate::events::$data::<$( $type ),*>::try_from( &packet[..event_len] )
                                .map_err(|e| EventError {
                                    for_event: Some(event_code),
                                    reason: EventErrorReason::Error(e),
                                })?
                        )),
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
        EncryptionChangeV1{EncryptionChangeV1Data} -> 0x08,
        ChangeConnectionLinkKeyComplete{ChangeConnectionLinkKeyCompleteData} -> 0x09,
        LinkKeyTypeChanged{LinkKeyTypeChangedData} -> 0x0A,
        ReadRemoteSupportedFeaturesComplete{ReadRemoteSupportedFeaturesCompleteData} -> 0x0B,
        ReadRemoteVersionInformationComplete{ReadRemoteVersionInformationCompleteData} -> 0x0C,
        QosSetupComplete{QosSetupCompleteData} -> 0x0D,
        CommandComplete{CommandCompleteData} -> 0x0E,
        CommandStatus{CommandStatusData} -> 0x0F,
        HardwareError{HardwareErrorData} -> 0x10,
        FlushOccurred{FlushOccurredData} -> 0x11,
        RoleChange{RoleChangeData} -> 0x12,
        NumberOfCompletedPackets{Multiple<NumberOfCompletedPacketsData>} -> 0x13,
        ModeChange{ModeChangeData} -> 0x14,
        ReturnLinkKeys{Multiple<ReturnLinkKeysData>} -> 0x15,
        PinCodeRequest{PinCodeRequestData} -> 0x16,
        LinkKeyRequest{LinkKeyRequestData} -> 0x17,
        LinkKeyNotification{LinkKeyNotificationData} -> 0x18,
        LoopbackCommand{LoopbackCommandData} -> 0x19,
        DataBufferOverflow{DataBufferOverflowData} -> 0x1A,
        MaxSlotsChange{MaxSlotsChangeData} -> 0x1B,
        ReadClockOffsetComplete{ReadClockOffsetCompleteData} -> 0x1C,
        ConnectionPacketTypeChanged{ConnectionPacketTypeChangedData} -> 0x1D,
        QosViolation{QosViolationData} -> 0x1E,
        PageScanRepetitionModeChange{PageScanRepetitionModeChangeData} -> 0x20,
        FlowSpecificationComplete{FlowSpecificationCompleteData} -> 0x21,
        InquiryResultWithRssi{Multiple<Result<InquiryResultWithRssiData,alloc::string::String>>} -> 0x22,
        ReadRemoteExtendedFeaturesComplete{ReadRemoteExtendedFeaturesCompleteData} -> 0x23,
        SynchronousConnectionComplete{SynchronousConnectionCompleteData} -> 0x2C,
        SynchronousConnectionChanged{SynchronousConnectionChangedData} -> 0x2D,
        SniffSubrating{SniffSubratingData} -> 0x2E,
        ExtendedInquiryResult{ExtendedInquiryResultData} -> 0x2F,
        EncryptionKeyRefreshComplete{EncryptionKeyRefreshCompleteData} -> 0x30,
        IoCapabilityRequest{IoCapabilityRequestData} -> 0x31,
        IoCapabilityResponse{IoCapabilityResponseData} -> 0x32,
        UserConfirmationRequest{UserConfirmationRequestData} -> 0x33,
        UserPasskeyRequest{UserPasskeyRequestData} -> 0x34,
        RemoteOobDataRequest{RemoteOobDataRequestData} -> 0x35,
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
        ConnectionlessPeripheralBroadcastReceive{ConnectionlessSlaveBroadcastReceiveData} -> 0x51,
        ConnectionlessPeripheralBroadcastTimeout{ConnectionlessSlaveBroadcastTimeoutData} -> 0x52,
        TruncatedPageComplete{TruncatedPageCompleteData} -> 0x53,
        PeripheralPageResponseTimeout{PeripheralPageResponseTimeoutData} -> 0x54,
        ConnectionlessSlaveBroadcastChannelMapChange{ConnectionlessSlaveBroadcastChannelMapChangeData} -> 0x55,
        InquiryResponseNotification{InquiryResponseNotificationData} -> 0x56,
        AuthenticatedPayloadTimeoutExpired{AuthenticatedPayloadTimeoutExpiredData} -> 0x57,
        SamStatusChange{SamStatusChangeData} -> 0x58,
        EncryptionChangeV2{EncryptionChangeV2Data} -> 0x59,
    }
}

impl Events {
    /// Check if an event can be masked
    ///
    /// This function checks that an event is maskable by the
    /// [set event mask], [set event mask page 2], or [LE set event mask] HCI commands. This method
    /// will return true for every event except for [`CommandComplete`], [`CommandStatus`], and
    /// [`NumberOfCompletedPackets`].
    ///
    /// [set event mask]: ../bo_tie_hci_host/commands/cb/set_event_mask/index.html
    /// [set event mask page 2]: ../bo_tie_hci_host/commands/cb/set_event_mask_page_2/index.html
    /// [LE set event mask]: ../bo_tie_hci_host/commands/le/groups/mandatory/set_event_mask/index.html
    /// [`CommandComplete`]: Events::CommandComplete
    /// [`CommandStatus`]: Events::CommandStatus
    /// [`NumberOfCompletedPackets`]: Events::NumberOfCompletedPackets
    pub fn is_maskable(&self) -> bool {
        match self {
            Events::CommandComplete => false,
            Events::CommandStatus => false,
            Events::NumberOfCompletedPackets => false,
            _ => true,
        }
    }

    /// Check if an event can be routed to a connection async task
    ///
    /// True is returned if this event can be routed to another async task. See
    /// [`EventRoutingPolicy`] and [`Host::set_event_routing_policy`] for details.
    ///
    /// [`EventRoutingPolicy`]:
    /// [`Host::set_event_routing_policy`]:
    pub fn is_routable(&self) -> bool {
        match self {
            Events::DisconnectionComplete |
            Events::AuthenticationComplete |
            Events::EncryptionChangeV1 |
            Events::EncryptionChangeV2 |
            Events::ChangeConnectionLinkKeyComplete |
            Events::LinkKeyTypeChanged |
            Events::ReadRemoteSupportedFeaturesComplete |
            Events::ReadRemoteVersionInformationComplete |
            Events::QosSetupComplete |
            Events::FlushOccurred |
            Events::ModeChange |
            Events::MaxSlotsChange |
            Events::ReadClockOffsetComplete |
            Events::ConnectionPacketTypeChanged |
            Events::QosViolation |
            Events::FlowSpecificationComplete |
            Events::ReadRemoteExtendedFeaturesComplete |
            Events::SynchronousConnectionChanged |
            Events::SniffSubrating |
            Events::EncryptionKeyRefreshComplete |
            Events::LinkSupervisionTimeoutChanged |
            Events::EnhancedFlushComplete |
            Events::LeMeta(LeMeta::ConnectionUpdateComplete) |
            Events::LeMeta(LeMeta::ReadRemoteFeaturesComplete) |
            Events::LeMeta(LeMeta::LongTermKeyRequest) |
            Events::LeMeta(LeMeta::RemoteConnectionParameterRequest) |
            Events::LeMeta(LeMeta::DataLengthChange) |
            Events::LeMeta(LeMeta::PhyUpdateComplete) |

            // Not sure if synced advertising will have their own
            // async tasks in the future, but it doesn't matter
            // for now as bo-tie doesn't support this yet :)
            Events::LeMeta(LeMeta::PeriodicAdvertisingSyncEstablished) |
            Events::LeMeta(LeMeta::PeriodicAdvertisingReport) |
            Events::LeMeta(LeMeta::PeriodicAdvertisingSyncLost) |
            Events::LeMeta(LeMeta::AdvertisingSetTerminated) |

            Events::LeMeta(LeMeta::ChannelSelectionAlgorithm) |
            Events::AuthenticatedPayloadTimeoutExpired => true,
            _ => false
        }
    }

    /// Shortcut for an empty list of Events
    ///
    /// This can be helpful when trying to disable all events with the event mask functions.
    pub fn empty_list() -> [Events; 0] {
        []
    }
}

impl EventsData {
    /// Get the Connection Handle
    ///
    /// This will return a handle if the event contains a connection handle or a sync handle.
    pub fn get_handle(&self) -> Option<ConnectionHandle> {
        match self {
            EventsData::DisconnectionComplete(d) => Some(d.connection_handle),
            EventsData::AuthenticationComplete(d) => Some(d.connection_handle),
            EventsData::EncryptionChangeV1(d) => Some(d.connection_handle),
            EventsData::EncryptionChangeV2(d) => Some(d.connection_handle),
            EventsData::ChangeConnectionLinkKeyComplete(d) => Some(d.connection_handle),
            EventsData::LinkKeyTypeChanged(d) => Some(d.connection_handle),
            EventsData::ReadRemoteSupportedFeaturesComplete(d) => Some(d.connection_handle),
            EventsData::ReadRemoteVersionInformationComplete(d) => Some(d.connection_handle),
            EventsData::QosSetupComplete(d) => Some(d.connection_handle),
            EventsData::FlushOccurred(d) => Some(d.handle),
            EventsData::ModeChange(d) => Some(d.connection_handle),
            EventsData::MaxSlotsChange(d) => Some(d.connection_handle),
            EventsData::ReadClockOffsetComplete(d) => Some(d.connection_handle),
            EventsData::ConnectionPacketTypeChanged(d) => Some(d.connection_handle),
            EventsData::QosViolation(d) => Some(d.connection_handle),
            EventsData::FlowSpecificationComplete(d) => Some(d.connection_handle),
            EventsData::ReadRemoteExtendedFeaturesComplete(d) => Some(d.connection_handle),
            EventsData::SynchronousConnectionChanged(d) => Some(d.connection_handle),
            EventsData::SniffSubrating(d) => Some(d.connection_handle),
            EventsData::EncryptionKeyRefreshComplete(d) => Some(d.connection_handle),
            EventsData::LinkSupervisionTimeoutChanged(d) => Some(d.connection_handle),
            EventsData::EnhancedFlushComplete(d) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::ConnectionUpdateComplete(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::ReadRemoteFeaturesComplete(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::LongTermKeyRequest(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::RemoteConnectionParameterRequest(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::DataLengthChange(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::PhyUpdateComplete(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::PeriodicAdvertisingSyncEstablished(d)) => Some(d.sync_handle),
            EventsData::LeMeta(LeMetaData::PeriodicAdvertisingReport(d)) => Some(d.sync_handle),
            EventsData::LeMeta(LeMetaData::PeriodicAdvertisingSyncLost(d)) => Some(d.sync_handle),
            EventsData::LeMeta(LeMetaData::AdvertisingSetTerminated(d)) => Some(d.connection_handle),
            EventsData::LeMeta(LeMetaData::ChannelSelectionAlgorithm(d)) => Some(d.connection_handle),
            EventsData::AuthenticatedPayloadTimeoutExpired(d) => Some(d.connection_handle),
            _ => None,
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

#[derive(Debug)]
enum EventErrorReason {
    // TODO: Temporary error message until strings are no longer used for event errors
    Error(alloc::string::String),
    EventCode(EventCodeError),
    MissingSubEventCode,
    VendorSpecificEvent(VendorSpecificEvent),
}

impl core::fmt::Display for EventErrorReason {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            EventErrorReason::Error(reason) => core::fmt::Display::fmt(reason, f),
            EventErrorReason::EventCode(code) => core::fmt::Display::fmt(code, f),
            EventErrorReason::MissingSubEventCode => f.write_str("missing sub event code"),
            EventErrorReason::VendorSpecificEvent(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

/// Error returned when trying to convert event codes into an `Events`
#[derive(Debug)]
pub struct EventCodeError {
    event_code: u8,
    sub_event_code: Option<u8>,
}

impl EventCodeError {
    fn new(code: u8, sub_code: u8) -> Self {
        const IRRELEVANT: LeMeta = LeMeta::ConnectionComplete;

        if code == Events::LeMeta(IRRELEVANT).get_event_code() {
            EventCodeError {
                event_code: code,
                sub_event_code: Some(sub_code),
            }
        } else {
            EventCodeError {
                event_code: code,
                sub_event_code: None,
            }
        }
    }
}

impl core::fmt::Display for EventCodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        if let Some(ref sub_code) = self.sub_event_code {
            write!(f, "unknown LE sub event code: {}", sub_code)
        } else {
            write!(f, "unknown event code: {}", self.event_code)
        }
    }
}

/// Vendor Specific Event
///
/// Vendors are allowed to send specific events of their choosing when using the event opcode 0xFF.
/// These events are out of scope of this library and cannot be processed by it.
pub struct VendorSpecificEvent {
    len: usize,
    payload: [u8; 16],
}

impl VendorSpecificEvent {
    fn new(packet: &[u8]) -> Self {
        debug_assert_eq!(0xFF, packet[0]);

        let len = packet[1] as usize;

        let mut payload = [0u8; 16];

        payload[..len].copy_from_slice(&packet[2..core::cmp::min(len + 2, 18)]);

        VendorSpecificEvent { len, payload }
    }
}

impl core::fmt::Debug for VendorSpecificEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "[255 (event code), {} (length)", self.len)?;

        for i in 0..self.len {
            write!(f, ", {}", self.payload[i])?;
        }

        if self.len == 16 {
            f.write_str(", ...]")
        } else {
            f.write_str("]")
        }
    }
}

impl core::fmt::Display for VendorSpecificEvent {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("vendor specific event: ")?;

        core::fmt::Display::fmt(self, f)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for VendorSpecificEvent {}
