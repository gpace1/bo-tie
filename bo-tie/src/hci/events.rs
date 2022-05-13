//! Host Controller Interface Events

use crate::hci::common::{
    ConnectionHandle, EnabledExtendedFeaturesItr, EnabledFeaturesIter, EncryptionLevel, ExtendedInquiryResponseDataItr,
};
use crate::hci::error::Error;
use crate::hci::events::EventErrorReason::UnknownEventCode;
use crate::hci::le;
use crate::hci::le::common::{
    AddressType, ConnectionInterval, ConnectionLatency, EnabledLeFeaturesItr, ExtendedAdvertisingAndScanResponseData,
    SupervisionTimeout,
};
use crate::BluetoothDeviceAddress;
use core::convert::From;

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

struct RawData<'a> {
    raw_data: &'a [u8],
}

impl<'a> From<&'a [u8]> for RawData<'a> {
    fn from(raw_data: &'a [u8]) -> Self {
        Self { raw_data }
    }
}

impl core::convert::AsRef<[u8]> for RawData<'_> {
    fn as_ref(&self) -> &[u8] {
        self.raw_data
    }
}

/// Create from implementation for $name
///
/// The parameter name for the from method is "raw" and its type is &[u8].
/// $inner is the contents of the from method.
macro_rules! impl_try_from_for_raw_packet {
    ( $name:ty, $param:tt, $inner:block ) => {
        #[allow(unused_assignments)]
        #[allow(unused_mut)]
        impl core::convert::TryFrom<RawData<'_>> for $name {
            type Error = alloc::string::String;
            fn try_from(param: RawData<'_>) -> Result<Self, Self::Error> {
                let mut $param = param.as_ref();
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

type BufferType<T> = alloc::vec::Vec<T>;

#[derive(Debug, Clone)]
pub struct Multiple<T> {
    data: BufferType<T>,
}

impl<T, C> From<C> for Multiple<T>
where
    C: Into<BufferType<T>>,
{
    fn from(c: C) -> Self {
        Multiple { data: c.into() }
    }
}

impl<T> core::ops::Deref for Multiple<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> core::iter::IntoIterator for Multiple<T> {
    type Item = T;
    type IntoIter = <BufferType<T> as core::iter::IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

#[derive(Debug, Clone)]
pub enum PageScanRepetitionMode {
    R0,
    R1,
    R2,
}

impl PageScanRepetitionMode {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        use self::PageScanRepetitionMode::*;

        match raw {
            0x00 => Ok(R0),
            0x01 => Ok(R1),
            0x02 => Ok(R2),
            _ => Err(alloc::format!("Unkown Page Scan Repitition Mode: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClassOfDevice {
    Class(u32),
    Unknown,
}

/// Converts a tuple of a 24 bit data
///
/// The tuple consists of the lower 16 bits of the data and the upper 8 bits of the data
impl ClassOfDevice {
    fn from(raw: [u8; 3]) -> Self {
        use self::ClassOfDevice::*;

        match raw {
            [0, 0, 0] => Unknown,
            _ => Class(u32::from_le(
                (raw[2] as u32) << 16 | (raw[1] as u32) << 8 | (raw[0] as u32),
            )),
        }
    }
}

#[derive(Debug, Clone)]
pub enum LinkType {
    SCOConnection,
    ACLConnection,
    ESCOConnection,
}

impl LinkType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        use self::LinkType::*;

        match raw {
            0x00 => Ok(SCOConnection),
            0x01 => Ok(ACLConnection),
            0x02 => Ok(ESCOConnection),
            _ => Err(alloc::format!("Unknown Link Type: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum LinkLevelEncryptionEnabled {
    Yes,
    No,
}

impl LinkLevelEncryptionEnabled {
    fn try_from(raw: u8) -> core::result::Result<Self, alloc::string::String> {
        use self::LinkLevelEncryptionEnabled::*;

        match raw {
            0x00 => Ok(Yes),
            0x01 => Ok(No),
            _ => Err(alloc::format!("Unknown Link Level Encryption Enabled: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionEnabled {
    raw: u8,
}

impl EncryptionEnabled {
    pub fn get_for_le(&self) -> EncryptionLevel {
        if self.raw == 0x01 {
            EncryptionLevel::AESCCM
        } else {
            EncryptionLevel::Off
        }
    }

    pub fn get_for_br_edr(&self) -> EncryptionLevel {
        match self.raw {
            0x00 => EncryptionLevel::Off,
            0x01 => EncryptionLevel::E0,
            0x02 => EncryptionLevel::AESCCM,
            _ => EncryptionLevel::Off,
        }
    }
}

impl From<u8> for EncryptionEnabled {
    fn from(raw: u8) -> Self {
        EncryptionEnabled { raw }
    }
}

#[derive(Debug, Clone)]
pub enum KeyFlag {
    SemiPermanentLinkKey,
    TemporaryLinkKey,
}

impl KeyFlag {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        use self::KeyFlag::*;

        match raw {
            0x00 => Ok(SemiPermanentLinkKey),
            0x01 => Ok(TemporaryLinkKey),
            _ => Err(alloc::format!("Unknown Key Flag: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ServiceType {
    NoTrafficAvailable,
    BestEffortAvailable,
    GuaranteedAvailable,
}

impl ServiceType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        use self::ServiceType::*;
        match raw {
            0x00 => Ok(NoTrafficAvailable),
            0x01 => Ok(BestEffortAvailable),
            0x02 => Ok(GuaranteedAvailable),
            _ => Err(alloc::format!("Unknown Service Type: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct InquiryCompleteData {
    pub status: Error,
}

impl_try_from_for_raw_packet! {
    InquiryCompleteData,
    packet,
    {
        Ok(InquiryCompleteData { status: Error::from(chew!(packet)) })
    }
}

#[derive(Debug, Clone)]
pub struct InquiryResultData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repetition_mode: PageScanRepetitionMode,
    pub class_of_device: ClassOfDevice,
    pub clock_offset: u16,
}

impl_try_from_for_raw_packet! {
    Multiple<Result<InquiryResultData, alloc::string::String>>,
    packet,
    {
        Ok(Multiple {
            data: {
                // The size of a each Inquiry Result in the event packet is 14 bytes.
                // Inquiry results start after the first byte (which would give the total number of
                // inquiry results).
                let mut vec = packet[1..].chunks_exact( 14 )
                    .map(|mut chunk| {

                        Ok(InquiryResultData {
                            bluetooth_address: chew_baddr!(chunk),

                            page_scan_repetition_mode: PageScanRepetitionMode::try_from(chew!(chunk))?,

                            class_of_device: ClassOfDevice::from({
                                let mut class_of_device = [0u8;3];
                                class_of_device.copy_from_slice(chew!(chunk,3));
                                class_of_device
                            }),

                            clock_offset: chew_u16!(chunk),
                        })
                    })
                    .collect::<alloc::vec::Vec<Result<InquiryResultData, alloc::string::String>>>();

                vec.truncate(packet[0] as usize);

                vec
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub bluetooth_address: BluetoothDeviceAddress,
    pub link_type: LinkType,
    pub encryption_enabled: LinkLevelEncryptionEnabled,
}

impl_try_from_for_raw_packet! {
    ConnectionCompleteData,
    packet,
    {
        Ok(ConnectionCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            bluetooth_address: chew_baddr!(packet),
            link_type: LinkType::try_from(chew!(packet))?,
            encryption_enabled: LinkLevelEncryptionEnabled::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub class_of_device: ClassOfDevice,
    pub link_type: LinkType,
}

impl_try_from_for_raw_packet! {
    ConnectionRequestData,
    packet,
    {
        Ok(ConnectionRequestData {
            bluetooth_address: chew_baddr!(packet),
            class_of_device: ClassOfDevice::from({
                let mut class = [0u8;3];
                class.copy_from_slice(chew!(packet,3));
                class
            }),
            link_type: LinkType::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DisconnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub reason: u8,
}

impl_try_from_for_raw_packet! {
    DisconnectionCompleteData,
    packet,
    {
        Ok(DisconnectionCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            reason: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticationCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    AuthenticationCompleteData,
    packet,
    {
        Ok(AuthenticationCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteNameRequestCompleteData {
    pub status: Error,
    pub bluetooth_address: BluetoothDeviceAddress,
    pub remote_name: Result<::alloc::string::String, ::alloc::sync::Arc<::alloc::string::FromUtf8Error>>,
}

impl_try_from_for_raw_packet! {
    RemoteNameRequestCompleteData,
    packet,
    {
        Ok(RemoteNameRequestCompleteData {
            status: Error::from(chew!(packet)),
            bluetooth_address: chew_baddr!(packet),
            remote_name: {
                let raw_msg = packet.iter().take_while(|v| **v != 0).map(|v| *v).collect::<alloc::vec::Vec<u8>>();

                alloc::string::String::from_utf8(raw_msg).map_err(|e| ::alloc::sync::Arc::new(e))
            }
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionChangeData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub encryption_enabled: EncryptionEnabled,
}

impl_try_from_for_raw_packet! {
    EncryptionChangeData,
    packet,
    {
        Ok(EncryptionChangeData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            encryption_enabled: EncryptionEnabled::from(chew!(packet)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChangeConnectionLinkKeyCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    ChangeConnectionLinkKeyCompleteData,
    packet,
    {
        Ok(ChangeConnectionLinkKeyCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct MasterLinkKeyCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub key: KeyFlag,
}

impl_try_from_for_raw_packet! {
    MasterLinkKeyCompleteData,
    packet,
    {
        Ok(MasterLinkKeyCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            key: KeyFlag::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReadRemoteSupportedFeaturesCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub lmp_features: EnabledFeaturesIter,
}

impl_try_from_for_raw_packet! {
    ReadRemoteSupportedFeaturesCompleteData,
    packet,
    {
        Ok(ReadRemoteSupportedFeaturesCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            lmp_features: EnabledFeaturesIter::from({
                let mut features = [0u8;8];
                features.copy_from_slice(chew!(packet,8));
                features
            }),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReadRemoteVersionInformationCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub version: u8,
    pub manufacturer_name: u16,
    pub subversion: u16,
}

impl_try_from_for_raw_packet! {
    ReadRemoteVersionInformationCompleteData,
    packet,
    {
        Ok(ReadRemoteVersionInformationCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            version: chew!(packet),
            manufacturer_name: chew_u16!(packet),
            subversion: chew_u16!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct QosSetupCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,

    pub service_type: ServiceType,
    /// Bytes per second rate
    pub token_rate: u32,
    /// In octets per second (eg. 24 -> 24 octets of data per second)
    pub peak_bandwith: u32,
    /// Latency in microseconds
    pub latency: u32,
    /// delay variation in microseconds
    pub delay_variation: u32,
}

impl_try_from_for_raw_packet! {
    QosSetupCompleteData,
    packet,
    {
        Ok(QosSetupCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            service_type: ServiceType::try_from(chew!(packet))?,
            token_rate: chew_u32!(packet),
            peak_bandwith: chew_u32!(packet),
            latency: chew_u32!(packet),
            delay_variation: chew_u32!(packet),
        })
    }
}

#[derive(Clone, Copy, PartialEq)]
pub enum CommandDataErr<UnpackErrorType>
where
    UnpackErrorType: core::fmt::Debug,
{
    /// If the api doesn't have a bug in it, then the controller is faulty if this error occurs
    RawDataLenTooSmall,
    /// The first value is the expected ocf the second value is the actual ocf given in the event
    IncorrectOCF(u16, u16),
    UnpackError(UnpackErrorType),
}

impl<UnpackErrorType> core::fmt::Display for CommandDataErr<UnpackErrorType>
where
    UnpackErrorType: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self {
            CommandDataErr::RawDataLenTooSmall => {
                write!(
                    f,
                    "Command complete data error, the size of the data was too small for type"
                )
            }
            CommandDataErr::IncorrectOCF(exp, act) => {
                write!(
                    f,
                    "Command complete data error, expected opcode is 0x{:X}, actual opcode is 0x{:X}",
                    exp, act
                )
            }
            CommandDataErr::UnpackError(ref e) => {
                write!(f, "Command complete contained error code for '{:?}'", e)
            }
        }
    }
}

impl<UnpackErrorType> core::fmt::Debug for CommandDataErr<UnpackErrorType>
where
    UnpackErrorType: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        (self as &dyn core::fmt::Display).fmt(f)
    }
}

macro_rules! impl_get_data_for_event_data {
    ( $event_data:path, $command:expr, $packed_data:ty, $data:ty, $return_ty:ty, $try_from_err_ty:ty ) => {
        impl crate::hci::events::DataResult for $data {
            type ReturnData = $return_ty;
            type UnpackErrorType = $try_from_err_ty;
        }

        impl crate::hci::events::GetDataForCommand<$data> for $event_data {
            unsafe fn get_return(
                &self,
            ) -> core::result::Result<
                core::option::Option<<$data as crate::hci::events::DataResult>::ReturnData>,
                crate::hci::events::CommandDataErr<<$data as crate::hci::events::DataResult>::UnpackErrorType>,
            > {
                let oc_pair = $command.as_opcode_pair();

                let expected_opcode = oc_pair.ocf | (oc_pair.ogf << 10);

                if self.command_opcode == Some(expected_opcode) {
                    <Self as crate::hci::events::GetDataForCommand<$data>>::get_return_unchecked(&self)
                } else if self.command_opcode.is_none() {
                    Ok(None)
                } else {
                    Err(crate::hci::events::CommandDataErr::IncorrectOCF(
                        oc_pair.ocf | (oc_pair.ogf << 10),
                        self.command_opcode.unwrap(),
                    ))
                }
            }

            unsafe fn get_return_unchecked(
                &self,
            ) -> core::result::Result<
                core::option::Option<<$data as crate::hci::events::DataResult>::ReturnData>,
                crate::hci::events::CommandDataErr<<$data as crate::hci::events::DataResult>::UnpackErrorType>,
            > {
                use core::mem::size_of;

                if self.raw_data.len() >= core::mem::size_of::<$packed_data>() {
                    let mut buffer = [0u8; size_of::<$packed_data>()];

                    buffer.copy_from_slice(&(*self.raw_data));

                    let p_data: $packed_data = core::mem::transmute(buffer);

                    match <$data>::try_from((p_data, self.number_of_hci_command_packets)) {
                        Ok(val) => Ok(Some(val)),
                        Err(e) => Err(crate::hci::events::CommandDataErr::UnpackError(e)),
                    }
                } else {
                    Err(crate::hci::events::CommandDataErr::RawDataLenTooSmall)
                }
            }
        }
    };
    ( $event_data:path, $command:expr, $packed_data:ty, $data:ty, $try_from_err_ty:ty ) => {
        impl_get_data_for_event_data!(
            $event_data,
            $command,
            $packed_data,
            $data,
            $data,
            $try_from_err_ty
        );
    };
}

#[derive(Debug, Clone)]
pub struct CommandCompleteData {
    pub number_of_hci_command_packets: u8,
    pub command_opcode: Option<u16>,
    /// only public for hci
    pub(super) raw_data: BufferType<u8>,
}

impl_try_from_for_raw_packet! {
    CommandCompleteData,
    packet,
    {
        let opcode_exists;

        Ok(CommandCompleteData {
            number_of_hci_command_packets: chew!(packet),
            command_opcode: {
                let opcode = chew_u16!(packet);

                opcode_exists = 0 != opcode;

                if opcode_exists { Some(opcode) } else { None }
            },
            raw_data: if opcode_exists {
                packet.to_vec()
            }
            else {
                BufferType::new()
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct CommandStatusData {
    pub status: Error,
    pub number_of_hci_command_packets: u8,
    pub command_opcode: Option<u16>,
}

impl_try_from_for_raw_packet! {
    CommandStatusData,
    packet,
    {
        Ok(CommandStatusData {
            status: Error::from(chew!(packet)),
            number_of_hci_command_packets: chew!(packet),
            command_opcode: {
                let opcode = chew_u16!(packet);

                if opcode != 0 { Some(opcode) } else { None }
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct HardwareErrorData {
    pub hardware_error: u8,
}

impl_try_from_for_raw_packet! {
    HardwareErrorData,
    packet,
    {
        Ok(HardwareErrorData {
            hardware_error: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FlushOccuredData {
    pub handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    FlushOccuredData,
    packet,
    {
        Ok(FlushOccuredData {
            handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum NewRole {
    NowMaster,
    NowSlave,
}

impl NewRole {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        use self::NewRole::*;

        match raw {
            0x00 => Ok(NowMaster),
            0x01 => Ok(NowSlave),
            _ => Err(alloc::format!("Unknown New Role: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RoleChangeData {
    pub status: Error,
    pub bluetooth_address: BluetoothDeviceAddress,
    pub new_role: NewRole,
}

impl_try_from_for_raw_packet! {
    RoleChangeData,
    packet,
    {
        Ok(RoleChangeData {
            status: Error::from(chew!(packet)),
            bluetooth_address: chew_baddr!(packet),
            new_role: NewRole::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct NumberOfCompletedPacketsData {
    pub connection_handle: ConnectionHandle,
    pub number_of_completed_packets: u16,
}

impl_try_from_for_raw_packet! {
    Multiple<NumberOfCompletedPacketsData>,
    packet,
    {
        Ok(Multiple {
            data: {
                // The size of a single "Number of Completed Packets" is 4 bytes.
                // The first byte is the number of handles, which is not needed
                let mut vec = packet[1..].chunks_exact( 4 )
                .map(|mut chunk| {
                    NumberOfCompletedPacketsData {
                        connection_handle: chew_handle!(chunk),
                        number_of_completed_packets: chew_u16!(chunk),
                    }
                })
                .collect::<alloc::vec::Vec<NumberOfCompletedPacketsData>>();
                vec.truncate(packet[0] as usize);
                vec
            },
        })
    }
}

#[derive(Debug, Clone)]
pub enum CurrentMode {
    ActiveMode,
    HoldMode(CurrentModeInterval),
    SniffMode(CurrentModeInterval),
}

impl CurrentMode {
    fn try_from(raw: &[u8]) -> Result<Self, alloc::string::String> {
        match raw[0] {
            0x00 => Ok(CurrentMode::ActiveMode),
            0x01 => Ok(CurrentMode::HoldMode(CurrentModeInterval::try_from(u16::from_le(
                raw[1] as u16 | (raw[2] as u16) << 8,
            ))?)),
            0x02 => Ok(CurrentMode::SniffMode(CurrentModeInterval::try_from(u16::from_le(
                raw[1] as u16 | (raw[2] as u16) << 8,
            ))?)),
            _ => Err(alloc::format!("Unknown Current Mode: {}", raw[0])),
        }
    }
}

#[derive(Debug, Clone)]
pub struct CurrentModeInterval {
    pub interval: u16,
}

impl CurrentModeInterval {
    const MIN: u16 = 0x0002;
    const MAX: u16 = 0xFFFE;
    const CVT: u64 = 625; // conversion between raw to ms

    fn try_from(raw: u16) -> Result<Self, alloc::string::String> {
        if raw >= Self::MIN && raw <= Self::MAX {
            Ok(CurrentModeInterval { interval: raw })
        } else {
            Err(alloc::string::String::from("Current Mode Interval out of bounds"))
        }
    }

    pub fn get_interval_as_duration(&self) -> core::time::Duration {
        core::time::Duration::from_millis(self.interval as u64 * Self::CVT)
    }
}

#[derive(Debug, Clone)]
pub struct ModeChangeData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub mode: CurrentMode,
}

impl_try_from_for_raw_packet! {
    ModeChangeData,
    packet,
    {
        Ok(ModeChangeData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),

            // look at CurrentMode::from method for why mode is calculated this way
            mode: if packet[0] == 0x00 {
                CurrentMode::try_from(chew!(packet,2))?
            }
            else {
                CurrentMode::try_from(chew!(packet,3))?
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReturnLinkKeysData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub link_key: [u8; 16],
}

impl_try_from_for_raw_packet! {
    Multiple<ReturnLinkKeysData>,
    packet,
    {
        Ok(Multiple {
            data: {
                // The size of a single Returned Link Keys is 22 bytes.
                // The first byte is the number of handles, which is not needed
                let mut vec = packet[1..].chunks_exact( 22 )
                .map(|mut chunk| {
                    ReturnLinkKeysData {
                        bluetooth_address: chew_baddr!(chunk),
                        link_key: [0u8;16], // per the specification, this is always 0's
                    }
                })
                .collect::<alloc::vec::Vec<ReturnLinkKeysData>>();
                vec.truncate(packet[0] as usize);
                vec
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct PINCodeRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    PINCodeRequestData,
    packet,
    {
        Ok(PINCodeRequestData {
            bluetooth_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LinkKeyRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    LinkKeyRequestData,
    packet,
    {
        Ok(LinkKeyRequestData {
            bluetooth_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum LinkKeyType {
    CombinationKey,
    LocalUnitKey,
    RemoteUnitKey,
    DebugCombinationKey,
    UnauthenticatedCombinationKeyGeneratedFromP192,
    AuthenticatedCombinationKeyGeneratedFromP192,
    ChangedCombinationKey,
    UnauthenticatedCombinationKeyGeneratedFromP256,
    AuthenticatedCombinationKeyGeneratedFromP256,
}

impl LinkKeyType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        use self::LinkKeyType::*;

        match raw {
            0x00 => Ok(CombinationKey),
            0x01 => Ok(LocalUnitKey),
            0x02 => Ok(RemoteUnitKey),
            0x03 => Ok(DebugCombinationKey),
            0x04 => Ok(UnauthenticatedCombinationKeyGeneratedFromP192),
            0x05 => Ok(AuthenticatedCombinationKeyGeneratedFromP192),
            0x06 => Ok(ChangedCombinationKey),
            0x07 => Ok(UnauthenticatedCombinationKeyGeneratedFromP256),
            0x08 => Ok(AuthenticatedCombinationKeyGeneratedFromP256),
            _ => Err(alloc::format!("Unknown Link Key Type {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LinkKeyNotificationData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub link_key: [u8; 16],
    pub link_key_type: LinkKeyType,
}

impl_try_from_for_raw_packet! {
    LinkKeyNotificationData,
    packet,
    {
        Ok(LinkKeyNotificationData {
            bluetooth_address: chew_baddr!(packet),
            link_key: {
                let mut key = [0u8;16];
                key.copy_from_slice(chew!(packet,16));
                key
            },
            link_key_type: LinkKeyType::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LoopbackCommandData {
    opcode: u16,
    hci_command_packet: BufferType<u8>,
}

impl_try_from_for_raw_packet! {
    LoopbackCommandData,
    packet,
    {
        Ok(LoopbackCommandData {
            opcode: chew_u16!(packet),
            hci_command_packet: packet.to_vec(),
        })
    }
}

#[derive(Debug, Clone)]
pub enum LinkTypeOverflow {
    /// Voice channel overflow
    SynchronousBufferOverflow,
    /// Data channel overflow
    ACLBufferOverflow,
}

impl LinkTypeOverflow {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LinkTypeOverflow::SynchronousBufferOverflow),
            0x01 => Ok(LinkTypeOverflow::ACLBufferOverflow),
            _ => Err(alloc::format!("Unknown Link Type (buffer) Overflow {}", raw)),
        }
    }
}
#[derive(Debug, Clone)]
pub struct DataBufferOverflowData {
    pub link_type_overflow: LinkTypeOverflow,
}

impl_try_from_for_raw_packet! {
    DataBufferOverflowData,
    packet,
    {
        Ok(DataBufferOverflowData {
            link_type_overflow: LinkTypeOverflow::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum LMPMaxSlots {
    One,
    Three,
    Five,
}

impl LMPMaxSlots {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x01 => Ok(LMPMaxSlots::One),
            0x03 => Ok(LMPMaxSlots::Three),
            0x05 => Ok(LMPMaxSlots::Five),
            _ => Err(alloc::format!("Unknown LMP Max Slots: {}", raw)),
        }
    }

    pub fn val(&self) -> u8 {
        match *self {
            LMPMaxSlots::One => 0x01,
            LMPMaxSlots::Three => 0x03,
            LMPMaxSlots::Five => 0x05,
        }
    }
}
#[derive(Debug, Clone)]
pub struct MaxSlotsChangeData {
    pub connection_handle: ConnectionHandle,
    pub lmp_max_slots: LMPMaxSlots,
}

impl_try_from_for_raw_packet! {
    MaxSlotsChangeData,
    packet,
    {
        Ok(MaxSlotsChangeData {
            connection_handle: chew_handle!(packet),
            lmp_max_slots: LMPMaxSlots::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ReadClockOffsetCompleteData {
    status: Error,
    connection_handle: ConnectionHandle,
    /// Bits 16-2 of CLKNslave-CLK
    clock_offset: u32,
}

impl_try_from_for_raw_packet! {
    ReadClockOffsetCompleteData,
    packet,
    {
        Ok(ReadClockOffsetCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            clock_offset: (chew_u16!(packet) as u32) << 2,
        })
    }
}

#[derive(Debug, Clone)]
pub enum PacketType {
    ACL(ACLPacketType),
    Sco(ScoPacketType),
}

#[derive(Debug, Clone)]
pub enum ACLPacketType {
    TwoDH1ShallNotBeUsed,
    ThreeDH1ShallNotBeUsed,
    DM1MayBeUsed,
    DH1MayBeUsed,
    TwoDH3ShallNotBeUsed,
    ThreeDH3ShallNotBeUsed,
    DM3MayBeUsed,
    DH3MayBeUsed,
    TwoDH5ShallNotBeUsed,
    ThreeDH5ShallNotBeUsed,
    DM5MayBeUsed,
    DH5MayBeUsed,
}

impl ACLPacketType {
    fn try_from(raw: u16) -> Result<Self, &'static str> {
        match raw {
            0x0002 => Ok(ACLPacketType::TwoDH1ShallNotBeUsed),
            0x0004 => Ok(ACLPacketType::ThreeDH1ShallNotBeUsed),
            0x0008 => Ok(ACLPacketType::DM1MayBeUsed),
            0x0010 => Ok(ACLPacketType::DH1MayBeUsed),
            0x0100 => Ok(ACLPacketType::TwoDH3ShallNotBeUsed),
            0x0200 => Ok(ACLPacketType::ThreeDH3ShallNotBeUsed),
            0x0400 => Ok(ACLPacketType::DM3MayBeUsed),
            0x0800 => Ok(ACLPacketType::DH3MayBeUsed),
            0x1000 => Ok(ACLPacketType::TwoDH5ShallNotBeUsed),
            0x2000 => Ok(ACLPacketType::ThreeDH5ShallNotBeUsed),
            0x4000 => Ok(ACLPacketType::DM5MayBeUsed),
            0x8000 => Ok(ACLPacketType::DH5MayBeUsed),
            _ => Err("Packet type not matched for ACLConnection"),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ScoPacketType {
    HV1,
    HV2,
    HV3,
}

impl ScoPacketType {
    fn try_from(raw: u16) -> Result<Self, &'static str> {
        match raw {
            0x0020 => Ok(ScoPacketType::HV1),
            0x0040 => Ok(ScoPacketType::HV2),
            0x0080 => Ok(ScoPacketType::HV3),
            _ => Err("Packet type not matched for SCOConnection"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionPacketTypeChangedData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    packet_type: u16,
}

impl ConnectionPacketTypeChangedData {
    /// Get the packet type based on the link type
    ///
    /// Returns an error if link type is not SCOConnection or ACLConnection or if the value cannot
    /// be converted to a packet type from the proveded link type
    pub fn get_packet_type(&self, link_type: LinkType) -> Result<PacketType, &'static str> {
        match link_type {
            LinkType::ACLConnection => Ok(PacketType::ACL(ACLPacketType::try_from(self.packet_type)?)),
            LinkType::SCOConnection => Ok(PacketType::Sco(ScoPacketType::try_from(self.packet_type)?)),
            _ => Err("Link Type is not SCOConnection or ACLConnection"),
        }
    }
}

impl_try_from_for_raw_packet! {
    ConnectionPacketTypeChangedData,
    packet,
    {
        Ok(ConnectionPacketTypeChangedData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            packet_type: chew_u16!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct QoSViolationData {
    connection_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    QoSViolationData,
    packet,
    {
        Ok(QoSViolationData {
            connection_handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PageScanRepetitionModeChangeData {
    bluetooth_address: BluetoothDeviceAddress,
    page_scan_repition_mode: PageScanRepetitionMode,
}

impl_try_from_for_raw_packet! {
    PageScanRepetitionModeChangeData,
    packet,
    {
        Ok(PageScanRepetitionModeChangeData {
            bluetooth_address: chew_baddr!(packet,0),
            page_scan_repition_mode: PageScanRepetitionMode::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum FlowDirection {
    /// Traffic sent over the ACL connection
    OutgoingFlow,
    /// Traffic received over the ACL connection
    IncomingFlow,
}

impl FlowDirection {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(FlowDirection::OutgoingFlow),
            0x01 => Ok(FlowDirection::IncomingFlow),
            _ => Err(alloc::format!("Unknown {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct FlowSpecificationCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub flow_direction: FlowDirection,
    pub service_type: ServiceType,
    pub token_rate: u32,
    pub token_bucket_size: u32,
    pub peak_bandwith: u32,
    pub access_latency: u32,
}

impl_try_from_for_raw_packet! {
    FlowSpecificationCompleteData,
    packet,
    {
        Ok(FlowSpecificationCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            flow_direction: FlowDirection::try_from(chew!(packet))?,
            service_type: ServiceType::try_from(chew!(packet))?,
            token_rate: chew_u32!(packet),
            token_bucket_size: chew_u32!(packet),
            peak_bandwith: chew_u32!(packet),
            access_latency: chew_u32!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct InquiryResultWithRSSIData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repition_mode: PageScanRepetitionMode,
    pub class_of_device: ClassOfDevice,
    pub clock_offset: u32,
    pub rssi: i8,
}

impl_try_from_for_raw_packet! {
    Multiple<Result<InquiryResultWithRSSIData, alloc::string::String>>,
    packet,
    {
        Ok(Multiple {
            data: {

                let mut vec = packet[1..].chunks_exact( 14 )
                .map( |mut chunk| {
                    Ok(InquiryResultWithRSSIData {
                        bluetooth_address: chew_baddr!(chunk),
                        page_scan_repition_mode: PageScanRepetitionMode::try_from(chew!(chunk))?,
                        class_of_device: ClassOfDevice::from({
                            let mut class = [0u8;3];
                            class.copy_from_slice(chew!(chunk,3));
                            class
                        }),
                        clock_offset: (chew_u16!(chunk) as u32) << 2,
                        rssi: chew!(chunk) as i8,
                    })
                })
                .collect::<alloc::vec::Vec<Result<InquiryResultWithRSSIData, alloc::string::String>>>();
                vec.truncate(packet[0] as usize);
                vec
            }
        })
    }
}

#[derive(Debug, Clone)]
pub enum FeatureType {
    Features(EnabledFeaturesIter),
    ExtendedFeatures(EnabledExtendedFeaturesItr),
}

#[derive(Debug, Clone)]
pub struct ReadRemoteExtendedFeaturesCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub page_number: u8,
    pub maximum_page_number: u8,
    pub extended_lmp_features: FeatureType,
}

impl_try_from_for_raw_packet! {
    ReadRemoteExtendedFeaturesCompleteData,
    packet,
    {
        let page = packet[3];

        Ok(ReadRemoteExtendedFeaturesCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            page_number: chew!(packet),
            maximum_page_number: chew!(packet),
            extended_lmp_features: if page == 0 {
                let mut features = [0u8;8];
                features.copy_from_slice(chew!(packet,8));
                FeatureType::Features(EnabledFeaturesIter::from(features))
            }
            else {
                FeatureType::ExtendedFeatures(EnabledExtendedFeaturesItr::from(packet, page))
            }
        })
    }
}

#[derive(Debug, Clone)]
pub enum AirMode {
    MicroLawLog,
    ALawLog,
    CVSD,
    TransparentData,
}

impl AirMode {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(AirMode::MicroLawLog),
            0x01 => Ok(AirMode::ALawLog),
            0x02 => Ok(AirMode::CVSD),
            0x03 => Ok(AirMode::TransparentData),
            _ => Err(alloc::format!("Unknown Air Mode: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SynchronousConnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub bluetooth_address: BluetoothDeviceAddress,
    pub link_type: LinkType,
    pub transmission_interval: u8,
    pub retransmission_window: u8,
    pub rx_packet_length: u16,
    pub tx_packet_length: u16,
    pub air_mode: AirMode,
}

impl_try_from_for_raw_packet! {
    SynchronousConnectionCompleteData,
    packet,
    {
        Ok(SynchronousConnectionCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            bluetooth_address: chew_baddr!(packet),
            link_type: LinkType::try_from(chew!(packet))?,
            transmission_interval: chew!(packet),
            retransmission_window: chew!(packet),
            rx_packet_length: chew_u16!(packet),
            tx_packet_length: chew_u16!(packet),
            air_mode: AirMode::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct SynchronousConnectionChangedData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub transmission_interval: u8,
    pub retransmission_interval: u8,
    pub rx_packet_length: u16,
    pub tx_packet_length: u16,
}

impl_try_from_for_raw_packet! {
    SynchronousConnectionChangedData,
    packet,
    {
        Ok(SynchronousConnectionChangedData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            transmission_interval: chew!(packet),
            retransmission_interval: chew!(packet),
            rx_packet_length: chew_u16!(packet),
            tx_packet_length: chew_u16!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SniffSubratingData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub maximum_transmit_latency: u16,
    pub maximum_receive_latency: u16,
    pub minimum_transmit_latency: u16,
    pub minimum_receive_latency: u16,
}

impl_try_from_for_raw_packet! {
    SniffSubratingData,
    packet,
    {
        Ok(SniffSubratingData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet,1),
            maximum_transmit_latency: chew_u16!(packet),
            maximum_receive_latency: chew_u16!(packet),
            minimum_transmit_latency: chew_u16!(packet),
            minimum_receive_latency: chew_u16!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ExtendedInquiryResultData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repition_mode: PageScanRepetitionMode,
    pub class_of_device: ClassOfDevice,
    pub clock_offset: u32,
    pub rssi: i8,
    pub extended_inquiry_response_data: ExtendedInquiryResponseDataItr,
}

impl_try_from_for_raw_packet! {
    ExtendedInquiryResultData,
    packet,
    {
        Ok(ExtendedInquiryResultData {
            bluetooth_address: chew_baddr!(packet),
            page_scan_repition_mode: PageScanRepetitionMode::try_from(chew!(packet))?,
            class_of_device: ClassOfDevice::from({
                let mut class = [0u8;3];
                class.copy_from_slice(chew!(packet,3));
                class
            }),
            clock_offset: (chew_u16!(packet) as u32) << 2,
            rssi: chew!(packet) as i8,
            extended_inquiry_response_data: ExtendedInquiryResponseDataItr::from(chew!(packet,240)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EncryptionKeyRefreshCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    EncryptionKeyRefreshCompleteData,
    packet,
    {
        Ok(EncryptionKeyRefreshCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct IOCapabilityRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    IOCapabilityRequestData,
    packet,
    {
        Ok(IOCapabilityRequestData {
            bluetooth_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum IOCapability {
    DisplayOnly,
    DisplayYesNo,
    KeyboardOnly,
    NoInputNoOutput,
}

impl IOCapability {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(IOCapability::DisplayOnly),
            0x01 => Ok(IOCapability::DisplayYesNo),
            0x02 => Ok(IOCapability::KeyboardOnly),
            0x03 => Ok(IOCapability::NoInputNoOutput),
            _ => Err(alloc::format!("Unknown IO Capability: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum OOBDataPresent {
    OOBAuthenticationDataNotPresent,
    OOBAuthenticationDataFromRemoteDevicePresent,
}

impl OOBDataPresent {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(OOBDataPresent::OOBAuthenticationDataNotPresent),
            0x01 => Ok(OOBDataPresent::OOBAuthenticationDataFromRemoteDevicePresent),
            _ => Err(alloc::format!("Unknown OOB Data Present: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthenticationRequirements {
    MITMProtectionNotRequiredNoBonding,
    MITMProtectionRequiredNoBonding,
    MITMProtectionNoRequiredDedicatedBonding,
    MITMProtectionRequiredDedicatedBonding,
    MITMProtectionNotRequiredGeneralBonding,
    MITMProtectionRequiredGeneralBonding,
}

impl AuthenticationRequirements {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(AuthenticationRequirements::MITMProtectionNotRequiredNoBonding),
            0x01 => Ok(AuthenticationRequirements::MITMProtectionRequiredNoBonding),
            0x02 => Ok(AuthenticationRequirements::MITMProtectionNoRequiredDedicatedBonding),
            0x03 => Ok(AuthenticationRequirements::MITMProtectionRequiredDedicatedBonding),
            0x04 => Ok(AuthenticationRequirements::MITMProtectionNotRequiredGeneralBonding),
            0x05 => Ok(AuthenticationRequirements::MITMProtectionRequiredGeneralBonding),
            _ => Err(alloc::format!("Unknown Authentication Requirement: {}", raw)),
        }
    }
}
#[derive(Debug, Clone)]
pub struct IOCapabilityResponseData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub io_capability: IOCapability,
    pub oob_data_present: OOBDataPresent,
    pub authentication_requirements: AuthenticationRequirements,
}

impl_try_from_for_raw_packet! {
    IOCapabilityResponseData,
    packet,
    {
        Ok(IOCapabilityResponseData {
            bluetooth_address: chew_baddr!(packet),
            io_capability: IOCapability::try_from(chew!(packet))?,
            oob_data_present: OOBDataPresent::try_from(chew!(packet))?,
            authentication_requirements: AuthenticationRequirements::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct UserConfirmationRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub numeric_value: u32,
}

impl_try_from_for_raw_packet! {
    UserConfirmationRequestData,
    packet,
    {
        Ok(UserConfirmationRequestData {
            bluetooth_address: chew_baddr!(packet),
            numeric_value: chew_u32!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct UserPasskeyRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    UserPasskeyRequestData,
    packet,
    {
        Ok(UserPasskeyRequestData {
            bluetooth_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteOOBDataRequestData {
    pub bluetooth_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    RemoteOOBDataRequestData,
    packet,
    {
        Ok(RemoteOOBDataRequestData {
            bluetooth_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct SimplePairingCompleteData {
    pub status: Error,
    pub bluetooth_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    SimplePairingCompleteData,
    packet,
    {
        Ok(SimplePairingCompleteData {
            status: Error::from(chew!(packet)),
            bluetooth_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LinkSupervisionTimeoutChangedData {
    pub connection_handle: ConnectionHandle,
    pub link_supervision_timeout: u16,
}

impl_try_from_for_raw_packet! {
    LinkSupervisionTimeoutChangedData,
    packet,
    {
        Ok(LinkSupervisionTimeoutChangedData {
            connection_handle: chew_handle!(packet),
            link_supervision_timeout: chew_u16!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct EnhancedFlushCompleteData {
    pub connection_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    EnhancedFlushCompleteData,
    packet,
    {
        Ok(EnhancedFlushCompleteData {
            connection_handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct UserPasskeyNotificationData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub passkey: u32,
}

impl_try_from_for_raw_packet! {
    UserPasskeyNotificationData,
    packet,
    {
        Ok(UserPasskeyNotificationData {
            bluetooth_address: chew_baddr!(packet),
            passkey: chew_u32!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum KeypressNotificationType {
    PasskeyEntrystarted,
    PasskeyDigitEntered,
    PasskeyDigitErased,
    PasskeyCleared,
    PasskeyEntryCompleted,
}

impl KeypressNotificationType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0 => Ok(KeypressNotificationType::PasskeyEntrystarted),
            1 => Ok(KeypressNotificationType::PasskeyDigitEntered),
            2 => Ok(KeypressNotificationType::PasskeyDigitErased),
            3 => Ok(KeypressNotificationType::PasskeyCleared),
            4 => Ok(KeypressNotificationType::PasskeyEntryCompleted),
            _ => Err(alloc::format!("Unkown {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct KeypressNotificationData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub notification_type: KeypressNotificationType,
}

impl_try_from_for_raw_packet! {
    KeypressNotificationData,
    packet,
    {
        Ok(KeypressNotificationData {
            bluetooth_address: chew_baddr!(packet,0),
            notification_type: KeypressNotificationType::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct RemoteHostSupportedFeaturesNotificationData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub host_supported_features: EnabledFeaturesIter,
}

impl_try_from_for_raw_packet! {
    RemoteHostSupportedFeaturesNotificationData,
    packet,
    {
        Ok(RemoteHostSupportedFeaturesNotificationData {
            bluetooth_address: chew_baddr!(packet),
            host_supported_features: EnabledFeaturesIter::from({
                let mut features = [0u8;8];
                features.copy_from_slice(chew!(packet,8));
                features
            }),
        })
    }
}

#[derive(Debug, Clone)]
pub struct PhysicalLinkCompleteData {
    pub status: Error,
    pub physical_link_handle: u8,
}

impl_try_from_for_raw_packet! {
    PhysicalLinkCompleteData,
    packet,
    {
        Ok(PhysicalLinkCompleteData {
            status: Error::from(chew!(packet)),
            physical_link_handle: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ChannelSelectedData {
    pub physical_link_handle: u8,
}

impl_try_from_for_raw_packet! {
    ChannelSelectedData,
    packet,
    {
        Ok(ChannelSelectedData {
            physical_link_handle: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DisconnectionPhysicalLinkCompleteData {
    pub status: Error,
    pub physical_link_handle: u8,
    pub reason: Error,
}

impl_try_from_for_raw_packet! {
    DisconnectionPhysicalLinkCompleteData,
    packet,
    {
        Ok(DisconnectionPhysicalLinkCompleteData {
            status: Error::from(chew!(packet)),
            physical_link_handle: chew!(packet),
            reason: Error::from(chew!(packet)),
        })
    }
}

#[derive(Debug, Clone)]
pub enum LinkLossReason {
    Unknown,
    RangeRelated,
    BandwidthRelated,
    ResolvingConflict,
    Interference,
}

impl LinkLossReason {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0 => Ok(LinkLossReason::Unknown),
            1 => Ok(LinkLossReason::RangeRelated),
            2 => Ok(LinkLossReason::BandwidthRelated),
            3 => Ok(LinkLossReason::ResolvingConflict),
            4 => Ok(LinkLossReason::Interference),
            _ => Err(alloc::format!("Unknown Link Loss Reason: {}", raw)),
        }
    }
}
#[derive(Debug, Clone)]
pub struct PhysicalLInkLossEarlyWarningData {
    pub physical_link_handle: u8,
    pub link_loss_reason: LinkLossReason,
}

impl_try_from_for_raw_packet! {
    PhysicalLInkLossEarlyWarningData,
    packet,
    {
        Ok(PhysicalLInkLossEarlyWarningData {
            physical_link_handle: chew!(packet),
            link_loss_reason: LinkLossReason::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PhysicalLinkRecoveryData {
    pub physical_link_handle: u8,
}

impl_try_from_for_raw_packet! {
    PhysicalLinkRecoveryData,
    packet,
    {
        Ok(PhysicalLinkRecoveryData {
            physical_link_handle: packet[0],
        })
    }
}

#[derive(Debug, Clone)]
pub struct LogicalLinkCompleteData {
    pub status: Error,
    pub logical_link_handle: ConnectionHandle,
    pub physical_link_handle: u8,
    pub tx_flow_spec_id: u8,
}

impl_try_from_for_raw_packet! {
    LogicalLinkCompleteData,
    packet,
    {
        Ok(LogicalLinkCompleteData {
            status: Error::from(chew!(packet)),
            logical_link_handle: chew_handle!(packet),
            physical_link_handle: chew!(packet),
            tx_flow_spec_id: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct DisconnectionLogicalLinkCompleteData {
    pub status: Error,
    pub logical_link_handle: ConnectionHandle,
    pub reason: Error,
}

impl_try_from_for_raw_packet! {
    DisconnectionLogicalLinkCompleteData,
    packet,
    {
        Ok(DisconnectionLogicalLinkCompleteData {
            status: Error::from(chew!(packet)),
            logical_link_handle: chew_handle!(packet,1),
            reason: Error::from(chew!(packet)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct FlowSpecModifyCompleteData {
    pub status: Error,
    pub handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    FlowSpecModifyCompleteData,
    packet,
    {
        Ok(FlowSpecModifyCompleteData {
            status: Error::from(chew!(packet)),
            handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum ControllerBlocks {
    /// Requesting means that the controller is requesting the host to issue the Read Data Block
    /// Size Commmand to the controller. This is because the size of the buffer pool may have
    /// changed on the controller.
    RequestingReadDataBlockSize,
    /// Number of data block buffers free to be used for storage of data packets for transmission.
    FreeBlockBuffers(u16),
}

impl ControllerBlocks {
    fn from(raw: u16) -> Self {
        if raw == 0 {
            ControllerBlocks::RequestingReadDataBlockSize
        } else {
            ControllerBlocks::FreeBlockBuffers(raw)
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompletedDataPacketsAndBlocks {
    pub handle: ConnectionHandle,
    /// This is the number of completed packets (transmitted or flushed) since the last time
    /// number of completed data blocks command was called.
    pub completed_packets: u16,
    /// Number of data blocks on the controller freed since the last time number of completed data
    /// blocks command was called
    pub completed_blocks: u16,
}

#[derive(Debug, Clone)]
pub struct NumberOfCompletedDataBlocksData {
    pub total_data_blocks: ControllerBlocks,
    pub completed_packets_and_blocks: BufferType<CompletedDataPacketsAndBlocks>,
}

impl_try_from_for_raw_packet! {
    NumberOfCompletedDataBlocksData,
    packet,
    {
        Ok(NumberOfCompletedDataBlocksData {
            total_data_blocks: ControllerBlocks::from(chew_u16!(packet)),
            completed_packets_and_blocks: {
                let handle_cnt = chew!(packet) as usize;
                let mut vec = packet.chunks_exact(6)
                .map(|mut chunk| {
                    CompletedDataPacketsAndBlocks {
                        handle: chew_handle!(chunk),
                        completed_packets: chew_u16!(chunk),
                        completed_blocks: chew_u16!(chunk),
                    }
                })
                .collect::<alloc::vec::Vec<CompletedDataPacketsAndBlocks>>();
                vec.truncate(handle_cnt);
                vec
            }
        })
    }
}

#[derive(Debug, Clone)]
pub enum ShortRangeModeState {
    Enabled,
    Disabled,
}

impl ShortRangeModeState {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0 => Ok(ShortRangeModeState::Enabled),
            1 => Ok(ShortRangeModeState::Disabled),
            _ => Err(alloc::format!("Unknown Short Range Mode State {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShortRangeModeChangeCompleteData {
    pub status: Error,
    pub physical_link_handle: u8,
    pub short_range_mode_state: ShortRangeModeState,
}

impl_try_from_for_raw_packet! {
    ShortRangeModeChangeCompleteData,
    packet,
    {
        Ok(ShortRangeModeChangeCompleteData {
            status: Error::from(chew!(packet)),
            physical_link_handle: chew!(packet),
            short_range_mode_state: ShortRangeModeState::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct AMPStatusChangeData {
    pub status: Error,
    /// Look at the specification for this values meaning (v5 | vol 2, part E 7.7.61 )
    pub amp_status: u8,
}

impl_try_from_for_raw_packet! {
    AMPStatusChangeData,
    packet,
    {
        Ok(AMPStatusChangeData {
            status: Error::from(chew!(packet)),
            amp_status: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AMPStartTestData {
    pub status: Error,
    pub test_scenario: u8,
}

impl_try_from_for_raw_packet! {
    AMPStartTestData,
    packet,
    {
        Ok(AMPStartTestData {
            status: Error::from(chew!(packet)),
            test_scenario: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct AMPTestEndData {
    pub status: Error,
    pub test_scenario: u8,
}

impl_try_from_for_raw_packet! {
    AMPTestEndData,
    packet,
    {
        Ok(AMPTestEndData {
            status: Error::from(chew!(packet)),
            test_scenario: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum AMPReceiverReportDataEventType {
    FramesReceivedReport,
    FramesReceivedAndBitsInRrrorReport,
}

impl AMPReceiverReportDataEventType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0 => Ok(AMPReceiverReportDataEventType::FramesReceivedReport),
            1 => Ok(AMPReceiverReportDataEventType::FramesReceivedAndBitsInRrrorReport),
            _ => Err(alloc::format!("Unknown {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct AMPReceiverReportData {
    controller_type: u8,
    reason: Error,
    event_type: AMPReceiverReportDataEventType,
    number_of_frames: u16,
    number_of_error_frames: u16,
    number_of_bits: u32,
    number_of_error_bits: u32,
}

impl_try_from_for_raw_packet! {
    AMPReceiverReportData,
    packet,
    {
        Ok(AMPReceiverReportData {
            controller_type: chew!(packet),
            reason: Error::from(chew!(packet)),
            event_type: AMPReceiverReportDataEventType::try_from(chew!(packet))?,
            number_of_frames: chew_u16!(packet),
            number_of_error_frames: chew_u16!(packet),
            number_of_bits: chew_u32!(packet),
            number_of_error_bits: chew_u32!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum LERole {
    Master,
    Slave,
}

impl LERole {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LERole::Master),
            0x01 => Ok(LERole::Slave),
            _ => Err(alloc::format!("Unknown Le Role: {}", raw)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LEConnectionAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
}

impl LEConnectionAddressType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEConnectionAddressType::PublicDeviceAddress),
            0x01 => Ok(LEConnectionAddressType::RandomDeviceAddress),
            _ => Err(alloc::format!("Unknown Le Connection Address Type: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ClockAccuracy {
    _500ppm,
    _250ppm,
    _150ppm,
    _100ppm,
    _75ppm,
    _50ppm,
    _30ppm,
    _20ppm,
}

impl ClockAccuracy {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(ClockAccuracy::_500ppm),
            0x01 => Ok(ClockAccuracy::_250ppm),
            0x02 => Ok(ClockAccuracy::_150ppm),
            0x03 => Ok(ClockAccuracy::_100ppm),
            0x04 => Ok(ClockAccuracy::_75ppm),
            0x05 => Ok(ClockAccuracy::_50ppm),
            0x06 => Ok(ClockAccuracy::_30ppm),
            0x07 => Ok(ClockAccuracy::_20ppm),
            _ => Err(alloc::format!("Unknown Clock Accuracy: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEConnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub role: LERole,
    pub peer_address_type: LEConnectionAddressType,
    pub peer_address: BluetoothDeviceAddress,
    pub connection_interval: ConnectionInterval,
    pub connection_latency: ConnectionLatency,
    pub supervision_timeout: SupervisionTimeout,
    pub master_clock_accuracy: ClockAccuracy,
}

impl LEConnectionCompleteData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;
        Ok(LEConnectionCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            role: LERole::try_from(chew!(packet))?,
            peer_address_type: LEConnectionAddressType::try_from(chew!(packet))?,
            peer_address: chew_baddr!(packet),
            connection_interval: ConnectionInterval::try_from_raw(chew_u16!(packet))?,
            connection_latency: ConnectionLatency::try_from_raw(chew_u16!(packet))?,
            supervision_timeout: SupervisionTimeout::try_from_raw(chew_u16!(packet))?,
            master_clock_accuracy: ClockAccuracy::try_from(chew!(packet))?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LEAdvEventType {
    ConnectableAndScannableUndirectedAdvertising,
    ConnectableDirectedAdvertising,
    ScannableUndirectedAdvertising,
    NonConnectableUndirectedAdvertising,
    ScanResponse,
}

impl LEAdvEventType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEAdvEventType::ConnectableAndScannableUndirectedAdvertising),
            0x01 => Ok(LEAdvEventType::ConnectableDirectedAdvertising),
            0x02 => Ok(LEAdvEventType::ScannableUndirectedAdvertising),
            0x03 => Ok(LEAdvEventType::NonConnectableUndirectedAdvertising),
            0x04 => Ok(LEAdvEventType::ScanResponse),
            _ => Err(alloc::format!("Unknown LE Event Type: {}", raw)),
        }
    }
}

pub struct ReportDataIter<'a> {
    data: &'a [u8],
}

impl<'a> core::iter::Iterator for ReportDataIter<'a> {
    type Item = Result<&'a [u8], crate::gap::assigned::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.data.len() > 0 {
            let len = self.data[0] as usize;

            if len > 0 {
                if len + 1 <= self.data.len() {
                    let (ret, rest_of) = self.data.split_at(len + 1);

                    self.data = rest_of;

                    // No need to include the length byte because the length is included in the slice
                    // fat pointer.
                    Some(Ok(&ret[1..]))
                } else {
                    // short data so that None is returned the next iteration
                    self.data = &self.data[self.data.len()..];

                    Some(Err(crate::gap::assigned::Error::IncorrectLength))
                }
            } else {
                None
            }
        } else {
            None
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEAdvertisingReportData {
    pub event_type: LEAdvEventType,
    pub address_type: AddressType,
    pub address: BluetoothDeviceAddress,
    pub data: alloc::vec::Vec<u8>,
    /// If rssi is None, the the value isn't available
    pub rssi: Option<i8>,
}

impl LEAdvertisingReportData {
    pub fn data_iter(&self) -> ReportDataIter<'_> {
        ReportDataIter { data: &self.data }
    }

    fn buf_from(data: &[u8]) -> BufferType<Result<Self, alloc::string::String>> {
        let mut packet = data;

        // The value of 127 indicates no rssi functionality
        fn get_rssi(val: u8) -> Option<i8> {
            if val != 127 {
                Some(val as i8)
            } else {
                None
            }
        }

        let mut reports = alloc::vec::Vec::with_capacity(chew!(packet) as usize);

        for _ in 0..reports.capacity() {
            // packet[index + 8] is the data length value as given by the controller
            reports.push(
                match (
                    LEAdvEventType::try_from(chew!(packet)),
                    AddressType::try_from_raw(chew!(packet)),
                ) {
                    (Ok(event_type), Ok(address_type)) => Ok(LEAdvertisingReportData {
                        event_type,
                        address_type,
                        address: chew_baddr!(packet),
                        data: {
                            let size = chew!(packet);
                            chew!(packet, size).to_vec()
                        },
                        rssi: get_rssi(chew!(packet)),
                    }),
                    (Err(err), _) | (_, Err(err)) => Err(err),
                },
            );
        }

        reports
    }
}

#[derive(Debug, Clone)]
pub struct LEConnectionUpdateCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub connection_interval: ConnectionInterval,
    pub connection_latency: ConnectionLatency,
    pub supervision_timeout: SupervisionTimeout,
}

impl LEConnectionUpdateCompleteData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEConnectionUpdateCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            connection_interval: ConnectionInterval::try_from_raw(chew_u16!(packet))?,
            connection_latency: ConnectionLatency::try_from_raw(chew_u16!(packet))?,
            supervision_timeout: SupervisionTimeout::try_from_raw(chew_u16!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEReadRemoteFeaturesCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub features: EnabledLeFeaturesItr,
}

impl LEReadRemoteFeaturesCompleteData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEReadRemoteFeaturesCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            features: EnabledLeFeaturesItr::from({
                let mut features = [0u8; 8];
                features.copy_from_slice(chew!(packet, 8));
                features
            }),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LELongTermKeyRequestData {
    pub connection_handle: ConnectionHandle,
    pub random_number: u64,
    pub encryption_diversifier: u16,
}

impl LELongTermKeyRequestData {
    #[allow(unused_assignments)]
    fn from(data: &[u8]) -> Self {
        let mut packet = data;

        LELongTermKeyRequestData {
            connection_handle: chew_handle!(packet),
            random_number: chew_u64!(packet),
            encryption_diversifier: chew_u16!(packet),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LERemoteConnectionParameterRequestData {
    pub connection_handle: ConnectionHandle,
    pub minimum_interval: le::common::ConnectionInterval,
    pub maximum_interval: le::common::ConnectionInterval,
    pub latency: ConnectionLatency,
    pub timeout: SupervisionTimeout,
}

impl LERemoteConnectionParameterRequestData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LERemoteConnectionParameterRequestData {
            connection_handle: chew_handle!(packet),
            minimum_interval: le::common::ConnectionInterval::try_from_raw(chew_u16!(packet))
                .map_err(|e| alloc::string::String::from(e))?,
            maximum_interval: le::common::ConnectionInterval::try_from_raw(chew_u16!(packet))
                .map_err(|e| alloc::string::String::from(e))?,
            latency: ConnectionLatency::try_from_raw(chew_u16!(packet)).map_err(|e| alloc::string::String::from(e))?,
            timeout: SupervisionTimeout::try_from_raw(chew_u16!(packet)).map_err(|e| alloc::string::String::from(e))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEMaxOctets {
    pub octets: u16,
}

impl LEMaxOctets {
    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16) -> Self {
        debug_assert!(raw >= 0x001B && raw <= 0x00FB);

        LEMaxOctets { octets: raw }
    }
}

#[derive(Debug, Clone)]
pub struct LEMaxTime {
    pub time: u16,
}

impl LEMaxTime {
    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16) -> Self {
        debug_assert!(raw >= 0x0148 && raw <= 0x4290);

        LEMaxTime { time: raw }
    }
}

#[derive(Debug, Clone)]
pub struct LEDataLengthChangeData {
    pub connection_handle: ConnectionHandle,
    pub max_tx_octets: LEMaxOctets,
    pub max_tx_time: LEMaxTime,
    pub max_rx_octets: LEMaxOctets,
    pub max_rx_time: LEMaxTime,
}

impl LEDataLengthChangeData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEDataLengthChangeData {
            connection_handle: chew_handle!(packet),
            max_tx_octets: LEMaxOctets::from(chew_u16!(packet)),
            max_tx_time: LEMaxTime::from(chew_u16!(packet)),
            max_rx_octets: LEMaxOctets::from(chew_u16!(packet)),
            max_rx_time: LEMaxTime::from(chew_u16!(packet)),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEReadLocalP256PublicKeyCompleteData {
    pub status: Error,
    pub key: [u8; 64],
}

impl LEReadLocalP256PublicKeyCompleteData {
    #[allow(unused_assignments)]
    fn from(data: &[u8]) -> Self {
        let mut packet = data;

        LEReadLocalP256PublicKeyCompleteData {
            status: Error::from(chew!(packet)),
            key: {
                let mut pub_key = [0u8; 64];
                pub_key.copy_from_slice(chew!(packet, 256));
                pub_key
            },
        }
    }
}

#[derive(Debug, Clone)]
/// DHKey stands for diffie Hellman Key
pub struct LEGenerateDHKeyCompleteData {
    status: Error,
    key: [u8; 32],
}

impl LEGenerateDHKeyCompleteData {
    #[allow(unused_assignments)]
    fn from(data: &[u8]) -> Self {
        let mut packet = data;

        LEGenerateDHKeyCompleteData {
            status: Error::from(chew!(packet)),
            key: {
                let mut dh_key = [0u8; 32];
                dh_key.copy_from_slice(&packet[2..34]);
                dh_key
            },
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEEnhancedConnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub role: LERole,
    pub peer_address_type: AddressType,
    pub peer_address: BluetoothDeviceAddress,
    pub local_resolvable_private_address: Option<BluetoothDeviceAddress>,
    pub peer_resolvable_private_address: Option<BluetoothDeviceAddress>,
    pub connection_interval: le::common::ConnectionInterval,
    pub connection_latency: ConnectionLatency,
    pub supervision_timeout: SupervisionTimeout,
    pub master_clock_accuracy: ClockAccuracy,
}

impl LEEnhancedConnectionCompleteData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        let peer_address_type: AddressType;

        macro_rules! if_rpa_is_used {
            () => {{
                let bdaddr = chew_baddr!(packet);
                if match peer_address_type {
                    AddressType::PublicIdentityAddress | AddressType::RandomIdentityAddress => true,
                    _ => false,
                } {
                    Some(bdaddr)
                } else {
                    None
                }
            }};
        }

        Ok(LEEnhancedConnectionCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            role: LERole::try_from(chew!(packet))?,
            peer_address_type: {
                peer_address_type = AddressType::try_from_raw(chew!(packet))?;
                peer_address_type.clone()
            },
            peer_address: chew_baddr!(packet),
            local_resolvable_private_address: if_rpa_is_used!(),
            peer_resolvable_private_address: if_rpa_is_used!(),
            connection_interval: le::common::ConnectionInterval::try_from_raw(chew_u16!(packet)).unwrap(),
            connection_latency: ConnectionLatency::try_from_raw(chew_u16!(packet))?,
            supervision_timeout: SupervisionTimeout::try_from_raw(chew_u16!(packet))?,
            master_clock_accuracy: ClockAccuracy::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub enum LEAdvertisingEventType {
    ConnectableDirectedLegacyAdvertising,
}

impl LEAdvertisingEventType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x01 => Ok(LEAdvertisingEventType::ConnectableDirectedLegacyAdvertising),
            _ => Err(alloc::format!("Unknown LE Advertising Event Type: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub enum LEDirectAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    PublicIdentityAddress,
    RandomIdentityAddress,
    UnresolvableRandomDeviceAddress,
}

impl LEDirectAddressType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEDirectAddressType::PublicDeviceAddress),
            0x01 => Ok(LEDirectAddressType::RandomDeviceAddress),
            0x02 => Ok(LEDirectAddressType::PublicIdentityAddress),
            0x03 => Ok(LEDirectAddressType::RandomIdentityAddress),
            0xFE => Ok(LEDirectAddressType::UnresolvableRandomDeviceAddress),
            _ => Err(alloc::format!("Unknown LE Direct Address Type: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEDirectedAdvertisingReportData {
    pub event_type: LEAdvertisingEventType,
    pub address_type: AddressType,
    pub address: BluetoothDeviceAddress,
    pub direct_address_type: LEDirectAddressType,
    pub direct_address: BluetoothDeviceAddress,
    pub rssi: Option<i8>,
}

impl LEDirectedAdvertisingReportData {
    #[allow(unused_assignments)]
    fn buf_from(data: &[u8]) -> BufferType<Result<Self, alloc::string::String>> {
        let mut packet = data;

        let report_count = chew!(packet) as usize;

        let mut vec = packet
            .chunks_exact(16)
            .map(|mut chunk| {
                Ok(LEDirectedAdvertisingReportData {
                    event_type: LEAdvertisingEventType::try_from(chew!(chunk))?,
                    address_type: AddressType::try_from_raw(chew!(chunk))?,
                    address: chew_baddr!(chunk),
                    direct_address_type: LEDirectAddressType::try_from(chew!(chunk))?,
                    direct_address: chew_baddr!(chunk),
                    rssi: {
                        let rssi_val = chew!(chunk) as i8;

                        if rssi_val != 127 {
                            Some(rssi_val)
                        } else {
                            None
                        }
                    },
                })
            })
            .collect::<alloc::vec::Vec<Result<Self, alloc::string::String>>>();

        vec.truncate(report_count);

        vec
    }
}

#[derive(Debug, Clone)]
pub enum LEPhy {
    _1M,
    _2M,
    Coded,
}

impl LEPhy {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x01 => Ok(LEPhy::_1M),
            0x02 => Ok(LEPhy::_2M),
            0x03 => Ok(LEPhy::Coded),
            _ => Err(alloc::format!("Unknown LE Phy: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEPHYUpdateCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub tx_phy: LEPhy,
    pub rx_phy: LEPhy,
}

impl LEPHYUpdateCompleteData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;
        Ok(LEPHYUpdateCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            tx_phy: LEPhy::try_from(chew!(packet))?,
            rx_phy: LEPhy::try_from(chew!(packet))?,
        })
    }
}

/// IncompleteTruncated means that the controller was not successfull of the reception of an
/// AUX_CHAIN_IND (Secondary advertising channel fragmented data) PDU, where as Incomplete means
/// that there is more data to come.
#[derive(Debug, Clone)]
pub enum LEDataStatus {
    Complete,
    Incomplete,
    IncompleteTruncated,
}

impl LEDataStatus {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0 => Ok(LEDataStatus::Complete),
            1 => Ok(LEDataStatus::Incomplete),
            2 => Ok(LEDataStatus::IncompleteTruncated),
            _ => Err(alloc::format!("Unknown LE Data Status: {}", raw)),
        }
    }
}

/// A mapping to the official abbreviation for the enumerations
/// AdvertisingInd                           -- ADV_IND
/// ConnectableAdvertisingInd                -- ADV_DIRECT_IND
/// AdvertisingScanInd                       -- ADV_SCAN_IND
/// AdvertisingNonConnectableNonScannableInd -- ADV_NONCONN_IND
/// ScanResponseToAdvertisingInd             -- SCAN_RSP to an ADV_IND
/// ScanResponseToAdvertisingScanInd         -- SCAN_RSP to an ADV_SCAN_IN
#[derive(Debug, Clone)]
pub enum LELegacyExtAdvEventTypePDUType {
    AdvertisingInd,
    ConnectableAdvertisingInd,
    AdvertisingScanInd,
    AdvertisingNonConnectableNonScannableInd,
    ScanResponseToAdvertisingInd,
    ScanResponseToAdvertisingScanInd,
}

#[derive(Debug, Clone)]
pub struct LEExtAdvEventType {
    raw: u16,
}

impl LEExtAdvEventType {
    fn from(raw: u16) -> Self {
        LEExtAdvEventType { raw: raw }
    }

    pub fn is_advertising_connectable(&self) -> bool {
        self.raw & (1 << 0) != 0
    }

    pub fn is_advertising_scannable(&self) -> bool {
        self.raw & (1 << 1) != 0
    }

    pub fn is_advertising_directed(&self) -> bool {
        self.raw & (1 << 2) != 0
    }

    pub fn is_scan_response(&self) -> bool {
        self.raw & (1 << 3) != 0
    }

    pub fn is_legacy_pdu_used(&self) -> bool {
        self.raw & (1 << 4) != 0
    }

    pub fn data_status(&self) -> Result<LEDataStatus, alloc::string::String> {
        LEDataStatus::try_from(((self.raw >> 5) & 3) as u8)
    }

    /// Returns the Legacy PDU type if the event type indicates the PDU type is legacy
    pub fn legacy_pdu_type(&self) -> Option<LELegacyExtAdvEventTypePDUType> {
        match self.raw {
            0b0010011 => Some(LELegacyExtAdvEventTypePDUType::AdvertisingInd),
            0b0010101 => Some(LELegacyExtAdvEventTypePDUType::ConnectableAdvertisingInd),
            0b0010010 => Some(LELegacyExtAdvEventTypePDUType::AdvertisingScanInd),
            0b0010000 => Some(LELegacyExtAdvEventTypePDUType::AdvertisingNonConnectableNonScannableInd),
            0b0011011 => Some(LELegacyExtAdvEventTypePDUType::ScanResponseToAdvertisingInd),
            0b0011010 => Some(LELegacyExtAdvEventTypePDUType::ScanResponseToAdvertisingScanInd),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEAdvertiseInterval {
    interval: u16,
}

impl LEAdvertiseInterval {
    const CNV: u64 = 1250; // unit: microseconds

    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16) -> Self {
        debug_assert!(raw >= 0x0006);

        LEAdvertiseInterval { interval: raw }
    }

    /// Get the minimum interval value as a duration
    pub fn as_duration(&self) -> core::time::Duration {
        core::time::Duration::from_micros((self.interval as u64) * Self::CNV)
    }
}

/// LE Extended Advertising Report Event Data
///
/// # Option Explanations
/// - If the address_type is None, this indicates that no address was provided and the advertisement
/// was anonomyous
/// - If the secondary_phy is None, then there is no packets on the secondary advertising channel
/// - If the advertising_sid is None, then there is no Advertising Data Info (ADI) field in the PDU
/// - If Tx_power is None, tx power is not available
/// - If rssi is None, rssi is not available
/// - If the periodic_advertising_interval is None, then there si no periodic advertising
#[derive(Debug, Clone)]
pub struct LEExtendedAdvertisingReportData {
    pub event_type: LEExtAdvEventType,
    pub address_type: Option<AddressType>,
    pub address: BluetoothDeviceAddress,
    pub primary_phy: LEPhy,
    pub secondary_phy: Option<LEPhy>,
    pub advertising_sid: Option<u8>,
    pub tx_power: Option<i8>,
    pub rssi: Option<i8>,
    pub periodic_advertising_interval: Option<LEAdvertiseInterval>,
    pub direct_address_type: LEDirectAddressType,
    pub direct_address: BluetoothDeviceAddress,
    pub data: ExtendedAdvertisingAndScanResponseData,
}

impl LEExtendedAdvertisingReportData {
    fn buf_from(data: &[u8]) -> BufferType<Result<LEExtendedAdvertisingReportData, alloc::string::String>> {
        let mut packet = data;

        let mut reports = alloc::vec::Vec::with_capacity(chew!(packet) as usize);

        let mut process_packet = || {
            Ok(LEExtendedAdvertisingReportData {
                event_type: LEExtAdvEventType::from(chew_u16!(packet)),
                address_type: {
                    let val = chew!(packet);

                    if val != 0xFF {
                        Some(AddressType::try_from_raw(val)?)
                    } else {
                        // A value of 0xFF indicates that no address was provided
                        None
                    }
                },
                address: chew_baddr!(packet),
                primary_phy: LEPhy::try_from(chew!(packet))?,
                secondary_phy: {
                    let val = chew!(packet);

                    if val != 0 {
                        Some(LEPhy::try_from(val)?)
                    } else {
                        // A value of 0 indicates that there are no packets on the secondary
                        // advertising channel
                        None
                    }
                },
                advertising_sid: {
                    let val = chew!(packet);

                    if val != 0xFF {
                        Some(val)
                    } else {
                        // A value of 0xFF indicates no ADI field in the PDU
                        None
                    }
                },
                tx_power: {
                    let val = chew!(packet) as i8;

                    if val != 127 {
                        Some(val)
                    } else {
                        // A value of 127 means that tx power isn't available
                        None
                    }
                },
                rssi: {
                    let val = chew!(packet) as i8;

                    if val != 127 {
                        Some(val)
                    } else {
                        // A value of 127 means that rssi isn't available
                        None
                    }
                },
                periodic_advertising_interval: {
                    let val = chew_u16!(packet);

                    if val != 0 {
                        Some(LEAdvertiseInterval::from(val))
                    } else {
                        // A value of 0 indicates no periodic advertising
                        None
                    }
                },
                direct_address_type: LEDirectAddressType::try_from(chew!(packet))?,
                direct_address: chew_baddr!(packet),
                data: {
                    let data_len = chew!(packet);

                    ExtendedAdvertisingAndScanResponseData::from(chew!(packet, data_len))
                },
            })
        };

        for _ in 0..reports.capacity() {
            reports.push(process_packet());
        }

        reports
    }
}

#[derive(Debug, Clone)]
pub struct LEPeriodicAdvertisingSyncEstablishedData {
    pub status: Error,
    pub sync_handle: ConnectionHandle,
    pub advertising_sid: u8,
    pub advertiser_address_type: AddressType,
    pub advertiser_address: BluetoothDeviceAddress,
    pub advertiser_phy: LEPhy,
    pub periodic_advertising_interval: LEAdvertiseInterval,
    pub advertiser_clock_accuracy: ClockAccuracy,
}

impl LEPeriodicAdvertisingSyncEstablishedData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEPeriodicAdvertisingSyncEstablishedData {
            status: Error::from(chew!(packet)),
            sync_handle: chew_handle!(packet),
            advertising_sid: chew!(packet),
            advertiser_address_type: AddressType::try_from_raw(chew!(packet))?,
            advertiser_address: chew_baddr!(packet),
            advertiser_phy: LEPhy::try_from(chew!(packet))?,
            periodic_advertising_interval: LEAdvertiseInterval::from(chew_u16!(packet)),
            advertiser_clock_accuracy: ClockAccuracy::try_from(chew!(packet))?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEPeriodicAdvertisingReportData {
    pub sync_handle: ConnectionHandle,
    pub tx_power: Option<i8>,
    pub rssi: Option<i8>,
    pub data_status: LEDataStatus,
    pub data: BufferType<u8>,
}

impl LEPeriodicAdvertisingReportData {
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;
        Ok(LEPeriodicAdvertisingReportData {
            sync_handle: chew_handle!(packet),
            tx_power: {
                let val = chew!(packet) as i8;
                if val != 127 {
                    Some(val)
                } else {
                    None
                }
            },
            rssi: {
                let val = chew!(packet) as i8;
                if val != 127 {
                    Some(val)
                } else {
                    None
                }
            },
            // There is a unused byte here, so the next chew needs to account for that
            data_status: LEDataStatus::try_from(chew!(packet, 1, 1)[0])?,
            data: {
                let len = chew!(packet) as usize;
                packet[..len].to_vec()
            },
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEPeriodicAdvertisingSyncLostData {
    sync_handle: ConnectionHandle,
}

impl LEPeriodicAdvertisingSyncLostData {
    #[allow(unused_assignments)]
    fn from(data: &[u8]) -> Self {
        let mut packet = data;
        LEPeriodicAdvertisingSyncLostData {
            sync_handle: chew_handle!(packet),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEAdvertisingSetTerminatedData {
    pub status: Error,
    pub advertising_handle: u8,
    pub connection_handle: ConnectionHandle,
    pub num_completed_extended_advertising_events: u8,
}

impl LEAdvertisingSetTerminatedData {
    #[allow(unused_assignments)]
    fn from(data: &[u8]) -> Self {
        let mut packet = data;

        LEAdvertisingSetTerminatedData {
            status: Error::from(chew!(packet)),
            advertising_handle: chew!(packet),
            connection_handle: chew_handle!(packet),
            num_completed_extended_advertising_events: chew!(packet),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEScanRequestReceivedData {
    pub advertising_handle: u8,
    pub scanner_address_type: AddressType,
    pub scanner_address: BluetoothDeviceAddress,
}

impl LEScanRequestReceivedData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEScanRequestReceivedData {
            advertising_handle: chew!(packet),
            scanner_address_type: AddressType::try_from_raw(chew!(packet))?,
            scanner_address: chew_baddr!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub enum LEChannelSelectionAlgorithm {
    Algorithm1,
    Algorithm2,
}

impl LEChannelSelectionAlgorithm {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEChannelSelectionAlgorithm::Algorithm1),
            0x01 => Ok(LEChannelSelectionAlgorithm::Algorithm2),
            _ => Err(alloc::format!("Unknown LE Channel Selection Algorithm: {}", raw)),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LEChannelSelectionAlgorithmData {
    pub connection_handle: ConnectionHandle,
    pub channel_selection_algorithm: LEChannelSelectionAlgorithm,
}

impl LEChannelSelectionAlgorithmData {
    #[allow(unused_assignments)]
    fn try_from(data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEChannelSelectionAlgorithmData {
            connection_handle: chew_handle!(packet),
            channel_selection_algorithm: LEChannelSelectionAlgorithm::try_from(chew!(packet))?,
        })
    }
}

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
    pub enum LEMeta ( #[derive(Debug,Clone)] enum LeMetaData ) {
        ConnectionComplete{LEConnectionCompleteData},
        AdvertisingReport{BufferType<Result<LEAdvertisingReportData, alloc::string::String>>},
        ConnectionUpdateComplete{LEConnectionUpdateCompleteData},
        ReadRemoteFeaturesComplete{LEReadRemoteFeaturesCompleteData},
        LongTermKeyRequest{LELongTermKeyRequestData},
        RemoteConnectionParameterRequest{LERemoteConnectionParameterRequestData},
        DataLengthChange{LEDataLengthChangeData},
        ReadLocalP256PublicKeyComplete{LEReadLocalP256PublicKeyCompleteData},
        GenerateDHKeyComplete{LEGenerateDHKeyCompleteData},
        EnhancedConnectionComplete{LEEnhancedConnectionCompleteData},
        DirectedAdvertisingReport{BufferType<Result<LEDirectedAdvertisingReportData, alloc::string::String>>},
        PHYUpdateComplete{LEPHYUpdateCompleteData},
        ExtendedAdvertisingReport{BufferType<Result<LEExtendedAdvertisingReportData, alloc::string::String>>},
        PeriodicAdvertisingSyncEstablished{LEPeriodicAdvertisingSyncEstablishedData},
        PeriodicAdvertisingReport{LEPeriodicAdvertisingReportData},
        PeriodicAdvertisingSyncLost{LEPeriodicAdvertisingSyncLostData},
        ScanTimeout,
        AdvertisingSetTerminated{LEAdvertisingSetTerminatedData},
        ScanRequestReceived{LEScanRequestReceivedData},
        ChannelSelectionAlgorithm{LEChannelSelectionAlgorithmData},
    }
}

impl LEMeta {
    pub fn try_from(raw: u8) -> Result<LEMeta, alloc::string::String> {
        match raw {
            0x01 => Ok(LEMeta::ConnectionComplete),
            0x02 => Ok(LEMeta::AdvertisingReport),
            0x03 => Ok(LEMeta::ConnectionUpdateComplete),
            0x04 => Ok(LEMeta::ReadRemoteFeaturesComplete),
            0x05 => Ok(LEMeta::LongTermKeyRequest),
            0x06 => Ok(LEMeta::RemoteConnectionParameterRequest),
            0x07 => Ok(LEMeta::DataLengthChange),
            0x08 => Ok(LEMeta::ReadLocalP256PublicKeyComplete),
            0x09 => Ok(LEMeta::GenerateDHKeyComplete),
            0x0A => Ok(LEMeta::EnhancedConnectionComplete),
            0x0B => Ok(LEMeta::DirectedAdvertisingReport),
            0x0C => Ok(LEMeta::PHYUpdateComplete),
            0x0D => Ok(LEMeta::ExtendedAdvertisingReport),
            0x0E => Ok(LEMeta::PeriodicAdvertisingSyncEstablished),
            0x0F => Ok(LEMeta::PeriodicAdvertisingReport),
            0x10 => Ok(LEMeta::PeriodicAdvertisingSyncLost),
            0x11 => Ok(LEMeta::ScanTimeout),
            0x12 => Ok(LEMeta::AdvertisingSetTerminated),
            0x13 => Ok(LEMeta::ScanRequestReceived),
            0x14 => Ok(LEMeta::ChannelSelectionAlgorithm),
            _ => Err(alloc::format!("Unknown LE Meta: {}", raw)),
        }
    }
}

impl LeMetaData {
    fn into_simple(&self) -> LEMeta {
        match *self {
            LeMetaData::ConnectionComplete(_) => LEMeta::ConnectionComplete,
            LeMetaData::AdvertisingReport(_) => LEMeta::AdvertisingReport,
            LeMetaData::ConnectionUpdateComplete(_) => LEMeta::ConnectionUpdateComplete,
            LeMetaData::ReadRemoteFeaturesComplete(_) => LEMeta::ReadRemoteFeaturesComplete,
            LeMetaData::LongTermKeyRequest(_) => LEMeta::LongTermKeyRequest,
            LeMetaData::RemoteConnectionParameterRequest(_) => LEMeta::RemoteConnectionParameterRequest,
            LeMetaData::DataLengthChange(_) => LEMeta::DataLengthChange,
            LeMetaData::ReadLocalP256PublicKeyComplete(_) => LEMeta::ReadLocalP256PublicKeyComplete,
            LeMetaData::GenerateDHKeyComplete(_) => LEMeta::GenerateDHKeyComplete,
            LeMetaData::EnhancedConnectionComplete(_) => LEMeta::EnhancedConnectionComplete,
            LeMetaData::DirectedAdvertisingReport(_) => LEMeta::DirectedAdvertisingReport,
            LeMetaData::PHYUpdateComplete(_) => LEMeta::PHYUpdateComplete,
            LeMetaData::ExtendedAdvertisingReport(_) => LEMeta::ExtendedAdvertisingReport,
            LeMetaData::PeriodicAdvertisingSyncEstablished(_) => LEMeta::PeriodicAdvertisingSyncEstablished,
            LeMetaData::PeriodicAdvertisingReport(_) => LEMeta::PeriodicAdvertisingReport,
            LeMetaData::PeriodicAdvertisingSyncLost(_) => LEMeta::PeriodicAdvertisingSyncLost,
            LeMetaData::ScanTimeout => LEMeta::ScanTimeout,
            LeMetaData::AdvertisingSetTerminated(_) => LEMeta::AdvertisingSetTerminated,
            LeMetaData::ScanRequestReceived(_) => LEMeta::ScanRequestReceived,
            LeMetaData::ChannelSelectionAlgorithm(_) => LEMeta::ChannelSelectionAlgorithm,
        }
    }
}

impl_try_from_for_raw_packet! {
    LeMetaData,
    packet,
    {
        use self::LeMetaData::*;
        match chew!(packet) {
            0x01 => Ok(ConnectionComplete(LEConnectionCompleteData::try_from(packet)?)),
            0x02 => Ok(AdvertisingReport(LEAdvertisingReportData::buf_from(packet))),
            0x03 => Ok(ConnectionUpdateComplete(LEConnectionUpdateCompleteData::try_from(packet)?)),
            0x04 => Ok(ReadRemoteFeaturesComplete(LEReadRemoteFeaturesCompleteData::try_from(packet)?)),
            0x05 => Ok(LongTermKeyRequest(LELongTermKeyRequestData::from(packet))),
            0x06 => Ok(RemoteConnectionParameterRequest(LERemoteConnectionParameterRequestData::try_from(packet)?)),
            0x07 => Ok(DataLengthChange(LEDataLengthChangeData::try_from(packet)?)),
            0x08 => Ok(ReadLocalP256PublicKeyComplete(LEReadLocalP256PublicKeyCompleteData::from(packet))),
            0x09 => Ok(GenerateDHKeyComplete(LEGenerateDHKeyCompleteData::from(packet))),
            0x0A => Ok(EnhancedConnectionComplete(LEEnhancedConnectionCompleteData::try_from(packet)?)),
            0x0B => Ok(DirectedAdvertisingReport(LEDirectedAdvertisingReportData::buf_from(packet))),
            0x0C => Ok(PHYUpdateComplete(LEPHYUpdateCompleteData::try_from(packet)?)),
            0x0D => Ok(ExtendedAdvertisingReport(LEExtendedAdvertisingReportData::buf_from(packet))),
            0x0E => Ok(PeriodicAdvertisingSyncEstablished(LEPeriodicAdvertisingSyncEstablishedData::try_from(packet)?)),
            0x0F => Ok(PeriodicAdvertisingReport(LEPeriodicAdvertisingReportData::try_from(packet)?)),
            0x10 => Ok(PeriodicAdvertisingSyncLost(LEPeriodicAdvertisingSyncLostData::from(packet))),
            0x11 => Ok(ScanTimeout),
            0x12 => Ok(AdvertisingSetTerminated(LEAdvertisingSetTerminatedData::from(packet))),
            0x13 => Ok(ScanRequestReceived(LEScanRequestReceivedData::try_from(packet)?)),
            0x14 => Ok(ChannelSelectionAlgorithm(LEChannelSelectionAlgorithmData::try_from(packet)?)),
            _    => Err(alloc::format!("Unknown LE meta event ID: {}", packet[0])),
        }
    }
}

impl From<LEMeta> for Events {
    fn from(meta: LEMeta) -> Events {
        Events::LEMeta(meta)
    }
}

#[derive(Debug, Clone)]
pub struct TriggeredClockCaptureData {}

impl_try_from_for_raw_packet! {
    TriggeredClockCaptureData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct SynchronizationTrainCompleteData {}

impl_try_from_for_raw_packet! {
    SynchronizationTrainCompleteData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct SynchronizationTrainReceivedData {}

impl_try_from_for_raw_packet! {
    SynchronizationTrainReceivedData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionlessSlaveBroadcastReceiveData {}

impl_try_from_for_raw_packet! {
    ConnectionlessSlaveBroadcastReceiveData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionlessSlaveBroadcastTimeoutData {}

impl_try_from_for_raw_packet! {
    ConnectionlessSlaveBroadcastTimeoutData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct TruncatedPageCompleteData {}

impl_try_from_for_raw_packet! {
    TruncatedPageCompleteData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct SlavePageRespoinseTimeoutData {}

impl_try_from_for_raw_packet! {
    SlavePageRespoinseTimeoutData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionlessSlaveBroadcastChannelMapChangeData {}

impl_try_from_for_raw_packet! {
    ConnectionlessSlaveBroadcastChannelMapChangeData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct InquiryResponseNotificationData {}

impl_try_from_for_raw_packet! {
    InquiryResponseNotificationData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Debug, Clone)]
pub struct AuthenticatedPayloadTimeoutExpiredData {
    connection_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    AuthenticatedPayloadTimeoutExpiredData,
    packet,
    {
        Ok(AuthenticatedPayloadTimeoutExpiredData {
            connection_handle: chew_handle!(packet)
        })
    }
}

#[derive(Debug, Clone)]
pub struct SAMStatusChangeData {}

impl_try_from_for_raw_packet! {
    SAMStatusChangeData,
    _packet_placeholder,
    {
        unimplemented!()
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

        impl crate::hci::events::$EnumName {
            /// Return the event code
            ///
            /// # Note
            /// This does not return the sub event code for a [`LEMeta`](Events::LEMeta) event
            pub fn get_event_code( &self ) -> u8 {
                match *self {
                    $(crate::hci::events::$EnumName::$name $(( $(put_!($enum_val))* ))* => $val,)*
                }
            }

            /// Try to create an event from an event code.
            ///
            /// The first input of this method is for the event code and the second is the LE Meta
            /// sub event code. When the first input matches [`LEMeta`](Events::LEMeta) the second
            /// input is used to determine the LEMeta sub event otherwise input `sub_event` is
            /// ignored.
            pub fn try_from_event_codes<S>(event: u8, sub_event: S)
            -> core::result::Result<crate::hci::events::$EnumName, EventError>
            where
                S: Into<Option<u8>>
            {
                match event {
                    $( $val => Ok( crate::hci::events::$EnumName::$name $(( $($enum_val::try_from(sub_event.into())?)* ))* ), )*
                    _ => Err(EventCodeError::new(event, sub_event.into()).into()),
                }
            }
        }

        impl crate::hci::events::$EnumDataName {

            pub fn get_event_name(&self) -> $EnumName {
                #[cfg(not(test))]
                match *self {
                    $( crate::hci::events::$EnumDataName::$name(ref _data) =>
                        crate::hci::events::$EnumName::$name $(( $(data_into_simple!($enum_val, _data)),* ))*, )*
                }

                #[cfg(test)]
                match *self {
                    $( crate::hci::events::$EnumDataName::$name(ref _data) =>
                        crate::hci::events::$EnumName::$name $(( $(data_into_simple!($enum_val, _data)),* ))*, )*
                }
            }

            /// Make an event from a raw HCI event packet
            ///
            /// The input `data` should contain *only* the data that is part of the HCI Event
            /// Packet as specified in the Bluetooth core specification (V 5.0, vol 2, Part E).
            /// Do not include the *HCI packet indicator* as that will (most likely) cause this
            /// method to panic.
            pub fn try_from_packet( data: &[u8] ) -> Result<Self, EventError> {

                use core::convert::TryFrom;

                debug_assert!( data.len() > 1 ,
                    "Error occurred in macro invocation of hci::events::events_markup");

                let mut packet = data;

                // packet[1] is the LEMeta specific sub event code if the event is LEMeta
                let event_code = crate::hci::events::$EnumName::try_from_event_codes(chew!(packet), packet[1])?;

                // The length of the packet and convert it into a usize
                let event_len = chew!(packet).into();

                match event_code {
                    $( Ok(crate::hci::events::$EnumName::$name $( ( $(put_!($enum_val)),* ) )*) =>
                        Ok(crate::hci::events::$EnumDataName::$name(
                            crate::hci::events::$data::<$( $type ),*>::try_from( RawData::from(&packet[..event_len]) )?)),
                    )*
                    Err(err) => Err(err.into()),
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
        PhysicalLinkComplete{PhysicalLinkCompleteData} -> 0x40,
        ChannelSelected{ChannelSelectedData} -> 0x41,
        DisconnectionPhysicalLinkComplete{DisconnectionPhysicalLinkCompleteData} -> 0x42,
        PhysicalLInkLossEarlyWarning{PhysicalLInkLossEarlyWarningData} -> 0x43,
        PhysicalLinkRecovery{PhysicalLinkRecoveryData} -> 0x44,
        LogicalLinkComplete{LogicalLinkCompleteData} -> 0x45,
        DisconnectionLogicalLinkComplete{DisconnectionLogicalLinkCompleteData} -> 0x46,
        FlowSpecModifyComplete{FlowSpecModifyCompleteData} -> 0x47,
        NumberOfCompletedDataBlocks{NumberOfCompletedDataBlocksData} -> 0x48,
        ShortRangeModeChangeComplete{ShortRangeModeChangeCompleteData} -> 0x4C,
        AMPStatusChange{AMPStatusChangeData} -> 0x4D,
        AMPStartTest{AMPStartTestData} -> 0x49,
        AMPTestEnd{AMPTestEndData} -> 0x4A,
        AMPReceiverReport{AMPReceiverReportData} -> 0x4B,
        LEMeta(LEMeta){LeMetaData} -> 0x3E,
        TriggeredClockCapture{TriggeredClockCaptureData} -> 0x4E,
        SynchronizationTrainComplete{SynchronizationTrainCompleteData} -> 0x4F,
        SynchronizationTrainReceived{SynchronizationTrainReceivedData} -> 0x50,
        ConnectionlessSlaveBroadcastReceive{ConnectionlessSlaveBroadcastReceiveData} -> 0x51,
        ConnectionlessSlaveBroadcastTimeout{ConnectionlessSlaveBroadcastTimeoutData} -> 0x52,
        TruncatedPageComplete{TruncatedPageCompleteData} -> 0x53,
        SlavePageRespoinseTimeout{SlavePageRespoinseTimeoutData} -> 0x54,
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
    // Temporary error message until strings are no longer used for event errors
    Error(alloc::string::String),
    EventCode(EventCodeError),
}

/// Error returned when trying to convert event codes into an `Events`
#[derive(Debug)]
pub struct EventCodeError {
    code: u8,
    sub_code: Option<u8>,
}

impl EventCodeError {
    fn new(code: u8, sub_code: u8) -> Self {
        const IRRELEVANT: LEMeta = LEMeta::ConnectionComplete;

        if code == Events::LEMeta(IRRELEVANT).get_event_code() {
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
            write!(f, "Unknown event code: {}", self.code)
        }
    }
}
