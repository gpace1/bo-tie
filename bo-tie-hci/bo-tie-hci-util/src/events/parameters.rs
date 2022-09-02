//! The event parameters data types
//!
//! `parameters` contains the data structures used to represent the event parameters.

use crate::le::{
    AddressType, ConnectionInterval, ConnectionLatency, ExtendedAdvertisingAndScanResponseData, SupervisionTimeout,
};
use crate::{ConnectionHandle, EncryptionLevel};
use bo_tie_util::errors::Error;
use bo_tie_util::{BluetoothDeviceAddress, DeviceFeatures, LeDeviceFeatures};

type BufferType<T> = alloc::vec::Vec<T>;

#[derive(Debug, Clone)]
pub struct Multiple<T> {
    data: BufferType<T>,
}

impl<T> core::ops::Deref for Multiple<T> {
    type Target = [T];

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> IntoIterator for Multiple<T> {
    type Item = T;
    type IntoIter = <BufferType<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

impl<'a, T> IntoIterator for &'a Multiple<T> {
    type Item = &'a T;
    type IntoIter = <&'a BufferType<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&self.data).into_iter()
    }
}

impl<'a, T> IntoIterator for &'a mut Multiple<T> {
    type Item = &'a mut T;
    type IntoIter = <&'a mut BufferType<T> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        (&mut self.data).into_iter()
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
    pub lmp_features: DeviceFeatures,
}

impl_try_from_for_raw_packet! {
    ReadRemoteSupportedFeaturesCompleteData,
    packet,
    {
        Ok(ReadRemoteSupportedFeaturesCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            // These are the default LMP features which is always page 0
            lmp_features: DeviceFeatures::new(0, chew!(packet,8)).unwrap(),
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

#[derive(Debug, Clone)]
pub struct CommandCompleteData {
    pub number_of_hci_command_packets: u8,
    pub command_opcode: Option<u16>,
    pub return_parameter: BufferType<u8>,
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
            return_parameter: if opcode_exists {
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
    pub completed_packets: u16,
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
                        completed_packets: chew_u16!(chunk),
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
    pub opcode: u16,
    pub hci_command_packet: BufferType<u8>,
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
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    /// Bits 16-2 of CLKNslave-CLK
    pub clock_offset: u32,
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
    pub connection_handle: ConnectionHandle,
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
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repetition_mode: PageScanRepetitionMode,
}

impl_try_from_for_raw_packet! {
    PageScanRepetitionModeChangeData,
    packet,
    {
        Ok(PageScanRepetitionModeChangeData {
            bluetooth_address: chew_baddr!(packet,0),
            page_scan_repetition_mode: PageScanRepetitionMode::try_from(chew!(packet))?,
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
pub struct ReadRemoteExtendedFeaturesCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub page_number: u8,
    pub maximum_page_number: u8,
    pub extended_lmp_features: DeviceFeatures,
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
            // DeviceFeatures::new does not need the exact size
            // for the features map associated to the page
            extended_lmp_features: DeviceFeatures::new(page.into(), chew!(packet, 8)).unwrap()
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
    pub extended_inquiry_response_data: [u8; 240],
}

impl ExtendedInquiryResultData {
    /// Iterate over the extended inquiry response structures
    ///
    /// This returns an iterator that iterates over [`EirStruct`]s. `EirStruct`s can be converted
    /// into either an assigned data type (see the Supplement to the Bluetooth Core Specification)
    /// or a custom extended inquiry response data type.
    ///
    /// [`EirStruct`]: bo_tie_gap::eir::EirStruct
    #[cfg(feature = "gap")]
    pub fn eir_iter(&self) -> bo_tie_gap::eir::EirStructIter<'_> {
        bo_tie_gap::eir::EirStructIter::new(&self.extended_inquiry_response_data)
    }
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
            extended_inquiry_response_data: {
                let mut buffer = [0u8; 240];

                buffer.copy_from_slice(chew!(packet,240));

                buffer
            },
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
    pub host_supported_features: DeviceFeatures,
}

impl_try_from_for_raw_packet! {
    RemoteHostSupportedFeaturesNotificationData,
    packet,
    {
        Ok(RemoteHostSupportedFeaturesNotificationData {
            bluetooth_address: chew_baddr!(packet),
            // These are always the enabled host LMP features
            // which is always page 1 (see Remote Name Request
            // Bluetooth Specification Vol 2, Part F, section 2)
            host_supported_features: DeviceFeatures::new(1, chew!(packet,8)).unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct CompletedDataPacketsAndBlocks {
    pub connection_handle: ConnectionHandle,
    /// This is the number of completed packets (transmitted or flushed) since the last time
    /// number of completed data blocks command was called.
    pub completed_packets: u16,
    /// Number of data blocks on the controller freed since the last time number of completed data
    /// blocks command was called
    pub completed_blocks: u16,
}

/// The number of completed data blocks
///
/// This event is periodically sent by the controller to update the status of the data block buffers
/// within it.
///
/// # The total number of data blocks
/// The controller is allowed to change the total number of data blocks provided for buffering HCI
/// ACL data packets. When `total_data_blocks` contains a number, it represents the new total
/// of data blocks provided. This value is always greater than the sum of the
/// [`completed_blocks`](CompletedDataPacketsAndBlocks::completed_blocks) within
/// `completed_packets_and_blocks`.
///
/// When `total_data_blocks` is `None` then the Host must resend the
/// [`read_data_block_size`](crate::hci::info_params::read_data_block_size) command to acquire the
/// new total number of data blocks. `total_data_blocks` is `None` only when the new total number
/// of data blocks is less than the sum of `completed_blocks` within `completed_packets_and_blocks`.
/// No new HCI ACL data packets shall be sent to the controller until after the
/// `read_data_block_size` command is completed.
///
/// # Note
/// This structure does not contain the field `Num_Handles` of the event parameters (as seen the
/// specification for the event) because it is equivalent to the length of
/// `completed_packets_and_blocks`.
#[derive(Debug, Clone)]
pub struct NumberOfCompletedDataBlocksData {
    pub total_data_blocks: Option<u16>,
    pub completed_packets_and_blocks: BufferType<CompletedDataPacketsAndBlocks>,
}

impl_try_from_for_raw_packet! {
    NumberOfCompletedDataBlocksData,
    packet,
    {
        Ok(NumberOfCompletedDataBlocksData {
            total_data_blocks: match chew_u16!(packet) {
                0 => None,
                cnt => Some(cnt)
            },
            completed_packets_and_blocks: {
                let handle_cnt = chew!(packet) as usize;
                let mut vec = packet.chunks_exact(6)
                .map(|mut chunk| {
                    CompletedDataPacketsAndBlocks {
                        connection_handle: chew_handle!(chunk),
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

impl_try_from_for_raw_packet! {
    LEConnectionCompleteData,
    packet,
    {
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
    /// Get an iterator over the AD structures
    ///
    /// This returns an iterator that will return the AD structures within field `data`.
    #[cfg(feature = "gap")]
    pub fn iter(&self) -> bo_tie_gap::assigned::EirOrAdIterator<'_> {
        bo_tie_gap::assigned::EirOrAdIterator::new(&self.data)
    }
}

impl_try_from_for_raw_packet! {
    Multiple<Result<LEAdvertisingReportData, alloc::string::String>>,
    packet,
    {
        // The value of 127 indicates no RSSI functionality
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

        Ok(Multiple { data: reports})
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

impl_try_from_for_raw_packet! {
    LEConnectionUpdateCompleteData,
    packet,
    {
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
    pub features: LeDeviceFeatures,
}

impl_try_from_for_raw_packet! {
    LEReadRemoteFeaturesCompleteData,
    packet,
    {
        Ok(LEReadRemoteFeaturesCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            features: LeDeviceFeatures::new(chew!(packet, 8)).unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LELongTermKeyRequestData {
    pub connection_handle: ConnectionHandle,
    pub random_number: u64,
    pub encryption_diversifier: u16,
}

impl_try_from_for_raw_packet! {
    LELongTermKeyRequestData,
    packet,
    {
        Ok(LELongTermKeyRequestData {
            connection_handle: chew_handle!(packet),
            random_number: chew_u64!(packet),
            encryption_diversifier: chew_u16!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LERemoteConnectionParameterRequestData {
    pub connection_handle: ConnectionHandle,
    pub minimum_interval: ConnectionInterval,
    pub maximum_interval: ConnectionInterval,
    pub latency: ConnectionLatency,
    pub timeout: SupervisionTimeout,
}

impl_try_from_for_raw_packet! {
    LERemoteConnectionParameterRequestData,
    packet,
    {
        Ok(LERemoteConnectionParameterRequestData {
            connection_handle: chew_handle!(packet),
            minimum_interval: ConnectionInterval::try_from_raw(chew_u16!(packet))
                .map_err(|e| alloc::string::String::from(e))?,
            maximum_interval: ConnectionInterval::try_from_raw(chew_u16!(packet))
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

impl_try_from_for_raw_packet! {
    LEDataLengthChangeData,
    packet,
    {
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

impl_try_from_for_raw_packet! {
    LEReadLocalP256PublicKeyCompleteData,
    packet,
    {
        Ok(LEReadLocalP256PublicKeyCompleteData {
            status: Error::from(chew!(packet)),
            key: {
                let mut pub_key = [0u8; 64];
                pub_key.copy_from_slice(chew!(packet, 256));
                pub_key
            },
        })
    }
}

#[derive(Debug, Clone)]
/// DHKey stands for diffie Hellman Key
pub struct LEGenerateDHKeyCompleteData {
    pub status: Error,
    pub key: [u8; 32],
}

impl_try_from_for_raw_packet! {
    LEGenerateDHKeyCompleteData,
    packet,
    {
        Ok(LEGenerateDHKeyCompleteData {
            status: Error::from(chew!(packet)),
            key: {
                let mut dh_key = [0u8; 32];
                dh_key.copy_from_slice(&packet[2..34]);
                dh_key
            },
        })
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
    pub connection_interval: ConnectionInterval,
    pub connection_latency: ConnectionLatency,
    pub supervision_timeout: SupervisionTimeout,
    pub master_clock_accuracy: ClockAccuracy,
}

impl_try_from_for_raw_packet! {
    LEEnhancedConnectionCompleteData,
    packet,
    {
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
            connection_interval: ConnectionInterval::try_from_raw(chew_u16!(packet)).unwrap(),
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

impl_try_from_for_raw_packet! {
    Multiple<Result<LEDirectedAdvertisingReportData, alloc::string::String>>,
    packet,
    {
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
            .collect::<alloc::vec::Vec<_>>();

        vec.truncate(report_count);

        Ok(Multiple { data: vec })
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

impl_try_from_for_raw_packet! {
    LEPHYUpdateCompleteData,
    packet,
    {
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

impl_try_from_for_raw_packet! {
    Multiple<Result<LEExtendedAdvertisingReportData, alloc::string::String>>,
    packet,
    {
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

        Ok(Multiple { data: reports })
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

impl_try_from_for_raw_packet! {
    LEPeriodicAdvertisingSyncEstablishedData,
    packet,
    {
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

impl_try_from_for_raw_packet! {
    LEPeriodicAdvertisingReportData,
    packet,
    {
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
    pub sync_handle: ConnectionHandle,
}

impl_try_from_for_raw_packet! {
    LEPeriodicAdvertisingSyncLostData,
    packet,
    {
        Ok(LEPeriodicAdvertisingSyncLostData {
            sync_handle: chew_handle!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEAdvertisingSetTerminatedData {
    pub status: Error,
    pub advertising_handle: u8,
    pub connection_handle: ConnectionHandle,
    pub num_completed_extended_advertising_events: u8,
}

impl_try_from_for_raw_packet! {
    LEAdvertisingSetTerminatedData,
    packet,
    {
        Ok(LEAdvertisingSetTerminatedData {
            status: Error::from(chew!(packet)),
            advertising_handle: chew!(packet),
            connection_handle: chew_handle!(packet),
            num_completed_extended_advertising_events: chew!(packet),
        })
    }
}

#[derive(Debug, Clone)]
pub struct LEScanRequestReceivedData {
    pub advertising_handle: u8,
    pub scanner_address_type: AddressType,
    pub scanner_address: BluetoothDeviceAddress,
}

impl_try_from_for_raw_packet! {
    LEScanRequestReceivedData,
    packet,
    {
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

impl_try_from_for_raw_packet! {
    LEChannelSelectionAlgorithmData,
    packet,
    {
        Ok(LEChannelSelectionAlgorithmData {
            connection_handle: chew_handle!(packet),
            channel_selection_algorithm: LEChannelSelectionAlgorithm::try_from(chew!(packet))?,
        })
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
pub struct SlavePageResponseTimeoutData {}

impl_try_from_for_raw_packet! {
    SlavePageResponseTimeoutData,
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
    pub connection_handle: ConnectionHandle,
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
