//! Host Controller Interface Events

use crate::hci::common::{
    ConnectionHandle,
    ConnectionInterval,
    ConnectionLatency,
    EnabledExtendedFeaturesItr,
    EnabledFeaturesIter,
    EnabledLEFeaturesItr,
    EncryptionLevel,
    ExtendedAdvertisingAndScanResponseDataItr,
    ExtendedInquiryResponseDataItr,
    LEAddressType,
    SupervisionTimeout,
};
use crate::hci::error::Error;
use crate::hci::le;
use crate::BluetoothDeviceAddress;
use core::convert::From;
use core::time::Duration;

macro_rules! make_u16 {
    ( $packet:ident, $start:expr ) => {
        u16::from_le( $packet[$start] as u16 | ($packet[$start + 1] as u16) << 8 )
    };
}

macro_rules! make_u32 {
    ( $packet:ident, $start:expr) => {
        u32::from_le(
            ($packet[$start] as u32)           |
            ($packet[$start + 1] as u32) << 8  |
            ($packet[$start + 2] as u32) << 16 |
            ($packet[$start + 3] as u32) << 24
        )
    }
}

macro_rules! make_u64 {
    ( $packet:ident, $start:expr) => {
        u64::from_le(
            ($packet[$start] as u64)           |
            ($packet[$start + 1] as u64) << 8  |
            ($packet[$start + 2] as u64) << 16 |
            ($packet[$start + 3] as u64) << 24 |
            ($packet[$start + 4] as u64) << 32 |
            ($packet[$start + 5] as u64) << 40 |
            ($packet[$start + 6] as u64) << 48 |
            ($packet[$start + 7] as u64) << 56
        )
    }
}

macro_rules! make_baddr {
    ( $packet:ident, $start:expr ) => {
        {
            let mut address = [0u8;6];
            address.copy_from_slice(&$packet[$start..($start + 6)]);
            BluetoothDeviceAddress::from(address)
        }
    }
}

macro_rules! make_handle {
    ( $packet:ident, $start:expr ) => {
        ConnectionHandle::try_from(make_u16!($packet,$start)).unwrap()
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
        impl<'a> core::convert::TryFrom<&'a [u8]> for $name {
            type Error = alloc::string::String;
            fn try_from( param: &'a [u8] ) -> Result<Self, Self::Error> {
                let mut $param = param;
                $inner
            }
        }

    }
}

/// "chews-off" and returns a slice of size $size from the beginning of $packet.
///
/// Invoking this with only one parameter returns an u8, otherwise a reference to a slice is
/// returned.
macro_rules! chew {
    ( $packet:ident, $start:expr, $size:expr) => {
        {
            let chewed = &$packet[$start..($size as usize)];
            $packet = &$packet[($start as usize) + ($size as usize)..];
            chewed
        }
    };
    ( $packet:ident, $size:expr ) => { chew!($packet,0,$size)};
    ( $packet:ident ) => {
        {
            let chewed_byte = $packet[0];
            $packet = &$packet[1..];
            chewed_byte
        }
    };
}

macro_rules! chew_u16 {
    ($packet:ident, $start:expr) => {
        {
            let chewed = make_u16!($packet,$start as usize);
            $packet = &$packet[$start as usize + 2..];
            chewed
        }
    };
    ($packet:ident) => { chew_u16!($packet,0) };
}

macro_rules! chew_u32 {
    ($packet:ident, $start:expr) => {
        {
            let chewed = make_u32!($packet,$start as usize);
            $packet = &$packet[$start as usize + 4..];
            chewed
        }
    };
    ($packet:ident) => { chew_u32!($packet,0) };
}

macro_rules! chew_u64 {
    ($packet:ident, $start:expr) => {
        {
            let chewed = make_u64!($packet,$start as usize);
            $packet = &$packet[$start as usize + 8..];
            chewed
        }
    };
    ($packet:ident) => { chew_u64!($packet, 0)};
}

macro_rules! chew_baddr {
    ($packet:ident, $start:expr ) => {
        {
            let chewed = make_baddr!($packet,$start as usize);
            $packet = &$packet[$start as usize + 6..];
            chewed
        }
    };
    ($packet:ident) => { chew_baddr!($packet,0)}
}

macro_rules! chew_handle {
    ($packet:ident, $start:expr) => {
        {
            let chewed = make_handle!($packet,$start as usize);
            $packet = &$packet[$start as usize + 2..];
            chewed
        }
    };
    ($packet:ident) => { chew_handle!($packet,0)};
}

type BufferType<T> = ::alloc::boxed::Box<T>;

#[derive(Clone)]
pub struct Multiple<T: ?Sized> {
    data: BufferType<T>
}

#[derive(Clone)]
pub enum PageScanRepitionMode {
    R0,
    R1,
    R2,
}

impl PageScanRepitionMode {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        use self::PageScanRepitionMode::*;

        match raw {
            0x00 => Ok(R0),
            0x01 => Ok(R1),
            0x02 => Ok(R2),
            _ => Err(alloc::format!("Unkown Page Scan Repitition Mode: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub enum ClassOfDevice {
    Class(u32),
    Unknown,
}

/// Converts a tuple of a 24 bit data
///
/// The tuple consists of the lower 16 bits of the data and the upper 8 bits of the data
impl ClassOfDevice {
    fn from(raw : [u8;3]) -> Self {
        use self::ClassOfDevice::*;

        match raw {
            [0,0,0] => Unknown,
            _       => Class( u32::from_le(
                (raw[2] as u32) << 16 |
                (raw[1] as u32) << 8 |
                (raw[0] as u32)
            ))
        }
    }
}

#[derive(Clone)]
pub enum LinkType {
    SCOConnection,
    ACLConnection,
    ESCOConnection
}

impl LinkType {
    fn try_from(raw:u8) -> Result<Self, alloc::string::String> {
        use self::LinkType::*;

        match raw {
            0x00 => Ok(SCOConnection),
            0x01 => Ok(ACLConnection),
            0x02 => Ok(ESCOConnection),
            _ => Err(alloc::format!("Unknown Link Type: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub enum LinkLevelEncryptionEnabled {
    Yes,
    No,
}

impl LinkLevelEncryptionEnabled {
    fn try_from(raw:u8) -> core::result::Result<Self, alloc::string::String> {
        use self::LinkLevelEncryptionEnabled::*;

        match raw {
            0x00 => Ok(Yes),
            0x01 => Ok(No),
            _ => Err(alloc::format!("Unknown Link Level Encryption Enabled: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub struct EncryptionEnabled {
    raw: u8,
}

impl EncryptionEnabled {

    pub fn get_for_le(&self) -> EncryptionLevel {
        if self.raw == 0x01 {
            EncryptionLevel::AESCCM
        }
        else {
            EncryptionLevel::Off
        }
    }

    pub fn get_for_br_edr(&self) -> EncryptionLevel {
        match self.raw {
            0x00 => EncryptionLevel::Off,
            0x01 => EncryptionLevel::E0,
            0x02 => EncryptionLevel::AESCCM,
            _    => EncryptionLevel::Off,
        }
    }

}

impl From<u8> for EncryptionEnabled {
    fn from(raw: u8) -> Self {
        EncryptionEnabled {
            raw: raw,
        }
    }
}

#[derive(Clone)]
pub enum KeyFlag {
    SemiPermanentLinkKey,
    TemporaryLinkKey,
}

impl KeyFlag {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        use self::KeyFlag::*;

        match raw  {
            0x00 => Ok(SemiPermanentLinkKey),
            0x01 => Ok(TemporaryLinkKey),
            _    => Err(alloc::format!("Unknown Key Flag: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub enum ServiceType {
    NoTrafficAvailable,
    BestEffortAvailable,
    GuaranteedAvailable,
}

impl ServiceType {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        use self::ServiceType::*;
        match raw {
            0x00 => Ok(NoTrafficAvailable),
            0x01 => Ok(BestEffortAvailable),
            0x02 => Ok(GuaranteedAvailable),
            _    => Err(alloc::format!("Unknown Service Type: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub struct InquiryCompleteData {
    pub status: Error,
}

impl_try_from_for_raw_packet!{
    InquiryCompleteData,
    packet,
    {
        Ok(InquiryCompleteData { status: Error::from(chew!(packet)) })
    }
}

#[derive(Clone)]
pub struct InquiryResultData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repition_mode: PageScanRepitionMode,
    pub class_of_device: ClassOfDevice,
    pub clock_offset: u16,
}

impl_try_from_for_raw_packet!{
    Multiple<[Result<InquiryResultData, alloc::string::String>]>,
    packet,
    {
        Ok(Multiple {
            data: {
                // The size of a single Inquiry Result in the event packet is 14 bytes
                // Also the first byte (which would give the total )
                let mut vec = packet[1..].chunks_exact( 14 )
                    .map(|mut chunk| {

                        Ok(InquiryResultData {
                            bluetooth_address: chew_baddr!(chunk),

                            page_scan_repition_mode: PageScanRepitionMode::try_from(chew!(chunk))?,

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

                vec.into_boxed_slice()
            },
        })
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct DisconnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub reason: u8
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct MasterLinkKeyCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub key: KeyFlag
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

#[derive(Clone)]
pub struct ReadRemoteSupportedFeaturesCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub lmp_features: EnabledFeaturesIter
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone,Copy,PartialEq)]
pub enum CommandDataErr<UnpackErrorType>
    where UnpackErrorType: core::fmt::Debug
{
    /// If the api doesn't have a bug in it, then the controller is faulty if this error occurs
    RawDataLenTooSmall,
    /// The first value is the expected ocf the second value is the actual ocf given in the event
    IncorrectOCF(u16,u16),
    UnpackError(UnpackErrorType),
}

impl<UnpackErrorType> core::fmt::Display for CommandDataErr<UnpackErrorType>
    where UnpackErrorType: core::fmt::Debug
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        match *self {
            CommandDataErr::RawDataLenTooSmall => {
                write!(f, "Command complete data error, the size of the data was too small for type")
            }
            CommandDataErr::IncorrectOCF(exp,act) => {
                write!(f, "Command complete data error, expected opcode is 0x{:X}, actual opcode is 0x{:X}",exp,act)
            }
            CommandDataErr::UnpackError(ref e) => {
                write!(f, "Command complete contained error code for '{:?}'", e)
            }
        }
    }
}

impl<UnpackErrorType> core::fmt::Debug for CommandDataErr<UnpackErrorType>
    where UnpackErrorType: core::fmt::Debug
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        (self as & dyn core::fmt::Display).fmt(f)
    }
}

pub(crate) trait DataResult
where <Self as crate::hci::events::DataResult>::UnpackErrorType: core::fmt::Debug + core::fmt::Display
{
    type ReturnData;
    type UnpackErrorType;
}

/// Try to get the return parameter data
///
/// This trait is for converting the raw byte information from a Command Complete Event into
/// a useable prameterized value. This method does a few checks to verify that command type
/// and data saze are correct for the expected return parameter.
///
/// There is a case where there is no associated data. This happens when the controller is only
/// telling the host the number of hci commands it can now process.
pub(crate) trait GetDataForCommand<T>
where T : DataResult
{
    /// Get the return parameter
    ///
    /// This function converts the raw bytes as given from the controller into an object of the
    /// generic type T.
    ///
    /// This functions will perform the checks as mentioned on the trait declaration. However if
    /// those two checks pass, this method isn't required to be implemented to do any further
    /// checking for full validity of the data. This is why it's marked unsafe
    ///
    /// Will return a None result if there is no data associated with the event
    ///
    /// # Errors
    /// - The command data doesn't match the return type
    /// - The buffered data is smaller then the size of the parameter data (packed, as in the spec)
    unsafe fn get_return(&self) -> Result<Option<T::ReturnData>,CommandDataErr<T::UnpackErrorType>>;

    /// Get the return parameter without checking the OpCode
    ///
    /// This is the same as get_return except that it doesn't validate that the command complete
    /// event was sent from the controller with the correct opcode. Use this only if you're absolutely
    /// positive that the controller is returning incorrect OpCode values only because the
    /// controller is implemented incorrectly.
    unsafe fn get_return_unchecked(&self) -> Result<Option<T::ReturnData>,CommandDataErr<T::UnpackErrorType>>;

    fn no_opcode(&self) -> bool {
        // This logic is safe because if there is no op_code then there is no unsafe data
        unsafe { match self.get_return() {
            Ok(None) => true,
            _ => false,
        } }
    }
}

#[derive(Clone)]
pub struct CommandCompleteData {
    pub number_of_hci_command_packets: u8,
    pub command_opcode: Option<u16>,
    /// only public for hci
    pub(super) raw_data: BufferType<[u8]>,
}

/// Implement GetDataForCommand
///
/// When using this macro keep in mind that the compiler will not understand how to correctly
/// convert the raw data into the usable data. The CommandCompleteData instance needs to be casted
/// to GetDataForCommand with the template type as the desired "usable data" to convert to.
/// Something like the following example needs to be done:
/// ```rust
/// # use ::hci::events::{GetDataForCommand, CommandCompleteData};
/// #
/// # /// Made up variables
/// # let command_data = events::EventsData::CommandComplete {
/// #   number_of_hci_command_packets: 0,
/// #   command_opcode: None,
/// #   raw_data: alloc::vec![1,2,3,4,5,6,7,8,9,10].into_boxed_slice(),
/// # };
/// # let ocf = 0;
/// # let ogf = 0;
/// # struct UseableDataType;
/// # type PackedDataType = u8;
/// # type TryFromReturnType = ();
/// # type TryFromErrorType = ();
/// # impl UseableDataType { fn try_from(packed: PackedDataType) -> Result(TryFromReturn, TryFromError)}
///
/// // If the type TryFromReturnType is the same as UseableDataType, then TryFromReturnType can be
/// // ommitted
/// impl_get_data_for_command!( ocf, ogf, PackedDataType, UseableDataType, TryFromReturnType, TryFromErrorType );
///
/// let return_data = (command_data as GetDataForCommand<UseableDataType>).get_return().unwrap();
///
/// ```
///
/// This macro also implements DataResult for the parameter "data"
///
/// # Parameters
/// - ocf: Opcode Command Field
/// - ogf: Opcode Group Field
/// - packed_data: The packed structure of the return parameter as sent by the controller.
/// - data: The type to convert the packed_data from.
///   - This type must implement the function 'try_from' in some fation (but this macro does not
///     perform for disambiguation if you implement the function multiple times). The return of
///     try_from can either be a result of "data" or the optional parameter "return_ty" with the
///     error type being try_from_err_ty
///   - This type should not be a packed data type.
/// - (optionl) return_ty: If the type "data" doesn't need to be returned and it would make sense
/// - try_from_err_ty: The error type of the return of the try_from function implemented for "data"
#[macro_use]
macro_rules! impl_get_data_for_command {
    ( $command:expr, $packed_data:ty, $data:ty, $return_ty:ty, $try_from_err_ty:ty ) => {
        impl crate::hci::events::DataResult for $data {
            type ReturnData = $return_ty;
            type UnpackErrorType = $try_from_err_ty;
        }

        impl crate::hci::events::GetDataForCommand<$data> for crate::hci::events::CommandCompleteData {
            unsafe fn get_return(&self) ->
                core::result::Result<
                    core::option::Option< <$data as crate::hci::events::DataResult>::ReturnData >,
                    crate::hci::events::CommandDataErr< <$data as crate::hci::events::DataResult>::UnpackErrorType >
                >
            {
                let oc_pair = $command.as_opcode_pair();

                let expected_opcode = oc_pair.ocf | (oc_pair.ogf << 10);

                if self.command_opcode == Some(expected_opcode) {
                    <Self as crate::hci::events::GetDataForCommand<$data>>::get_return_unchecked(&self)
                } else if self.command_opcode.is_none() {
                    Ok(None)
                } else {
                    Err(crate::hci::events::CommandDataErr::IncorrectOCF(
                        oc_pair.ocf | (oc_pair.ogf << 10),
                        self.command_opcode.unwrap()))
                }
            }

            unsafe fn get_return_unchecked(&self) ->
                core::result::Result<
                    core::option::Option< <$data as crate::hci::events::DataResult>::ReturnData >,
                    crate::hci::events::CommandDataErr< <$data as crate::hci::events::DataResult>::UnpackErrorType >
                >
            {
                use core::mem::size_of;

                if self.raw_data.len() >= core::mem::size_of::<$packed_data>() {
                    let mut buffer = [0u8;size_of::<$packed_data>()];

                    buffer.copy_from_slice(&(*self.raw_data));

                    let p_data: $packed_data = core::mem::transmute(buffer);

                    match <$data>::try_from(p_data) {
                        Ok(val) => Ok(Some(val)),
                        Err(e)  => Err(crate::hci::events::CommandDataErr::UnpackError(e))
                    }
                }
                else {
                    Err(crate::hci::events::CommandDataErr::RawDataLenTooSmall)
                }
            }
        }
    };
    ( $command:expr, $packed_data:ty, $data:ty, $try_from_err_ty:ty ) => {
        impl_get_data_for_command!($command, $packed_data, $data, $data, $try_from_err_ty);
    };
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
                packet.to_vec().into_boxed_slice()
            }
            else {
                BufferType::new([])
            },
        })
    }
}

#[derive(Clone)]
pub struct CommandStatusData {
    pub status: Error,
    pub number_of_hci_command_packets: u8,
    pub command_opcode: Option<u16>
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum NewRole {
    NowMaster,
    NowSlave,
}

impl NewRole {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        use self::NewRole::*;

        match raw {
            0x00 => Ok(NowMaster),
            0x01 => Ok(NowSlave),
            _    => Err(alloc::format!("Unknown New Role: {}", raw)),
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct NumberOfCompletedPacketsData {
    pub connection_handle: ConnectionHandle,
    pub number_of_completed_packets: u16,
}

impl_try_from_for_raw_packet! {
    Multiple<[NumberOfCompletedPacketsData]>,
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
                vec.into_boxed_slice()
            },
        })
    }
}

#[derive(Clone)]
pub enum CurrentMode {
    ActiveMode,
    HoldMode(CurrentModeInterval),
    SniffMode(CurrentModeInterval),
}

impl CurrentMode {
    fn try_from( raw: &[u8] ) -> Result<Self, alloc::string::String> {
        match raw[0] {
            0x00 => Ok(CurrentMode::ActiveMode),
            0x01 => Ok(CurrentMode::HoldMode (
                CurrentModeInterval::try_from ( u16::from_le( raw[1] as u16 | (raw[2] as u16) << 8 ) )? )
            ),
            0x02 => Ok(CurrentMode::SniffMode (
                CurrentModeInterval::try_from ( u16::from_le( raw[1] as u16 | (raw[2] as u16) << 8 ) )? )
            ),
            _    => Err(alloc::format!("Unknown Current Mode: {}", raw[0])),
        }
    }
}

#[derive(Clone)]
pub struct CurrentModeInterval {
    pub interval: u16
}

impl CurrentModeInterval {
    const MIN: u16 = 0x0002;
    const MAX: u16 = 0xFFFE;
    const CVT: u64 = 625; // conversion between raw to ms

    fn try_from( raw: u16 ) -> Result<Self, alloc::string::String> {
        if raw >= Self::MIN && raw <= Self::MAX {
            Ok(CurrentModeInterval {
                interval: raw
            })
        }
        else {
            Err(alloc::string::String::from("Current Mode Interval out of bounds"))
        }
    }

    pub fn get_interval_as_duration(&self) -> Duration {
        Duration::from_millis( self.interval as u64 * Self::CVT )
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct ReturnLinkKeysData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub link_key: [u8;16],
}

impl_try_from_for_raw_packet! {
    Multiple<[ReturnLinkKeysData]>,
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
                vec.into_boxed_slice()
            },
        })
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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
    fn try_from( raw: u8) -> Result<Self, alloc::string::String> {
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
            _    => Err(alloc::format!("Unknown Link Key Type {}", raw)),
        }
    }
}

#[derive(Clone)]
pub struct LinkKeyNotificationData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub link_key: [u8;16],
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

#[derive(Clone)]
pub struct LoopbackCommandData {
    opcode: u16,
    hci_command_packet: BufferType<[u8]>,
}

impl_try_from_for_raw_packet! {
    LoopbackCommandData,
    packet,
    {
        Ok(LoopbackCommandData {
            opcode: chew_u16!(packet),
            hci_command_packet: packet.to_vec().into_boxed_slice(),
        })
    }
}

#[derive(Clone)]
pub enum LinkTypeOverflow {
    /// Voice channel overflow
    SynchronousBufferOverflow,
    /// Data channel overflow
    ACLBufferOverflow,
}

impl LinkTypeOverflow {
    fn try_from( raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LinkTypeOverflow::SynchronousBufferOverflow),
            0x01 => Ok(LinkTypeOverflow::ACLBufferOverflow),
            _    => Err(alloc::format!("Unknown Link Type (buffer) Overflow {}", raw)),
        }
    }
}
#[derive(Clone)]
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

#[derive(Clone)]
pub enum LMPMaxSlots {
    One,
    Three,
    Five,
}

impl LMPMaxSlots {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        match raw {
            0x01 => Ok(LMPMaxSlots::One),
            0x03 => Ok(LMPMaxSlots::Three),
            0x05 => Ok(LMPMaxSlots::Five),
            _    => Err(alloc::format!("Unknown LMP Max Slots: {}", raw))
        }
    }

    pub fn val( &self ) -> u8 {
        match *self {
            LMPMaxSlots::One   => 0x01,
            LMPMaxSlots::Three => 0x03,
            LMPMaxSlots::Five  => 0x05,
        }
    }
}
#[derive(Clone)]
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

#[derive(Clone)]
pub struct ReadClockOffsetCompleteData {
    status: Error,
    connection_handle: ConnectionHandle,
    /// Bits 16-2 of CLKNslave-CLK
    clock_offset: u32
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

#[derive(Clone)]
pub enum PacketType {
    Acl(AclPacketType),
    Sco(ScoPacketType),
}

#[derive(Clone)]
pub enum AclPacketType {
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

impl AclPacketType {
    fn try_from( raw: u16 ) -> Result<Self, &'static str> {
        match raw {
            0x0002 => Ok(AclPacketType::TwoDH1ShallNotBeUsed),
            0x0004 => Ok(AclPacketType::ThreeDH1ShallNotBeUsed),
            0x0008 => Ok(AclPacketType::DM1MayBeUsed),
            0x0010 => Ok(AclPacketType::DH1MayBeUsed),
            0x0100 => Ok(AclPacketType::TwoDH3ShallNotBeUsed),
            0x0200 => Ok(AclPacketType::ThreeDH3ShallNotBeUsed),
            0x0400 => Ok(AclPacketType::DM3MayBeUsed),
            0x0800 => Ok(AclPacketType::DH3MayBeUsed),
            0x1000 => Ok(AclPacketType::TwoDH5ShallNotBeUsed),
            0x2000 => Ok(AclPacketType::ThreeDH5ShallNotBeUsed),
            0x4000 => Ok(AclPacketType::DM5MayBeUsed),
            0x8000 => Ok(AclPacketType::DH5MayBeUsed),
            _      => Err("Packet type not matched for ACLConnection"),
        }
    }
}

#[derive(Clone)]
pub enum ScoPacketType {
    HV1,
    HV2,
    HV3,
}

impl ScoPacketType {
    fn try_from( raw: u16 ) -> Result<Self, &'static str> {
        match raw {
            0x0020 => Ok(ScoPacketType::HV1),
            0x0040 => Ok(ScoPacketType::HV2),
            0x0080 => Ok(ScoPacketType::HV3),
            _      => Err("Packet type not matched for SCOConnection")
        }
    }
}

#[derive(Clone)]
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
    pub fn get_packet_type( &self, link_type: LinkType ) -> Result<PacketType, &'static str> {
        match link_type {
            LinkType::ACLConnection => Ok(PacketType::Acl(AclPacketType::try_from(self.packet_type)?)),
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct PageScanRepitionModeChangeData {
    bluetooth_address: BluetoothDeviceAddress,
    page_scan_repition_mode: PageScanRepitionMode,
}

impl_try_from_for_raw_packet! {
    PageScanRepitionModeChangeData,
    packet,
    {
        Ok(PageScanRepitionModeChangeData {
            bluetooth_address: chew_baddr!(packet,0),
            page_scan_repition_mode: PageScanRepitionMode::try_from(chew!(packet))?,
        })
    }
}

#[derive(Clone)]
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
            _    => Err(alloc::format!("Unknown {}", raw)),
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct InquiryResultWithRSSIData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repition_mode: PageScanRepitionMode,
    pub class_of_device: ClassOfDevice,
    pub clock_offset: u32,
    pub rssi: i8,
}

impl_try_from_for_raw_packet! {
    Multiple<[Result<InquiryResultWithRSSIData, alloc::string::String>]>,
    packet,
    {
        Ok(Multiple {
            data: {

                let mut vec = packet[1..].chunks_exact( 14 )
                .map( |mut chunk| {
                    Ok(InquiryResultWithRSSIData {
                        bluetooth_address: chew_baddr!(chunk),
                        page_scan_repition_mode: PageScanRepitionMode::try_from(chew!(chunk))?,
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
                vec.into_boxed_slice()
            }
        })
    }
}

#[derive(Clone)]
pub enum FeatureType {
    Features(EnabledFeaturesIter),
    ExtendedFeatures(EnabledExtendedFeaturesItr),
}

#[derive(Clone)]
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

#[derive(Clone)]
pub enum AirMode {
    MicroLawLog,
    ALawLog,
    CVSD,
    TransparentData,
}

impl AirMode {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(AirMode::MicroLawLog),
            0x01 => Ok(AirMode::ALawLog),
            0x02 => Ok(AirMode::CVSD),
            0x03 => Ok(AirMode::TransparentData),
            _    => Err(alloc::format!("Unknown Air Mode: {}", raw)),
        }
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct SniffSubratingData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub maximum_transmit_latency: u16,
    pub maximum_receive_latency: u16,
    pub minimum_transmit_latency: u16,
    pub minimum_receive_latency: u16
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

#[derive(Clone)]
pub struct ExtendedInquiryResultData {
    pub bluetooth_address: BluetoothDeviceAddress,
    pub page_scan_repition_mode: PageScanRepitionMode,
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
            page_scan_repition_mode: PageScanRepitionMode::try_from(chew!(packet))?,
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum IOCapability {
    DisplayOnly,
    DisplayYesNo,
    KeyboardOnly,
    NoInputNoOutput,
}

impl IOCapability {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(IOCapability::DisplayOnly),
            0x01 => Ok(IOCapability::DisplayYesNo),
            0x02 => Ok(IOCapability::KeyboardOnly),
            0x03 => Ok(IOCapability::NoInputNoOutput),
            _    => Err(alloc::format!("Unknown IO Capability: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub enum OOBDataPresent {
    OOBAuthenticationDataNotPresent,
    OOBAuthenticationDataFromRemoteDevicePresent,
}

impl OOBDataPresent {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(OOBDataPresent::OOBAuthenticationDataNotPresent),
            0x01 => Ok(OOBDataPresent::OOBAuthenticationDataFromRemoteDevicePresent),
            _    => Err(alloc::format!("Unknown OOB Data Present: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub enum AuthenticationRequirements {
    MITMProtectionNotRequiredNoBonding,
    MITMProtectionRequiredNoBonding,
    MITMProtectionNoRequiredDedicatedBonding,
    MITMProtectionRequiredDedicatedBonding,
    MITMProtectionNotRequiredGeneralBonding,
    MITMProtectionRequiredGeneralBonding,
}

impl AuthenticationRequirements {
    fn try_from(raw:u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(AuthenticationRequirements::MITMProtectionNotRequiredNoBonding),
            0x01 => Ok(AuthenticationRequirements::MITMProtectionRequiredNoBonding),
            0x02 => Ok(AuthenticationRequirements::MITMProtectionNoRequiredDedicatedBonding),
            0x03 => Ok(AuthenticationRequirements::MITMProtectionRequiredDedicatedBonding),
            0x04 => Ok(AuthenticationRequirements::MITMProtectionNotRequiredGeneralBonding),
            0x05 => Ok(AuthenticationRequirements::MITMProtectionRequiredGeneralBonding),
            _    => Err(alloc::format!("Unknown Authentication Requirement: {}", raw)),
        }
    }
}
#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct LinkSupervisionTimeoutChangedData {
    pub connection_handle: ConnectionHandle,
    pub link_supervision_timeout: u16
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum KeypressNotificationType {
    PasskeyEntrystarted,
    PasskeyDigitEntered,
    PasskeyDigitErased,
    PasskeyCleared,
    PasskeyEntryCompleted,
}

impl KeypressNotificationType {
    fn try_from(raw:u8) -> Result<Self, alloc::string::String> {
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub struct ChannelSelectedData {
    pub physical_link_handle: u8
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum LinkLossReason {
    Unknown,
    RangeRelated,
    BandwidthRelated,
    ResolvingConflict,
    Interference,
}

impl LinkLossReason {
    fn try_from(raw:u8) -> Result<Self, alloc::string::String> {
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
#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum ControllerBlocks {
    /// Requesting means that the controller is requesting the host to issue the Read Data Block
    /// Size Commmand to the controller. This is because the size of the buffer pool may have
    /// changed on the controller.
    RequestingReadDataBlockSize,
    /// Number of data block buffers free to be used for storage of data packets for transmission.
    FreeBlockBuffers(u16),
}

impl ControllerBlocks {
    fn from( raw: u16 ) -> Self {
        if raw == 0 {
            ControllerBlocks::RequestingReadDataBlockSize
        }
        else {
            ControllerBlocks::FreeBlockBuffers(raw)
        }
    }
}

#[derive(Clone)]
pub struct CompletedDataPacketsAndBlocks {
    pub handle: ConnectionHandle,
    /// This is the number of completed packets (transmitted or flushed) since the last time
    /// number of completed data blocks command was called.
    pub completed_packets: u16,
    /// Number of data blocks on the controller freed since the last time number of completed data
    /// blocks command was called
    pub completed_blocks: u16,
}

#[derive(Clone)]
pub struct NumberOfCompletedDataBlocksData {
    pub total_data_blocks: ControllerBlocks,
    pub completed_packets_and_blocks: BufferType<[CompletedDataPacketsAndBlocks]>,
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
                vec.into_boxed_slice()
            }
        })
    }
}

#[derive(Clone)]
pub enum ShortRangeModeState {
    Enabled,
    Disabled
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

#[derive(Clone)]
pub struct ShortRangeModeChangeCompleteData {
    pub status: Error,
    pub physical_link_handle: u8,
    pub short_range_mode_state: ShortRangeModeState
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
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

#[derive(Clone)]
pub enum LERole {
    Master,
    Slave,
}

impl LERole {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LERole::Master),
            0x01 => Ok(LERole::Slave),
            _    => Err(alloc::format!("Unknown Le Role: {}", raw)),
        }
    }
}

#[derive(Clone,Copy,PartialEq,Eq)]
pub enum LEConnectionAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
}

impl LEConnectionAddressType {
    fn try_from(raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEConnectionAddressType::PublicDeviceAddress),
            0x01 => Ok(LEConnectionAddressType::RandomDeviceAddress),
            _    => Err(alloc::format!("Unknown Le Connection Address Type: {}", raw)),
        }
    }
}

#[derive(Clone)]
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
            _    => Err(alloc::format!("Unknown Clock Accuracy: {}", raw)),
        }
    }
}

#[derive(Clone)]
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
    fn try_from( data: &[u8] ) -> Result<Self,alloc::string::String> {
        let mut packet = data;
        Ok(LEConnectionCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            role: LERole::try_from(chew!(packet))?,
            peer_address_type: LEConnectionAddressType::try_from(chew!(packet))?,
            peer_address: chew_baddr!(packet),
            connection_interval: ConnectionInterval::try_from_received(chew_u16!(packet))?,
            connection_latency: ConnectionLatency::from(chew_u16!(packet)),
            supervision_timeout: SupervisionTimeout::from(chew_u16!(packet)),
            master_clock_accuracy: ClockAccuracy::try_from(chew!(packet))?,
        })
    }
}

#[derive(Clone)]
pub enum LEEventType {
    ConnectableAndScannableUndirectedAdvertising,
    ConnectableDirectedAdvertising,
    ScannableUndirectedAdvertising,
    NonConnectableUndirectedAdvertising,
    ScanResponse,
}

impl LEEventType {
    fn try_from( raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEEventType::ConnectableAndScannableUndirectedAdvertising),
            0x01 => Ok(LEEventType::ConnectableDirectedAdvertising),
            0x02 => Ok(LEEventType::ScannableUndirectedAdvertising),
            0x03 => Ok(LEEventType::NonConnectableUndirectedAdvertising),
            0x04 => Ok(LEEventType::ScanResponse),
            _    => Err(alloc::format!("Unknown LE Event Type: {}", raw)),
        }
    }
}

pub struct ReportDataIter<'a> {
    data: &'a [u8]
}

impl<'a> core::iter::Iterator for ReportDataIter<'a> {
    type Item = Result<&'a [u8], crate::gap::advertise::Error>;

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
                }
                else {
                    // short data so that None is returned the next iteration
                    self.data = &self.data[self.data.len()..];

                    Some(Err(crate::gap::advertise::Error::IncorrectLength))
                }
            }
            else {
                None
            }
        }
        else {
            None
        }
    }
}

#[derive(Clone)]
pub struct LEAdvertisingReportData {
    pub event_type: LEEventType,
    pub address_type: LEAddressType,
    pub address: BluetoothDeviceAddress,
    pub data: BufferType<[u8]>,
    /// If rssi is None, the the value isn't available
    pub rssi: Option<i8>,
}

impl LEAdvertisingReportData {

    pub fn data_iter<'a>(&'a self) -> ReportDataIter<'a> {
        ReportDataIter {
            data: &self.data,
        }
    }

    fn buf_from(data: &[u8]) -> BufferType<[Result<Self, alloc::string::String>]> {
        let mut packet = data;

        // The value of 127 indicates no rssi functionality
        fn get_rssi( val: u8 ) -> Option<i8> { if val != 127 { Some(val as i8) } else { None } }

        let mut reports =alloc::vec::Vec::with_capacity(chew!(packet) as usize);

        for _ in 0..reports.capacity() {
            // packet[index + 8] is the data length value as given by the controller
            reports.push(
                match LEEventType::try_from(chew!(packet)) {
                    Ok(e_type) => Ok(LEAdvertisingReportData {
                            event_type: e_type,
                            address_type: LEAddressType::from(chew!(packet)),
                            address: chew_baddr!(packet),
                            data: {
                                let size = chew!(packet);
                                chew!(packet, size).to_vec().into_boxed_slice()
                            },
                            rssi: get_rssi(chew!(packet)),
                        }),
                    Err(err) => Err(err),
                }
            );
        }

        reports.into_boxed_slice()
    }
}

#[derive(Clone)]
pub struct LEConnectionUpdateCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub connection_interval: ConnectionInterval,
    pub connection_latency: ConnectionLatency,
    pub supervision_timeout: SupervisionTimeout,
}

impl LEConnectionUpdateCompleteData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8] ) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEConnectionUpdateCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            connection_interval: ConnectionInterval::try_from_received(chew_u16!(packet))?,
            connection_latency: ConnectionLatency::from(chew_u16!(packet)),
            supervision_timeout: SupervisionTimeout::from(chew_u16!(packet))
        })
    }
}

#[derive(Clone)]
pub struct LEReadRemoteFeaturesCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub features: EnabledLEFeaturesItr,
}

impl LEReadRemoteFeaturesCompleteData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8] ) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEReadRemoteFeaturesCompleteData {
            status: Error::from(chew!(packet)),
            connection_handle: chew_handle!(packet),
            features: EnabledLEFeaturesItr::from({
                let mut features = [0u8;8];
                features.copy_from_slice(chew!(packet,8));
                features
            }),
        })
    }
}

#[derive(Clone)]
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

#[derive(Clone)]
pub struct LEConnectionTimeout {
    timeout: u16
}

impl LEConnectionTimeout {
    const CNV: u64 = 10; // unit: milliseconds

    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16 ) -> Self {
        debug_assert!( raw >= 0x000A && raw <= 0x0C80 );

        LEConnectionTimeout {
            timeout: raw,
        }
    }

    /// Get the maximum interval value as a duration
    pub fn as_duration(&self) -> Duration {
        Duration::from_millis((self.timeout as u64) * Self::CNV)
    }
}

#[derive(Clone)]
pub struct LERemoteConnectionParameterRequestData {
    pub connection_handle: ConnectionHandle,
    pub minimum_interval: le::connection::ConnectionInterval,
    pub maximum_interval: le::connection::ConnectionInterval,
    pub latency: ConnectionLatency,
    pub timeout: LEConnectionTimeout,
}

impl LERemoteConnectionParameterRequestData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8] ) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LERemoteConnectionParameterRequestData {
            connection_handle: chew_handle!(packet),
            minimum_interval: le::connection::ConnectionInterval::try_from_raw( chew_u16!(packet) ).map_err(|e| alloc::string::String::from(e))?,
            maximum_interval: le::connection::ConnectionInterval::try_from_raw( chew_u16!(packet) ).map_err(|e| alloc::string::String::from(e))?,
            latency: ConnectionLatency::from( chew_u16!(packet) ),
            timeout: LEConnectionTimeout::from( chew_u16!(packet) ),
        })
    }
}

#[derive(Clone)]
pub struct LEMaxOctets {
    pub octets: u16
}

impl LEMaxOctets {
    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16 ) -> Self {
        debug_assert!( raw >= 0x001B && raw <= 0x00FB );

        LEMaxOctets {
            octets: raw,
        }
    }
}

#[derive(Clone)]
pub struct LEMaxTime {
    pub time: u16
}

impl LEMaxTime {
    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16 ) -> Self {
        debug_assert!( raw >= 0x0148 && raw <= 0x4290 );

        LEMaxTime {
            time: raw,
        }
    }
}

#[derive(Clone)]
pub struct LEDataLengthChangeData {
    pub connection_handle: ConnectionHandle,
    pub max_tx_octets: LEMaxOctets,
    pub max_tx_time: LEMaxTime,
    pub max_rx_octets: LEMaxOctets,
    pub max_rx_time: LEMaxTime,
}

impl LEDataLengthChangeData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEDataLengthChangeData {
            connection_handle: chew_handle!(packet),
            max_tx_octets: LEMaxOctets::from( chew_u16!(packet) ),
            max_tx_time: LEMaxTime::from( chew_u16!(packet) ),
            max_rx_octets: LEMaxOctets::from( chew_u16!(packet) ),
            max_rx_time: LEMaxTime::from( chew_u16!(packet) ),
        })
    }
}

#[derive(Clone)]
pub struct LEReadLocalP256PublicKeyCompleteData{
    pub status: Error,
    pub key: [u8;64],
}

impl LEReadLocalP256PublicKeyCompleteData {
    #[allow(unused_assignments)]
    fn from( data: &[u8] ) -> Self {
        let mut packet = data;

        LEReadLocalP256PublicKeyCompleteData {
            status: Error::from(chew!(packet)),
            key: {
                let mut pub_key = [0u8;64];
                pub_key.copy_from_slice(chew!(packet,256));
                pub_key
            },
        }
    }
}

#[derive(Clone)]
/// DHKey stands for diffie Hellman Key
pub struct LEGenerateDHKeyCompleteData {
    status: Error,
    key: [u8;32],
}

impl LEGenerateDHKeyCompleteData {
    #[allow(unused_assignments)]
    fn from( data: &[u8] ) -> Self {
        let mut packet = data;

        LEGenerateDHKeyCompleteData {
            status: Error::from(chew!(packet)),
            key: {
                let mut dh_key = [0u8;32];
                dh_key.copy_from_slice(&packet[2..34]);
                dh_key
            },
        }
    }
}

#[derive(Clone)]
pub struct LEEnhancedConnectionCompleteData {
    pub status: Error,
    pub connection_handle: ConnectionHandle,
    pub role: LERole,
    pub peer_address_type: LEAddressType,
    pub peer_address: BluetoothDeviceAddress,
    pub local_resolvable_private_address: Option<BluetoothDeviceAddress>,
    pub peer_resolvable_private_address: Option<BluetoothDeviceAddress>,
    pub connection_interval: le::connection::ConnectionInterval,
    pub connection_latency: ConnectionLatency,
    pub supervision_timeout: SupervisionTimeout,
    pub master_clock_accuracy: ClockAccuracy,
}

impl LEEnhancedConnectionCompleteData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        let peer_address_type: LEAddressType;

        macro_rules! if_rpa_is_used {
            () => {{
                let bdaddr = chew_baddr!(packet);
                if match peer_address_type {
                    LEAddressType::PublicIdentityAddress | LEAddressType::RandomdIdentityAddress => true,
                    _ => false
                } {
                    Some(bdaddr)
                }
                else {
                    None
                }
            }}
        }

        Ok(LEEnhancedConnectionCompleteData {
            status: Error::from( chew!(packet) ),
            connection_handle: chew_handle!(packet),
            role: LERole::try_from( chew!(packet) )?,
            peer_address_type: {
                peer_address_type = LEAddressType::from(chew!(packet));
                peer_address_type.clone()
            },
            peer_address: chew_baddr!(packet),
            local_resolvable_private_address: if_rpa_is_used!(),
            peer_resolvable_private_address: if_rpa_is_used!(),
            connection_interval: le::connection::ConnectionInterval::try_from_raw( chew_u16!(packet) ).unwrap(),
            connection_latency: ConnectionLatency::from( chew_u16!(packet) ),
            supervision_timeout: SupervisionTimeout::from( chew_u16!(packet) ),
            master_clock_accuracy: ClockAccuracy::try_from( chew!(packet) )?,
        })
    }
}

#[derive(Clone)]
pub enum LEAdvertisingEventType {
    ConnectableDirectedLegacyAdvertising
}

impl LEAdvertisingEventType {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        match raw {
            0x01 => Ok(LEAdvertisingEventType::ConnectableDirectedLegacyAdvertising),
            _ => Err(alloc::format!("Unknown LE Advertising Event Type: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub enum LEDirectAddressType {
    PublicDeviceAddress,
    RandomDeviceAddress,
    PublicIdentityAddress,
    RandomIdentityAddress,
    UnresolvableRandomDeviceAddress,
}

impl LEDirectAddressType {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
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

#[derive(Clone)]
pub struct LEDirectedAdvertisingReportData {
    pub event_type: LEAdvertisingEventType,
    pub address_type: LEAddressType,
    pub address: BluetoothDeviceAddress,
    pub direct_address_type: LEDirectAddressType,
    pub direct_address: BluetoothDeviceAddress,
    pub rssi: Option<i8>,
}

impl LEDirectedAdvertisingReportData {
    #[allow(unused_assignments)]
    fn buf_from( data: &[u8] ) -> BufferType<[Result<Self, alloc::string::String>]> {
        let mut packet = data;

        let report_count = chew!(packet) as usize;

        let mut vec = packet.chunks_exact(16)
        .map( |mut chunk| {
            Ok(LEDirectedAdvertisingReportData {
                event_type: LEAdvertisingEventType::try_from( chew!(chunk) )?,
                address_type: LEAddressType::from( chew!(chunk) ),
                address: chew_baddr!(chunk),
                direct_address_type: LEDirectAddressType::try_from( chew!(chunk) )?,
                direct_address: chew_baddr!(chunk),
                rssi: {
                    let rssi_val = chew!(chunk) as i8;

                    if rssi_val != 127 {Some(rssi_val)} else {None}
                }
            })
        })
        .collect::<alloc::vec::Vec<Result<Self, alloc::string::String>>>();

        vec.truncate(report_count);

        vec.into_boxed_slice()
    }
}

#[derive(Clone)]
pub enum LEPhy {
    _1M,
    _2M,
    Coded,
}

impl LEPhy {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
        match raw {
            0x01 => Ok(LEPhy::_1M),
            0x02 => Ok(LEPhy::_2M),
            0x03 => Ok(LEPhy::Coded),
            _ => Err(alloc::format!("Unknown LE Phy: {}", raw)),
        }
    }
}

#[derive(Clone)]
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
#[derive(Clone)]
pub enum LEDataStatus {
    Complete,
    Incomplete,
    IncompleteTruncated,
}

impl LEDataStatus {
    fn try_from( raw: u8 ) -> Result<Self, alloc::string::String> {
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
#[derive(Clone)]
pub enum LELegacyExtAdvEventTypePDUType {
    AdvertisingInd,
    ConnectableAdvertisingInd,
    AdvertisingScanInd,
    AdvertisingNonConnectableNonScannableInd,
    ScanResponseToAdvertisingInd,
    ScanResponseToAdvertisingScanInd,
}

#[derive(Clone)]
pub struct LEExtAdvEventType {
    raw: u16,
}

impl LEExtAdvEventType {
    fn from(raw: u16) -> Self {
        LEExtAdvEventType {
            raw: raw
        }
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
        LEDataStatus::try_from( ((self.raw >> 5) & 3) as u8)
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
            _         => None
        }
    }
}

#[derive(Clone)]
pub struct LEAdvertiseInterval {
    interval: u16
}

impl LEAdvertiseInterval {
    const CNV: u64 = 1250; // unit: microseconds

    /// Raw is a pair for (minimum, maximum)
    fn from(raw: u16 ) -> Self {
        debug_assert!( raw >= 0x0006 );

        LEAdvertiseInterval {
            interval: raw,
        }
    }

    /// Get the minimum interval value as a duration
    pub fn as_duration(&self) -> Duration {
        Duration::from_micros((self.interval as u64) * Self::CNV)
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
#[derive(Clone)]
pub struct LEExtendedAdvertisingReportData {
    pub event_type: LEExtAdvEventType,
    pub address_type: Option<LEAddressType>,
    pub address: BluetoothDeviceAddress,
    pub primary_phy: LEPhy,
    pub secondary_phy: Option<LEPhy>,
    pub advertising_sid: Option<u8>,
    pub tx_power: Option<i8>,
    pub rssi: Option<i8>,
    pub periodic_advertising_interval: Option<LEAdvertiseInterval>,
    pub direct_address_type: LEDirectAddressType,
    pub direct_address: BluetoothDeviceAddress,
    pub data: ExtendedAdvertisingAndScanResponseDataItr,
}

impl LEExtendedAdvertisingReportData {
    fn buf_from( data: &[u8] ) -> BufferType<[Result<LEExtendedAdvertisingReportData, alloc::string::String>]> {
        let mut packet = data;

        let mut reports =alloc::vec::Vec::with_capacity(chew!(packet) as usize);

        let mut process_packet = || {
            Ok( LEExtendedAdvertisingReportData {
                event_type: LEExtAdvEventType::from(chew_u16!(packet)),
                address_type: {
                    let val = chew!(packet);

                    if val != 0xFF {
                        Some(LEAddressType::from(val))
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

                    ExtendedAdvertisingAndScanResponseDataItr::from(chew!(packet,data_len))
                }
            })
        };

        for _ in 0..reports.capacity() {
            reports.push( process_packet() );
        }

        reports.into_boxed_slice()
    }
}

#[derive(Clone)]
pub struct LEPeriodicAdvertisingSyncEstablishedData {
    pub status: Error,
    pub sync_handle: ConnectionHandle,
    pub advertising_sid: u8,
    pub advertiser_address_type: LEAddressType,
    pub advertiser_address: BluetoothDeviceAddress,
    pub advertiser_phy: LEPhy,
    pub periodic_advertising_interval: LEAdvertiseInterval,
    pub advertiser_clock_accuracy: ClockAccuracy,
}

impl LEPeriodicAdvertisingSyncEstablishedData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8]) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEPeriodicAdvertisingSyncEstablishedData {
            status: Error::from(chew!(packet)),
            sync_handle: chew_handle!(packet),
            advertising_sid: chew!(packet),
            advertiser_address_type: LEAddressType::from(chew!(packet)),
            advertiser_address: chew_baddr!(packet),
            advertiser_phy: LEPhy::try_from(chew!(packet))?,
            periodic_advertising_interval: LEAdvertiseInterval::from(chew_u16!(packet)),
            advertiser_clock_accuracy: ClockAccuracy::try_from(chew!(packet))?,
        })
    }
}

#[derive(Clone)]
pub struct LEPeriodicAdvertisingReportData {
    pub sync_handle: ConnectionHandle,
    pub tx_power: Option<i8>,
    pub rssi: Option<i8>,
    pub data_status: LEDataStatus,
    pub data: BufferType<[u8]>,
}

impl LEPeriodicAdvertisingReportData {
    fn try_from( data: &[u8]) -> Result<Self, alloc::string::String> {
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
            data_status: LEDataStatus::try_from(chew!(packet,1,1)[0])?,
            data: {
                let len = chew!(packet) as usize;
                packet[..len].to_vec().into_boxed_slice()
            }
        })
    }
}

#[derive(Clone)]
pub struct LEPeriodicAdvertisingSyncLostData {
    sync_handle: ConnectionHandle,
}

impl LEPeriodicAdvertisingSyncLostData {
    #[allow(unused_assignments)]
    fn from( data: &[u8] ) -> Self {
        let mut packet = data;
        LEPeriodicAdvertisingSyncLostData {
            sync_handle: chew_handle!(packet)
        }
    }
}


#[derive(Clone)]
pub struct LEAdvertisingSetTerminatedData {
    pub status: Error,
    pub advertising_handle: u8,
    pub connection_handle: ConnectionHandle,
    pub num_completed_extended_advertising_events: u8,
}

impl LEAdvertisingSetTerminatedData {
    #[allow(unused_assignments)]
    fn from( data: &[u8] ) -> Self {
        let mut packet = data;

        LEAdvertisingSetTerminatedData {
            status: Error::from(chew!(packet)),
            advertising_handle: chew!(packet),
            connection_handle: chew_handle!(packet),
            num_completed_extended_advertising_events: chew!(packet),
        }
    }
}

#[derive(Clone)]
pub struct LEScanRequestReceivedData {
    advertising_handle: u8,
    scanner_address_type: LEAddressType,
    scanner_address: BluetoothDeviceAddress,
}

impl LEScanRequestReceivedData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8] ) -> Result<Self, alloc::string::String> {
        let mut packet = data;

        Ok(LEScanRequestReceivedData {
            advertising_handle: chew!(packet),
            scanner_address_type: LEAddressType::from(chew!(packet)),
            scanner_address: chew_baddr!(packet),
        })
    }
}

#[derive(Clone)]
pub enum LEChannelSelectionAlgorithm {
    Algorithm1,
    Algorithm2,
}

impl LEChannelSelectionAlgorithm {
    fn try_from( raw: u8) -> Result<Self, alloc::string::String> {
        match raw {
            0x00 => Ok(LEChannelSelectionAlgorithm::Algorithm1),
            0x01 => Ok(LEChannelSelectionAlgorithm::Algorithm2),
            _ => Err(alloc::format!("Unknown LE Channel Selection Algorithm: {}", raw)),
        }
    }
}

#[derive(Clone)]
pub struct LEChannelSelectionAlgorithmData {
    pub connection_handle: ConnectionHandle,
    pub channel_selection_algorithm: LEChannelSelectionAlgorithm
}

impl LEChannelSelectionAlgorithmData {
    #[allow(unused_assignments)]
    fn try_from( data: &[u8] ) -> Result<Self, alloc::string::String> {
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
    pub enum LEMeta ( #[derive(Clone)] enum LEMetaData ) {
        ConnectionComplete{LEConnectionCompleteData},
        AdvertisingReport{BufferType<[Result<LEAdvertisingReportData, alloc::string::String>]>},
        ConnectionUpdateComplete{LEConnectionUpdateCompleteData},
        ReadRemoteFeaturesComplete{LEReadRemoteFeaturesCompleteData},
        LongTermKeyRequest{LELongTermKeyRequestData},
        RemoteConnectionParameterRequest{LERemoteConnectionParameterRequestData},
        DataLengthChange{LEDataLengthChangeData},
        ReadLocalP256PublicKeyComplete{LEReadLocalP256PublicKeyCompleteData},
        GenerateDHKeyComplete{LEGenerateDHKeyCompleteData},
        EnhancedConnectionComplete{LEEnhancedConnectionCompleteData},
        DirectedAdvertisingReport{BufferType<[Result<LEDirectedAdvertisingReportData, alloc::string::String>]>},
        PHYUpdateComplete{LEPHYUpdateCompleteData},
        ExtendedAdvertisingReport{BufferType<[Result<LEExtendedAdvertisingReportData, alloc::string::String>]>},
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
    pub fn try_from( raw: u8 ) -> Result<LEMeta, alloc::string::String> {
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
            _    => Err(alloc::format!("Unknown LE Meta: {}", raw)),
        }
    }
}

impl LEMetaData {
    fn into_simple(&self) -> LEMeta {
        match *self {
            LEMetaData::ConnectionComplete(_) => LEMeta::ConnectionComplete,
            LEMetaData::AdvertisingReport(_) => LEMeta::AdvertisingReport,
            LEMetaData::ConnectionUpdateComplete(_) => LEMeta::ConnectionUpdateComplete,
            LEMetaData::ReadRemoteFeaturesComplete(_) => LEMeta::ReadRemoteFeaturesComplete,
            LEMetaData::LongTermKeyRequest(_) => LEMeta::LongTermKeyRequest,
            LEMetaData::RemoteConnectionParameterRequest(_) => LEMeta::RemoteConnectionParameterRequest,
            LEMetaData::DataLengthChange(_) => LEMeta::DataLengthChange,
            LEMetaData::ReadLocalP256PublicKeyComplete(_) => LEMeta::ReadLocalP256PublicKeyComplete,
            LEMetaData::GenerateDHKeyComplete(_) => LEMeta::GenerateDHKeyComplete,
            LEMetaData::EnhancedConnectionComplete(_) => LEMeta::EnhancedConnectionComplete,
            LEMetaData::DirectedAdvertisingReport(_) => LEMeta::DirectedAdvertisingReport,
            LEMetaData::PHYUpdateComplete(_) => LEMeta::PHYUpdateComplete,
            LEMetaData::ExtendedAdvertisingReport(_) => LEMeta::ExtendedAdvertisingReport,
            LEMetaData::PeriodicAdvertisingSyncEstablished(_) => LEMeta::PeriodicAdvertisingSyncEstablished,
            LEMetaData::PeriodicAdvertisingReport(_) => LEMeta::PeriodicAdvertisingReport,
            LEMetaData::PeriodicAdvertisingSyncLost(_) => LEMeta::PeriodicAdvertisingSyncLost,
            LEMetaData::ScanTimeout => LEMeta::ScanTimeout,
            LEMetaData::AdvertisingSetTerminated(_) => LEMeta::AdvertisingSetTerminated,
            LEMetaData::ScanRequestReceived(_) => LEMeta::ScanRequestReceived,
            LEMetaData::ChannelSelectionAlgorithm(_) => LEMeta::ChannelSelectionAlgorithm,
        }
    }
}

impl_try_from_for_raw_packet! {
    LEMetaData,
    packet,
    {
        use self::LEMetaData::*;
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

#[derive(Clone)]
pub struct TriggeredClockCaptureData { }

impl_try_from_for_raw_packet! {
    TriggeredClockCaptureData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct SynchronizationTrainCompleteData { }

impl_try_from_for_raw_packet! {
    SynchronizationTrainCompleteData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct SynchronizationTrainReceivedData { }

impl_try_from_for_raw_packet! {
    SynchronizationTrainReceivedData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct ConnectionlessSlaveBroadcastReceiveData { }

impl_try_from_for_raw_packet! {
    ConnectionlessSlaveBroadcastReceiveData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct ConnectionlessSlaveBroadcastTimeoutData { }

impl_try_from_for_raw_packet! {
    ConnectionlessSlaveBroadcastTimeoutData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct TruncatedPageCompleteData { }

impl_try_from_for_raw_packet! {
    TruncatedPageCompleteData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct SlavePageRespoinseTimeoutData { }

impl_try_from_for_raw_packet! {
    SlavePageRespoinseTimeoutData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct ConnectionlessSlaveBroadcastChannelMapChangeData { }

impl_try_from_for_raw_packet! {
    ConnectionlessSlaveBroadcastChannelMapChangeData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct InquiryResponseNotificationData { }

impl_try_from_for_raw_packet! {
    InquiryResponseNotificationData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

#[derive(Clone)]
pub struct AuthenticatedPayloadTimeoutExpiredData {
    connection_handle: ConnectionHandle
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

#[derive(Clone)]
pub struct SAMStatusChangeData { }

impl_try_from_for_raw_packet! {
    SAMStatusChangeData,
    _packet_placeholder,
    {
        unimplemented!()
    }
}

macro_rules! put_ { ( $t:tt ) => { _ } }

macro_rules! data_into_simple { ($unused_rpt:tt, $data_var:expr) => { $data_var.into_simple() } }

macro_rules! events_markup {
    ( pub enum $EnumName:tt ( $EnumDataName:tt ) {
        $( $name:tt $(( $($enum_val:tt),* ))* {$data:ident $(< $type:ty >)*} -> $val:expr, )*
    } ) => (

        enumerate_split! {
            #[derive(Debug,Hash,Clone,Copy,PartialEq,Eq,PartialOrd,Ord)]
            pub enum $EnumName ( enum $EnumDataName ){
                $( $name $(( $($enum_val),* ))* {$data $(< $type >)*}, )*
            }
        }

        impl crate::hci::events::$EnumName {
            pub fn get_val( &self ) -> u8 {
                match *self {
                    $(crate::hci::events::$EnumName::$name $(( $(put_!($enum_val))* ))* => $val,)*
                }
            }

            /// The from raw normaly only needs to have the first val (`vals.0`) for determining the
            /// enum conversion. But in the case where the first val matches LEMeta, the second
            /// value (`vals.1`) is used to determine the LEMeta sub event.
            pub fn from_raw( vals: (u8, u8) ) -> core::result::Result<crate::hci::events::$EnumName, alloc::string::String> {
                match vals.0 {
                    $( $val => Ok( crate::hci::events::$EnumName::$name $(( $($enum_val::try_from(vals.1)?)* ))* ), )*
                    _ => Err(alloc::format!("Unknown Event ID: {}", vals.0)),
                }
            }
        }

        impl crate::hci::events::$EnumDataName {

            pub fn get_enum_name(&self) -> $EnumName {
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
            pub fn from_packet( data: &[u8] ) -> Result<Self, alloc::string::String> {

                use core::convert::TryFrom;

                debug_assert!( data.len() > 1 ,
                    "Error occured in macro invocation of hci::events::events_markup");

                let mut packet = data;

                // packet[0] is the LEMeta specific event code if the event is LEMeta
                let event_code = crate::hci::events::$EnumName::from_raw((chew!(packet), packet[1]));

                /// The length of the packet and convert it into a usize
                let event_len  = chew!(packet).into();

                match event_code {
                    $( Ok(crate::hci::events::$EnumName::$name $( ( $(put_!($enum_val)),* ) )*) =>
                        Ok(crate::hci::events::$EnumDataName::$name(
                            crate::hci::events::$data::<$( $type ),*>::try_from(&packet[..event_len])?)),
                    )*
                    Err(err) => Err(err),
                }
            }
        }

        impl core::fmt::Debug for crate::hci::events::$EnumDataName {
            fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
                write!( f, "{}", match *self {
                    $(crate::hci::events::$EnumDataName::$name(_) => stringify!(::hci::events::$EnumDataName::$name) ),*
                })
            }
        }
    )
}

events_markup! {
    pub enum Events(EventsData) {
        InquiryComplete{InquiryCompleteData} -> 0x01,
        InquiryResult{Multiple<[Result<InquiryResultData,alloc::string::String>]>} -> 0x02,
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
        NumberOfCompletedPackets{Multiple<[NumberOfCompletedPacketsData]>} -> 0x13,
        ModeChange{ModeChangeData} -> 0x14,
        ReturnLinkKeys{Multiple<[ReturnLinkKeysData]>} -> 0x15,
        PINCodeRequest{PINCodeRequestData} -> 0x16,
        LinkKeyRequest{LinkKeyRequestData} -> 0x17,
        LinkKeyNotification{LinkKeyNotificationData} -> 0x18,
        LoopbackCommand{LoopbackCommandData} -> 0x19,
        DataBufferOverflow{DataBufferOverflowData} -> 0x1A,
        MaxSlotsChange{MaxSlotsChangeData} -> 0x1B,
        ReadClockOffsetComplete{ReadClockOffsetCompleteData} -> 0x1C,
        ConnectionPacketTypeChanged{ConnectionPacketTypeChangedData} -> 0x1D,
        QoSViolation{QoSViolationData} -> 0x1E,
        PageScanRepitionModeChange{PageScanRepitionModeChangeData} -> 0x20,
        FlowSpecificationComplete{FlowSpecificationCompleteData} -> 0x21,
        InquiryResultWithRSSI{Multiple<[Result<InquiryResultWithRSSIData,alloc::string::String>]>} -> 0x22,
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
        LEMeta(LEMeta){LEMetaData} -> 0x3E,
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
