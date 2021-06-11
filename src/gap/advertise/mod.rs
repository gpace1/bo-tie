//! Advertising, Periodic Advertising, and Scanning Data
//!
//! Advertising is a sequence of AD types. Data is packaged under a assigned number and given a
//! format defined by the Bluetooth SIG. The assigned numbers can be found in the *Generic Access
//! Profile* assigned number document, and formats for the data are found in the *Bluetooth
//! Supplement to the Core*. The assigned number and format are wrapped in an *AD* type defined in
//! the Bluetooth Core Specification (v5.2 | Vol 3, Part C| sec. 11).
use core::fmt;

/// Helper macro for implementing TryFromRaw
///
/// It provides some validation to the raw data before running the block `$to_do`
///
/// # Note
/// `$arr` is assumed to be a slice reference containing just the AD type and AD data. The length is
/// inferred to the the length of the slice.
macro_rules! from_raw {
    ($arr:expr, $( $ad:path, )* $to_do:block) => {
        if $arr.len() > 0 && ( $($arr[0] == $ad.val())||* ) {
            Ok($to_do)
        }
        else {
            if $arr.len() == 0 {
                Err(crate::gap::advertise::Error::RawTooSmall)
            }
            else {
                Err(crate::gap::advertise::Error::IncorrectDataType)
            }
        }
    };
}

pub mod flags;
pub mod local_name;
pub mod sc_confirm_value;
pub mod sc_random_value;
pub mod service_data;
pub mod service_uuids;

pub enum AssignedTypes {
    Flags,
    IncompleteListOf16bitServiceClassUUIDs,
    CompleteListOf16bitServiceClassUUIDs,
    IncompleteListOf32bitServiceClassUUIDs,
    CompleteListOf32bitServiceClassUUIDs,
    IncompleteListOf128bitServiceClassUUIDs,
    CompleteListOf128bitServiceClassUUIDs,
    ShortenedLocalName,
    CompleteLocalName,
    TxPowerLevel,
    ClassOfDevice,
    SimplePairingHashC,
    SimplePairingHashC192,
    SimplePairingRandomizerR,
    SimplePairingRandomizerR192,
    DeviceID,
    SecurityManagerTKValue,
    SecurityManagerOutOfBandFlags,
    SlaveConnectionIntervalRange,
    ListOf16bitServiceSolicitationUUIDs,
    ListOf128bitServiceSolicitationUUIDs,
    ServiceData,
    ServiceData16BitUUID,
    PublicTargetAddress,
    RandomTargetAddress,
    Appearance,
    AdvertisingInterval,
    LEBluetoothDeviceAddress,
    LERole,
    SimplePairingHashC256,
    SimplePairingRandomizerR256,
    ListOf32bitServiceSolicitationUUIDs,
    ServiceData32BitUUID,
    ServiceData128BitUUID,
    LESecureConnectionsConfirmationValue,
    LESecureConnectionsRandomValue,
    URI,
    IndoorPositioning,
    TransportDiscoveryData,
    LESupportedFeatures,
    ChannelMapUpdateIndication,
    PBADV,
    MeshMessage,
    MeshBeacon,
    _3DInformationData,
    ManufacturerSpecificData,
}

impl AssignedTypes {
    fn val(&self) -> u8 {
        match *self {
            AssignedTypes::Flags => 0x01,
            AssignedTypes::IncompleteListOf16bitServiceClassUUIDs => 0x02,
            AssignedTypes::CompleteListOf16bitServiceClassUUIDs => 0x03,
            AssignedTypes::IncompleteListOf32bitServiceClassUUIDs => 0x04,
            AssignedTypes::CompleteListOf32bitServiceClassUUIDs => 0x05,
            AssignedTypes::IncompleteListOf128bitServiceClassUUIDs => 0x06,
            AssignedTypes::CompleteListOf128bitServiceClassUUIDs => 0x07,
            AssignedTypes::ShortenedLocalName => 0x08,
            AssignedTypes::CompleteLocalName => 0x09,
            AssignedTypes::TxPowerLevel => 0x0A,
            AssignedTypes::ClassOfDevice => 0x0D,
            AssignedTypes::SimplePairingHashC => 0x0E,
            AssignedTypes::SimplePairingHashC192 => 0x0E,
            AssignedTypes::SimplePairingRandomizerR => 0x0F,
            AssignedTypes::SimplePairingRandomizerR192 => 0x0F,
            AssignedTypes::DeviceID => 0x10,
            AssignedTypes::SecurityManagerTKValue => 0x10,
            AssignedTypes::SecurityManagerOutOfBandFlags => 0x11,
            AssignedTypes::SlaveConnectionIntervalRange => 0x12,
            AssignedTypes::ListOf16bitServiceSolicitationUUIDs => 0x14,
            AssignedTypes::ListOf128bitServiceSolicitationUUIDs => 0x15,
            AssignedTypes::ServiceData => 0x16,
            AssignedTypes::ServiceData16BitUUID => 0x16,
            AssignedTypes::PublicTargetAddress => 0x17,
            AssignedTypes::RandomTargetAddress => 0x18,
            AssignedTypes::Appearance => 0x19,
            AssignedTypes::AdvertisingInterval => 0x1A,
            AssignedTypes::LEBluetoothDeviceAddress => 0x1B,
            AssignedTypes::LERole => 0x1C,
            AssignedTypes::SimplePairingHashC256 => 0x1D,
            AssignedTypes::SimplePairingRandomizerR256 => 0x1E,
            AssignedTypes::ListOf32bitServiceSolicitationUUIDs => 0x1F,
            AssignedTypes::ServiceData32BitUUID => 0x20,
            AssignedTypes::ServiceData128BitUUID => 0x21,
            AssignedTypes::LESecureConnectionsConfirmationValue => 0x22,
            AssignedTypes::LESecureConnectionsRandomValue => 0x23,
            AssignedTypes::URI => 0x24,
            AssignedTypes::IndoorPositioning => 0x25,
            AssignedTypes::TransportDiscoveryData => 0x26,
            AssignedTypes::LESupportedFeatures => 0x27,
            AssignedTypes::ChannelMapUpdateIndication => 0x28,
            AssignedTypes::PBADV => 0x29,
            AssignedTypes::MeshMessage => 0x2A,
            AssignedTypes::MeshBeacon => 0x2B,
            AssignedTypes::_3DInformationData => 0x3D,
            AssignedTypes::ManufacturerSpecificData => 0xFF,
        }
    }
}

#[derive(Debug)]
pub enum Error {
    IncorrectDataType,
    IncorrectLength,
    RawTooSmall,
    UTF8Error(alloc::str::Utf8Error),
    LeBytesConversionError,
    AttributeFormat(crate::att::TransferFormatError),
}

impl From<crate::att::TransferFormatError> for Error {
    fn from(e: crate::att::TransferFormatError) -> Self {
        Error::AttributeFormat(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::IncorrectDataType => write!(f, "Incorrect Data Type Field"),
            Error::IncorrectLength => write!(
                f,
                "The length of this type is larger than the remaining bytes in the packet"
            ),
            Error::RawTooSmall => write!(f, "Raw data length is too small"),
            Error::UTF8Error(utf8_err) => write!(
                f,
                "UTF-8 conversion error, valid up to {}: '{}'",
                utf8_err.valid_up_to(),
                alloc::string::ToString::to_string(&utf8_err)
            ),
            Error::LeBytesConversionError => write!(f, "Error converting bytes from le"),
            Error::AttributeFormat(ref e) => e.fmt(f),
        }
    }
}

/// Create a new raw buffer for a data type
///
/// This method is use d for initialize a raw vector with the length & type fields
fn new_raw_type(ad_type: u8) -> alloc::vec::Vec<u8> {
    alloc::vec![0, ad_type]
}

fn set_len(buf: &mut [u8]) {
    buf[0] = (buf.len() as u8) - 1
}

/// A trait for converting the Advertising Data Structure into its raw (byte slice) form
pub trait IntoRaw {
    /// Convert the data into a vector of bytes
    ///
    /// This converts the data into the form that will be passed from devices over the air
    fn into_raw(&self) -> alloc::vec::Vec<u8>;
}

/// A trait for attempting to convert a slice of bytes into an Advertising Data Structure
pub trait TryFromRaw
where
    Self: core::marker::Sized,
{
    /// Attempt to convert the data from its raw form into this type
    ///
    /// Takes the data protion of one raw advertising or extended inquiry struct and converts
    /// it into this data type.  An error will be returned if the raw data cannot be converted
    /// into this type.
    ///
    /// The passed parameter `raw` needs to refer to a slice to a single data portion *without* the
    /// length byte. The slice should start with the type id. Refer to the Core specification
    /// (Version 5.0 | Vol 3, Part C Section 11) for raw data format details.
    fn try_from_raw(raw: &[u8]) -> Result<Self, Error>;
}

#[derive(Debug)]
pub struct DataTooLargeError {
    pub(crate) overflow: usize,
    pub(crate) remaining: usize,
}

impl DataTooLargeError {
    /// Return the number of bytes that would overflow the advertising packet buffer
    pub fn overflow(&self) -> usize {
        self.overflow
    }

    /// The number of bytes remaining in the advertising buffer at the time that this error was
    /// generated.
    pub fn remaining(&self) -> usize {
        self.remaining
    }
}

impl ::core::fmt::Display for DataTooLargeError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Advertising Data Too Large")
    }
}
