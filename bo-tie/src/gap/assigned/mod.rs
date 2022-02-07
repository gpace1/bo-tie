//! Assigned numbers and the associated data formats
//!
//! The assigned numbers for GAP come from the Bluetooth SIG and can be found on the official
//! [Bluetooth](https://www.bluetooth.com/specifications/assigned-numbers/) webpage. These numbers
//! are used to identify the meaning and corresponding data format for whoever is the receiver. GAP
//! assigned numbers are used within Extended Inquiry Response (EIR), Advertising Data (AD), and
//! out of band (OOB) pairing (which is different for BR/EDR and LE).
//!
//! While data assigned a number is used in different places, the general format for the container
//! of the data is the same. One byte for length, one byte for the assigned number, and multiple
//! bytes for the data. There are two names for these containers, they are *EIR struct* and *AD
//! struct*. An EIR struct appears in an Extended Inquiry Response and in the OOB data block for
//! BR/EDR pairing, and an AD struct appears within advertising data and out of band data for secure
//! connections pairing.

pub mod flags;
pub mod le_device_address;
pub mod le_role;
pub mod local_name;
pub mod sc_confirm_value;
pub mod sc_random_value;
pub mod service_data;
pub mod service_uuids;

/// The size of the header for either an EIR or AD structure
///
/// The full size of either an EIR or AD structure is this plus the size of the data.
const HEADER_SIZE: usize = 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
    pub const fn val(&self) -> u8 {
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
    /// The assigned type within the structure is different from the expected type
    IncorrectAssignedType,
    /// The length byte contains an invalid value
    IncorrectLength,
    /// The buffer is too small for the structure
    RawTooSmall,
    /// Failed converting from an assumed UTF8 formatted bytes
    UTF8Error(alloc::str::Utf8Error),
    /// Invalid format of ATT data.
    AttributeFormat(crate::att::TransferFormatError),
}

impl From<crate::att::TransferFormatError> for Error {
    fn from(e: crate::att::TransferFormatError) -> Self {
        Error::AttributeFormat(e)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            Error::IncorrectAssignedType => write!(f, "Incorrect Assigned Type Field"),
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
            Error::AttributeFormat(ref e) => e.fmt(f),
        }
    }
}

/// An intermediary for help creating a EIR or AD Structure from a local type
///
/// The common format of either an EIR or AD Structure is one byte for the length of the data, one
/// byte for the AD type, and zero or more bytes for the AD data.
struct StructIntermediate<'a> {
    len: u8,
    struct_type: u8,
    ad: &'a mut [u8],
}

impl<'a> StructIntermediate<'a> {
    /// Create an new `AdStructIntermediate`
    ///
    /// Input `ad` is where the data is to be placed and
    ///
    /// # Error
    /// The size of `ad` if it is less than than 2.
    fn new(b: &'a mut [u8], struct_type: u8) -> Option<Self> {
        const AD_DATA_MAX_LEN: usize = u8::MAX as usize - 1;

        let data = match b.len() {
            0..=2 => return None,
            3..=AD_DATA_MAX_LEN => b,
            _ => &mut b[..AD_DATA_MAX_LEN],
        };

        if data.len() < 2 {
            None
        } else {
            let ad = if data.len() > u8::MAX.into() {
                &mut data[..u8::MAX as usize]
            } else {
                data
            };

            // The length starts at 1 because that is the size of the ad type
            Some(Self {
                len: 1,
                struct_type,
                ad,
            })
        }
    }

    /// Get the next byte
    fn next(&mut self) -> Option<&mut u8> {
        self.len.checked_add(1).and_then(move |len| {
            self.len = len;

            // This works because `self.len` is initialized to one.
            // AD struct -> [len, ad type, ad data .. ]
            self.ad.get_mut(len as usize)
        })
    }

    /// Extend by transfer formatted `T`
    ///
    /// This will try to extend the AD data by the Attribute transfer formatted data of `t`. If
    /// there were not enough bytes available, then none of the bytes will be added and `None` will
    /// be returned.
    fn try_extend_by<T>(&mut self, t: &T) -> Option<()>
    where
        T: crate::att::TransferFormatInto,
    {
        use core::convert::TryInto;

        let to_add_len = crate::att::TransferFormatInto::len_of_into(t);

        self.len.checked_add(to_add_len.try_into().ok()?).and_then(|len| {
            if self.ad.len() >= 1 + len as usize {
                let start = self.len as usize + 1;
                let end = self.len as usize + 1 + to_add_len;

                crate::att::TransferFormatInto::build_into_ret(t, &mut self.ad[start..end]);

                self.len = len;

                Some(())
            } else {
                None
            }
        })
    }

    /// Fill-out the AD type
    ///
    /// The return is the bytes within the `ad` that were not used
    ///
    /// # Note
    /// This method is intended to be called at the end of an implementation of method
    /// [`convert_into`](IntoAdvDataStruct::convert_into) so return is always `Ok(_)`.
    fn finish(self) -> Option<EirOrAdStruct<'a>> {
        self.ad[0] = self.len;
        self.ad[1] = self.struct_type;

        Some(EirOrAdStruct(&mut self.ad[(1 + self.len) as usize..]))
    }
}

/// A trait for converting a local type into an Extended Inquiry Response (EIR) or Advertising Data
/// (AD) Structure
pub trait IntoStruct {
    /// The required data length of an EIR or AD struct
    ///
    /// If the data does not have a set or required size, then an error is returned with the full
    /// size of the data. Some types that have a shortened version will return this Error.
    fn data_len(&self) -> Result<usize, usize>;

    /// Covert into its structure
    ///
    /// Input `b` is the buffer to contain the Structure. The implementor needs to create a
    /// structure and place it at the beginning of the buffer. If `b` is too small then the return
    /// is `None`.
    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Option<EirOrAdStruct<'a>>;
}

/// A trait for attempting to convert an Extended Inquiry Response (EIR) or Advertising Data (AD)
/// Structure to a local type
pub trait TryFromStruct<'a> {
    /// Attempt to convert an EIR or AD struct into this type
    fn try_from_struct(st: EirOrAdStruct<'a>) -> Result<Self, Error>
    where
        Self: Sized;
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

/// A wrapper around an EIR or AD structure
///
/// There is no functional difference between an EIR struct and an AD struct, but they are used
/// in different places within the Bluetooth specification and consequently this library. Within
/// the library these places have provided an alias to this as either an EIR struct or an AD struct.
#[derive(Clone, Copy, Debug)]
pub struct EirOrAdStruct<'a>(&'a [u8]);

impl<'a> EirOrAdStruct<'a> {
    /// Try to create a new `EirOrAdStruct`
    ///
    /// This will return a new `EirOrAdStruct` if it bytes starts with and contains a complete
    /// EIR or AD struct. A slice to the rest of the bytes is returned with a new `EirOrAdStruct`.
    ///
    /// `None` is returned if the length in the structure is zero. This is used to indicate an
    /// early termination of the entire data sequence, so any bytes that come after it are to be
    /// ignored.
    pub(crate) fn try_new(bytes: &'a [u8]) -> Result<Option<(Self, &'a [u8])>, Error> {
        let len = *bytes.get(0).ok_or(Error::RawTooSmall)? as usize;

        match len {
            0 => Ok(None),
            len if len < bytes.len() => Ok(Some((Self(&bytes[..1 + len]), &bytes[1 + len..]))),
            _ => Err(Error::IncorrectLength),
        }
    }

    /// Return the type (assigned number)
    ///
    /// This returns the EIR or AD type, which is the part of the structure that contains the
    /// assigned number.
    pub fn get_type(&self) -> u8 {
        self.0[1]
    }

    /// Get the data bytes
    pub fn get_data(&'a self) -> &'a [u8] {
        if self.0[0] > 1 {
            &self.0[2..]
        } else {
            &[]
        }
    }

    /// Get the size of the structure
    pub fn size(&self) -> usize {
        self.0.len()
    }

    /// Try to convert this struct into the type `T`
    pub fn try_into<T>(self) -> Result<T, Error>
    where
        T: TryFromStruct<'a>,
    {
        T::try_from_struct(self)
    }

    /// Convert into the inner struct data
    pub fn into_inner(self) -> &'a [u8] {
        self.0
    }
}

/// An iterator over EIR or AD structs
///
/// This is used to iterate over a contiguous series of either EIR or AD structures.
///
/// The iterator will stop if it a structure if there is no more data or a length field is zero
/// (which is used to indicate an early termination).
///
/// # Note: OOB data block
/// An OOB data block contain more data than just a series of EIR structures. Be sure to only
/// include the part that contains EIR structures when creating a `EirOrAdIterator`.
#[derive(Clone, Copy, Debug)]
pub struct EirOrAdIterator<'a>(&'a [u8]);

impl<'a> EirOrAdIterator<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        EirOrAdIterator(data)
    }

    /// Create a iterator that doesn't report an error
    ///
    /// In general it is not the fault of the recipient when they receive incorrectly formatted EIR
    /// or AD structures, so instead of reporting an error this will just end the iteration.
    pub fn silent(self) -> impl Iterator<Item = EirOrAdStruct<'a>> + 'a {
        struct Silent<'a>(&'a [u8]);

        impl<'a> Iterator for Silent<'a> {
            type Item = EirOrAdStruct<'a>;

            fn next(&mut self) -> Option<Self::Item> {
                EirOrAdStruct::try_new(self.0).ok().flatten().map(|(ad, rest)| {
                    self.0 = rest;
                    ad
                })
            }
        }

        Silent(self.0)
    }
}

impl<'a> From<&'a [u8]> for EirOrAdIterator<'a> {
    fn from(data: &'a [u8]) -> Self {
        Self::new(data)
    }
}

impl<'a> Iterator for EirOrAdIterator<'a> {
    type Item = Result<EirOrAdStruct<'a>, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0
            .len()
            .ne(&0)
            .then(|| match EirOrAdStruct::try_new(self.0) {
                Ok(None) => None,
                Ok(Some((ad, rest))) => {
                    self.0 = rest;
                    Some(Ok(ad))
                }
                Err(e) => {
                    self.0 = &[];
                    Some(Err(e))
                }
            })
            .flatten()
    }
}

/// An collector of EIR or AD structures
///
/// This is used to place multiple different types that implement [`IntoStruct`] into a sequence of
/// EIR or AD structures.
///
/// ```
/// # use bo_tie::gap::assigned;
/// # let buffer = &mut [u8;32];
///
/// let local_name = assigned::local_name::LocalName::new("My Device", None);
///
/// assigned::Sequence::new(buffer).try_add(&local_name)?;
///
/// assert_eq!(buffer[0..11], [0xa, 0x9, 0x4d, 0x79, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,]);
/// ```
#[derive(Debug)]
pub struct Sequence<'a>(&'a mut [u8]);

impl<'a> Sequence<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self(buffer)
    }

    /// Try to add a local type to the sequence
    ///
    /// The type is converted into a struct and added to the sequence.
    ///
    /// # Error
    /// An error is returned if there is not enough space left within the buffer
    pub fn try_add<T: IntoStruct + ?Sized>(self, t: &T) -> Result<Self, SequenceAddError> {
        if t.data_len().unwrap_or_default() + HEADER_SIZE > self.0.len() {
            let err = SequenceAddError {
                required: t.data_len().unwrap_or_default() + HEADER_SIZE,
                remaining: self.0.len(),
            };

            Err(err)
        } else {
            t.convert_into(self.0).unwrap();

            Ok(self)
        }
    }

    pub fn into_inner(self) -> &'a mut [u8] {
        self.0
    }
}

impl core::ops::Deref for Sequence<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

/// The error when a type cannot be added to a sequence of EIR or AD structures.
#[derive(Debug, Clone, Copy)]
pub struct SequenceAddError {
    /// The required number of bytes that need to be available for the struct
    pub required: usize,
    /// The remaining number of bytes within the buffer
    pub remaining: usize,
}

impl core::fmt::Display for SequenceAddError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Not enough space in buffer to add item. It requires {} bytes but only {} bytes are \
            available within the buffer",
            self.required, self.remaining
        )
    }
}

/// Sequence within a vector
///
/// The advantage of this over [`Sequence`] is that it can grow to add structures to the sequence
/// which means it cannot fail adding to the sequence. The downside is that it must allocate the
/// buffered space.
/// ```
/// # use bo_tie::gap::assigned;
/// # let buffer = &mut [u8;32];
///
/// let local_name = assigned::local_name::LocalName::new("My Device", None);
///
/// let buffer = assigned::Sequence::new(buffer).add(&local_name).take_inner();
///
/// assert_eq!(buffer, [0xa, 0x9, 0x4d, 0x79, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,]);
/// ```
#[derive(Clone, Debug, Default)]
pub struct SequenceVec(alloc::vec::Vec<u8>);

impl SequenceVec {
    /// Create a new `SequenceVec`
    pub fn new() -> Self {
        SequenceVec(alloc::vec::Vec::new())
    }

    /// Add an item to the sequence
    pub fn add<T: IntoStruct>(&mut self, t: T) -> &mut Self {
        let start = self.0.len();

        let data_len = match t.data_len() {
            Ok(len) => len,
            Err(len) => len,
        };

        self.0.resize(data_len + HEADER_SIZE, 0);

        t.convert_into(&mut self.0[start..]);

        self
    }

    /// Take the inner vector
    ///
    /// This will take the inner buffer, replacing it with an new vector
    pub fn take_inner(&mut self) -> alloc::vec::Vec<u8> {
        core::mem::take(&mut self.0)
    }

    /// Get the inner vector
    pub fn into_inner(self) -> alloc::vec::Vec<u8> {
        self.0
    }
}
