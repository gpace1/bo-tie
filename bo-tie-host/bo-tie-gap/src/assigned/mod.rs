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

/// The maximum number of bytes within the data portion of an EIR or AD structure
const DATA_MAX_LEN: usize = u8::MAX as usize - 1;

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

#[derive(Debug, PartialEq)]
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
    AttributeFormat(bo_tie_att::TransferFormatError),
}

impl From<bo_tie_att::TransferFormatError> for Error {
    fn from(e: bo_tie_att::TransferFormatError) -> Self {
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
    len: usize,
    assigned_type: u8,
    buffer: &'a mut [u8],
}

impl<'a> StructIntermediate<'a> {
    /// Create an new `AdStructIntermediate`
    ///
    /// Input `b` is the buffer to put the structure. Input `assigned_type` is the assigned number
    /// for the data structure.
    ///
    /// Buffer `b` must have a length of two or greater or `None` is returned.
    fn new(b: &'a mut [u8], assigned_type: u8) -> Result<Self, ConvertError> {
        // The maximum size of an EIR or AD structure
        //
        // The length field of a structure is a byte so
        // the maximum size of a structure is one plus
        // the maximum of a `u8`.
        const MAXIMUM_SIZE: usize = <u8>::MAX as usize + 1;

        let buffer = match b.len() {
            0..=1 => {
                return Err(ConvertError {
                    required: HEADER_SIZE,
                    remaining: b.len(),
                })
            }
            HEADER_SIZE..=MAXIMUM_SIZE => b,
            // The size of the buffer is maxed to the largest sized structure
            _ => &mut b[..MAXIMUM_SIZE],
        };

        Ok(Self {
            len: HEADER_SIZE,
            assigned_type,
            buffer,
        })
    }

    /// Get the next byte
    fn next(&mut self) -> Option<&mut u8> {
        (self.buffer.len() != self.len).then(|| {
            let byte = &mut self.buffer[self.len];

            self.len += 1;

            byte
        })
    }

    /// Encode a character
    ///
    /// Encode a character as utf-8 into the buffer.
    ///
    /// # Panic
    /// This method assumes there is enough space to encode the character within the buffer
    fn encode_utf8(&mut self, c: char) {
        debug_assert_ne!(self.len, self.buffer.len());

        let old_len = self.len;

        self.len += c.len_utf8();

        c.encode_utf8(&mut self.buffer[old_len..self.len]);
    }

    /// Get the length of the remaining bytes of the buffer
    ///
    /// The return is the number of bytes that can be added to this buffer.
    pub fn remaining_len(&self) -> usize {
        self.buffer.len() - self.len
    }

    /// Extend by transfer formatted `T`
    ///
    /// This will try to extend the AD data by the Attribute transfer formatted data of `t`. If
    /// there were not enough bytes available, then none of the bytes will be added and `None` will
    /// be returned.
    fn try_extend_by<T>(&mut self, t: &T) -> Result<(), ConvertError>
    where
        T: bo_tie_att::TransferFormatInto,
    {
        let to_add_len = bo_tie_att::TransferFormatInto::len_of_into(t);

        if self.buffer.len() >= self.len + to_add_len {
            let start = self.len;

            self.len = self.len + to_add_len;

            bo_tie_att::TransferFormatInto::build_into_ret(t, &mut self.buffer[start..self.len]);

            Ok(())
        } else {
            Err(ConvertError {
                required: to_add_len,
                remaining: self.buffer.len() - self.len,
            })
        }
    }

    /// Fill-out the AD type
    ///
    /// The return is the bytes within the `ad` that were not used
    ///
    /// # Note
    /// This method is intended to be called at the end of an implementation of method
    /// [`convert_into`](IntoAdvDataStruct::convert_into) so return is always `Ok(_)`.
    fn finish(self) -> EirOrAdStruct<'a> {
        self.buffer[0] = (self.len - 1).try_into().unwrap();
        self.buffer[1] = self.assigned_type;

        EirOrAdStruct(&mut self.buffer[..self.len])
    }
}

/// A trait for converting a local type into an Extended Inquiry Response (EIR) or Advertising Data
/// (AD) Structure
pub trait IntoStruct {
    /// The required data length of an EIR or AD struct
    ///
    /// # Returning an Error
    /// If the data does not have a set or required size, then an error is returned with the full
    /// size of the data. Some types that have a shortened version will return this Error. If an
    /// error is returned it tells a user of this method (such as [`Sequence`]) that this is the
    /// suggested data length and to not report an error if there is not enough room for the full
    /// data.
    ///
    /// If `data_len` returns an `Err` then the implementation of `convert_into` must be able to
    /// accept a buffer `b` with a size less than needed for the full data and still return an
    /// `EirOrAdStruct`.
    ///
    /// A [`LocalName`](local_name::LocalName) is an example of a type that can return an `Err`.
    fn data_len(&self) -> Result<usize, usize>;

    /// Covert into its structure
    ///
    /// Input `b` is the buffer to contain the Structure. The implementor needs to create a
    /// structure and place it at the beginning of the buffer. If `b` is too small then the return
    /// is `None`.
    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Result<EirOrAdStruct<'a>, ConvertError>;
}

/// A trait for attempting to convert an Extended Inquiry Response (EIR) or Advertising Data (AD)
/// Structure to a local type
pub trait TryFromStruct<'a> {
    /// Attempt to convert an EIR or AD struct into this type
    fn try_from_struct(st: EirOrAdStruct<'a>) -> Result<Self, Error>
    where
        Self: Sized;
}

/// Error returned by [`IntoStruct::convert_into`]
///
/// This error is returned whenever converting a data type into an EIR or Ad structure fails because
/// there is not enough room in the buffer. `ConvertError` contains the number of bytes `required`
/// for creating the structure along with the number of bytes `remaining` in the buffer that can be
/// used for data structures.
#[derive(Debug, Clone, Copy)]
pub struct ConvertError {
    /// The required number of bytes that need to be available for the struct
    pub required: usize,
    /// The remaining number of bytes within the buffer
    pub remaining: usize,
}

impl core::fmt::Display for ConvertError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "Not enough space in buffer to add item. It requires {} bytes but only {} bytes are \
            available within the buffer",
            self.required, self.remaining
        )
    }
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

impl core::fmt::Display for DataTooLargeError {
    fn fmt(&self, f: &mut ::core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "Advertising Data Too Large")
    }
}

/// A wrapper around an EIR or AD structure
///
/// There is no functional difference between an EIR struct and an AD struct, but they are used
/// in different places within the Bluetooth specification and consequently within `bo-tie`. When
/// used, these places have provided an alias to this as either an EIR struct or an AD struct.
#[derive(Clone, Copy, Debug)]
pub struct EirOrAdStruct<'a>(&'a [u8]);

impl<'a> EirOrAdStruct<'a> {
    /// Try to create a new `EirOrAdStruct`
    ///
    /// This will return a new `EirOrAdStruct` if the bytes starts with and contains a complete
    /// EIR or AD struct. A slice to the rest of `bytes` is returned with the new `EirOrAdStruct`.
    ///
    /// `None` is returned if the length in the structure is zero. This is used to indicate an
    /// early termination of the entire data sequence, so any bytes that come after it are to be
    /// ignored.
    ///
    /// # Errors
    /// The length field of the first structure extended past the end of `bytes`. An error also
    /// occurs if `bytes` is empty.
    pub fn try_new(bytes: &'a [u8]) -> Result<Option<(Self, &'a [u8])>, Error> {
        let len = *bytes.get(0).ok_or(Error::RawTooSmall)? as usize;

        match len {
            0 => Ok(None),
            len if len < bytes.len() => Ok(Some((Self(&bytes[..1 + len]), &bytes[1 + len..]))),
            _ => Err(Error::IncorrectLength),
        }
    }

    /// Return the type
    ///
    /// This returns the EIR or AD type.
    pub fn get_type(&self) -> u8 {
        self.0[1]
    }

    /// Get the data bytes
    pub fn get_data(&self) -> &'a [u8] {
        if self.0[0] > 1 {
            &self.0[2..]
        } else {
            &[]
        }
    }

    /// Get the size of the structure
    ///
    /// This is the full size of the structure.
    ///
    /// ```
    /// # use bo_tie_gap::assigned::EirOrAdStruct;
    ///
    /// let eir = EirOrAdStruct::try_new(&[5,4,3,2,1,0]).unwrap().unwrap().0;
    ///
    /// assert_eq!(eir.size(), 2 + eir.get_data().len())
    /// ```
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
/// # use bo_tie_gap::assigned;
/// # use bo_tie_gap::assigned::IntoStruct;
/// # let buffer = &mut [0u8;32];
///
/// let local_name = assigned::local_name::LocalName::new("My Device", None);
///
/// assigned::Sequence::new(buffer).try_add(&local_name).unwrap();
///
/// assert_eq!(buffer[0..11], [0xa, 0x9, 0x4d, 0x79, 0x20, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65,]);
/// ```
#[derive(Debug)]
pub struct Sequence<'a> {
    len: usize,
    buffer: &'a mut [u8],
}

impl<'a> Sequence<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        let len = 0;

        Sequence { len, buffer }
    }

    /// Try to a a fully sized structure
    ///
    /// This will try to add the full size of the data type to the buffer returning an error if it
    /// cannot.
    fn try_add_full<T: IntoStruct + ?Sized>(&mut self, data_size: usize, t: &T) -> Result<(), ConvertError> {
        let struct_len = data_size + HEADER_SIZE;

        if struct_len > self.buffer.len() {
            let err = ConvertError {
                required: t.data_len().unwrap_or_default() + HEADER_SIZE,
                remaining: self.buffer.len(),
            };

            Err(err)
        } else {
            let end = self.len + struct_len;

            t.convert_into(&mut self.buffer[self.len..end])?;

            self.len += struct_len;

            Ok(())
        }
    }

    /// Try to add either the full size or a smaller size
    ///
    /// This will try to add the full size of the data type to the buffer. If it cannot then it
    /// will try falling back to an alternative size of the data before returning an error when all
    /// possible sizes do not fit.
    fn try_add_full_or<T: IntoStruct + ?Sized>(&mut self, data_size: usize, t: &T) -> Result<(), ConvertError> {
        use core::cmp::min;

        let struct_len = min(
            min(HEADER_SIZE + data_size, self.buffer[self.len..].len()),
            DATA_MAX_LEN,
        );

        let end = self.len + struct_len;

        let structure = t.convert_into(&mut self.buffer[self.len..end])?;

        self.len += structure.size();

        Ok(())
    }

    /// Try to add a local type to the sequence
    ///
    /// The type is converted into a struct and added to the sequence.
    ///
    /// # Error
    /// An error is returned if there is not enough space left within the buffer
    pub fn try_add<T: IntoStruct + ?Sized>(&mut self, t: &T) -> Result<(), ConvertError> {
        match t.data_len() {
            Ok(data_len) => self.try_add_full(data_len, t),
            Err(suggested_len) => self.try_add_full_or(suggested_len, t),
        }
    }

    /// Try to add the early termination structure
    ///
    /// This will add the early termination structure so long as there is at least one byte of space
    /// left within the buffer used to create this `Sequence`.
    pub fn try_add_early_term(&mut self) -> Result<(), ConvertError> {
        (self.len != self.buffer.len())
            .then(|| {
                self.buffer[self.len] = 0;

                self.len += 1;
            })
            .ok_or(ConvertError {
                required: 1,
                remaining: 0,
            })
    }

    /// Return the sequenced data
    ///
    /// The return is the sequenced structures (EIR or AD) within the buffer used to create the
    /// `Sequence`. The returned slice is also truncated to only contain the sequenced data.  
    pub fn into_inner(self) -> &'a mut [u8] {
        &mut self.buffer[..self.len]
    }
}

impl core::ops::Deref for Sequence<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.buffer
    }
}

/// Sequence within a vector
///
/// The advantage of this over [`Sequence`] is that it can grow to add structures to the sequence
/// which means it cannot fail adding to the sequence. The downside is that it must allocate the
/// buffered space.
/// ```
/// # use bo_tie_gap::assigned;
///
/// let local_name = assigned::local_name::LocalName::new("My Device", None);
///
/// let buffer = assigned::SequenceVec::new().add(local_name).take_inner();
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

        // this cannot fail unless the return of convert_to is incorrect
        t.convert_into(&mut self.0[start..]).unwrap();

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
