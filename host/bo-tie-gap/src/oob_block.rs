//! Out of band data block type
//!
//! This is used to create the data block sent as part of the out-of-band process for simple
//! pairing. The OOB data block for use with a Security Manager is created within the [bo-tie-sm]
//! crate.

use bo_tie_core::buffer::TryExtend;
use bo_tie_core::BluetoothDeviceAddress;

/// Builder of a Simple Pairing OOB data block for
pub struct SimplePairingOobBuilder<B> {
    buffer: B,
}

#[cfg(feature = "alloc")]
impl SimplePairingOobBuilder<alloc::vec::Vec<u8>> {
    /// Create a new `OobDataBlockBuilder`
    pub fn new(address: crate::BluetoothDeviceAddress) -> Self {
        let mut buffer = alloc::vec::Vec::new();

        // the length will eventually go here
        buffer.resize(2, 0);

        buffer.extend(address.0);

        SimplePairingOobBuilder { buffer }
    }
}

impl<T> SimplePairingOobBuilder<T>
where
    T: Extend<u8>,
{
    /// Add an EIR or AD type
    ///
    /// # Panic
    /// This will panic if the total data size will be greater than [`<u16>::MAX`]
    pub fn add<V>(&mut self, value: V)
    where
        V: IntoIterator<Item = u8>,
    {
        self.try_add(value).unwrap()
    }
}

impl<T> SimplePairingOobBuilder<T>
where
    T: TryExtend<u8>,
{
    /// Try to create a new `SimplePairingOobBuilder`
    ///
    /// # Error
    /// This will fail if the buffer fails to extend the length and address fields of the Simple
    /// Pairing OOB data.
    pub fn try_new(
        &mut self,
        mut buffer: T,
        address: BluetoothDeviceAddress,
    ) -> Result<Self, <T as TryExtend<u8>>::Error> {
        buffer.try_extend(core::iter::repeat_n(0, 2))?;

        buffer.try_extend(address.0)?;

        Ok(SimplePairingOobBuilder { buffer })
    }

    /// Try to add an EIR or AD type
    ///
    /// This will add the data type as long as there is enough room in the buffer.
    ///
    /// # Error
    /// An error is returned if either the buffer is out of room or the size of the data has
    /// exceeded [`<u16>::MAX`].
    pub fn try_add<V>(&mut self, value: V) -> Result<(), <T as TryExtend<u8>>::Error>
    where
        V: IntoIterator<Item = u8>,
    {
        self.buffer.try_extend(value)
    }

    /// Create the OOB data block
    ///
    /// [`&dyn IntoStruct`]: IntoStruct
    pub fn build(mut self) -> Result<T, ()>
    where
        T: core::ops::DerefMut<Target = [u8]>,
    {
        /// The minimum length for an OOB data block
        const MIN_SIZE: usize = 8;

        let len = <u16>::try_from(self.buffer.len() - MIN_SIZE).map_err(|_| ())?;

        self.buffer[0..2].copy_from_slice(&len.to_le_bytes());

        Ok(self.buffer)
    }
}
