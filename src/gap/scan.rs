/// Bluetooth scan

/// An iterator over a received scan payload
///
/// This is used for iterating over the data within an advertising payload and extracting out
/// everything that can be converted into `T`.
pub struct ScanPayloadIter<'a, T> {
    bytes: &'a [u8],
    pd: core::marker::PhantomData<T>,
}

impl<'a, T> ScanPayloadIter<'a, T> {
    /// Create an iterator over
    pub fn iter(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            pd: core::marker::PhantomData,
        }
    }
}

impl<T> Iterator for ScanPayloadIter<'_, T>
where
    T: super::advertise::TryFromRaw,
{
    type Item = Result<T, super::advertise::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        self.bytes.split_first().map(|(first, rest)| {
            let len = *first as usize;

            if rest.len() >= len {
                let (raw_data, rest_of) = rest.split_at(len);

                self.bytes = rest_of;

                T::try_from_raw(raw_data)
            } else {
                // This should happen only if a length (any of them) value is bad

                self.bytes = &[];

                Err(super::advertise::Error::IncorrectLength)
            }
        })
    }
}
