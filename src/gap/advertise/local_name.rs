//! Local name data type
use super::*;

pub struct LocalName {
    name: alloc::string::String,
    is_short: bool,
}

impl LocalName {
    const SHORTENED_TYPE: AssignedTypes = AssignedTypes::ShortenedLocalName;
    const COMPLETE_TYPE: AssignedTypes = AssignedTypes::CompleteLocalName;

    /// Create a new local name data type
    ///
    /// If the name is 'short' then set the `short` parameter to true.
    /// See the Bluetooth Core Supplement Spec. section 1.2.1 for more details.
    pub fn new<T>(name: T, short: bool) -> Self
    where
        T: Into<alloc::string::String>,
    {
        Self {
            name: name.into(),
            is_short: short,
        }
    }

    pub fn is_short(&self) -> bool {
        self.is_short
    }
}

impl AsRef<str> for LocalName {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl core::ops::Deref for LocalName {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl From<LocalName> for alloc::string::String {
    fn from(ln: LocalName) -> alloc::string::String {
        ln.name
    }
}

impl IntoRaw for LocalName {
    fn into_raw(&self) -> alloc::vec::Vec<u8> {
        let data_type = if self.is_short {
            Self::SHORTENED_TYPE
        } else {
            Self::COMPLETE_TYPE
        };

        let mut val = new_raw_type(data_type.val());

        val.extend(self.name.clone().bytes());

        set_len(&mut val);

        val
    }
}

impl TryFromRaw for LocalName {
    fn try_from_raw(raw: &[u8]) -> Result<Self, Error> {
        log::trace!("Trying to convert '{:X?}' to Local Name", raw);

        from_raw!(raw, Self::SHORTENED_TYPE, Self::COMPLETE_TYPE, {
            use core::str::from_utf8;

            let ref_name = if raw.len() > 1 {
                from_utf8(&raw[1..]).map_err(|e| super::Error::UTF8Error(e))?
            } else {
                ""
            };

            Self {
                name: alloc::string::ToString::to_string(&ref_name),
                is_short: raw[0] == Self::SHORTENED_TYPE.val(),
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_from_raw_test() {
        let test_name_1 = [];
        // data containing invalid utf8 (any value > 0x7F in a byte is invalid)
        let test_name_2 = [AssignedTypes::CompleteLocalName.val(), 3, 12, 11, 0x80];
        // 'hello world' as name
        let test_name_3 = [
            AssignedTypes::CompleteLocalName.val(),
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x20,
            0x77,
            0x6f,
            0x72,
            0x6c,
            0x64,
        ];
        // 'hello wo' as name
        let test_name_4 = [
            AssignedTypes::ShortenedLocalName.val(),
            0x68,
            0x65,
            0x6c,
            0x6c,
            0x6f,
            0x20,
            0x77,
            0x6f,
        ];
        // Wrong AD type
        let test_name_5 = [AssignedTypes::Flags.val(), 0x68, 0x65, 0x6c, 0x6c];

        // The first two tests names should return errors
        assert!(LocalName::try_from_raw(&test_name_1).is_err());
        assert!(LocalName::try_from_raw(&test_name_2).is_err());

        // The next two tests names should be valid
        assert!(LocalName::try_from_raw(&test_name_3).is_ok());
        assert!(LocalName::try_from_raw(&test_name_4).is_ok());

        // Last one has wrong ad type
        assert!(LocalName::try_from_raw(&test_name_5).is_err());
    }
}
