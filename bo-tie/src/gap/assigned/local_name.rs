//! Local name data type
use super::*;
use alloc::string::String;

/// An advertised Local Name
///
/// Local names are either complete or incomplete within the advertising packet. As part of the
/// format of the local name, there is a flag to indicate if the name has been shortened from its
/// full length. A `LocalName` can be crated with this flag deliberately set or have it
/// automatically set if the size of the name is larger than the remaining bytes in an advertising
/// payload.
///
/// # Automatic Sizing
/// When the local name is to be automatically sized, it is sized down to the remaining bytes
/// available within an advertising payload. There is no limit to this size, so it can be sized down
/// to zero characters.
///
/// # Deliberate Sizing
/// When the size is deliberately set, the full length of the name that is assigned as part of the
/// creation of a `LocalName` must fit in the remaining bytes of an advertising payload.
pub struct LocalName<'a> {
    name: &'a str,
    is_full_name: Option<bool>,
}

impl<'a> LocalName<'a> {
    const SHORTENED_TYPE: AssignedTypes = AssignedTypes::ShortenedLocalName;
    const COMPLETE_TYPE: AssignedTypes = AssignedTypes::CompleteLocalName;

    /// Create a new local name data type
    pub fn new<S>(name: &'a str, is_full_name: S) -> Self
    where
        S: Into<Option<bool>>,
    {
        Self {
            name,
            is_full_name: is_full_name.into(),
        }
    }

    /// Check if the name is complete
    ///
    /// # Note
    /// True is returned if this `LocalName` was created without specifying if the name is complete
    /// or shortened.
    pub fn is_complete(&self) -> bool {
        self.is_full_name.unwrap_or(true)
    }
}

impl AsRef<str> for LocalName<'_> {
    fn as_ref(&self) -> &str {
        &self.name
    }
}

impl core::ops::Deref for LocalName<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.name
    }
}

impl alloc::string::ToString for LocalName<'_> {
    fn to_string(&self) -> String {
        self.name.to_string()
    }
}

impl IntoStruct for LocalName<'_> {
    fn data_len(&self) -> Result<usize, usize> {
        self.is_full_name.map(|_| self.name.len()).ok_or(self.name.len())
    }

    fn convert_into<'a>(&self, b: &'a mut [u8]) -> Option<EirOrAdStruct<'a>> {
        let ad_type = match self.is_full_name {
            Some(true) => Self::COMPLETE_TYPE,
            Some(false) => Self::SHORTENED_TYPE,
            None if self.name.len() > b.len().checked_sub(2)? => Self::SHORTENED_TYPE,
            None => Self::COMPLETE_TYPE,
        }
        .val();

        let mut interm = StructIntermediate::new(b, ad_type)?;

        if self.is_full_name.is_some() {
            self.name.bytes().try_for_each(|b| interm.next().map(|r| *r = b))?;
        } else {
            // This does not return if the end of slice in `interm` is reached.
            self.name.bytes().try_for_each(|b| interm.next().map(|r| *r = b));
        }

        interm.finish()
    }
}

impl<'a> TryFromStruct<'a> for LocalName<'a> {
    fn try_from_struct(r#struct: EirOrAdStruct<'a>) -> Result<Self, Error> {
        use core::str::from_utf8;

        let assigned_type = r#struct.get_type();

        let name = from_utf8(r#struct.into_inner()).map_err(|e| Error::UTF8Error(e))?;

        if assigned_type == Self::SHORTENED_TYPE.val() {
            Ok(Self {
                name,
                is_full_name: Some(false),
            })
        } else if assigned_type == Self::COMPLETE_TYPE.val() {
            Ok(Self {
                name,
                is_full_name: Some(true),
            })
        } else {
            Err(Error::IncorrectAssignedType)
        }
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
