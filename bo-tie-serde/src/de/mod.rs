use crate::varnum;
use serde::de::{DeserializeSeed, IntoDeserializer, Visitor};

/// Hints for deserializing
///
/// Many structures defined within the Bluetooth Speceification use information within the protocol
/// headers to forgo needed serialization meta information.
pub trait DeserializerHint {
    /// Set the length of the next unsized type
    ///
    /// Set the length to be used for the next string, byte array, or sequence.
    fn set_next_len(&mut self, len: usize);
}

struct Deserializer<'de> {
    ser: &'de [u8],
    next_len: Option<usize>,
}

impl<'de> From<&'de [u8]> for Deserializer<'de> {
    fn from(ser: &'de [u8]) -> Self {
        Deserializer { ser, next_len: None }
    }
}

impl<'a, 'de: 'a> Deserializer<'de> {
    fn try_take(&'a mut self, how_many: usize) -> Option<&'de [u8]> {
        (self.ser.len() >= how_many).then(|| {
            let (ret, saved) = self.ser.split_at(how_many);

            self.ser = saved;

            ret
        })
    }

    fn take_next_len(&mut self) -> Option<usize> {
        self.next_len.take()
    }

    fn try_take_sized<const SIZE: usize>(&mut self) -> Option<[u8; SIZE]> {
        (self.ser.len() >= SIZE).then(|| {
            let (ret, saved) = self.ser.split_at(SIZE);

            let mut buffer = [0u8; SIZE];

            self.ser = saved;

            buffer.copy_from_slice(ret);

            buffer
        })
    }

    fn take_char(&mut self) -> Option<char> {
        // Determine how many bytes make up the char.
        //
        // This doesn't need to perform full validation as
        // that will be done within `from_utf8` later.
        let len = match self.ser.get(0) {
            None => return None,
            Some(x) if 0xC0 & x == 0xC0 => 2,
            Some(x) if 0xE0 & x == 0xE0 => 3,
            Some(x) if 0xF0 & x == 0xF0 => 4,
            _ => 1,
        };

        if self.ser.len() >= len {
            let (utf8, saved) = self.ser.split_at(len);

            self.ser = saved;

            core::str::from_utf8(utf8).ok().and_then(|str| str.chars().next())
        } else {
            None
        }
    }

    fn try_take_varnum_usize<V>(&mut self) -> Option<usize>
    where
        V: crate::varnum::DecodeUsize,
    {
        V::try_decode(self.ser).ok().map(|(value, size)| {
            self.ser = &self.ser[size..];

            value
        })
    }

    fn try_take_varnum_variant(&mut self) -> Option<u32> {
        use varnum::DecodeU32;

        varnum::VariantIndex::try_decode(self.ser).ok().map(|(value, size)| {
            self.ser = &self.ser[size..];

            value
        })
    }
}

macro_rules! impl_deserialize_num {
    ($this:expr, $num_ty:ty, $err:expr, $visitor:expr, $visit_fun:ident) => {{
        const SIZE: usize = core::mem::size_of::<$num_ty>();

        $this
            .try_take_sized::<SIZE>()
            .ok_or($err)
            .and_then(|raw| $visitor.$visit_fun(<$num_ty>::from_le_bytes(raw)))
    }};
}

impl<'a, 'de: 'a> serde::Deserializer<'de> for &'a mut Deserializer<'de> {
    type Error = crate::Error;

    fn deserialize_any<V>(self, _: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Self::Error::DeserializeAny)
    }

    fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.try_take(1).ok_or(Self::Error::ExpectedBoolean)? {
            [0] => visitor.visit_bool(false),
            [1] => visitor.visit_bool(true),
            _ => Err(Self::Error::ExpectedBoolean),
        }
    }

    fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, i8, Self::Error::ExpectedI8, visitor, visit_i8)
    }

    fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, i16, Self::Error::ExpectedI16, visitor, visit_i16)
    }

    fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, i32, Self::Error::ExpectedI32, visitor, visit_i32)
    }

    fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, i64, Self::Error::ExpectedI64, visitor, visit_i64)
    }

    fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, i128, Self::Error::ExpectedI128, visitor, visit_i128)
    }

    fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, u8, Self::Error::ExpectedU8, visitor, visit_u8)
    }

    fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, u16, Self::Error::ExpectedU16, visitor, visit_u16)
    }

    fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, u32, Self::Error::ExpectedU32, visitor, visit_u32)
    }

    fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, u64, Self::Error::ExpectedU64, visitor, visit_u64)
    }

    fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, u128, Self::Error::ExpectedU128, visitor, visit_u128)
    }

    fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, f32, Self::Error::ExpectedF32, visitor, visit_f32)
    }

    fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        impl_deserialize_num!(self, f64, Self::Error::ExpectedF64, visitor, visit_f64)
    }

    fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let char = self.take_char().ok_or(Self::Error::ExpectedChar)?;

        visitor.visit_char(char)
    }

    fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::StringLen>()
                .ok_or(Self::Error::ExpectedStrUTF8)?,
        );

        let bytes = self.try_take(len).ok_or(Self::Error::ExpectedStrUTF8)?;

        let str = core::str::from_utf8(bytes).map_err(|_| Self::Error::ExpectedStrUTF8)?;

        visitor.visit_borrowed_str(str)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_str(visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::BytesLen>()
                .ok_or(Self::Error::ExpectedArray("u8"))?,
        );

        let bytes = self.try_take(len).ok_or(Self::Error::ExpectedArray("u8"))?;

        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_bytes(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.try_take(1).ok_or(Self::Error::ExpectedOption)? {
            [0] => visitor.visit_none(),
            [1] => visitor.visit_some(self),
            _ => Err(Self::Error::BadOption),
        }
    }

    fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_unit(visitor)
    }

    fn deserialize_newtype_struct<V>(self, _name: &'static str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::SequenceLen>()
                .ok_or(Self::Error::ExpectedSeq)?,
        );

        let seq_access = DeserializeSeq {
            len,
            deserializer: self,
        };

        visitor.visit_seq(seq_access)
    }

    fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let seq_access = DeserializeSeq {
            len,
            deserializer: self,
        };

        visitor.visit_seq(seq_access)
    }

    fn deserialize_tuple_struct<V>(self, _name: &'static str, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(len, visitor)
    }

    fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::MapLen>()
                .ok_or(Self::Error::ExpectedMap)?,
        );

        visitor.visit_map(DeserializeMap {
            len,
            deserializer: self,
        })
    }

    fn deserialize_struct<V>(
        self,
        _name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.deserialize_tuple(fields.len(), visitor)
    }

    fn deserialize_enum<V>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(self)
    }

    fn deserialize_identifier<V>(self, _: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Self::Error::StaticMessage("deserialize identifier not supported"))
    }

    fn deserialize_ignored_any<V>(self, _: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        Err(Self::Error::StaticMessage("deserialize ignored any not supported"))
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

struct DeserializeSeq<'a, 'de> {
    len: usize,
    deserializer: &'a mut Deserializer<'de>,
}

impl<'a, 'de: 'a> serde::de::SeqAccess<'de> for DeserializeSeq<'a, 'de> {
    type Error = crate::Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        self.len
            .checked_sub(1)
            .map(|new_len| {
                self.len = new_len;

                seed.deserialize(&mut *self.deserializer)
            })
            .transpose()
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

struct DeserializeMap<'a, 'de> {
    len: usize,
    deserializer: &'a mut Deserializer<'de>,
}

impl<'a, 'de: 'a> serde::de::MapAccess<'de> for DeserializeMap<'a, 'de> {
    type Error = crate::Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        self.len
            .checked_sub(1)
            .map(|new_len| {
                self.len = new_len;
                seed.deserialize(&mut *self.deserializer)
            })
            .transpose()
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        seed.deserialize(&mut *self.deserializer)
    }

    fn size_hint(&self) -> Option<usize> {
        Some(self.len)
    }
}

impl<'a, 'de: 'a> serde::de::EnumAccess<'de> for &'a mut Deserializer<'de> {
    type Error = crate::Error;
    type Variant = Self;

    fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let variant = self.try_take_varnum_variant().ok_or(Self::Error::Eof)?;

        let v = seed.deserialize(variant.into_deserializer())?;

        Ok((v, self))
    }
}

impl<'a, 'de: 'a> serde::de::VariantAccess<'de> for &'a mut Deserializer<'de> {
    type Error = crate::Error;

    fn unit_variant(self) -> Result<(), Self::Error> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self)
    }

    fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        serde::Deserializer::deserialize_tuple(self, len, visitor)
    }

    fn struct_variant<V>(self, fields: &'static [&'static str], visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        serde::Deserializer::deserialize_tuple(self, fields.len(), visitor)
    }
}

/// Deserialize to type `T`
///
/// Deserialize the input `s` to type `T`.
pub fn deserialize<'de, T>(s: &'de [u8]) -> Result<T, crate::error::Error>
where
    T: serde::Deserialize<'de>,
{
    let mut deserializer = Deserializer::from(s);

    T::deserialize(&mut deserializer)
}

/// Deserialize with a seed to type `T::Value`
///
/// Deserialize the input `s` using input `seed` to type `T::Value`.
pub fn deserialize_seeded<'de, T>(s: &'de [u8], seed: T) -> Result<T::Value, crate::error::Error>
where
    T: serde::de::DeserializeSeed<'de>,
{
    let mut deserializer = Deserializer::from(s);

    seed.deserialize(&mut deserializer)
}
