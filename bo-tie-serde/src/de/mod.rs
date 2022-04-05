use crate::varnum;
use serde::de::{DeserializeSeed, IntoDeserializer, Visitor};

/// Hints for deserializing
///
/// Many structures defined within the Bluetooth Specification use information within the protocol
/// headers to forgo needed serialization meta information.
pub trait DeserializerHint {
    /// Clear all hints
    ///
    /// This method should be called in every `deserialize_*` method once all relevant hints have
    /// been acquired by the deserialize method.
    ///
    /// This is deliberately unimplemented to force the implementation. Hints left uncleared can be
    /// difficult to debug where they were set, so clearing all unused hints is key to easier
    /// deserialization.
    fn clear_hints(&mut self);

    /// Set the length of the next unsized type
    ///
    /// Set the length to be used for the next string, byte array, sequence, or map. This hint is
    /// used whenever the length for these types is serialized outside the normal length meta data
    /// serialization placement.
    fn hint_next_len(&mut self, len: usize) {
        let _ = len;
    }
}

pub trait HintedDeserialize<'de>: Sized {
    fn hinted_deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: HintedDeserializer<'de> + DeserializerHint;
}

pub trait HintedDeserializeSeed<'de>: Sized {
    type Value;

    fn hinted_deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: HintedDeserializer<'de> + DeserializerHint;
}

pub trait HintedDeserializer<'de>: serde::de::Deserializer<'de> + DeserializerHint {
    fn hinted_deserialize_any<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_any(self, visitor)
    }

    fn hinted_deserialize_bool<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_bool(self, visitor)
    }

    fn hinted_deserialize_i8<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_i8(self, visitor)
    }

    fn hinted_deserialize_i16<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_i16(self, visitor)
    }

    fn hinted_deserialize_i32<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_i32(self, visitor)
    }

    fn hinted_deserialize_i128<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_i128(self, visitor)
    }

    fn hinted_deserialize_u8<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_u8(self, visitor)
    }

    fn hinted_deserialize_u16<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_u16(self, visitor)
    }

    fn hinted_deserialize_u32<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_u32(self, visitor)
    }

    fn hinted_deserialize_u64<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_u64(self, visitor)
    }

    fn hinted_deserialize_u128<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_u128(self, visitor)
    }

    fn hinted_deserialize_f32<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_f32(self, visitor)
    }

    fn hinted_deserialize_f64<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_f64(self, visitor)
    }

    fn hinted_deserialize_char<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_char(self, visitor)
    }

    fn hinted_deserialize_str<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_str(self, visitor)
    }

    fn hinted_deserialize_string<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_string(self, visitor)
    }

    fn hinted_deserialize_bytes<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_bytes(self, visitor)
    }

    fn hinted_deserialize_byte_buf<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_byte_buf(self, visitor)
    }

    fn hinted_deserialize_option<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_option(self, visitor)
    }

    fn hinted_deserialize_unit<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_unit(self, visitor)
    }

    fn hinted_deserialize_unit_struct<V>(mut self, name: &'static str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_unit_struct(self, name, visitor)
    }

    fn hinted_deserialize_newtype_struct<V>(mut self, name: &'static str, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_newtype_struct(self, name, visitor)
    }

    fn hinted_deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_seq(self, visitor)
    }

    fn hinted_deserialize_tuple<V>(mut self, len: usize, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_tuple(self, len, visitor)
    }

    fn hinted_deserialize_tuple_struct<V>(
        mut self,
        name: &'static str,
        len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_tuple_struct(self, name, len, visitor)
    }

    fn hinted_deserialize_map<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_map(self, visitor)
    }

    fn hinted_deserialize_struct<V>(
        mut self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_struct(self, name, fields, visitor)
    }

    fn hinted_deserialize_enum<V>(
        mut self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_enum(self, name, variants, visitor)
    }

    fn hinted_deserialize_identifier<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_identifier(self, visitor)
    }

    fn hinted_deserialize_ignored_any<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        self.clear_hints();

        serde::de::Deserializer::deserialize_ignored_any(self, visitor)
    }
}

pub trait HintedVisitor<'de>: Visitor<'de> {
    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: HintedDeserializer<'de>,
    {
        let _ = deserializer;
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Option, &self))
    }

    fn visit_newtype_struct<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: HintedDeserializer<'de>,
    {
        let _ = deserializer;
        Err(serde::de::Error::invalid_type(
            serde::de::Unexpected::NewtypeStruct,
            &self,
        ))
    }

    fn visit_seq<A>(self, seq: A) -> Result<Self::Value, A::Error>
    where
        A: DeserializerHint + serde::de::SeqAccess<'de>,
    {
        let _ = seq;
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Seq, &self))
    }

    fn visit_map<A>(self, map: A) -> Result<Self::Value, A::Error>
    where
        A: DeserializerHint + serde::de::MapAccess<'de>,
    {
        let _ = map;
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Map, &self))
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: DeserializerHint + serde::de::EnumAccess<'de>,
    {
        let _ = data;
        Err(serde::de::Error::invalid_type(serde::de::Unexpected::Enum, &self))
    }
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

impl DeserializerHint for &mut Deserializer<'_> {
    fn clear_hints(&mut self) {
        self.next_len = None;
    }

    fn hint_next_len(&mut self, len: usize) {
        self.next_len = Some(len);
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
        let len = self
            .try_take_varnum_usize::<varnum::StringLen>()
            .ok_or(Self::Error::ExpectedStrUTF8)?;

        let bytes = self.try_take(len).ok_or(Self::Error::ExpectedStrUTF8)?;

        let str = core::str::from_utf8(bytes).map_err(|_| Self::Error::ExpectedStrUTF8)?;

        visitor.visit_borrowed_str(str)
    }

    fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        serde::de::Deserializer::deserialize_str(self, visitor)
    }

    fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let len = self
            .try_take_varnum_usize::<varnum::BytesLen>()
            .ok_or(Self::Error::ExpectedArray("u8"))?;

        let bytes = self.try_take(len).ok_or(Self::Error::ExpectedArray("u8"))?;

        visitor.visit_borrowed_bytes(bytes)
    }

    fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        serde::de::Deserializer::deserialize_bytes(self, visitor)
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
        serde::de::Deserializer::deserialize_unit(self, visitor)
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
        let len = self
            .try_take_varnum_usize::<varnum::SequenceLen>()
            .ok_or(Self::Error::ExpectedSeq)?;

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
        serde::de::Deserializer::deserialize_tuple(self, len, visitor)
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
        serde::de::Deserializer::deserialize_tuple(self, fields.len(), visitor)
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

impl<'a, 'de: 'a> HintedDeserializer<'de> for &'a mut Deserializer<'de> {
    fn hinted_deserialize_str<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::StringLen>()
                .ok_or(Self::Error::ExpectedStrUTF8)?,
        );

        self.clear_hints();

        let bytes = self.try_take(len).ok_or(Self::Error::ExpectedStrUTF8)?;

        let str = core::str::from_utf8(bytes).map_err(|_| Self::Error::ExpectedStrUTF8)?;

        visitor.visit_borrowed_str(str)
    }

    fn hinted_deserialize_string<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        HintedDeserializer::hinted_deserialize_str(self, visitor)
    }

    fn hinted_deserialize_bytes<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::BytesLen>()
                .ok_or(Self::Error::ExpectedArray("u8"))?,
        );

        self.clear_hints();

        let bytes = self.try_take(len).ok_or(Self::Error::ExpectedArray("u8"))?;

        visitor.visit_borrowed_bytes(bytes)
    }

    fn hinted_deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        HintedDeserializer::hinted_deserialize_bytes(self, visitor)
    }

    fn hinted_deserialize_seq<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::SequenceLen>()
                .ok_or(Self::Error::ExpectedSeq)?,
        );

        self.clear_hints();

        let seq_access = DeserializeSeq {
            len,
            deserializer: self,
        };

        HintedVisitor::visit_seq(visitor, seq_access)
    }

    fn hinted_deserialize_map<V>(mut self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: HintedVisitor<'de>,
    {
        let len = self.take_next_len().unwrap_or(
            self.try_take_varnum_usize::<varnum::MapLen>()
                .ok_or(Self::Error::ExpectedMap)?,
        );

        self.clear_hints();

        HintedVisitor::visit_map(
            visitor,
            DeserializeMap {
                len,
                deserializer: self,
            },
        )
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

impl DeserializerHint for DeserializeSeq<'_, '_> {
    fn clear_hints(&mut self) {
        self.deserializer.clear_hints()
    }

    fn hint_next_len(&mut self, len: usize) {
        self.deserializer.hint_next_len(len)
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

impl DeserializerHint for DeserializeMap<'_, '_> {
    fn clear_hints(&mut self) {
        self.deserializer.clear_hints()
    }

    fn hint_next_len(&mut self, len: usize) {
        self.deserializer.hint_next_len(len)
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
    T: HintedDeserialize<'de>,
{
    let mut deserializer = Deserializer::from(s);

    T::hinted_deserialize(&mut deserializer)
}

/// Deserialize with a seed to type `T::Value`
///
/// Deserialize the input `s` using input `seed` to type `T::Value`.
pub fn deserialize_seeded<'de, T>(s: &'de [u8], seed: T) -> Result<T::Value, crate::error::Error>
where
    T: HintedDeserializeSeed<'de>,
{
    let mut deserializer = Deserializer::from(s);

    seed.hinted_deserialize(&mut deserializer)
}
