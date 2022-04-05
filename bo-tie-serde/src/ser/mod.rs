use crate::varnum;
use crate::Error;
use crate::TryExtend;
use serde::ser::{
    Serialize, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant, SerializeTuple,
    SerializeTupleStruct, SerializeTupleVariant,
};

/// Hints for serializing
///
/// Many structures defined within the Bluetooth Specification use information within the protocol
/// headers to forgo need serialization meta information. This is used to hint to the deserializer
/// whether meta data used for deserializing should be skipped.
pub trait SerializerHint {
    /// Clear all hints
    ///
    /// This method should be called in every `serialize_*` method once all relevant hints have
    /// been acquired by the deserialize method.
    ///
    /// This is deliberately unimplemented to force the implementation. Hints left uncleared can be
    /// difficult to debug where they were set, so clearing all unused hints is key to easier
    /// serialization.
    fn clear_hints(&mut self);

    /// Skip serializing the length Meta Data
    ///
    /// This hint is used to indicate to the deserializer that the length meta data of a string,
    /// byte array, sequence, or map does not need to be serialized. This hint only affects the next
    /// instance of one of those four data types.
    #[inline]
    fn set_skip_len_hint(&mut self) {}
}

pub trait HintedSerialize {
    fn hinted_serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: HintedSerializer,
        S::SerializeSeq: SerializerHint,
        S::SerializeTuple: SerializerHint,
        S::SerializeTupleStruct: SerializerHint,
        S::SerializeTupleVariant: SerializerHint,
        S::SerializeMap: SerializerHint,
        S::SerializeStruct: SerializerHint,
        S::SerializeStructVariant: SerializerHint;
}

/// A serializer
pub trait HintedSerializer: serde::ser::Serializer + SerializerHint {
    /// Serialize a bool
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_bool`](serde::ser::Serializer::serialize_bool)
    fn hinted_serialize_bool(mut self, v: bool) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_bool(self, v)
    }

    /// Serialize an i8
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_i8`](serde::ser::Serializer::serialize_i8)
    fn hinted_serialize_i8(mut self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_i8(self, v)
    }

    /// Serialize an i16
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_i16`](serde::ser::Serializer::serialize_i16)
    fn hinted_serialize_i16(mut self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_i16(self, v)
    }

    /// Serialize an i32
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_i32`](serde::ser::Serializer::serialize_i32)
    fn hinted_serialize_i32(mut self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_i32(self, v)
    }

    /// Serialize an i64
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_i64`](serde::ser::Serializer::serialize_i64)
    fn hinted_serialize_i64(mut self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_i64(self, v)
    }

    /// Serialize an i128
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_i128`](serde::ser::Serializer::serialize_i128)
    fn hinted_serialize_i128(mut self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_i128(self, v)
    }

    /// Serialize an u8
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_u8`](serde::ser::Serializer::serialize_u8)
    fn hinted_serialize_u8(mut self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_u8(self, v)
    }

    /// Serialize an u16
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_u16`](serde::ser::Serializer::serialize_u16)
    fn hinted_serialize_u16(mut self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_u16(self, v)
    }

    /// Serialize an u32
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_u32`](serde::ser::Serializer::serialize_u32)
    fn hinted_serialize_u32(mut self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_u32(self, v)
    }

    /// Serialize an u64
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_u64`](serde::ser::Serializer::serialize_u64)
    fn hinted_serialize_u64(mut self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_u64(self, v)
    }

    /// Serialize an u128
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_u128`](serde::ser::Serializer::serialize_u128)
    fn hinted_serialize_u128(mut self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_u128(self, v)
    }

    /// Serialize an f32
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_f32`](serde::ser::Serializer::serialize_f32)
    fn hinted_serialize_f32(mut self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_f32(self, v)
    }

    /// Serialize an f64
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_f64`](serde::ser::Serializer::serialize_f64)
    fn hinted_serialize_f64(mut self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_f64(self, v)
    }

    /// Serialize an char
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_char`](serde::ser::Serializer::serialize_char)
    fn hinted_serialize_char(mut self, v: char) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_char(self, v)
    }

    /// Serialize an str
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_str`](serde::ser::Serializer::serialize_str)
    fn hinted_serialize_str(mut self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_str(self, v)
    }

    /// Serialize an bytes
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_bytes`](serde::ser::Serializer::serialize_bytes)
    fn hinted_serialize_bytes(mut self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_bytes(self, v)
    }

    /// Serialize `None`
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_none`](serde::ser::Serializer::serialize_none)
    fn hinted_serialize_none(mut self) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_none(self)
    }

    /// Serialize `Some(T)`
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_some`](serde::ser::Serializer::serialize_some)
    fn hinted_serialize_some<V: ?Sized>(mut self, value: &V) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_some(self, value)
    }

    /// Serialize `()`
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_unit`](serde::ser::Serializer::serialize_unit)
    fn hinted_serialize_unit(mut self) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_unit(self)
    }

    /// Serialize a Unit Struct
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_unit_struct`](serde::ser::Serializer::serialize_unit_struct)
    fn hinted_serialize_unit_struct(mut self, name: &'static str) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_unit_struct(self, name)
    }

    /// Serialize a Unit Variant
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_unit_variant`](serde::ser::Serializer::serialize_unit_variant)
    fn hinted_serialize_unit_variant(
        mut self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.clear_hints();

        serde::ser::Serializer::serialize_unit_variant(self, name, variant_index, variant)
    }

    /// Serialize a New Type Struct
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_newtype_struct`](serde::ser::Serializer::serialize_newtype_struct)
    fn hinted_serialize_newtype_struct<V: ?Sized>(
        mut self,
        name: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_newtype_struct(self, name, value)
    }

    /// Serialize a New Type Variant
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_newtype_variant`](serde::ser::Serializer::serialize_newtype_variant)
    fn hinted_serialize_newtype_variant<V: ?Sized>(
        mut self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_newtype_variant(self, name, variant_index, variant, value)
    }

    /// Serialize a Sequence
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_seq`](serde::ser::Serializer::serialize_seq)
    fn hinted_serialize_seq(mut self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error>
    where
        Self::SerializeSeq: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_seq(self, len)
    }

    /// Serialize a Tuple
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_tuple`](serde::ser::Serializer::serialize_tuple)
    fn hinted_serialize_tuple(mut self, len: usize) -> Result<Self::SerializeTuple, Self::Error>
    where
        Self::SerializeTuple: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_tuple(self, len)
    }

    /// Serialize a Tuple Struct
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_tuple_struct`](serde::ser::Serializer::serialize_tuple_struct)
    fn hinted_serialize_tuple_struct(
        mut self,
        name: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error>
    where
        Self::SerializeTupleStruct: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_tuple_struct(self, name, len)
    }

    /// Serialize a Tuple Variant
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_tuple_variant`](serde::ser::Serializer::serialize_tuple_variant)
    fn hinted_serialize_tuple_variant(
        mut self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error>
    where
        Self::SerializeTupleVariant: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_tuple_variant(self, name, variant_index, variant, len)
    }

    /// Serialize a Map
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_map`](serde::ser::Serializer::serialize_map)
    fn hinted_serialize_map(mut self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error>
    where
        Self::SerializeMap: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_map(self, len)
    }

    /// Serialize a Struct
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_struct`](serde::ser::Serializer::serialize_struct)
    fn hinted_serialize_struct(mut self, name: &'static str, len: usize) -> Result<Self::SerializeStruct, Self::Error>
    where
        Self::SerializeStruct: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_struct(self, name, len)
    }

    /// Serialize a Struct Variant
    ///
    ///
    /// The default implementation clears all hints before calling
    /// [`Serializer::serialize_struct_variant`](serde::ser::Serializer::serialize_struct_variant)
    fn hinted_serialize_struct_variant(
        mut self,
        name: &'static str,
        variant_index: u32,
        variant: &'static str,
        len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error>
    where
        Self::SerializeStructVariant: SerializerHint,
    {
        self.clear_hints();

        serde::ser::Serializer::serialize_struct_variant(self, name, variant_index, variant, len)
    }
}

#[derive(Default)]
struct Serializer<T> {
    skip_next_len: bool,
    buffer: T,
}

impl<T> TryExtend<u8> for Serializer<T>
where
    T: TryExtend<u8>,
{
    fn try_extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) -> Result<(), Error>
    where
        I::IntoIter: ExactSizeIterator,
    {
        self.buffer.try_extend(iter)
    }
}

impl<'a, T> TryExtend<&'a u8> for Serializer<T>
where
    T: TryExtend<u8>,
{
    fn try_extend<I: IntoIterator<Item = &'a u8>>(&mut self, iter: I) -> Result<(), Error>
    where
        I::IntoIter: ExactSizeIterator,
    {
        self.buffer.try_extend(iter.into_iter().cloned())
    }
}

impl<T: TryExtend<u8>> core::fmt::Write for &mut Serializer<T> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.buffer.try_extend(s.bytes()).or(Err(core::fmt::Error))
    }
}

impl<T: TryExtend<u8>> serde::ser::Serializer for &mut Serializer<T> {
    type Ok = ();
    type Error = crate::Error;
    type SerializeSeq = Self;
    type SerializeTuple = Self;
    type SerializeTupleStruct = Self;
    type SerializeTupleVariant = Self;
    type SerializeMap = Self;
    type SerializeStruct = Self;
    type SerializeStructVariant = Self;

    fn serialize_bool(self, v: bool) -> Result<Self::Ok, Self::Error> {
        serde::ser::Serializer::serialize_u8(self, if v { 1u8 } else { 0u8 })
    }

    fn serialize_i8(self, v: i8) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_i16(self, v: i16) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_i32(self, v: i32) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_i64(self, v: i64) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_i128(self, v: i128) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_u8(self, v: u8) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_u16(self, v: u16) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_u32(self, v: u32) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_u64(self, v: u64) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_u128(self, v: u128) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_f32(self, v: f32) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_f64(self, v: f64) -> Result<Self::Ok, Self::Error> {
        self.try_extend(v.to_le_bytes())
    }

    fn serialize_char(self, v: char) -> Result<Self::Ok, Self::Error> {
        let char_buff = &mut [0u8; core::mem::size_of::<char>()];

        self.try_extend(v.encode_utf8(char_buff).bytes())
    }

    fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
        self.try_extend(varnum::StringLen::new(v.len()))?;

        self.try_extend(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        self.try_extend(varnum::BytesLen::new(v.len()))?;

        self.try_extend(v)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        serde::ser::Serializer::serialize_u8(self, 0)
    }

    fn serialize_some<V: ?Sized>(self, value: &V) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        serde::ser::Serializer::serialize_u8(&mut *self, 1)?;

        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
    ) -> Result<Self::Ok, Self::Error> {
        self.try_extend(varnum::VariantIndex::new(variant_index))
    }

    fn serialize_newtype_struct<V: ?Sized>(self, _name: &'static str, value: &V) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        value.serialize(self)
    }

    fn serialize_newtype_variant<V: ?Sized>(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        value: &V,
    ) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        self.try_extend(varnum::VariantIndex::new(variant_index))?;

        value.serialize(self)
    }

    fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        if let Some(len) = len {
            self.try_extend(varnum::SequenceLen::new(len))?;
        } else {
            return Err(Self::Error::StaticMessage("unknown length of sequence"));
        }

        Ok(self)
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, Self::Error> {
        self.try_extend(varnum::VariantIndex::new(variant_index))?;

        Ok(self)
    }

    fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        if let Some(len) = len {
            self.try_extend(varnum::MapLen::new(len))?;
        } else {
            return Err(Self::Error::StaticMessage("unknown length of map collection"));
        }

        Ok(self)
    }

    fn serialize_struct(self, _name: &'static str, _len: usize) -> Result<Self::SerializeStruct, Self::Error> {
        Ok(self)
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        variant_index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, Self::Error> {
        self.try_extend(varnum::VariantIndex::new(variant_index))?;

        Ok(self)
    }

    #[cfg(not(any(feature = "std", feature = "alloc")))]
    fn collect_str<T: ?Sized>(self, value: &T) -> Result<Self::Ok, Self::Error>
    where
        T: core::fmt::Display,
    {
        core::fmt::write(self, format_args!("{}", value)).map_err(|_| Error::TooLarge)
    }

    fn is_human_readable(&self) -> bool {
        false
    }
}

impl<T: TryExtend<u8>> SerializeSeq for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<V: ?Sized>(&mut self, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T: TryExtend<u8>> SerializeTuple for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_element<V: ?Sized>(&mut self, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T: TryExtend<u8>> SerializeTupleStruct for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized>(&mut self, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T: TryExtend<u8>> SerializeTupleVariant for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized>(&mut self, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T: TryExtend<u8>> SerializeMap for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_key<V: ?Sized>(&mut self, key: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        key.serialize(&mut **self)
    }

    fn serialize_value<V: ?Sized>(&mut self, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T: TryExtend<u8>> SerializeStruct for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized>(&mut self, _key: &'static str, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T: TryExtend<u8>> SerializeStructVariant for &mut Serializer<T> {
    type Ok = ();
    type Error = Error;

    fn serialize_field<V: ?Sized>(&mut self, _key: &'static str, value: &V) -> Result<(), Self::Error>
    where
        V: Serialize,
    {
        value.serialize(&mut **self)
    }

    fn end(self) -> Result<Self::Ok, Self::Error> {
        Ok(())
    }
}

impl<T> SerializerHint for &mut Serializer<T> {
    fn clear_hints(&mut self) {
        self.skip_next_len = false;
    }

    fn set_skip_len_hint(&mut self) {
        self.skip_next_len = true
    }
}

impl<T: TryExtend<u8>> HintedSerializer for &mut Serializer<T> {
    fn hinted_serialize_str(mut self, v: &str) -> Result<Self::Ok, Self::Error> {
        if !self.skip_next_len {
            self.try_extend(varnum::StringLen::new(v.len()))?;
        }

        self.clear_hints();

        self.try_extend(v.as_bytes())
    }

    fn hinted_serialize_bytes(mut self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        if !self.skip_next_len {
            self.try_extend(varnum::BytesLen::new(v.len()))?;
        }

        self.clear_hints();

        self.try_extend(v)
    }

    fn hinted_serialize_seq(mut self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
        if !self.skip_next_len {
            if let Some(len) = len {
                self.try_extend(varnum::SequenceLen::new(len))?;
            } else {
                return Err(Self::Error::StaticMessage("unknown length of sequence"));
            }
        }

        self.clear_hints();

        Ok(self)
    }

    fn hinted_serialize_map(mut self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
        if !self.skip_next_len {
            if let Some(len) = len {
                self.try_extend(varnum::MapLen::new(len))?;
            }
        }

        self.clear_hints();

        Ok(self)
    }
}

/// Serialize some data to a sized buffer
///
/// The input `t` will be serialized into a statically allocated buffer of size `SIZE`. The only
/// condition being that the generated serialization cannot be more bytes than SIZE.
pub fn serialize_sized<S, const SIZE: usize>(t: S) -> Result<impl core::ops::Deref<Target = [u8]>, Error>
where
    S: HintedSerialize,
{
    let mut serializer: Serializer<crate::StaticBuffer<SIZE>> = Default::default();

    t.hinted_serialize(&mut serializer).map(|_| serializer.buffer)
}

/// Serialize the input
///
/// Generates a serialization of input `t`.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn serialize<S>(t: S) -> Result<alloc::vec::Vec<u8>, Error>
where
    S: HintedSerialize,
{
    let mut serializer: Serializer<alloc::vec::Vec<u8>> = Default::default();

    t.hinted_serialize(&mut serializer).map(|_| serializer.buffer)
}
