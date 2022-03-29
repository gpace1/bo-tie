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
/// headers to forgo need serialization meta information.
///
pub trait SerializerHint {
    /// Skip the length of the next unsized type
    ///
    /// Skipping the length works for strings, byte arrays, and sequences. When this hint is set
    /// the *next* call to `serialize_str`, `serialize_bytes`, `serialize_seq`, or `serialize_map`
    /// will not serialize a length with the data. This method should only be called just before
    /// calling one of these methods.
    fn skip_next_len(&mut self);
}

#[derive(Default)]
struct Serializer<T> {
    skip_next_len: bool,
    buffer: T,
}

impl<T> Serializer<T> {
    fn take_length_skip(&mut self) -> bool {
        core::mem::take(&mut self.skip_next_len)
    }
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

impl<T> SerializerHint for Serializer<T> {
    fn skip_next_len(&mut self) {
        self.skip_next_len = true;
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
        self.serialize_u8(if v { 1u8 } else { 0u8 })
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
        if !self.take_length_skip() {
            self.try_extend(varnum::StringLen::new(v.len()))?;
        }

        self.try_extend(v.as_bytes())
    }

    fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
        if !self.take_length_skip() {
            self.try_extend(varnum::BytesLen::new(v.len()))?;
        }

        self.try_extend(v)
    }

    fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
        self.serialize_u8(0)
    }

    fn serialize_some<V: ?Sized>(self, value: &V) -> Result<Self::Ok, Self::Error>
    where
        V: Serialize,
    {
        self.serialize_u8(1)?;

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
        if !self.take_length_skip() {
            if let Some(len) = len {
                self.try_extend(varnum::SequenceLen::new(len))?;
            } else {
                return Err(Self::Error::StaticMessage("unknown length of sequence"));
            }
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
        if !self.take_length_skip() {
            if let Some(len) = len {
                self.try_extend(varnum::MapLen::new(len))?;
            }
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

/// Serialize some data to a sized buffer
///
/// The input `t` will be serialized into a statically allocated buffer of size `SIZE`. The only
/// condition being that the generated serialization cannot be more bytes than SIZE.
pub fn serialize_sized<D, const SIZE: usize>(t: D) -> Result<impl core::ops::Deref<Target = [u8]>, Error>
where
    D: Serialize,
{
    let mut serializer: Serializer<crate::StaticBuffer<SIZE>> = Default::default();

    t.serialize(&mut serializer).map(|_| serializer.buffer)
}

/// Serialize the input
///
/// Generates a serialization of input `t`.
#[cfg(any(feature = "alloc", feature = "std"))]
pub fn serialize<D>(t: D) -> Result<alloc::vec::Vec<u8>, Error>
where
    D: Serialize,
{
    let mut serializer: Serializer<alloc::vec::Vec<u8>> = Default::default();

    t.serialize(&mut serializer).map(|_| serializer.buffer)
}
