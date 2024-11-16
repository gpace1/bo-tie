//! GATT attribute profile characteristics
//!
//! These are the characteristics of the GATT Attribute profile.

use crate::characteristic::VecArray;
use bo_tie_att::server::AccessValue;
use bo_tie_att::{TransferFormatError, TransferFormatInto, TransferFormatTryFrom};
use bo_tie_core::buffer::stack::LinearBuffer;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// The Value of the Service Changed Characteristic
#[derive(Debug)]
pub struct ServiceChangedValue {
    pub starting_handle: u16,
    pub ending_handle: u16,
}

impl TransferFormatInto for ServiceChangedValue {
    fn len_of_into(&self) -> usize {
        4
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret[0..2].copy_from_slice(&self.starting_handle.to_le_bytes());
        into_ret[2..4].copy_from_slice(&self.ending_handle.to_le_bytes());
    }
}

impl TransferFormatTryFrom for ServiceChangedValue {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        if raw.len() != 4 {
            return Err(TransferFormatError::bad_size("service changed", 4, raw.len()));
        }

        let starting_handle = <u16>::from_le_bytes([raw[0], raw[1]]);

        let ending_handle = <u16>::from_le_bytes([raw[2], raw[3]]);

        Ok(ServiceChangedValue {
            starting_handle,
            ending_handle,
        })
    }
}

/// Client Supported Features Characteristic
#[derive(Copy, Clone, PartialEq, bo_tie_macros::DepthCount)]
pub enum ClientFeatures {
    RobustCaching,
    EnhancedAttBearer,
    MultipleHandleValueNotifications,
}

type ClientFeaturesVec = VecArray<{ ClientFeatures::full_depth() }, ClientFeatures>;

pub(crate) struct ClientFeaturesValueAccessor<F> {
    features: ClientFeaturesVec,
    on_change: F,
}

impl<F> ClientFeaturesValueAccessor<F> {
    pub(crate) fn new(init_features: &[ClientFeatures], on_change: F) -> Self {
        let mut features = VecArray(LinearBuffer::new());

        init_features.iter().for_each(|feature| {
            if !features.0.contains(feature) {
                features.0.try_push(*feature).unwrap()
            }
        });

        Self { features, on_change }
    }
}

impl<Fun, Fut> AccessValue for ClientFeaturesValueAccessor<Fun>
where
    Fun: FnMut(ClientFeatures, bool) -> Fut + Send + 'static,
    Fut: core::future::Future + Send,
{
    type ReadValue = ClientFeaturesVec;
    type ReadGuard<'a> = &'a ClientFeaturesVec where Self: 'a;
    type Read<'a> = core::future::Ready<Result<Self::ReadGuard<'a>, bo_tie_att::pdu::Error>> where Self: 'a;
    type WriteValue = ClientFeaturesVec;
    type Write<'a> = WriteAccessor<'a, Fun, Fut> where Self: 'a;

    fn read(&mut self) -> Self::Read<'_> {
        core::future::ready(Ok(&self.features))
    }

    fn write(&mut self, features: Self::WriteValue) -> Self::Write<'_> {
        let previous = core::mem::replace(&mut self.features, features.clone());

        WriteAccessor {
            accessor: self,
            future: None,
            previous,
            new: features,
        }
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

pub(crate) struct WriteAccessor<'a, Fun, Fut> {
    accessor: &'a mut ClientFeaturesValueAccessor<Fun>,
    future: Option<Fut>,
    previous: ClientFeaturesVec,
    new: ClientFeaturesVec,
}

impl<Fun, Fut> Future for WriteAccessor<'_, Fun, Fut>
where
    Fun: FnMut(ClientFeatures, bool) -> Fut + Send,
    Fut: Future + Send,
{
    type Output = Result<(), crate::att::pdu::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.future.as_mut().take() {
                None => match this.new.0.pop() {
                    Some(feature) => match this.previous.0.iter().enumerate().find(|(_, f)| **f == feature) {
                        Some((index, _)) => {
                            this.previous.0.try_remove(index).unwrap();
                        }
                        None => this.future = Some((this.accessor.on_change)(feature, true)),
                    },
                    None => match this.previous.0.pop() {
                        Some(feature) => this.future = Some((this.accessor.on_change)(feature, false)),
                        None => return Poll::Ready(Ok(())),
                    },
                },
                Some(future) => match unsafe { Pin::new_unchecked(future).poll(cx) } {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(_) => {
                        this.future.take();
                    }
                },
            }
        }
    }
}

impl TransferFormatInto for ClientFeaturesVec {
    fn len_of_into(&self) -> usize {
        ClientFeatures::full_depth() / 8 + 1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let mut bit_field = 0;

        for feature in self.0.iter() {
            match feature {
                ClientFeatures::RobustCaching => bit_field |= 1 << 0,
                ClientFeatures::EnhancedAttBearer => bit_field |= 1 << 1,
                ClientFeatures::MultipleHandleValueNotifications => bit_field |= 1 << 2,
            }
        }

        into_ret[0] = bit_field;
    }
}

impl TransferFormatTryFrom for ClientFeaturesVec {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let mut ret = VecArray(LinearBuffer::new());

        if raw.len() == 1 {
            for i in 0..<u8>::BITS {
                match raw[0] & (1 << i) {
                    1 => ret.0.try_push(ClientFeatures::RobustCaching).unwrap(),
                    2 => ret.0.try_push(ClientFeatures::EnhancedAttBearer).unwrap(),
                    4 => ret
                        .0
                        .try_push(ClientFeatures::MultipleHandleValueNotifications)
                        .unwrap(),
                    _ => (),
                }
            }

            Ok(ret)
        } else {
            Err(TransferFormatError::bad_min_size("ClientFeatures", 1, raw.len()))
        }
    }
}

#[cfg(feature = "cryptography")]
#[derive(PartialEq)]
pub(crate) struct HashValue(u128);

#[cfg(feature = "cryptography")]
impl HashValue {
    /// Create a hash of all zeros
    ///
    /// This is used to create a temporary before all services have been added to a server builder.
    pub(crate) fn all_zero() -> HashValue {
        HashValue(0)
    }

    pub(crate) fn generate(server_attributes: &crate::att::server::ServerAttributes) -> Self {
        use crate::characteristic;
        use crate::characteristic::extended_properties::ExtendedProperties;
        use crate::characteristic::VecArray;
        use crate::{ServiceDefinition, ServiceInclude};

        // The largest size of a single attribute concat is
        // * 2 bytes for the attribute handle.
        // * 2 bytes for the attribute type (all are 16 bit shortened).
        // * 19 bytes for a characteristic declaration with a 16 byte value UUID.
        const CONCAT_SIZE: usize = 2 + 2 + 19;

        let msg = server_attributes
            .iter_info()
            .filter_map(|attribute_info| {
                let mut concat = LinearBuffer::<CONCAT_SIZE, u8>::new();

                match attribute_info.get_uuid() {
                    &ServiceDefinition::PRIMARY_SERVICE_TYPE
                    | &ServiceDefinition::SECONDARY_SERVICE_TYPE
                    | &ServiceInclude::TYPE
                    | &characteristic::declaration::TYPE
                    | &characteristic::extended_properties::TYPE
                    | &characteristic::user_description::TYPE
                    | &characteristic::client_config::TYPE
                    | &characteristic::server_config::TYPE
                    | &characteristic::presentation_format::TYPE
                    | &characteristic::aggregate_format::TYPE => (),
                    _ => return None,
                };

                for byte in attribute_info.get_handle().to_le_bytes().into_iter() {
                    concat.try_push(byte).unwrap();
                }

                let u16_type: u16 = (*attribute_info.get_uuid()).try_into().unwrap();

                for byte in u16_type.to_le_bytes() {
                    concat.try_push(byte).unwrap();
                }

                macro_rules! extend_hash_att_val {
                    ($kind:ty) => {{
                        let val = server_attributes.get_value::<$kind>(attribute_info.get_handle());

                        let len = val.len_of_into();

                        for _ in 0..len {
                            concat.try_push(0).unwrap();
                        }

                        val.build_into_ret(&mut concat[2..]);
                    }};
                }

                match attribute_info.get_uuid() {
                    &ServiceDefinition::PRIMARY_SERVICE_TYPE => extend_hash_att_val!(crate::Uuid),
                    &ServiceDefinition::SECONDARY_SERVICE_TYPE => extend_hash_att_val!(crate::Uuid),
                    &ServiceInclude::TYPE => extend_hash_att_val!(crate::ServiceInclude),
                    &characteristic::declaration::TYPE => extend_hash_att_val!(super::declaration::Declaration),
                    &characteristic::extended_properties::TYPE => {
                        extend_hash_att_val!(VecArray<{ ExtendedProperties::full_depth() }, ExtendedProperties>)
                    }
                    _ => (),
                }

                Some(concat)
            })
            .flatten();

        HashValue(bo_tie_core::cryptography::aes_cmac_generate(0, msg))
    }
}

#[cfg(feature = "cryptography")]
impl TransferFormatInto for HashValue {
    fn len_of_into(&self) -> usize {
        self.0.len_of_into()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        self.0.build_into_ret(into_ret)
    }
}

#[cfg(feature = "cryptography")]
impl TransferFormatTryFrom for HashValue {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let hash: u128 = TransferFormatTryFrom::try_from(raw)?;

        Ok(HashValue(hash))
    }
}

/// Features supported by the GATT server
#[derive(Copy, Clone, PartialEq, bo_tie_macros::DepthCount)]
pub enum ServerFeatures {
    /// Support for enhanced ATT bearers
    EattSupported,
}

#[derive(PartialEq)]
pub(crate) struct ServerFeaturesList {
    pub(crate) features: LinearBuffer<{ ServerFeatures::full_depth() }, ServerFeatures>,
}

impl ServerFeaturesList {
    pub(crate) fn new() -> Self {
        ServerFeaturesList {
            features: LinearBuffer::new(),
        }
    }
}

impl core::ops::Deref for ServerFeaturesList {
    type Target = [ServerFeatures];

    fn deref(&self) -> &Self::Target {
        &*self.features
    }
}

impl TransferFormatInto for ServerFeaturesList {
    fn len_of_into(&self) -> usize {
        ServerFeatures::full_depth()
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        for feature in self.features.iter() {
            match feature {
                ServerFeatures::EattSupported => into_ret[0] |= 1 << 0,
            }
        }
    }
}

impl TransferFormatTryFrom for ServerFeaturesList {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let mut list = ServerFeaturesList::new();

        if let Some(byte) = raw.get(0) {
            if 0 != byte & (1 << 0) {
                list.features.try_push(ServerFeatures::EattSupported).unwrap()
            }
        }

        Ok(list)
    }
}
