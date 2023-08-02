//! GATT attribute profile characteristics
//!
//! These are the characteristics of the GATT Attribute profile.

use bo_tie_att::{TransferFormatError, TransferFormatInto, TransferFormatTryFrom};
use bo_tie_core::buffer::stack::LinearBuffer;

/// The Value of the Service Changed Characteristic
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

#[derive(Default, PartialEq)]
pub(crate) struct ClientFeaturesValue {
    features: LinearBuffer<{ ClientFeatures::full_depth() }, ClientFeatures>,
}

impl ClientFeaturesValue {
    pub(crate) fn add_feature(&mut self, feature: ClientFeatures) {
        if !self.features.contains(&feature) {
            self.features.try_push(feature).unwrap();
        }
    }
}

impl TransferFormatInto for ClientFeaturesValue {
    fn len_of_into(&self) -> usize {
        ClientFeatures::full_depth() / 8 + 1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let mut bit_field = 0;

        for feature in self.features.iter() {
            match feature {
                ClientFeatures::RobustCaching => bit_field |= 1 << 0,
                ClientFeatures::EnhancedAttBearer => bit_field |= 1 << 1,
                ClientFeatures::MultipleHandleValueNotifications => bit_field |= 1 << 2,
            }
        }

        into_ret[0] = bit_field;
    }
}

impl TransferFormatTryFrom for ClientFeaturesValue {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let mut ret = ClientFeaturesValue {
            features: LinearBuffer::new(),
        };

        if raw.len() == 1 {
            for i in 0..<u8>::BITS {
                match raw[0] & (1 << i) {
                    1 => ret.features.try_push(ClientFeatures::RobustCaching).unwrap(),
                    2 => ret.features.try_push(ClientFeatures::EnhancedAttBearer).unwrap(),
                    4 => ret
                        .features
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
