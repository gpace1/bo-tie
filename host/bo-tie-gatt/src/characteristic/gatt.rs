//! GATT attribute profile characteristics
//!
//! These are the characteristics of the GATT Attribute profile.

use crate::characteristic::{Characteristic, Properties};
use crate::{att, CharacteristicAdder};
use bo_tie_att::server::ServerAttributes;
use bo_tie_att::{AttributePermissions, TransferFormatError, FULL_PERMISSIONS};
use bo_tie_host_util::Uuid;
use bo_tie_util::buffer::stack::LinearBuffer;

pub type ServiceChangedValue = (u16, u16);

/// Service Changed Characteristic
pub struct ServiceChanged;

impl ServiceChanged {
    const UUID: Uuid = Uuid::from_u16(0x2A05);

    const VALUE_PERMISSIONS: [AttributePermissions; 0] = [];

    const PROPERTIES: [Properties; 1] = [Properties::Indicate];

    pub fn make_characteristic(adder: CharacteristicAdder<'_>) -> CharacteristicAdder<'_> {
        adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(Self::PROPERTIES).set_uuid(Self::UUID))
                .set_value(ServiceChangedValue::default())
        })
    }
}

/// Client Supported Features Characteristic
pub struct ClientFeatures;

impl ClientFeatures {
    const UUID: Uuid = Uuid::from_u16(0x2B29);

    const VALUE_PERMISSIONS: [AttributePermissions; 12] = FULL_PERMISSIONS;

    const PROPERTIES: [Properties; 2] = [Properties::Read, Properties::Write];

    pub fn make_characteristic(adder: CharacteristicAdder<'_>) -> CharacteristicAdder<'_> {
        adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(Self::PROPERTIES).set_uuid(Self::UUID))
                .set_value(ClientFeaturesValue::default())
        })
    }
}

#[derive(Default)]
struct ClientFeaturesValue {
    features: LinearBuffer<{ crate::ClientFeatures::full_depth() }, crate::ClientFeatures>,
}

impl att::TransferFormatInto for ClientFeaturesValue {
    fn len_of_into(&self) -> usize {
        crate::ClientFeatures::full_depth() / 8 + 1
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let mut bit_field = 0;

        for feature in self.features.iter() {
            match feature {
                crate::ClientFeatures::RobustCaching => bit_field |= (1 << 0),
                crate::ClientFeatures::EnhancedAttBearer => bit_field |= (1 << 1),
                crate::ClientFeatures::MultipleHandleValueNotifications => bit_field |= (1 << 2),
            }
        }
    }
}

impl att::TransferFormatTryFrom for ClientFeaturesValue {
    fn try_from(raw: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        let mut ret = ClientFeaturesValue {
            features: LinearBuffer::Default(),
        };

        if raw.len() == 1 {
            for i in 0..<u8>::BITS {
                match raw[0] & (1 << i) {
                    1 => ret.features.try_push(crate::ClientFeatures::RobustCaching).unwrap(),
                    2 => ret.features.try_push(crate::ClientFeatures::EnhancedAttBearer).unwrap(),
                    4 => ret
                        .features
                        .try_push(crate::ClientFeatures::MultipleHandleValueNotifications)
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

/// Database Hash Characteristic
pub struct DatabaseHash;

impl ClientFeatures {
    const UUID: Uuid = Uuid::from_u16(0x2B29);

    const VALUE_PERMISSIONS: [AttributePermissions; 12] = FULL_PERMISSIONS;

    const PROPERTIES: [Properties; 2] = [Properties::Read, Properties::Write];

    pub fn make_characteristic(adder: CharacteristicAdder<'_>) -> CharacteristicAdder<'_> {
        adder.new_characteristic(|builder| {
            builder
                .set_declaration(|builder| builder.set_properties(Self::PROPERTIES).set_uuid(Self::UUID))
                .set_value(ClientFeaturesValue::default())
        })
    }
}

#[cfg(feature = "cryptography")]
pub struct HashValue(u128);

#[cfg(feature = "cryptography")]
impl HashValue {
    fn generate<'a, T>(&mut self, services: T)
    where
        T: IntoIterator<Item = crate::Service<'a>>,
    {
        services.into_iter().map(|service| {
            service.
        })
    }
}
