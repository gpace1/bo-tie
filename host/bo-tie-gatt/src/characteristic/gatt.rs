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
    type ReadGuard<'a>
        = &'a ClientFeaturesVec
    where
        Self: 'a;
    type Read<'a>
        = core::future::Ready<Result<Self::ReadGuard<'a>, bo_tie_att::pdu::Error>>
    where
        Self: 'a;
    type WriteValue = ClientFeaturesVec;
    type Write<'a>
        = WriteAccessor<'a, Fun, Fut>
    where
        Self: 'a;

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

    fn create_glob(server_attributes: &crate::att::server::ServerAttributes) -> impl Iterator<Item = u8> + '_ {
        use crate::characteristic;
        use crate::characteristic::extended_properties::ExtendedProperties;
        use crate::characteristic::VecArray;
        use crate::{ServiceDefinition, ServiceInclude};

        // The largest size of a single attribute concat is
        // * 2 bytes for the attribute handle.
        // * 2 bytes for the attribute type (hashed attributes only have 16 bit UUIDs).
        // * 19 bytes for a characteristic declaration with a 16 byte value UUID.
        const CONCAT_SIZE: usize = 2 + 2 + 19;

        server_attributes
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
                    | &characteristic::aggregate_format::TYPE => (), // hashed
                    _ => return None, // others are not hashed
                };

                attribute_info
                    .get_handle()
                    .to_le_bytes()
                    .into_iter()
                    .for_each(|byte| concat.try_push(byte).unwrap());

                // All the attribute UUIDs can be converted to a 16 bit shortened form
                <u16 as TryFrom<crate::Uuid>>::try_from(*attribute_info.get_uuid())
                    .unwrap()
                    .to_le_bytes()
                    .into_iter()
                    .for_each(|byte| concat.try_push(byte).unwrap());

                macro_rules! extend_hash_att_val {
                    ($kind:ty) => {{
                        let val = server_attributes
                            .get_value::<$kind>(attribute_info.get_handle())
                            .unwrap();

                        for _ in 0..val.len_of_into() {
                            concat.try_push(0).unwrap();
                        }

                        val.build_into_ret(&mut concat[4..]);
                    }};
                }

                match attribute_info.get_uuid() {
                    &ServiceDefinition::PRIMARY_SERVICE_TYPE => extend_hash_att_val!(crate::Uuid),
                    &ServiceDefinition::SECONDARY_SERVICE_TYPE => extend_hash_att_val!(crate::Uuid),
                    &ServiceInclude::TYPE => extend_hash_att_val!(ServiceInclude),
                    &characteristic::declaration::TYPE => extend_hash_att_val!(super::declaration::Declaration),
                    &characteristic::extended_properties::TYPE => {
                        extend_hash_att_val!(VecArray<{ ExtendedProperties::full_depth() }, ExtendedProperties>)
                    }
                    _ => (), // all others do not have their attribute value hashed
                }

                Some(concat)
            })
            .flatten()
    }

    pub(crate) fn generate(server_attributes: &crate::att::server::ServerAttributes) -> Self {
        HashValue(bo_tie_core::cryptography::aes_cmac_generate(
            0,
            Self::create_glob(server_attributes),
        ))
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

#[cfg(test)]
mod tests {
    use crate::characteristic::gatt::HashValue;
    use crate::characteristic::{
        ClientConfiguration, ExtendedProperties, Properties, ServerConfiguration, ServerConfigurationBuilder,
    };
    use crate::ServerBuilder;
    use bo_tie_att::{FULL_READ_PERMISSIONS, FULL_RESTRICTIONS};
    use std::time::Duration;

    /// `HashValue` pretests
    ///
    /// These tests are tests that break down the full test of hash_value_generate so that an error
    /// within the full test can more easily be understood.
    #[cfg(feature = "cryptography")]
    mod pretest_hash_value {
        use super::*;

        #[test]
        fn only_hash_characteristic() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn another_service() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder.add_service(0x1234u16).make_empty();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12,
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn secondary_service() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder.add_service(0x1234u16).make_secondary().make_empty();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x01, 0x28, 0x34, 0x12,
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn include_service() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            let record = server_builder
                .add_service(0x1234u16)
                .make_secondary()
                .make_empty()
                .as_record();

            server_builder
                .add_service(0xabcdu16)
                .into_includes_adder()
                .include_service(record)
                .unwrap()
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x01, 0x28, 0x34, 0x12, // included secondary service
                0x05, 0x00, 0x00, 0x28, 0xcd, 0xab, // primary service
                0x06, 0x00, 0x02, 0x28, 0x04, 0x00, 0x04, 0x00, 0x34, 0x12,
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn characteristic() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder
                .add_service(0x1234u16)
                .add_characteristics()
                .new_characteristic(|builder| {
                    builder
                        .set_declaration(|d| {
                            d.set_properties([Properties::Read, Properties::Write])
                                .set_uuid(0x1001u16)
                        })
                        .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                })
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12, // service
                0x05, 0x00, 0x03, 0x28, 0x0a, 0x06, 0x00, 0x01, 0x10, // characteristic declaration
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn characteristic_u128() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder
                .add_service(0x1234u16)
                .add_characteristics()
                .new_characteristic(|builder| {
                    builder
                        .set_declaration(|d| {
                            d.set_properties([Properties::Read, Properties::Write])
                                .set_uuid(0xC132F5C9F618CBA7D302FB8E77E3BFBDu128)
                        })
                        .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                })
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            #[rustfmt::skip]
            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12, // service
                // characteristic declaration
                0x05, 0x00, 0x03, 0x28, 0x0a, 0x06, 0x00, 0xbd, 0xbf, 0xe3, 0x77, 0x8e, 0xfb, 0x02, 0xd3, 0xa7, 0xcb, 0x18, 0xf6, 0xc9, 0xf5, 0x32, 0xc1,
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn characteristic_extended_properties() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder
                .add_service(0x1234u16)
                .add_characteristics()
                .new_characteristic(|builder| {
                    builder
                        .set_declaration(|d| {
                            d.set_properties([Properties::Read, Properties::Write, Properties::ExtendedProperties])
                                .set_uuid(0x1001u16)
                        })
                        .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                        .set_extended_properties(|e| e.set_extended_properties([ExtendedProperties::ReliableWrite]))
                })
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12, // service
                0x05, 0x00, 0x03, 0x28, 0x8a, 0x06, 0x00, 0x01, 0x10, // characteristic declaration
                0x07, 0x00, 0x00, 0x29, 0x01, 0x00, // characteristic extended properties
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn characteristic_user_description() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder
                .add_service(0x1234u16)
                .add_characteristics()
                .new_characteristic(|builder| {
                    builder
                        .set_declaration(|d| {
                            d.set_properties([Properties::Read, Properties::Write, Properties::ExtendedProperties])
                                .set_uuid(0x1001u16)
                        })
                        .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                        .set_user_description(|d| {
                            d.set_read_only_description("user description")
                                .set_read_only_restrictions(FULL_RESTRICTIONS)
                        })
                })
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12, // service
                0x05, 0x00, 0x03, 0x28, 0x8a, 0x06, 0x00, 0x01, 0x10, // characteristic declaration
                0x07, 0x00, 0x01, 0x29, // characteristic user description
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn client_characteristic_configuration() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder
                .add_service(0x1234u16)
                .add_characteristics()
                .new_characteristic(|builder| {
                    builder
                        .set_declaration(|d| {
                            d.set_properties([Properties::Read, Properties::Write, Properties::ExtendedProperties])
                                .set_uuid(0x1001u16)
                        })
                        .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                        .set_client_configuration(|c| c.set_config([ClientConfiguration::Notification]))
                })
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12, // service
                0x05, 0x00, 0x03, 0x28, 0x8a, 0x06, 0x00, 0x01, 0x10, // characteristic declaration
                0x07, 0x00, 0x02, 0x29, // client characteristic configuration
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        #[test]
        fn server_characteristic_configuration() {
            let mut server_builder = ServerBuilder::new_empty();

            server_builder.add_gatt_service(|builder| builder.add_database_hash());

            server_builder
                .add_service(0x1234u16)
                .add_characteristics()
                .new_characteristic(|builder| {
                    builder
                        .set_declaration(|d| {
                            d.set_properties([Properties::Read, Properties::Write, Properties::ExtendedProperties])
                                .set_uuid(0x1001u16)
                        })
                        .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                        .set_server_configuration(|| {
                            let mut server_configuration = ServerConfiguration::new();

                            server_configuration.set_broadcast();

                            ServerConfigurationBuilder::new()
                                .set_config(bo_tie_att::server::TrivialAccessor(server_configuration))
                                .set_write_restrictions([])
                        })
                })
                .finish_service();

            let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

            let hash = HashValue::generate(&server_builder.attributes);

            let exp_glob = [
                0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
                0x02, 0x00, 0x03, 0x28, 0x02, 0x03, 0x00, 0x2a, 0x2b, // Database Hash characteristic
                0x04, 0x00, 0x00, 0x28, 0x34, 0x12, // service
                0x05, 0x00, 0x03, 0x28, 0x8a, 0x06, 0x00, 0x01, 0x10, // characteristic declaration
                0x07, 0x00, 0x03, 0x29, // client characteristic configuration
            ];

            let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

            assert_eq!(glob, exp_glob);

            assert_eq!(hash.0, exp_hash);
        }

        // todo: `characteristic_presentation_format` and `characteristic_aggregate_format`
    }

    #[test]
    #[cfg(feature = "cryptography")]
    fn hash_value_generate() {
        let mut server_builder = ServerBuilder::new_empty();

        server_builder.add_gatt_service(|builder| {
            builder
                .add_service_changed(false, |_| async {}, [])
                .add_database_hash()
                .add_client_supported_features([], |_, _| async {})
        });

        server_builder.add_gap_service(None, None, |builder| {
            builder.device_is_discoverable();
            builder.add_preferred_connection_parameters(
                Duration::from_millis(80),
                Duration::from_millis(400),
                10,
                Duration::from_millis(1000),
                None,
            );
        });

        let record = server_builder
            .add_service(0x4002u16)
            .add_characteristics()
            .new_characteristic(|builder| {
                builder
                    .set_declaration(|d| {
                        d.set_properties([
                            Properties::Broadcast,
                            Properties::Read,
                            Properties::Write,
                            Properties::Notify,
                            Properties::ExtendedProperties,
                        ])
                        .set_uuid(0x5002u16)
                    })
                    .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
                    .set_extended_properties(|e| e.set_extended_properties([ExtendedProperties::ReliableWrite]))
                    .set_user_description(|d| {
                        d.set_read_only_description("this is the description")
                            .set_read_only_restrictions(FULL_RESTRICTIONS)
                    })
                    .set_client_configuration(|c| {
                        c.set_config([ClientConfiguration::Notification, ClientConfiguration::Indication])
                            .set_write_callback(|_| async {})
                            .set_write_restrictions(FULL_RESTRICTIONS)
                    })
                    .set_server_configuration(|| {
                        let mut server_configuration = ServerConfiguration::new();

                        server_configuration.set_broadcast();

                        ServerConfigurationBuilder::new()
                            .set_config(bo_tie_att::server::TrivialAccessor(server_configuration))
                            .set_write_restrictions([])
                    })
                /* todo add the characteristic presentation format and characteristic aggregate format descriptors */
            })
            .finish_service()
            .as_record();

        server_builder
            .add_service(0x6623_44B9_BF0C_A488_A7A3_4FC4_A463_B157u128)
            .into_includes_adder()
            .include_service(record)
            .unwrap()
            .add_characteristics()
            .new_characteristic(|builder| {
                builder
                    .set_declaration(|d| {
                        d.set_properties([Properties::Read])
                            .set_uuid(0x7F95_A2B0_9E51_5CD8_C8CF_523F_C107_FD93u128)
                    })
                    .set_value(|v| v.set_value(0usize).set_permissions(FULL_READ_PERMISSIONS))
            })
            .finish_service();

        let glob = HashValue::create_glob(&server_builder.attributes).collect::<Vec<_>>();

        let hash = HashValue::generate(&server_builder.attributes);

        #[rustfmt::skip]
        let exp_glob = [
            0x01, 0x00, 0x00, 0x28, 0x01, 0x18, // GATT service
            0x02, 0x00, 0x03, 0x28, 0x20, 0x03, 0x00, 0x05, 0x2a, // Service Changed
            0x04, 0x00, 0x02, 0x29, // Service Changed client characteristic configuration
            0x05, 0x00, 0x03, 0x28, 0x02, 0x06, 0x00, 0x2a, 0x2b, // Database Hash
            0x07, 0x00, 0x03, 0x28, 0x0a, 0x08, 0x00, 0x29, 0x2b, // client supported features
            0x09, 0x00, 0x00, 0x28, 0x00, 0x18, // GAP service
            0x0a, 0x00, 0x03, 0x28, 0x02, 0x0b, 0x00, 0x00, 0x2a, // device name
            0x0c, 0x00, 0x03, 0x28, 0x02, 0x0d, 0x00, 0x01, 0x2a, // appearance
            0x0e, 0x00, 0x03, 0x28, 0x02, 0x0f, 0x00, 0x04, 0x2a, // peripheral preferred connection parameters
            0x10, 0x00, 0x00, 0x28, 0x02, 0x40, // first custom service
            0x11, 0x00, 0x03, 0x28, 0x9b, 0x12, 0x00, 0x02, 0x50, // first service's characteristic
            0x13, 0x00, 0x00, 0x29, 0x01, 0x00, // characteristic extended properties
            0x14, 0x00, 0x01, 0x29, // characteristic user description
            0x15, 0x00, 0x02, 0x29, // user characteristic configuration
            0x16, 0x00, 0x03, 0x29, // server characteristic configuration
            // second custom service
            0x17, 0x00, 0x00, 0x28, 0x57, 0xb1, 0x63, 0xa4, 0xc4, 0x4f, 0xa3, 0xa7, 0x88, 0xa4, 0x0c, 0xbf, 0xb9, 0x44, 0x23, 0x66,
            0x18, 0x00, 0x02, 0x28, 0x10, 0x00, 0x16, 0x00, 0x02, 0x40, // included service
            // second service's characteristic
            0x19, 0x00, 0x03, 0x28, 0x02, 0x1a, 0x00, 0x93, 0xfd, 0x07, 0xc1, 0x3f, 0x52, 0xcf, 0xc8, 0xd8, 0x5c, 0x51, 0x9e, 0xb0, 0xa2, 0x95, 0x7f,
        ];

        let exp_hash = bo_tie_core::cryptography::aes_cmac_generate(0, exp_glob);

        assert_eq!(glob, exp_glob);

        assert_eq!(hash.0, exp_hash);
    }
}
