//! The GATT Server
//!
//! This example creates a GATT server with only the Heart Rate profile.

use bo_tie::host::att::server::{AccessValue, NoQueuedWrites};
use bo_tie::host::att::{
    AttributePermissions, AttributeRestriction, EncryptionKeySize, TransferFormatError, TransferFormatInto,
    TransferFormatTryFrom,
};
use bo_tie::host::gatt::characteristic::Properties;
use bo_tie::host::gatt::{GapServiceBuilder, ServerBuilder};
use bo_tie::host::l2cap::{LeU, MinimumMtu};
use bo_tie::host::{gatt, Uuid};
use std::any::Any;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Appearance of a Generic Heart Rate Sensor (see the assigned number document section 2.6)
const APPEARANCE: u16 = 0x340;

/// The server for example
pub struct Server {
    server: gatt::Server<NoQueuedWrites>,
    heart_rate_measurement: HeartRateMeasurementArc,
}

/**
  Service UUIDs
*/
pub const HEART_RATE_SERVICE_UUID: Uuid = Uuid::from_u16(0x180D);
const DEVICE_INFORMATION_SERVICE_UUID: Uuid = Uuid::from_u16(0x1809);

/**
   Characteristic UUIDs for the Heart Rate Service

   Only the mandatory characteristics are used as "body sensor location" and "heart rate control
   point" do not make sense for this example
*/
const HEART_RATE_MEASUREMENT_UUID: Uuid = Uuid::from_u16(0x2A37);

/**
   Characteristic UUIDs for the Device Information Service
*/
// As per the specification for the Heart Rate Profile the Manufacture Name String is mandatory
const MANUFACTURER_NAME_STRING_UUID: Uuid = Uuid::from_u16(0);

impl Server {
    const ENCRYPTION_PERMISSIONS: [AttributePermissions; 2] = [
        AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
        AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    ];

    pub fn new(heart_rate_measurement: HeartRateMeasurementArc) -> Server {
        let mut gap_service = GapServiceBuilder::new(crate::EXAMPLE_NAME, APPEARANCE);

        // Connection interval of about half a second, the subrate
        // factor is never changed in this example (so it is always one)
        gap_service.add_preferred_connection_parameters(
            Duration::from_millis(450),
            Duration::from_millis(500),
            2,
            Duration::from_secs(3),
            None,
        );

        gap_service.add_rpa_only();

        let mut server_builder = ServerBuilder::from(gap_service);

        // add the service for heart rate measurement
        server_builder
            .new_service(HEART_RATE_SERVICE_UUID)
            .add_characteristics()
            .new_characteristic(|heart_rate_measurement_characteristic| {
                heart_rate_measurement_characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties([Properties::Read])
                            .set_uuid(HEART_RATE_MEASUREMENT_UUID)
                    })
                    .set_value(|value| {
                        value
                            .set_accessible_value(heart_rate_measurement.clone())
                            .set_permissions([AttributePermissions::Read(AttributeRestriction::Encryption(
                                EncryptionKeySize::Bits256,
                            ))])
                    })
                    .set_client_configuration(|client_config| client_config)
            })
            .finish_service();

        // add the service for the device information. Note: the heart rate profile requires the
        // manufactures name string within this service.
        server_builder
            .new_service(DEVICE_INFORMATION_SERVICE_UUID)
            .add_characteristics()
            .new_characteristic(|manufacture_name_string| {
                manufacture_name_string
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties([Properties::Read])
                            .set_uuid(MANUFACTURER_NAME_STRING_UUID)
                    })
                    .set_value(|value| {
                        value
                            .set_value(crate::EXAMPLE_NAME.to_string())
                            .set_permissions([AttributePermissions::Read(AttributeRestriction::None)])
                    })
            })
            .finish_service();

        let server = server_builder.make_server(NoQueuedWrites);

        println!("server:");
        for service in server.get_service_info() {
            println!(
                "service: {:x}, handle: {}, end handle: {}",
                service.get_uuid(),
                service.get_handle(),
                service.get_end_group_handle()
            );
        }

        Self {
            server,
            heart_rate_measurement,
        }
    }

    /// Get the Heart Rate Measurement Data
    ///
    /// This returns a `HeartRateMeasurement` which is a wrapper around an atomically counted
    /// reference to the heart rate measurement data.
    pub fn get_heart_rate_measurement_data(&self) -> HeartRateMeasurementArc {
        self.heart_rate_measurement.clone()
    }

    /// Process a L2CAP packet containing ATT protocol data
    pub async fn process<C: bo_tie::host::l2cap::ConnectionChannel>(
        &mut self,
        channel: &mut C,
        packet: &bo_tie::host::l2cap::BasicInfoFrame<Vec<u8>>,
    ) {
        self.server.process_acl_data(channel, packet).await.unwrap()
    }

    /// Give Permissions to the client when encrypted
    pub fn on_encryption(&mut self) {
        self.server.give_permissions_to_client(Self::ENCRYPTION_PERMISSIONS);
    }

    /// Revoke permissions to the client when unencrypted
    pub fn on_unencrypted(&mut self) {
        self.server.revoke_permissions_of_client(Self::ENCRYPTION_PERMISSIONS);
    }
}

/// A wrapper around the heart rate measurement data
///
/// This is a shared counted reference to the data that in the GATT server for the heart rate
/// measurement
#[derive(Clone)]
pub struct HeartRateMeasurementArc(Arc<Mutex<HeartRateMeasurementData>>);

impl HeartRateMeasurementArc {
    pub(crate) fn new() -> HeartRateMeasurementArc {
        let data = HeartRateMeasurementData {
            value: HeartRateValue::Uint8(0),
            contact_status: ContactStatus::NoContact,
            energy_expended: EnergyExpended::Unavailable,
            rr_intervals: VecDeque::new(),
            mtu: LeU::MIN_MTU,
        };

        let shared = Arc::new(Mutex::new(data));

        HeartRateMeasurementArc(shared)
    }

    pub async fn set_heart_rate(&mut self, rate: u16) {
        let value = <u8 as TryFrom<u16>>::try_from(rate)
            .map(|rate| HeartRateValue::Uint8(rate))
            .unwrap_or(HeartRateValue::Uint16(rate));

        self.0.lock().await.value = value;
    }

    pub async fn set_contact_status(&mut self, contact_status: ContactStatus) {
        self.0.lock().await.contact_status = contact_status
    }

    pub async fn increase_energy_expended(&mut self, by: u16) {
        let mut lock = self.0.lock().await;

        if let EnergyExpended::KiloJoules(expended) = lock.energy_expended {
            lock.energy_expended = match expended.checked_add(by) {
                None => EnergyExpended::KiloJoules(<u16>::MAX),
                Some(new_expended) => EnergyExpended::KiloJoules(new_expended),
            }
        } else {
            lock.energy_expended = EnergyExpended::KiloJoules(by)
        }
    }

    pub async fn reset_energy_expended(&mut self) {
        self.0.lock().await.energy_expended = EnergyExpended::KiloJoules(0)
    }

    pub async fn disable_energy_expended(&mut self) {
        self.0.lock().await.energy_expended = EnergyExpended::Unavailable
    }

    pub async fn add_rr_interval(&mut self, interval: u16) {
        self.0.lock().await.rr_intervals.push_back(interval)
    }

    /// Set the connection MTU
    ///
    /// The rr-intervals cannot be ['blobbed']. Only the number of rr-intervals that can fit within
    /// the maximum size of an ATT PDU
    ///
    /// ['blobbed']: /bo_tie/host/att/server/index.html#data-blobbing
    pub async fn set_mtu(&mut self, mtu: usize) {
        assert!(
            mtu >= LeU::MIN_MTU,
            "`mtu` cannot be less than the minimum MTU for a LE-U connection"
        );

        self.0.lock().await.mtu = mtu;
    }
}

impl AccessValue for HeartRateMeasurementArc {
    type ReadValue = HeartRateMeasurementData;
    type ReadGuard<'a> = tokio::sync::MutexGuard<'a, Self::ReadValue> where Self: 'a ;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a ;
    type WriteValue = ();
    type Write<'a> = Pin<Box<dyn Future<Output=()> +  Send + Sync>> where Self: 'a ;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(self.0.lock())
    }

    fn write(&mut self, _: Self::WriteValue) -> Self::Write<'_> {
        Box::pin(async { unreachable!() })
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}

pub struct HeartRateMeasurementData {
    value: HeartRateValue,
    contact_status: ContactStatus,
    energy_expended: EnergyExpended,
    rr_intervals: VecDeque<u16>,
    mtu: usize,
}

impl HeartRateMeasurementData {
    fn make_flags(&self) -> u8 {
        let mut flags = 0u8;

        match self.value {
            HeartRateValue::Uint8(_) => flags |= 0 << 0,
            HeartRateValue::Uint16(_) => flags |= 1 << 0,
        }

        match self.contact_status {
            ContactStatus::NoContact => flags |= 0 << 1,
            ContactStatus::PoorContact => flags |= 1 << 1,
            ContactStatus::FullContact => flags |= 0b11 << 1,
        }

        match self.energy_expended {
            EnergyExpended::Unavailable => flags |= 0 << 3,
            EnergyExpended::KiloJoules(_) => flags |= 1 << 3,
        }

        if self.rr_intervals.len() != 0 {
            flags |= 1 << 4
        }

        flags
    }
}

impl TransferFormatInto for HeartRateMeasurementData {
    fn len_of_into(&self) -> usize {
        let value_size = match self.value {
            HeartRateValue::Uint8(_) => 1,
            HeartRateValue::Uint16(_) => 2,
        };

        let energy_expended_size = match self.energy_expended {
            EnergyExpended::Unavailable => 0,
            EnergyExpended::KiloJoules(_) => 2,
        };

        let rr_intervals = self.rr_intervals.len() * 2;

        let total_size = value_size + energy_expended_size + rr_intervals;

        std::cmp::min(self.mtu, total_size)
    }

    fn build_into_ret(&self, mut into_ret: &mut [u8]) {
        into_ret[0] = self.make_flags();

        into_ret = &mut into_ret[1..];

        match self.value {
            HeartRateValue::Uint8(val) => {
                into_ret[0] = val;

                into_ret = &mut into_ret[1..];
            }
            HeartRateValue::Uint16(val) => {
                val.build_into_ret(&mut into_ret[..2]);

                into_ret = &mut into_ret[2..];
            }
        }

        match self.energy_expended {
            EnergyExpended::Unavailable => {}
            EnergyExpended::KiloJoules(val) => {
                val.build_into_ret(&mut into_ret[..2]);

                into_ret = &mut into_ret[2..];
            }
        }

        let mut rr_iter = self.rr_intervals.iter().copied();

        while into_ret.len() >= 2 {
            // this unwrap cannot fail as into_ret is always
            // less than or equal to the transfer data size
            rr_iter.next().unwrap().build_into_ret(&mut into_ret);

            into_ret = &mut into_ret[2..];
        }
    }
}

impl TransferFormatTryFrom for HeartRateMeasurementData {
    fn try_from(_: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

impl PartialEq for HeartRateMeasurementData {
    fn eq(&self, _: &Self) -> bool {
        // it does not make sense that two heart rate
        // measurements should be "equal".
        false
    }
}

pub enum HeartRateValue {
    Uint8(u8),
    Uint16(u16),
}

pub enum ContactStatus {
    NoContact,
    PoorContact,
    FullContact,
}

enum EnergyExpended {
    Unavailable,
    KiloJoules(u16),
}
