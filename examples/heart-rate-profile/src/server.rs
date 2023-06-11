//! The GATT Server
//!
//! This example creates a GATT server with only the Heart Rate profile.

use bo_tie::host::att::client::ClientPduName;
use bo_tie::host::att::server::{AccessValue, NoQueuedWrites};
use bo_tie::host::att::{
    AttributePermissions, AttributeRestriction, EncryptionKeySize, TransferFormatError, TransferFormatInto,
    TransferFormatTryFrom,
};
use bo_tie::host::gatt::characteristic::{ClientConfiguration, Properties};
use bo_tie::host::gatt::{GapServiceBuilder, ServerBuilder};
use bo_tie::host::l2cap::{LeU, MinimumMtu};
use bo_tie::host::{gatt, Uuid};
use std::any::Any;
use std::collections::VecDeque;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// Appearance of a Generic Heart Rate Sensor (see the assigned number document section 2.6)
const APPEARANCE: u16 = 0x340;

/// The server for example
pub struct Server {
    server: gatt::Server<NoQueuedWrites>,
    local_heart_rate_measurement: LocalHeartRateMeasurementArc,
    hrd_handle: u16,
    notify_hrd: Arc<AtomicBool>,
}

/**
  Service UUIDs
*/
pub const HEART_RATE_SERVICE_UUID: Uuid = Uuid::from_u16(0x180D);
const DEVICE_INFORMATION_SERVICE_UUID: Uuid = Uuid::from_u16(0x180a);

/**
   Characteristic UUIDs for the Heart Rate Service

   Only the mandatory characteristics are used as "body sensor location" and "heart rate control
   point" do not make sense for this example
*/
const HEART_RATE_MEASUREMENT_UUID: Uuid = Uuid::from_u16(0x2A37);

const HEART_RATE_CONTROL_POINT_UUID: Uuid = Uuid::from_u16(0x2a39);

/**
   Characteristic UUIDs for the Device Information Service
*/
const MANUFACTURER_NAME_STRING_UUID: Uuid = Uuid::from_u16(0x2A29);

/**
    Error Codes
*/
const CONTROL_POINT_NOT_SUPPORTED: u8 = 0x80;

impl Server {
    const ENCRYPTION_PERMISSIONS: [AttributePermissions; 2] = [
        AttributePermissions::Read(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
        AttributePermissions::Write(AttributeRestriction::Encryption(EncryptionKeySize::Bits256)),
    ];

    pub fn new(heart_rate_measurement: HeartRateMeasurementArc, is_notifications_enabled: bool) -> Server {
        let notify_hrd: Arc<AtomicBool> = Arc::new(AtomicBool::new(is_notifications_enabled));

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

        let local_heart_rate_measurement = LocalHeartRateMeasurementArc::new(heart_rate_measurement);

        server_builder.new_gatt_service(|gatt_service| gatt_service.add_database_hash());

        // add the service for heart rate measurement
        let heart_rate_characteristic_adder = server_builder
            .new_service(HEART_RATE_SERVICE_UUID)
            .add_characteristics()
            .new_characteristic(|heart_rate_measurement_characteristic| {
                heart_rate_measurement_characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties([Properties::Read, Properties::Notify])
                            .set_uuid(HEART_RATE_MEASUREMENT_UUID)
                    })
                    .set_value(|value| {
                        value
                            .set_accessible_value(local_heart_rate_measurement.clone())
                            .set_permissions([AttributePermissions::Read(AttributeRestriction::Encryption(
                                EncryptionKeySize::Bits256,
                            ))])
                    })
                    .set_client_configuration(|client_config| {
                        let notify_hrd = notify_hrd.clone();
                        let local = local_heart_rate_measurement.clone();

                        let init_config: &[ClientConfiguration] = if is_notifications_enabled {
                            &[ClientConfiguration::Notification]
                        } else {
                            &[]
                        };

                        client_config
                            .set_config([ClientConfiguration::Notification])
                            .init_config(init_config)
                            .set_write_callback(move |client_config| {
                                let enable_notify = client_config.contains(&ClientConfiguration::Notification);

                                notify_hrd.store(enable_notify, Ordering::Relaxed);

                                let local = local.clone();

                                async move {
                                    if !enable_notify {
                                        local.arc.lock().await.rr_offset = None
                                    }
                                }
                            })
                            .set_write_restrictions([AttributeRestriction::Encryption(EncryptionKeySize::Bits256)])
                    })
            });

        let hrd_handle = heart_rate_characteristic_adder
            .get_last_record()
            .unwrap()
            .get_value_handle();

        heart_rate_characteristic_adder
            .new_characteristic(|heart_rate_control_point_characteristic| {
                heart_rate_control_point_characteristic
                    .set_declaration(|declaration| {
                        declaration
                            .set_properties([Properties::Write])
                            .set_uuid(HEART_RATE_CONTROL_POINT_UUID)
                    })
                    .set_value(|value| {
                        value
                            .set_accessible_value(ControlPoint::new(local_heart_rate_measurement.clone()))
                            .set_permissions([AttributePermissions::Write(AttributeRestriction::Encryption(
                                EncryptionKeySize::Bits256,
                            ))])
                    })
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

        Self {
            server,
            local_heart_rate_measurement,
            hrd_handle,
            notify_hrd,
        }
    }

    /// Send a Notification containing the heart rate data
    ///
    /// This will send a notification to the Client containing the heart rate data **if** the client
    /// has enabled notifications for the heart rate data characteristic.
    pub async fn send_hrd_notification<C: bo_tie::host::l2cap::ConnectionChannel>(&mut self, channel: &C) {
        if self.notify_hrd.load(Ordering::Relaxed) {
            self.server.send_notification(channel, self.hrd_handle).await.unwrap();
        }
    }

    /// Process a L2CAP packet containing ATT protocol data
    pub async fn process<C: bo_tie::host::l2cap::ConnectionChannel>(
        &mut self,
        channel: &mut C,
        packet: &bo_tie::host::l2cap::BasicFrame<Vec<u8>>,
    ) {
        let parse_result = self.server.parse_att_pdu(packet);

        if let Ok((ClientPduName::ExchangeMtuRequest, payload)) = parse_result {
            let mtu: u16 = TransferFormatTryFrom::try_from(payload).unwrap();

            self.local_heart_rate_measurement.set_mtu(mtu.into()).await
        }

        self.server.process_att_pdu(channel, packet).await.unwrap();
    }

    /// Give Permissions to the client when encrypted
    pub fn on_encryption(&mut self) {
        self.server.give_permissions_to_client(Self::ENCRYPTION_PERMISSIONS);
    }

    /// Revoke permissions to the client when unencrypted
    pub fn on_unencrypted(&mut self) {
        self.server.revoke_permissions_of_client(Self::ENCRYPTION_PERMISSIONS);
    }

    /// Check if notifications are being sent to the Client
    pub fn is_notifying(&self) -> bool {
        self.notify_hrd.load(Ordering::Relaxed)
    }
}

/// A wrapper around the heart rate measurement data
///
/// This is a shared counted reference to the data that in the GATT server for the heart rate
/// measurement
#[derive(Clone)]
pub struct HeartRateMeasurementArc {
    arc: Arc<Mutex<HeartRateMeasurementData>>,
}

impl HeartRateMeasurementArc {
    pub(crate) fn new() -> HeartRateMeasurementArc {
        let data = HeartRateMeasurementData {
            value: HeartRateValue::Uint8(0),
            contact_status: ContactStatus::NoContact,
            energy_expended: EnergyExpended::Unavailable,
            rr_atomic_offset: 0,
            rr_intervals: VecDeque::with_capacity(HeartRateMeasurementData::MAXED_SAVED_RR_INTERVALS),
        };

        let shared = Arc::new(Mutex::new(data));

        HeartRateMeasurementArc { arc: shared }
    }

    pub async fn set_heart_rate(&self, rate: u16) {
        let value = <u8 as TryFrom<u16>>::try_from(rate)
            .map(|rate| HeartRateValue::Uint8(rate))
            .unwrap_or(HeartRateValue::Uint16(rate));

        self.arc.lock().await.value = value;
    }

    pub async fn set_contact_status(&self, contact_status: ContactStatus) {
        self.arc.lock().await.contact_status = contact_status
    }

    pub async fn increase_energy_expended(&self, by: u16) {
        let mut lock = self.arc.lock().await;

        if let EnergyExpended::KiloJoules(expended) = lock.energy_expended {
            lock.energy_expended = EnergyExpended::KiloJoules(expended.saturating_add(by));
        } else {
            lock.energy_expended = EnergyExpended::KiloJoules(by)
        }
    }

    pub async fn reset_energy_expended(&self) {
        self.arc.lock().await.energy_expended = EnergyExpended::KiloJoules(0)
    }

    pub async fn add_rr_interval(&self, interval: u16) {
        let mut guard = self.arc.lock().await;

        guard.rr_atomic_offset = guard.rr_atomic_offset.wrapping_add(1);

        if guard.rr_intervals.len() > HeartRateMeasurementData::MAXED_SAVED_RR_INTERVALS {
            guard.rr_intervals.pop_front();
        }

        guard.rr_intervals.push_back(interval);
    }
}

struct LocalHeartRateMeasurement {
    rr_offset: Option<usize>,
    mtu: usize,
    shared: HeartRateMeasurementArc,
}

#[derive(Clone)]
struct LocalHeartRateMeasurementArc {
    arc: Arc<Mutex<LocalHeartRateMeasurement>>,
}

impl LocalHeartRateMeasurementArc {
    fn new(shared: HeartRateMeasurementArc) -> Self {
        let mtu = LeU::MIN_SUPPORTED_MTU;
        let rr_offset = None;

        let local = LocalHeartRateMeasurement { rr_offset, mtu, shared };

        let arc = Arc::new(Mutex::new(local));

        Self { arc }
    }

    /// Set the connection MTU
    ///
    /// The rr-intervals cannot be ['blobbed']. Only the number of rr-intervals that can fit within
    /// the maximum size of an ATT PDU
    ///
    /// ['blobbed']: /bo_tie/host/att/server/index.html#data-blobbing
    async fn set_mtu(&mut self, mtu: usize) {
        if mtu >= LeU::MIN_SUPPORTED_MTU {
            self.arc.lock().await.mtu = mtu;
        }
    }
}

impl AccessValue for LocalHeartRateMeasurementArc {
    type ReadValue = HeartRateMeasurement;
    type ReadGuard<'a> = Box<Self::ReadValue>;
    type Read<'a> = Pin<Box<dyn Future<Output = Self::ReadGuard<'a>> + Send + Sync + 'a>> where Self: 'a ;
    type WriteValue = ();
    type Write<'a> = std::future::Pending<Result<(), bo_tie::host::att::pdu::Error>> where Self: 'a ;

    fn read(&self) -> Self::Read<'_> {
        Box::pin(async {
            let local = &mut *self.arc.lock().await;

            let rr_offset = &mut local.rr_offset;

            let global_lock = local.shared.arc.lock().await;

            let measurement = global_lock.create_measurement(rr_offset, local.mtu);

            Box::new(measurement)
        })
    }

    fn write(&mut self, _: Self::WriteValue) -> Self::Write<'_> {
        unreachable!()
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
    rr_atomic_offset: usize,
    rr_intervals: VecDeque<u16>,
}

impl HeartRateMeasurementData {
    const MAXED_SAVED_RR_INTERVALS: usize = 256;

    fn create_measurement(&self, rr_local_offset: &mut Option<usize>, mtu: usize) -> HeartRateMeasurement {
        let distance = match rr_local_offset {
            Some(offset) => {
                let mut distance = if self.rr_atomic_offset >= *offset {
                    self.rr_atomic_offset - *offset
                } else {
                    <usize>::MAX - *offset + self.rr_atomic_offset
                };

                if distance > Self::MAXED_SAVED_RR_INTERVALS {
                    *offset = self.rr_atomic_offset.wrapping_sub(Self::MAXED_SAVED_RR_INTERVALS);

                    distance = Self::MAXED_SAVED_RR_INTERVALS
                }

                distance
            }
            None => {
                *rr_local_offset = Some(self.rr_atomic_offset);

                0
            }
        };

        let ret = HeartRateMeasurement {
            value: self.value,
            contact_status: self.contact_status,
            energy_expended: self.energy_expended,
            rr_intervals: self
                .rr_intervals
                .iter()
                .copied()
                .skip(self.rr_intervals.len().wrapping_sub(distance))
                .collect(),
            mtu,
        };

        *rr_local_offset = (rr_local_offset.unwrap())
            .wrapping_add(core::cmp::min(distance, ret.max_sent_rr_intervals()))
            .into();

        ret
    }
}

struct HeartRateMeasurement {
    value: HeartRateValue,
    contact_status: ContactStatus,
    energy_expended: EnergyExpended,
    rr_intervals: Vec<u16>,
    mtu: usize,
}

impl HeartRateMeasurement {
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

    /// Get the maximum number of rr intervals that can be sent in this measurement
    fn max_sent_rr_intervals(&self) -> usize {
        let flags_size = 1;

        let value_size = match self.value {
            HeartRateValue::Uint8(_) => 1,
            HeartRateValue::Uint16(_) => 2,
        };

        let energy_expended_size = match self.energy_expended {
            EnergyExpended::Unavailable => 0,
            EnergyExpended::KiloJoules(_) => 2,
        };

        (self.mtu - (flags_size + value_size + energy_expended_size)) / core::mem::size_of::<u16>()
    }
}

impl TransferFormatInto for HeartRateMeasurement {
    fn len_of_into(&self) -> usize {
        let flags_size = 1;

        let value_size = match self.value {
            HeartRateValue::Uint8(_) => 1,
            HeartRateValue::Uint16(_) => 2,
        };

        let energy_expended_size = match self.energy_expended {
            EnergyExpended::Unavailable => 0,
            EnergyExpended::KiloJoules(_) => 2,
        };

        let rr_intervals = self.rr_intervals.len() * 2;

        let total_size = flags_size + value_size + energy_expended_size + rr_intervals;

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
            rr_iter.next().unwrap().build_into_ret(&mut into_ret[..2]);

            into_ret = &mut into_ret[2..];
        }
    }
}

impl TransferFormatTryFrom for HeartRateMeasurement {
    fn try_from(_: &[u8]) -> Result<Self, TransferFormatError>
    where
        Self: Sized,
    {
        unreachable!()
    }
}

impl PartialEq for HeartRateMeasurement {
    fn eq(&self, _: &Self) -> bool {
        // it does not make sense that two heart rate
        // measurements should be "equal".
        false
    }
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum HeartRateValue {
    Uint8(u8),
    Uint16(u16),
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
pub enum ContactStatus {
    NoContact,
    PoorContact,
    FullContact,
}

#[derive(Copy, Clone)]
#[allow(dead_code)]
enum EnergyExpended {
    Unavailable,
    KiloJoules(u16),
}

struct ControlPoint {
    local: LocalHeartRateMeasurementArc,
}

impl ControlPoint {
    fn new(local: LocalHeartRateMeasurementArc) -> Self {
        Self { local }
    }
}

impl AccessValue for ControlPoint {
    type ReadValue = ();
    type ReadGuard<'a> = &'a () where Self: 'a;
    type Read<'a> = std::future::Pending<Self::ReadGuard<'a>> where Self: 'a;
    type WriteValue = u8;
    type Write<'a> = Pin<Box<dyn Future<Output = Result<(), bo_tie::host::att::pdu::Error>> + Send + Sync>>;

    fn read(&self) -> Self::Read<'_> {
        unreachable!()
    }

    fn write(&mut self, val: Self::WriteValue) -> Self::Write<'_> {
        use bo_tie::host::att::pdu::{Error, ErrorConversionError};

        if val == 0x1 {
            let local = self.local.clone();

            Box::pin(async move {
                local.arc.lock().await.shared.reset_energy_expended().await;
                Ok(())
            })
        } else {
            Box::pin(async move {
                Err(Error::Other(
                    ErrorConversionError::try_from(CONTROL_POINT_NOT_SUPPORTED).unwrap(),
                ))
            })
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn Any {
        self
    }
}
