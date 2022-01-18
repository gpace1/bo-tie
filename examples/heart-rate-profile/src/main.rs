use bo_tie::gap::assigned;
use bo_tie::hci;
use bo_tie::hci::{
    events,
    le::transmitter::{set_advertising_data, set_advertising_enable, set_advertising_parameters},
};
use std::sync::{
    atomic::{AtomicU16, AtomicU8, Ordering},
    Arc,
};

/// 0xFFFF is a reserved value as of the Bluetooth Spec. v5, so it isn't a valid value sent
/// from the controller to the user.
const INVALID_CONNECTION_HANDLE: u16 = 0xFFFF;

#[derive(Default)]
struct AsyncLock(futures::lock::Mutex<()>);

impl<'a> bo_tie::hci::AsyncLock<'a> for AsyncLock {
    type Guard = futures::lock::MutexGuard<'a, ()>;
    type Locker = futures::lock::MutexLockFuture<'a, ()>;

    fn lock(&'a self) -> Self::Locker {
        self.0.lock()
    }
}

/// Heart Rate Service
///
/// Everything in here is unique for creating the heart rate profile. The only reason it's in its
/// own module is to differentiate the GATT server portion from the normal lE bluetooth setup.
mod heart_rate_service {
    use bo_tie::att::server::BasicQueuedWriter;
    use bo_tie::gatt;
    use bo_tie::l2cap;

    pub const HEART_RATE_SERVICE_UUID: bo_tie::UUID = bo_tie::UUID::from_u16(0x180D);

    pub mod characteristics {
        use bo_tie::att;
        use bo_tie::att::server::PinnedFuture;
        use bo_tie::gatt;
        use std::sync::{atomic, Arc};

        /// This is the UUID for the Heart Rate Measurement Characteristic
        pub const HEART_RATE_MEASUREMENT_UUID: bo_tie::UUID = bo_tie::UUID::from_u16(0x2A37);

        #[derive(PartialEq, Clone, Copy)]
        pub struct HrsFlags {
            value_is_16_bit: bool,
            in_skin_contact: Option<bool>, // `None` if skin contact is not supported
            energy_expended_status_support: bool,
            rr_interval_is_included: bool,
        }

        impl HrsFlags {
            /// Set the heart rate value format
            ///
            /// The format of the value can either be a UINT8 (U8) or UINT16 (U16). The default value is
            /// U8
            fn set_heart_rate_value_format(&self, flag: u8) -> u8 {
                match self.value_is_16_bit {
                    false => flag | (1 << 0),
                    true => flag & !(1 << 0),
                }
            }

            /// Set the skin contact flag
            fn set_skin_contact(&self, flag: u8) -> u8 {
                match self.in_skin_contact {
                    // in contact and skin contact supported
                    Some(true) => flag | (3 << 1),

                    // not in contact and skin contact supported
                    Some(false) => flag & !(1 << 1) | (1 << 2),

                    // skin contact not supported
                    None => flag & !(3 << 1),
                }
            }

            fn set_energy_expended_status(&self, flag: u8) -> u8 {
                match self.energy_expended_status_support {
                    true => flag | (1 << 3),
                    false => flag | !(1 << 3),
                }
            }

            fn set_include_rr_interval_field(&self, flag: u8) -> u8 {
                match self.rr_interval_is_included {
                    true => flag | (1 << 4),
                    false => flag & !(1 << 4),
                }
            }
        }

        impl att::TransferFormatTryFrom for HrsFlags {
            fn try_from(_: &[u8]) -> Result<Self, bo_tie::att::TransferFormatError> {
                panic!("Tried to make Heart Rate Monitor data from raw data")
            }
        }

        impl att::TransferFormatInto for HrsFlags {
            fn len_of_into(&self) -> usize {
                1
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                into_ret[0] = self.set_heart_rate_value_format(
                    self.set_skin_contact(self.set_energy_expended_status(self.set_include_rr_interval_field(0))),
                );
            }
        }

        /// Heart Rate Measurement data
        ///
        /// For this example, only the heart rate measurement data is included in the message sent to
        /// the client. In this example, the server runs in a different thread from the thread that
        /// generates the random heart rate data. Thus, the heart rate value is an atomic so that the
        /// threads can run in sync.
        ///
        /// # Note
        /// This size of this heart rate is only 1 byte
        pub struct HeartRateMeasurement {
            flags: HrsFlags,
            val: Arc<atomic::AtomicU8>,
        }

        impl PartialEq<HrsData> for HeartRateMeasurement {
            fn eq(&self, other: &HrsData) -> bool {
                use std::sync::atomic::Ordering::Relaxed;

                (self.flags == other.0) && (self.val.load(Relaxed) == other.1)
            }
        }

        impl HeartRateMeasurement {
            pub const GATT_PERMISSIONS: &'static [gatt::characteristic::Properties] =
                &[gatt::characteristic::Properties::Notify];

            pub const ATT_PERMISSIONS: &'static [att::AttributePermissions] =
                &[att::AttributePermissions::Read(att::AttributeRestriction::None)];

            pub fn new(init: Arc<atomic::AtomicU8>) -> Self {
                HeartRateMeasurement {
                    flags: HrsFlags {
                        value_is_16_bit: false,
                        in_skin_contact: None,
                        energy_expended_status_support: false,
                        rr_interval_is_included: false,
                    },
                    val: init.clone(),
                }
            }
        }

        #[derive(PartialEq)]
        pub struct HrsData(HrsFlags, u8);

        impl att::server::ServerAttributeValue for HeartRateMeasurement {
            type Value = HrsData;

            fn read_and<'a, F, T>(&'a self, f: F) -> PinnedFuture<'a, T>
            where
                F: FnOnce(&Self::Value) -> T + Unpin + 'a,
            {
                Box::pin(async move { f(&HrsData(self.flags, self.val.load(atomic::Ordering::Relaxed))) })
            }

            fn write_val(&mut self, _: Self::Value) -> PinnedFuture<'_, ()> {
                unreachable!("The user cannot write to the value")
            }

            fn eq<'a>(&'a self, other: &'a Self::Value) -> PinnedFuture<'a, bool> {
                Box::pin(async move { &HrsData(self.flags, self.val.load(atomic::Ordering::Relaxed)) == other })
            }
        }

        impl att::TransferFormatTryFrom for HrsData {
            fn try_from(_: &[u8]) -> Result<Self, att::TransferFormatError> {
                /* Return an error since writing cannot be done */
                Err(att::TransferFormatError::from(
                    "Cannot write Heart Rate Data".to_string(),
                ))
            }
        }

        impl att::TransferFormatInto for HrsData {
            fn len_of_into(&self) -> usize {
                if self.0.value_is_16_bit {
                    2
                } else {
                    1
                }
            }

            fn build_into_ret(&self, into_ret: &mut [u8]) {
                self.0.build_into_ret(&mut into_ret[..1]);

                if self.0.value_is_16_bit {
                    unreachable!("16 bit heart rate value is not implemented")
                } else {
                    into_ret[1] = self.1;
                }
            }
        }
    }

    /// Create the Heart Rate Measurement Server
    ///
    /// This creates an attribute protocol server that handles the 'serving' of the heart rate
    /// data.
    ///
    /// To build a server, a connection channel (`connection_channel`) and the maximum transfer
    /// unit (`mtu`, the maximum size of the data to be transferred) is required to create an
    /// attribute server. The connection channel is created when a central is connected to a
    /// peripheral; this example is the peripheral because it's a heart rate monitor.
    pub fn build_server<C>(
        measurement: characteristics::HeartRateMeasurement,
        connection_chanel: &C,
    ) -> gatt::Server<'_, C, bo_tie::att::server::BasicQueuedWriter>
    where
        C: l2cap::ConnectionChannel,
    {
        let gsp = gatt::GapServiceBuilder::new("Heart Rate Example", 0);

        let mut server_builder = gatt::ServerBuilder::from(gsp);

        server_builder
            .new_service(HEART_RATE_SERVICE_UUID, true)
            .add_characteristics()
            .new_characteristic()
            .set_properties(characteristics::HeartRateMeasurement::GATT_PERMISSIONS.to_vec())
            .set_uuid(characteristics::HEART_RATE_MEASUREMENT_UUID)
            .set_value(measurement)
            .set_permissions(characteristics::HeartRateMeasurement::ATT_PERMISSIONS)
            .set_client_configuration(
                vec![gatt::characteristic::ClientConfiguration::Notification],
                [].as_ref(),
            )
            .complete_characteristic()
            .finish_service();

        server_builder.make_server(connection_chanel, BasicQueuedWriter::new(2048))
    }
}

/// This sets up the advertising and waits for the connection complete event
async fn advertise_setup<'a, M: Send + 'static>(
    hi: &'a hci::HostInterface<bo_tie_linux::HCIAdapter, M>,
    local_name: &'a str,
) {
    let adv_name = assigned::local_name::LocalName::new(local_name, false);

    let mut adv_flags = assigned::flags::Flags::new();

    // This is the flag specification for a LE-only, limited discoverable advertising
    adv_flags
        .get_core(assigned::flags::CoreFlags::LELimitedDiscoverableMode)
        .enable();
    adv_flags
        .get_core(assigned::flags::CoreFlags::LEGeneralDiscoverableMode)
        .disable();
    adv_flags
        .get_core(assigned::flags::CoreFlags::BREDRNotSupported)
        .enable();
    adv_flags
        .get_core(assigned::flags::CoreFlags::ControllerSupportsSimultaniousLEAndBREDR)
        .disable();
    adv_flags
        .get_core(assigned::flags::CoreFlags::HostSupportsSimultaniousLEAndBREDR)
        .disable();

    let mut adv_uuids = assigned::service_uuids::new_16(false);

    adv_uuids.add(std::convert::TryFrom::try_from(heart_rate_service::HEART_RATE_SERVICE_UUID).unwrap());

    let mut adv_data = set_advertising_data::AdvertisingData::new();

    adv_data.try_push(adv_name).unwrap();
    adv_data.try_push(adv_flags).unwrap();
    adv_data.try_push(adv_uuids).unwrap();

    set_advertising_enable::send(&hi, false).await.unwrap();

    set_advertising_data::send(&hi, adv_data).await.unwrap();

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    adv_prams.own_address_type = bo_tie::hci::le::common::OwnAddressType::RandomDeviceAddress;

    set_advertising_parameters::send(&hi, adv_prams).await.unwrap();

    set_advertising_enable::send(&hi, true).await.unwrap();
}

// For simplicity, I've left the a race condition in here. There could be a case where the
// connection is made and the ConnectionComplete event isn't propagated & processed
async fn wait_for_connection<M: Send + 'static>(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter, M>,
) -> Result<hci::events::LEConnectionCompleteData, impl std::fmt::Display> {
    println!("Waiting for a connection (timeout is 60 seconds)");

    let awaited_event = Some(events::Events::from(events::LEMeta::ConnectionComplete));

    let evt_rsl = hi.wait_for_event(awaited_event).await;

    set_advertising_enable::send(&hi, false).await.unwrap();

    match evt_rsl {
        Ok(event) => {
            use bo_tie::hci::events::{EventsData, LEMetaData};

            println!("Connection Made!");

            if let EventsData::LEMeta(LEMetaData::ConnectionComplete(le_conn_comp_event)) = event {
                Ok(le_conn_comp_event)
            } else {
                Err(format!("Received the incorrect event {:?}", event))
            }
        }
        Err(e) => Err(format!("Timeout Occured: {:?}", e)),
    }
}

async fn disconnect<M: Send + 'static>(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter, M>,
    connection_handle: hci::common::ConnectionHandle,
) {
    use bo_tie::hci::le::connection::disconnect;

    let prams = disconnect::DisconnectParameters {
        connection_handle,
        disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(&hi, prams).await.expect("Failed to disconnect");
}

fn handle_sig<M: Sync + Send + 'static>(
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter, M>>,
    raw_handle: Arc<AtomicU16>,
) {
    simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term], move |_| {
        // Cancel advertising if advertising (there is no consequence if not advertising)
        futures::executor::block_on(set_advertising_enable::send(&hi, false)).unwrap();

        // todo fix the race condition where a connection is made but the handle hasn't been
        // stored in raw_handle yet.
        let handle_val = raw_handle.load(Ordering::SeqCst);

        if handle_val != INVALID_CONNECTION_HANDLE {
            let handle = bo_tie::hci::common::ConnectionHandle::try_from(handle_val).expect("Incorrect Handle");

            futures::executor::block_on(disconnect(&hi, handle));
        }
    });
}

fn main() {
    use futures::executor;

    use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let raw_connection_handle = Arc::new(AtomicU16::new(INVALID_CONNECTION_HANDLE));

    let interface = executor::block_on(hci::HostInterface::<_, AsyncLock>::new());

    handle_sig(interface.clone(), raw_connection_handle.clone());

    // Its fine for the setup to be blocked on b/c its fast to the user
    executor::block_on(advertise_setup(&interface, "HRS Example"));

    // Waiting for some bluetooth device to connect is slow, so the waiting for the future is done
    // on a different thread.
    match executor::block_on(wait_for_connection(&interface)) {
        Ok(connection_complete_event) => {
            use std::thread;

            let raw_handle = connection_complete_event.connection_handle.get_raw_handle();

            let connect_interval = connection_complete_event.connection_interval.as_duration();

            raw_connection_handle.store(raw_handle, Ordering::SeqCst);

            let join_handle = thread::spawn(move || {
                const AVERAGE_HEART_RATE: u8 = 70; // A number that seems reasonable

                let heart_rate = Arc::new(AtomicU8::new(AVERAGE_HEART_RATE));

                let heart_rate_clone = heart_rate.clone();

                let hrm = heart_rate_service::characteristics::HeartRateMeasurement::new(heart_rate.clone());

                let connection_channel = interface.flow_ctrl_channel(connection_complete_event.connection_handle, 512);

                let server = heart_rate_service::build_server(hrm, &connection_channel);

                thread::spawn(move || {
                    use rand::random;

                    loop {
                        // The simulated sensor measures the heart rate 10 times per second
                        thread::sleep(std::time::Duration::from_millis(100));

                        // Flutter the heart rate at AVERAGE_HEART_RATE +- 5;
                        let hr = AVERAGE_HEART_RATE + (random::<u8>() % 11) - 5;

                        heart_rate_clone.store(hr, Ordering::SeqCst);
                    }
                });

                loop {
                    let hrs_value_handle = 3;

                    assert!(executor::block_on(server.send_notification(hrs_value_handle)));

                    thread::sleep(connect_interval)
                }
            });

            println!("Device Connected, and heart rate service started! (use ctrl-c to disconnect and exit)");

            join_handle.join().expect("Thread should not exit!");

            panic!("Thread Ended!");
        }
        Err(err) => println!("Error: {}", err),
    };
}
