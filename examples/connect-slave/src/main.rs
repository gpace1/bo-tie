//! Connection state in the slave role example
//!
//! This example shows the basic way to form a connection with this device in the slave role. The
//! only real important part to look at are the async functions.
//!
//! To fully execute this example you'll need another bluetooth enabled device that can run in the
//! master role. If you have an android phone, you can use the 'nRF Connect' app to connect with
//! this example
//!
//! # WARNING
//! There is no security implemented in this example, but no data is exposed either. Be careful
//! when extending/using this example for your purposes.
//!
//! # Important Notes
//! Super User privileges may be required to interact with your bluetooth peripheral. To do will
//! probably require the full path to cargo. The cargo binary is usually located in your home
//! directory at `.cargo/bin/cargo`.
//!
//! This example assumes there isn't any bonding/caching between the device that is to be connected
//! with this example. This will cause the the example to get stuck and eventually time out waiting
//! to connect to the device. If this occurs, using a different random address should work (or
//! power cycle the bluetooth controller to get a newly generated default random address). If
//! there are still problems, delete the cache, whitelist, and any other memory associated with the
//! bluetooth on the device to connect with, but please note this will git rid of all information
//! associated with the bluetooth and other devices will need to be reconnected.

use bo_tie::{
    att,
    gap::assigned,
    gatt, hci,
    hci::events,
    hci::le::transmitter::{set_advertising_data, set_advertising_enable, set_advertising_parameters},
};
use simplelog::ColorChoice;
use std::sync::{
    atomic::{AtomicU16, Ordering},
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

async fn events_setup<M: Send + 'static>(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter, M>) {
    use bo_tie::hci::cb::set_event_mask::{self, EventMask};
    use bo_tie::hci::le::mandatory::set_event_mask as le_set_event_mask;
    use events::LeMeta;

    let enabled_events = &[EventMask::LeMeta, EventMask::DisconnectionComplete];

    let enabled_le_events = &[LeMeta::ConnectionComplete];

    set_event_mask::send(hi, enabled_events).await.unwrap();

    le_set_event_mask::send(hi, enabled_le_events).await.unwrap();
}

/// This sets up the advertising and waits for the connection complete event
async fn advertise_setup<M: Send + 'static>(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter, M>, local_name: &str) {
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

    let mut adv_data = set_advertising_data::AdvertisingData::new();

    adv_data.try_push(adv_flags).unwrap();
    adv_data.try_push(adv_name).unwrap();

    set_advertising_enable::send(&hi, false).await.unwrap();

    set_advertising_data::send(&hi, adv_data).await.unwrap();

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    adv_prams.own_address_type = bo_tie::hci::le::common::OwnAddressType::RandomDeviceAddress;

    set_advertising_parameters::send(&hi, adv_prams).await.unwrap();

    set_advertising_enable::send(&hi, true).await.unwrap();
}

// For simplicity, I've left the race condition in here. There could be a case where the connection
// is made and the ConnectionComplete event isn't propagated & processed
async fn wait_for_connection<M: Send + 'static>(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter, M>,
) -> Result<hci::events::LEConnectionCompleteData, impl std::fmt::Display> {
    println!("Waiting for a connection (timeout is 60 seconds)");

    let waited_event = Some(events::Events::from(events::LeMeta::ConnectionComplete));

    let evt_rsl = hi.wait_for_event(waited_event).await;

    match evt_rsl {
        Ok(event) => {
            use bo_tie::hci::events::{EventsData, LeMetaData};

            if let EventsData::LeMeta(LeMetaData::ConnectionComplete(event_data)) = event {
                Ok(event_data)
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

    if let Err(e) = disconnect::send(&hi, prams).await {
        println!("Failed to disconnect: {}", e)
    }
}

/// Initialize the Attribute Server
///
/// The attribute server is organized via the gatt protocol. This example is about connecting
/// to a client and not about featuring the attribue server, so only the minimalistic gatt server
/// is present.
fn gatt_server_init<'c, C>(
    connection_channel: &'c C,
    local_name: &str,
) -> gatt::Server<'c, C, bo_tie::att::server::BasicQueuedWriter>
where
    C: bo_tie::l2cap::ConnectionChannel,
{
    let gsb = gatt::GapServiceBuilder::new(local_name, None);

    let queue_writer = bo_tie::att::server::BasicQueuedWriter::new(1024);

    let mut server = gatt::ServerBuilder::from(gsb).make_server(connection_channel, queue_writer);

    server.give_permissions_to_client(att::AttributePermissions::Read(att::AttributeRestriction::None));

    server
}

fn att_server_loop<C>(connection_channel: C, local_name: &str) -> !
where
    C: bo_tie::l2cap::ConnectionChannel + std::marker::Unpin,
{
    use futures::executor::block_on;

    let mut server = gatt_server_init(&connection_channel, local_name);

    loop {
        block_on(connection_channel.receive_b_frame())
            .map(|l2cap_pdus| {
                l2cap_pdus
                    .iter()
                    .for_each(|l2cap_pdu| match block_on(server.process_acl_data(l2cap_pdu)) {
                        Ok(_) => (),
                        Err(e) => println!("Cannot process acl data, '{}'", e),
                    })
            })
            .expect("l2cap pdu")
    }
}

fn handle_sig<M: Sync + Send + 'static>(
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter, M>>,
    raw_handle: Arc<AtomicU16>,
) {
    simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term], move |_| {
        // Cancel advertising if advertising (there is no consequence if not advertising)
        futures::executor::block_on(set_advertising_enable::send(&hi, false)).unwrap();

        let handle_val = raw_handle.load(Ordering::SeqCst);

        if handle_val != INVALID_CONNECTION_HANDLE {
            let handle = bo_tie::hci::common::ConnectionHandle::try_from(handle_val).expect("Incorrect Handle");

            futures::executor::block_on(disconnect(&hi, handle));

            println!("Bluetooth connection terminated")
        }

        println!("Exiting example");

        std::process::exit(0);
    });
}

fn main() {
    use futures::executor;
    use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};

    let local_name = "Connection Test";

    TermLogger::init(
        LevelFilter::Trace,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();

    let raw_connection_handle = Arc::new(AtomicU16::new(INVALID_CONNECTION_HANDLE));

    let interface = futures::executor::block_on(hci::HostInterface::<_, AsyncLock>::new());

    handle_sig(interface.clone(), raw_connection_handle.clone());

    executor::block_on(events_setup(&interface));

    executor::block_on(advertise_setup(&interface, local_name));

    // Waiting for some bluetooth device to connect is slow, so the waiting for the future is done
    // on a different thread.
    match executor::block_on(wait_for_connection(&interface)) {
        Ok(event_data) => {
            raw_connection_handle.store(event_data.connection_handle.get_raw_handle(), Ordering::SeqCst);

            let connection_channel = interface.clone().flow_ctrl_channel(event_data.connection_handle, 512);

            std::thread::spawn(move || {
                att_server_loop(connection_channel, local_name);
            });

            executor::block_on(set_advertising_enable::send(&interface, false)).unwrap();

            println!("Device Connected! (use ctrl-c to disconnect and exit)");

            executor::block_on(interface.wait_for_event(events::Events::DisconnectionComplete)).ok();
        }
        Err(err) => println!("Error: {}", err),
    };
}
