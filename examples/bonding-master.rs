//! Bonding Master test
//!
//! This will bond with a connectible device advertising with the name "Bonding Test".
//!
//! # Notes
//! The advertising device must be advertising in connectible undirected and the address must not
//! be a resolvable private address.
//!
//! You will need to delete the bonding information on the peer device unless it doesn't save
//! bonding information.

use std::time::Duration;
use bo_tie::hci;
use core::sync::atomic::{AtomicU16, Ordering};

type Base = bo_tie_linux::HCIAdapter;

/// Looked for advertising name
const ADV_NAME: &'static str = "Bonding Test";

/// 0xFFFF is a reserved value as of the Bluetooth Spec. v5, so it isn't a valid value sent
/// from the controller to the user.
const INVALID_CONNECTION_HANDLE: u16 = 0xFFFF;

/// Scan for a specific address
async fn start_scanning_for_addr(
    hi: &hci::HostInterface<Base>,
) -> bo_tie::hci::events::LEAdvertisingReportData {
    use bo_tie::hci::cb::set_event_mask::{self,EventMask};
    use bo_tie::hci::common::LEAddressType;
    use bo_tie::hci::events::{LEMeta, EventsData, LEMetaData, LEAdvEventType};
    use bo_tie::hci::le::receiver::{set_scan_parameters,set_scan_enable};
    use bo_tie::hci::le::mandatory::set_event_mask as le_set_event_mask;

    set_scan_enable::send(hi, false, false).await.unwrap();

    set_event_mask::send(hi, &[EventMask::LEMeta]).await.unwrap();

    set_event_mask::send(hi, &[LEMeta::AdvertisingReport]).await.unwrap();

    set_scan_parameters::send(hi, set_scan_parameters::ScanningParameters::default()).await.unwrap();

    set_scan_enable::send(hi, true, true).await.unwrap();

    let ret = loop {
        match hi.wait_for_event(LEMeta::AdvertisingReport.into(), None).await.unwrap() {
            EventsData::LEMeta(LEMetaData::AdvertisingReport(reports)) => for report in reports {
                if let Some(report) = process_adv_reports(&reports) { break report }
            },
            e => panic!("Received unexpected event data: {:?}", e),
        }
    };

    set_scan_enable::send(hi, false, false).await.unwrap();

    ret
}

fn process_adv_reports( reports: &[hci::le::events::LEAdvertisingReportData] )
-> Option<&hci::le::events::LEAdvertisingReportData>
{
    use bo_tie::gap::advertise::local_name::LocalName;
    use bo_tie::gap::advertise::TryFromRaw;

    for report in reports {
        let mut data = &report.data;

        while data.len() > 0 {
            let (len, rest) = data.split_first();

            let (first, rest) = rest.split_at(len as usize);

            data = rest;

            if let Ok(_) = LocalName.try_from_raw(first) { return report.into() }
        }
    }

    None
}

async fn connect_to<'a>(
    hi: &'a hci::HostInterface<Base>,
    peer_address: bo_tie::BluetoothDeviceAddress,
    peer_address_type: bo_tie::hci::common::LEAddressType,
    raw_handle: Arc<AtomicU16>,
) -> impl bo_tie::l2cap::ConnectionChannel + 'a
{
    use bo_tie::hci::cb::set_event_mask::{self,EventMask};
    use bo_tie::hci::common::LEAddressType;
    use bo_tie::hci::events::{LEMeta, EventsData, LEMetaData};
    use bo_tie::hci::le::connection::create_connection::{
        self,
        ConnectionParameters,
        ScanningInterval,
        ScanningWindow
    };
    use bo_tie::hci::common::{
        LEAddressType,
        OwnAddressType,
        ConnectionIntervalBounds,
        ConnectionLatency,
        SupervisionTimeout,
        ConnectionEventLength,
        ConnectionInterval
    };

    set_event_mask::send(hi, &[EventMask::DisconnectionComplete, EventMask::LEMeta]).await.unwrap();

    set_event_mask::send(hi, &[LEMeta::ConnectionComplete]).await.unwrap();

    let parameters = ConnectionParameters {
        scan_interval: ScanningInterval::default(),
        scan_window: ScanningWindow::default(),
        peer_address_type,
        peer_address,
        own_address_type: OwnAddressType::RandomDeviceAddress,
        connection_interval: ConnectionIntervalBounds {
                min: ConnectionInterval::default(),
                max: ConnectionInterval::default()
            },
        connection_latency: ConnectionLatency::try_from(0).unwrap(),
        supervision_timeout: SupervisionTimeout::try_from(0x10).unwrap(),
        connection_event_len: ConnectionEventLength {
            min: 0,
            max: 0xFFFF,
        }
    };

    set_event_mask::send(hi, parameters).await.unwrap();

    match hi.wait_for_event(LEMeta::ConnectionComplete.into(), None).await.unwrap() {
        EventsData::LEMeta(LEMetaData::ConnectionComplete(data)) => {
            raw_handle.store(data.connection_channel.get_raw_handle, Ordering::Relaxed);

            hi.new_connection_channel(data.connection_handle)
        },
        e => panic!("Received Unexpected event: {:?}"),
    }
}

/// Start pairing
///
/// Returns the long term key (LTK) if the pairing process succeeded.
async fn pair<C>( cc: C, msm: &mut bo_tie::sm::initiator::MasterSecurityManager<'_, C> )
-> Option<u128>
where C: bo_tie::l2cap::ConnectionChannel
{
    for pairing_step in msm.start_pairing() {
        match cc.future_receiver().await {
            Ok(data) => {
                match pairing_step.process(data) {
                    Ok(Some(keys)) => keys.ltk.clone(),
                    Err(e) => panic!("Pairing Error Occured: {:?}", e),
                    Ok(None) => {},
                }
            },
            Err(e) => panic!("Error when await for received packets"),
        }
    }

    false
}

/// Start encryption
async fn encrypt(hi: &HostInterface<Base>, connection_handle: hci::common::ConnectionHandle, ltk: u128) {
    use bo_tie::hci::cb::set_event_mask::{self,EventMask};
    use bo_tie::hci::le::encryption::start_encryption::{self, Parameter};

    set_event_mask::send(hi, &[EventMask::DisconnectionComplete, EventMask::EncryptionChange]).await.unwrap();

    // Because the security manager implementation only supports LE secure connections
    // implementation, both the `random_number` and `encrypted_diversifier` are zero as per the
    // specification (v5.0 | Vol 3, Part H, Section 2.4.4).
    let parameter = Parameter {
        handle: connection_handle,
        random_number: 0,
        encrypted_diversifier: 0,
        long_term_key: ltk
    };

    start_encryption::send(hi, parameter).await.unwrap();

    match hi.await_for_event(EventMask::EncryptionChange, Duration::from_secs(5) ).await.unwrap() {
        Ok(EventsData::EncryptionChange(data)) => println!("Encryption started!"),
        OK(e) => panic!("Received incorrect event: {:?}", e),
        Err(e) => panic!("Encryption failed: {:?}"),
    }
}

fn handle_sig(
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter>>,
    raw_handle: Arc<AtomicU16>
) {
    use hci::le::connection::create_connection_cancel;
    use hci::common::ConnectionHandle;
    use hci::link_control::disconnect::{self, DisconnectReason, DisconnectParameters};

    simple_signal::set_handler(
        &[simple_signal::Signal::Int, simple_signal::Signal::Term],
        move |_| {
            // Cancel connecting (if in process of connecting, there is no consequence if not
            // connecting)
            futures::executor::block_on(create_connection_cancel::send(&hi)).ok();

            let handle = ConnectionHandle::try_from(raw_handle.load(Ordering::Relaxed));

            if let Ok(connection_handle) = handle {
                let dp = DisconnectParameters {
                    connection_handle,
                    disconnect_reason: DisconnectReason::RemoteUserTerminatedConnection
                };

                disconnect::send(&hi, dp)
            }

            println!("Exiting example");

            std::process::exit(0);
        }
    );
}

fn main() {
    use futures::executor;
    use simplelog::{TermLogger, LevelFilter, Config, TerminalMode};

    let local_name = "Connection Test";

    TermLogger::init( LevelFilter::Trace, Config::default(), TerminalMode::Mixed ).unwrap();

    let raw_connection_handle = Arc::new(AtomicU16::new(INVALID_CONNECTION_HANDLE));

    let interface = Arc::new(hci::HostInterface::default());

    handle_sig(interface.clone(), raw_connection_handle.clone());

    let adv_info = executor::block_on(start_scanning_for_addr(&interface, )
    executor::block_on( connect_to(&interface, peer_addr, peer_addr_type, raw_connection_handle) );

    executor::block_ok( pair(&interface, ) )
}