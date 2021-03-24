//! Bonding Master tests
//!
//! This will bond with a connectible device advertising with the name provided for .
//!
//! # Notes
//! The advertising device must be advertising in connectible undirected and the address must not
//! be a resolvable private address.
//!
//! You will need to delete the bonding information on the peer device after the example has run
//! unless it doesn't save bonding information.

use bo_tie::hci;
use std::sync::{
    atomic::{AtomicU16, Ordering},
    Arc,
};
use std::time::Duration;

type Base = bo_tie_linux::HCIAdapter;

/// 0xFFFF is a reserved value as of the Bluetooth Spec. v5, so it isn't a valid value sent
/// from the controller to the user.
const INVALID_CONNECTION_HANDLE: u16 = 0xFFFF;

/// Scan for a specific address
async fn start_scanning_for_addr(
    hi: &hci::HostInterface<Base>,
    local_name: &str,
) -> bo_tie::hci::events::LEAdvertisingReportData {
    use bo_tie::hci::cb::set_event_mask::{self, EventMask};
    use bo_tie::hci::events::{Events, EventsData, LEMeta, LEMetaData};
    use bo_tie::hci::le::mandatory::set_event_mask as le_set_event_mask;
    use bo_tie::hci::le::receiver::{set_scan_enable, set_scan_parameters};

    let scan_params = set_scan_parameters::ScanningParameters::default();

    // Some systems you cannot disable scanning through the host controller interface, if at all,
    // so the result is just converted into an option.
    set_scan_enable::send(hi, false, false).await.ok();

    set_event_mask::send(hi, &[EventMask::LEMeta]).await.unwrap();

    le_set_event_mask::send(hi, &[LEMeta::AdvertisingReport.into()])
        .await
        .unwrap();

    set_scan_parameters::send(hi, scan_params).await.unwrap();

    set_scan_enable::send(hi, true, true).await.unwrap();

    let waited_event = Some(Events::from(LEMeta::AdvertisingReport));
    let ret = 'outer: loop {
        match hi.wait_for_event(waited_event).await.unwrap() {
            EventsData::LEMeta(LEMetaData::AdvertisingReport(reports)) => {
                if let Some(report) = reports
                    .iter()
                    .filter_map(|r| r.as_ref().ok())
                    .find(|r| match_report(r, local_name))
                {
                    break 'outer report.clone();
                }
            }
            e => panic!("Received unexpected event data: {:?}", e),
        }
    };

    set_scan_enable::send(hi, false, false).await.unwrap();

    ret
}

fn match_report(report: &&hci::events::LEAdvertisingReportData, name: &str) -> bool {
    use bo_tie::gap::advertise::local_name::LocalName;
    use bo_tie::gap::advertise::TryFromRaw;

    let mut data: &[u8] = &report.data;

    // In a AD type, the first byte gives the length of the data part of the type
    while let Some((len, rest)) = data.split_first() {
        let (first, rest) = rest.split_at(*len as usize);

        data = rest;

        if LocalName::try_from_raw(first)
            .map(|ln| &*ln == name)
            .unwrap_or_default()
        {
            return true;
        }
    }

    false
}

async fn connect_to<'a>(
    hi: &'a hci::HostInterface<Base>,
    peer_address: &bo_tie::BluetoothDeviceAddress,
    peer_address_type: bo_tie::hci::common::LEAddressType,
    raw_handle: Arc<AtomicU16>,
) -> impl bo_tie::l2cap::ConnectionChannel + 'a {
    use bo_tie::hci::cb::set_event_mask::{self, EventMask};
    use bo_tie::hci::common::{ConnectionLatency, SupervisionTimeout};
    use bo_tie::hci::events::{Events, EventsData, LEMeta, LEMetaData};
    use bo_tie::hci::le::common::{ConnectionEventLength, OwnAddressType};
    use bo_tie::hci::le::connection::{
        create_connection::{self, ConnectionParameters, ScanningInterval, ScanningWindow},
        ConnectionInterval, ConnectionIntervalBounds,
    };
    use bo_tie::hci::le::mandatory::set_event_mask as le_set_event_mask;

    set_event_mask::send(hi, &[EventMask::DisconnectionComplete, EventMask::LEMeta])
        .await
        .unwrap();

    le_set_event_mask::send(hi, &[LEMeta::ConnectionComplete])
        .await
        .unwrap();

    let parameters = ConnectionParameters::new_without_whitelist(
        ScanningInterval::default(),
        ScanningWindow::default(),
        peer_address_type,
        peer_address.clone(),
        OwnAddressType::PublicDeviceAddress,
        ConnectionIntervalBounds::try_from(
            ConnectionInterval::try_from_raw(0x10).unwrap(),
            ConnectionInterval::try_from_raw(0x10).unwrap(),
        )
        .unwrap(),
        ConnectionLatency::try_from(0).unwrap(),
        SupervisionTimeout::try_from_raw(0x10).unwrap(),
        ConnectionEventLength {
            minimum: 0,
            maximum: 0xFFFF,
        },
    );

    create_connection::send(hi, parameters).await.unwrap();

    let awaited_event = Some(Events::from(LEMeta::ConnectionComplete));

    match hi.wait_for_event(awaited_event).await.unwrap() {
        EventsData::LEMeta(LEMetaData::ConnectionComplete(data)) => {
            raw_handle.store(data.connection_handle.get_raw_handle(), Ordering::Relaxed);

            hi.new_connection_channel(data.connection_handle)
        }
        e => panic!("Received Unexpected event: {:?}", e),
    }
}

/// Start pairing
///
/// Returns the long term key (LTK) if the pairing process succeeded.
async fn pair<C>(cc: &C, msm: &mut bo_tie::sm::initiator::MasterSecurityManager<'_, C>) -> Option<u128>
where
    C: bo_tie::l2cap::ConnectionChannel,
{
    msm.start_pairing().await;

    'outer: loop {
        match cc.future_receiver().await {
            Ok(vec_data) => {
                for data in vec_data {
                    // All data that is not Security Manager related is ignored for this example
                    if data.get_channel_id() == bo_tie::sm::L2CAP_CHANNEL_ID {
                        match msm.continue_pairing(data).await {
                            Ok(true) => break 'outer msm.get_keys().and_then(|keys| keys.get_ltk()),
                            Ok(false) => {}
                            Err(e) => panic!("Pairing Error Occured: {:?}", e),
                        }
                    }
                }
            }
            Err(e) => panic!("Error when receiving ACL data: {:?}", e),
        }
    }
}

/// Start encryption
async fn encrypt(hi: &hci::HostInterface<Base>, connection_handle: hci::common::ConnectionHandle, ltk: u128) {
    use hci::cb::set_event_mask::{self, EventMask};
    use hci::common::EncryptionLevel;
    use hci::events::{Events, EventsData};
    use hci::le::encryption::start_encryption::{self, Parameter};

    set_event_mask::send(hi, &[EventMask::DisconnectionComplete, EventMask::EncryptionChange])
        .await
        .unwrap();

    // Because the security manager implementation only supports a LE secure connections
    // implementation, both the `random_number` and `encrypted_diversifier` are zero as per the
    // specification (v5.0 | Vol 3, Part H, Section 2.4.4).
    let parameter = Parameter {
        handle: connection_handle,
        random_number: 0,
        encrypted_diversifier: 0,
        long_term_key: ltk,
    };

    start_encryption::send(hi, parameter).await.unwrap();

    match hi.wait_for_event(Events::EncryptionChange).await {
        Ok(EventsData::EncryptionChange(data)) => {
            if (data.encryption_enabled.get_for_le() == EncryptionLevel::AESCCM)
                || (data.encryption_enabled.get_for_le() == EncryptionLevel::E0)
            {
                println!("Encryption started!")
            } else {
                panic!("Encryption did not start")
            }
        }
        Ok(e) => panic!("Received incorrect event: {:?}", e),
        Err(e) => panic!("Encryption failed: {:?}", e),
    }
}

async fn disconnect(hi: &hci::HostInterface<Base>, connection_handle: hci::common::ConnectionHandle) {
    use hci::link_control::disconnect::{self, DisconnectParameters, DisconnectReason};

    let dp = DisconnectParameters {
        connection_handle,
        disconnect_reason: DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(hi, dp).await.ok();
}

fn handle_sig(hi: Arc<hci::HostInterface<Base>>, raw_handle: Arc<AtomicU16>) {
    use hci::common::ConnectionHandle;
    use hci::le::connection::create_connection_cancel;

    simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term], move |_| {
        // Cancel connecting (if in process of connecting, there is no consequence if not
        // connecting, but an error is returned so all errors are ignored as a result)
        futures::executor::block_on(create_connection_cancel::send(&hi)).ok();

        let handle = ConnectionHandle::try_from(raw_handle.load(Ordering::Relaxed));

        if let Ok(connection_handle) = handle {
            futures::executor::block_on(disconnect(&hi, connection_handle));
        }

        println!("Exiting example");

        // Force dropping the `HostInterface`. Not doing this may cause problems with your
        // bluetooth controller if the HCI is not closed cleanly, espically when running
        // with a superuser.
        unsafe {
            let b = Box::from_raw(Arc::into_raw(hi.clone()) as *mut hci::HostInterface<Base>);

            std::mem::drop(b)
        };

        std::process::exit(0);
    });
}

async fn bonding(interface: Arc<hci::HostInterface<Base>>, raw_ch: Arc<AtomicU16>, adv_local_name: &str) {
    use bo_tie::sm::initiator::MasterSecurityManagerBuilder;

    let this_addr = hci::info_params::read_bd_addr::send(&interface).await.unwrap();

    let adv_info = start_scanning_for_addr(&interface, &adv_local_name).await;

    let peer_addr = adv_info.address;

    let peer_addr_type = adv_info.address_type;

    let cc = connect_to(&interface, &peer_addr, peer_addr_type, raw_ch.clone()).await;

    let connection_handle = hci::common::ConnectionHandle::try_from(raw_ch.load(Ordering::Relaxed)).unwrap();

    let mut msm = MasterSecurityManagerBuilder::new(
        &cc,
        &peer_addr,
        &this_addr,
        peer_addr_type == hci::common::LEAddressType::RandomDeviceAddress,
        false,
    )
    .build();

    let ltk = pair(&cc, &mut msm).await.expect("Pairing Failed");

    encrypt(&interface, connection_handle, ltk).await;

    msm.set_encrypted(true);

    println!("Bonding Complete");
}

#[derive(structopt::StructOpt)]
struct Opts {
    #[structopt(short = "n", long = "local-name", default_value = "Bonding Test")]
    /// The complete local name in the advertising data
    ///
    /// The is the name that will appear as part of the advertising data of the device to run this
    /// example with. The advertising packet for this tests requires a complete local name so that
    /// this example can determine what advertiser to connect to.
    local_name: String,
}

fn main() {
    use futures::executor;
    use simplelog::{Config, LevelFilter, TermLogger, TerminalMode};
    use structopt::StructOpt;

    let args = Opts::from_args();

    TermLogger::init(LevelFilter::Trace, Config::default(), TerminalMode::Mixed).unwrap();

    let raw_connection_handle = Arc::new(AtomicU16::new(INVALID_CONNECTION_HANDLE));

    let interface = Arc::new(hci::HostInterface::default());

    handle_sig(interface.clone(), raw_connection_handle.clone());

    executor::block_on(bonding(
        interface.clone(),
        raw_connection_handle.clone(),
        &args.local_name,
    ));

    std::thread::sleep(Duration::from_secs(5));

    if let Ok(handle) = hci::common::ConnectionHandle::try_from(raw_connection_handle.load(Ordering::Relaxed)) {
        executor::block_on(disconnect(&interface, handle));
    }

    println!("Exiting example");
}
