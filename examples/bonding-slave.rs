use bo_tie:: {
    att,
    gap::advertise,
    gatt,
    hci,
    hci::events,
    hci::le::{
        transmitter::{
            set_advertising_data,
            set_advertising_parameters,
            set_advertising_enable,
            set_random_address,
        },
    },
    sm::responder::SlaveSecurityManager,
};
use std::sync::{Arc, atomic::{AtomicU16, Ordering}};
use std::time::Duration;

/// 0xFFFF is a reserved value as of the Bluetooth Spec. v5, so it isn't a valid value sent
/// from the controller to the user.
const INVALID_CONNECTION_HANDLE: u16 = 0xFFFF;

/// This sets up the advertising and waits for the connection complete event
async fn advertise_setup<'a>(
    hi: &'a hci::HostInterface<bo_tie_linux::HCIAdapter>,
    this_address: bo_tie::BluetoothDeviceAddress,
    local_name: &'a str )
{
    let adv_name = advertise::local_name::LocalName::new(local_name, false);

    let mut adv_flags = advertise::flags::Flags::new();

    // This is the flag specification for a LE-only, limited discoverable advertising
    adv_flags.get_core(advertise::flags::CoreFlags::LELimitedDiscoverableMode).enable();
    adv_flags.get_core(advertise::flags::CoreFlags::LEGeneralDiscoverableMode).disable();
    adv_flags.get_core(advertise::flags::CoreFlags::BREDRNotSupported).enable();
    adv_flags.get_core(advertise::flags::CoreFlags::ControllerSupportsSimultaniousLEAndBREDR).disable();
    adv_flags.get_core(advertise::flags::CoreFlags::HostSupportsSimultaniousLEAndBREDR).disable();

    let mut adv_data = set_advertising_data::AdvertisingData::new();

    adv_data.try_push(adv_flags).unwrap();
    adv_data.try_push(adv_name).unwrap();

    set_advertising_enable::send(&hi, false).await.unwrap();

    set_random_address::send(&hi, this_address.clone()).await.unwrap();

    set_advertising_data::send(&hi, adv_data).await.unwrap();

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    adv_prams.own_address_type = bo_tie::hci::le::common::OwnAddressType::RandomDeviceAddress;

    set_advertising_parameters::send(&hi, adv_prams).await.unwrap();

    set_advertising_enable::send(&hi, true).await.unwrap();
}

async fn connection_update_request(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>) {
    use bo_tie::hci::le::con_pram_req::remote_connection_parameter_request_reply::{
        send,
        CommandParameters
    };
    use bo_tie::hci::common::{
        ConnectionInterval,
        ConnectionLatency,
        SupervisionTimeout,
    };
    use bo_tie::hci::le::common::ConnectionEventLength;

    loop {
        let e = hi.wait_for_event(events::LEMeta::RemoteConnectionParameterRequest.into(), None).await;

        match e {
            Ok(events::EventsData::LEMeta(events::LEMetaData::RemoteConnectionParameterRequest(e))) => {
                let cp = CommandParameters {
                    handle: e.connection_handle,
                    interval_min: ConnectionInterval::try_from(400).unwrap(),
                    interval_max: ConnectionInterval::try_from(400).unwrap(),
                    latency: ConnectionLatency::try_from(0).unwrap(),
                    timeout: SupervisionTimeout::try_from_duration(Duration::from_secs(5)).unwrap(),
                    ce_len: ConnectionEventLength { minimum: 0, maximum: 0xFFFF },
                };

                send(hi, cp).await.err()
                    .map(|e| log::error!("LE Connection Parameter Request Reply failed: {:?}", e) );
            }
            e => log::error!("Received unexpected event or error: {:?}", e)
        }

    }
}

// For simplicity, I've left the race condition in here. There could be a case where the connection
// is made and the ConnectionComplete event isn't propicated & processed
async fn wait_for_connection(hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter>>)
-> Result<hci::events::LEConnectionCompleteData, impl std::fmt::Display>
{
    use bo_tie::hci::events::LEMeta;

    let hi_cln = hi.clone();

    std::thread::spawn(move || {
        futures::executor::block_on(connection_update_request(&hi_cln))
    });

    let le_events_mask = &[LEMeta::ConnectionComplete, LEMeta::RemoteConnectionParameterRequest];

    bo_tie::hci::le::mandatory::set_event_mask::send( &hi, le_events_mask).await.unwrap();

    println!("Waiting for a connection (timeout is 60 seconds)");

    let evt_rsl = hi.wait_for_event(events::LEMeta::ConnectionComplete.into(), Duration::from_secs(60)).await;

    match evt_rsl {
        Ok(event) => {
            use bo_tie::hci::events::{EventsData,LEMetaData};
                use bo_tie::hci::le::con_pram_req::remote_connection_parameter_request_reply;
                use bo_tie::hci::common::{
                    ConnectionInterval,
                    ConnectionLatency,
                    SupervisionTimeout,
                };
                use bo_tie::hci::le::common::ConnectionEventLength;

            if let EventsData::LEMeta(LEMetaData::ConnectionComplete(event_data)) = event {

                set_advertising_enable::send(&hi, false).await.unwrap();

                Ok(event_data)
            }
            else {
                Err(format!("Received the incorrect event {:?}", event))
            }
        }
        Err(e) => {
            Err(format!("Timeout Occured: {:?}", e))
        }
    }
}

async fn disconnect(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    connection_handle: hci::common::ConnectionHandle )
{
    use bo_tie::hci::le::connection::disconnect;

    let prams = disconnect::DisconnectParameters {
        connection_handle,
        disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(&hi, prams).await.err().map(|e| log::error!("Failed to disconnect: {:?}", e));
}

/// Initialize the Attribute Server
///
/// The attribute server is organized via the gatt protocol. This example is about connecting
/// to a client and not about featuring the attribue server, so only the minimalistic gatt server
/// is present.
fn gatt_server_init<'c, C>(channel: &'c C, local_name: &str) -> gatt::Server<'c, C>
where C: bo_tie::l2cap::ConnectionChannel
{
    let att_mtu = 256;

    let gsb = gatt::GapServiceBuilder::new(local_name, None);

    let mut server = gatt::ServerBuilder::new_with_gap(gsb).make_server(channel, att_mtu);

    server.as_mut().give_permission_to_client(att::AttributePermissions::Read);

    server
}

async fn enable_encrypt_events(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>) {
    use bo_tie::hci::cb::set_event_mask::{self, EventMask};
    use bo_tie::hci::le::mandatory::set_event_mask as le_set_event_mask;
    use bo_tie::hci::events::LEMeta;

    set_event_mask::send(
        hi,
        &[
            EventMask::DisconnectionComplete,
            EventMask::EncryptionChange,
            EventMask::LEMeta,
        ]
    ).await.unwrap();

    le_set_event_mask::send(
        hi,
        &[
            LEMeta::RemoteConnectionParameterRequest,
            LEMeta::LongTermKeyRequest,
        ]
    ).await.unwrap();
}

async fn process_acl_data<C>(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    connection_channel: &C,
    ch: hci::common::ConnectionHandle,
    att_server: &mut gatt::Server<'_,C>,
    slave_security_manager: &mut SlaveSecurityManager<'_,C>
) -> Option<u128>
where C: bo_tie::l2cap::ConnectionChannel
{
    use bo_tie::l2cap::{ChannelIdentifier, LeUserChannelIdentifier};

    let acl_data_vec = connection_channel.future_receiver().await.unwrap();
    let mut ret = None;

    for acl_data in acl_data_vec {
        match acl_data.get_channel_id() {
            ChannelIdentifier::LE(LeUserChannelIdentifier::AttributeProtocol) =>
                match att_server.process_acl_data(&acl_data) {
                    Ok(_) => (),
                    Err(e) => log::error!("Cannot process acl data for ATT, '{}'", e),
                }
            ChannelIdentifier::LE(LeUserChannelIdentifier::SecurityManagerProtocol) =>
                match slave_security_manager.process_command(acl_data.get_payload()) {
                    Ok(None) => (),
                    Err(e) => log::error!("Cannot process acl data for SM, '{:?}'", e),
                    Ok(Some(db_entry)) => ret = db_entry.get_ltk()
                }
            _ => (),
        }
    }

    ret
}

async fn await_ltk_request(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    ch: hci::common::ConnectionHandle,
) -> bool {
    use bo_tie::hci::le::encryption::long_term_key_request_negative_reply;
    use events::{EventsData, LEMeta, LEMetaData};

    let event = hi.wait_for_event(LEMeta::LongTermKeyRequest.into(), None).await;

    log::trace!("Received Long Term Key Request");

    match event {
        Ok(EventsData::LEMeta(LEMetaData::LongTermKeyRequest(ltk_req))) if ltk_req.connection_handle == ch => {
            true
        },
        Ok(EventsData::LEMeta(LEMetaData::LongTermKeyRequest(ltk_req))) => {
            long_term_key_request_negative_reply::send(hi, ltk_req.connection_handle).await.unwrap();
            false
        },
        Ok(e) => {
            log::error!("Received incorrect event {:?}", e);
            false
        },
        Err(e) => panic!("Event error: {:?}", e),
    }
}

async fn send_ltk(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    ch: hci::common::ConnectionHandle,
    ltk: Option<u128>,
){
    use bo_tie::hci::le::encryption::long_term_key_request_reply;
    use bo_tie::hci::le::encryption::long_term_key_request_negative_reply;

    match ltk {
        Some(ltk) => { long_term_key_request_reply::send(hi, ch, ltk).await.unwrap(); },
        None => { long_term_key_request_negative_reply::send(hi, ch).await.unwrap(); }
    }
}

async fn await_encryption(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    ch: hci::common::ConnectionHandle,
) -> bool
{
    use events::Events::{EncryptionChange, EncryptionKeyRefreshComplete};
    use events::EventsData::EncryptionChange as EC;
    use bo_tie::hci::common::EncryptionLevel::{AESCCM, Off};
    use futures::{select, future::FutureExt};

    let evnt = hi.wait_for_event(EncryptionChange, None).await;

    match evnt {
        Ok(EC(e_data)) =>
            match (e_data.encryption_enabled.get_for_le(), e_data.connection_handle) {
                (AESCCM, handle) if ch == handle => true,
                (Off, _) => (false),
                (e, h) => {
                    log::error!("Using encrypt {:?} for handle {:?}, expected {:?}", e, h, ch);
                    false
                },
            },
        _ => {
            log::error!("Expected EncryptinoChange event");
            false
        }
    }
}

fn server_loop<C>(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    connection_channel: &C,
    ch: hci::common::ConnectionHandle,
    mut att_server: gatt::Server<'_,C>,
    mut slave_security_manager: SlaveSecurityManager<'_,C>
)
where C: bo_tie::l2cap::ConnectionChannel
{
    use bo_tie::l2cap::ChannelIdentifier;
    use bo_tie::l2cap::LeUserChannelIdentifier;
    use futures::{select, future::FutureExt};

    let mut ltk = None;
    let mut encrypted = false;
    let mut irk_sent = false;

    futures::executor::block_on( enable_encrypt_events(hi) );

    let mut e = Box::pin(await_encryption(hi, ch).fuse());
    let mut l = Box::pin(await_ltk_request(hi, ch).fuse());

    loop {
        let a = process_acl_data(hi, connection_channel, ch, &mut att_server, &mut slave_security_manager);

        futures::executor::block_on( async {
            select!{
                a_res = Box::pin(a.fuse()) => ltk = a_res,

                e_res = e => encrypted = e_res,

                l_res = l => if l_res { send_ltk(hi, ch, ltk).await },
            }
        });

        slave_security_manager.set_encrypted(encrypted);

        if encrypted && irk_sent == false {
            println!("Sending IRK to Master");

            if slave_security_manager.send_irk() {
                irk_sent = true;
            } else {
                log::error!("Failed to send IRK");
            }
        }
    }
}

fn handle_sig(
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter>>,
    raw_handle: Arc<AtomicU16> )
{
    simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term],
        move |_| {
            // Cancel advertising if advertising (there is no consequence if not advertising)
            if let Err(e) = futures::executor::block_on(set_advertising_enable::send(&hi, false)) {
                log::error!("Failed to stop advertising: {:?}", e);
            }

            // todo fix the race condition where a connection is made but the handle hasn't been
            // stored here yet
            let handle_val = raw_handle.load(Ordering::SeqCst);

            if handle_val != INVALID_CONNECTION_HANDLE {

                let handle = bo_tie::hci::common::ConnectionHandle::try_from(handle_val).expect("Incorrect Handle");

                futures::executor::block_on(disconnect(&hi, handle));

                println!("Bluetooth connection terminated")
            }

            println!("Exiting example");

            std::process::exit(0);
        }
    );
}

fn main() {
    use futures::executor;
    use simplelog::{TermLogger, LevelFilter, Config, TerminalMode};

    let local_name = "Bonding Test";

    TermLogger::init( LevelFilter::Trace, Config::default(), TerminalMode::Mixed ).unwrap();

    let raw_connection_handle = Arc::new(AtomicU16::new(INVALID_CONNECTION_HANDLE));

    let interface = Arc::new(hci::HostInterface::default());

    handle_sig(interface.clone(), raw_connection_handle.clone());

    let this_address = [0x70, 0x92, 0x07, 0x23, 0xac, 0xc3];

    println!("This public address: {:x?}", this_address);

    executor::block_on(advertise_setup(&interface, this_address.clone(), local_name));

    // Waiting for some bluetooth device to connect is slow, so the waiting for the future is done
    // on a different thread.
    match executor::block_on(wait_for_connection(interface.clone())) {
        Ok(event_data) => {

            raw_connection_handle.store(event_data.connection_handle.get_raw_handle(), Ordering::SeqCst);

            let interface_clone = interface.clone();

            let master_address = event_data.peer_address.clone();

            let master_address_type = event_data.peer_address_type.clone();

            std::thread::spawn( move || {

                let connection_channel = interface_clone.new_le_acl_connection_channel(&event_data);

                let server = gatt_server_init(&connection_channel, local_name);

                let sm = bo_tie::sm::SecurityManager::new(Vec::new());

                let slave_sm = sm.new_slave_builder(
                    &connection_channel,
                    &master_address,
                    master_address_type == bo_tie::hci::events::LEConnectionAddressType::RandomDeviceAddress,
                    &this_address,
                    true // using a random address
                )
                .set_min_and_max_encryption_key_size(16,16).unwrap()
                .create_security_manager();

                server_loop(&interface_clone, &connection_channel, event_data.connection_handle, server, slave_sm);
            });

            println!("Device Connected! (use ctrl-c to disconnect and exit)");

            executor::block_on(interface.wait_for_event(events::Events::DisconnectionComplete, None)).ok();
        },
        Err(err) => println!("Error: {}", err),
    };
}
