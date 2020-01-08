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

// For simplicity, I've left the race condition in here. There could be a case where the connection
// is made and the ConnectionComplete event isn't propicated & processed
async fn wait_for_connection(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>)
-> Result<hci::events::LEConnectionCompleteData, impl std::fmt::Display>
{
    use bo_tie::hci::events::LEMeta;

    bo_tie::hci::le::mandatory::set_event_mask::send(
        hi,
        &[
            LEMeta::ConnectionComplete,
            //LEMeta::RemoteConnectionParameterRequest,
        ]
    ).await
    .unwrap();
    
    println!("Waiting for a connection (timeout is 60 seconds)");

    let evt_rsl = hi.wait_for_event(events::LEMeta::ConnectionComplete.into(), Duration::from_secs(60)).await;

    println!("Connection made");

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
        connection_handle: connection_handle,
        disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(&hi, prams).await.expect("Failed to disconnect");
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

fn server_loop<C>(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    connection_channel: &C,
    ch: hci::common::ConnectionHandle,
    mut att_server: gatt::Server<C>,
    mut slave_security_manager: SlaveSecurityManager<'_,C>
)
where C: bo_tie::l2cap::ConnectionChannel
{
    use bo_tie::l2cap::ChannelIdentifier;
    use bo_tie::l2cap::LeUserChannelIdentifier;

    loop {
        futures::executor::block_on(
            async {
                let acl_data_vec = connection_channel.future_receiver().await.unwrap();
    
                for acl_data in acl_data_vec {
                    match acl_data.get_channel_id() {
                        ChannelIdentifier::LE(LeUserChannelIdentifier::AttributeProtocol) =>
                            match att_server.process_acl_data(&acl_data) {
                                Ok(_) => (),
                                Err(e) => println!("Cannot process acl data for ATT, '{}'", e),
                            }
                        ChannelIdentifier::LE(LeUserChannelIdentifier::SecurityManagerProtocol) =>
                            match slave_security_manager.process_command(acl_data.get_payload()) {
                                Ok(None) => (),
                                Err(e) => println!("Cannot process acl data for SM, '{:?}'", e),
                                Ok(Some(lazy)) => {
                                    // TODO    
                                }
                            }
                        _ => (),
                    }
                }
            }
        );
    }
}

fn handle_sig(
    hi: Arc<hci::HostInterface<bo_tie_linux::HCIAdapter>>,
    raw_handle: Arc<AtomicU16> )
{
    simple_signal::set_handler(&[simple_signal::Signal::Int, simple_signal::Signal::Term],
        move |_| {
            // Cancel advertising if advertising (there is no consequence if not advertising)
            futures::executor::block_on(set_advertising_enable::send(&hi, false)).unwrap();

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
    match executor::block_on(wait_for_connection(&interface)) {
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

