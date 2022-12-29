#![doc = include_str!("../README.md")]

mod io;

use bo_tie::hci::{ConnectionHandle, Host, HostChannelEnds};
use bo_tie::host::sm::Keys;

#[derive(Clone, Copy)]
struct AddressInfo {
    address: bo_tie::BluetoothDeviceAddress,
    is_pub: bool,
}

enum AdvertisingType {
    Undirected(&'static str, AddressInfo),
    Resolvable(Keys),
}

impl AdvertisingType {
    fn get_keys(&self) -> Option<Keys> {
        match self {
            AdvertisingType::Resolvable(keys) => keys.clone().into(),
            _ => None,
        }
    }
}

/// Starting advertising
///
/// There is two different kinds of advertising done by this example. The example starts out in
/// undirected advertising (with the flag `LeLimitedDiscoverableMode`), and any device can
/// successfully form a connection to the device running this example. Not much is different from
/// this form of advertising to the advertising done in the `le-peripheral` example. However, after
/// bonding is completed advertising is switched to directed, where by the address fields of the
/// advertising PDU for both the advertiser and target are resolvable private addresses. Network
/// privacy is used, so in order a device to connect it must also use a resolvable private address
/// in its connection initiation message (for itself). This means that only the bonded devices will
/// be allowed by the controller to form a Connection as both the central and peripheral must be
/// able to resolve each other's addresses.
async fn advertising_setup<H: HostChannelEnds>(hi: &mut Host<H>, ty: &AdvertisingType) {
    use bo_tie::hci::commands::le::OwnAddressType;
    use bo_tie::hci::commands::le::{
        set_advertising_data, set_advertising_enable, set_advertising_parameters, set_random_address,
    };
    use bo_tie::hci::events::{Events, LeMeta};
    use bo_tie::host::gap::assigned;

    let mut adv_data = set_advertising_data::AdvertisingData::new();

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    hi.mask_events([
        Events::LeMeta(LeMeta::EnhancedConnectionComplete),
        Events::DisconnectionComplete,
    ])
    .await
    .unwrap();

    match ty {
        AdvertisingType::Undirected(local_name, address_info) => {
            let mut adv_flags = assigned::flags::Flags::new();

            adv_flags
                .get_core(assigned::flags::CoreFlags::LeLimitedDiscoverableMode)
                .enable();
            adv_flags
                .get_core(assigned::flags::CoreFlags::BrEdrNotSupported)
                .enable();

            let adv_name = assigned::local_name::LocalName::new(*local_name, None);

            adv_data.try_push(adv_flags).unwrap();
            adv_data.try_push(adv_name).unwrap();

            adv_prams.own_address_type = if address_info.is_pub {
                OwnAddressType::PublicDeviceAddress
            } else {
                OwnAddressType::RandomDeviceAddress
            };

            set_random_address::send(hi, address_info.address).await.unwrap();
        }
        AdvertisingType::Resolvable(keys) => {
            let identity = keys.get_identity().unwrap().get_address();

            set_random_address::send(hi, identity).await.unwrap();

            use_resolving_list(hi, keys).await;

            // If the peer has given its IRK then advertising
            // will be directed, if it has not then advertising
            // is undirected. This is so the identity address
            // of this device is not exposed.
            if keys.get_peer_irk().is_some() {
                adv_prams.advertising_type =
                    set_advertising_parameters::AdvertisingType::ConnectableLowDutyCycleDirectedAdvertising;
            } else {
                adv_prams.advertising_type =
                    set_advertising_parameters::AdvertisingType::ConnectableAndScannableUndirectedAdvertising;
            }

            // This is directed advertising so the peer identity address is needed.
            adv_prams.peer_address = keys.get_peer_identity().unwrap().get_address();

            adv_prams.peer_address_type = if keys.get_peer_identity().unwrap().is_public() {
                set_advertising_parameters::PeerAddressType::PublicAddress
            } else {
                set_advertising_parameters::PeerAddressType::RandomAddress
            };

            // this is the key for advertising with a resolvable private address
            adv_prams.own_address_type = OwnAddressType::RpaFromLocalIrkOrRandomAddress;
        }
    }

    set_advertising_data::send(hi, adv_data).await.unwrap();

    set_advertising_parameters::send(hi, adv_prams).await.unwrap();

    set_advertising_enable::send(hi, true).await.unwrap();
}

/// Use the resolving list
///
/// This is required to ensure 'Network Privacy' with the Controller. It adds the information within
/// `keys` to the Controller's resolving list and sets the privacy mode to network privacy (note:
/// this is the default privacy of the controller).
async fn use_resolving_list<H: HostChannelEnds>(hi: &mut Host<H>, keys: &Keys) {
    use bo_tie::hci::commands::le::{
        add_device_to_resolving_list, set_address_resolution_enable, set_privacy_mode,
        set_resolvable_private_address_timeout, PeerIdentityAddressType,
    };

    let peer_identity_address_type = if keys.get_peer_identity().unwrap().is_public() {
        PeerIdentityAddressType::PublicIdentityAddress
    } else {
        PeerIdentityAddressType::RandomStaticIdentityAddress
    };

    let peer_identity_address = keys.get_peer_identity().unwrap().get_address();

    // The peer may have or may not have sent an IRK.
    let peer_irk = keys.get_peer_irk().unwrap_or_default();

    let local_irk = keys.get_irk().unwrap();

    let parameter = add_device_to_resolving_list::Parameter {
        peer_identity_address_type,
        peer_identity_address,
        peer_irk,
        local_irk,
    };

    add_device_to_resolving_list::send(hi, parameter).await.unwrap();

    // The default mode of `NetworkPrivacy` is recommended to
    // be used over `DevicePrivacy` but no all test apps (like
    // nRF connect) support `NetworkPrivacy` mode.
    let privacy_mode = set_privacy_mode::PrivacyMode::NetworkPrivacy;

    let parameter = set_privacy_mode::Parameter {
        peer_identity_address_type,
        peer_identity_address,
        privacy_mode,
    };

    // this is a 5.0+ command so it may not be available,
    // but that is fine as 4.2 only supports the equivalent
    // of NetworkPrivacy.
    set_privacy_mode::send(hi, parameter).await.ok();

    // This isn't totally necessary for this example as
    // the client is going to reconnect right away, but
    // most applications should use this command.
    set_resolvable_private_address_timeout::send(hi, std::time::Duration::from_secs(60 * 4))
        .await
        .unwrap();

    // This is only needed if the peer sent an IRK
    set_address_resolution_enable::send(hi, true).await.unwrap();
}

async fn remove_from_resolving_list<H: HostChannelEnds>(hi: &mut Host<H>, keys: &Keys) {
    use bo_tie::hci::commands::le::{
        remove_device_from_resolving_list, set_address_resolution_enable, PeerIdentityAddressType,
    };

    set_address_resolution_enable::send(hi, false).await.unwrap();

    let peer_identity_address_type = if keys.get_peer_identity().unwrap().is_public() {
        PeerIdentityAddressType::PublicIdentityAddress
    } else {
        PeerIdentityAddressType::RandomStaticIdentityAddress
    };

    let peer_identity_address = keys.get_peer_identity().unwrap().get_address();

    let parameter = remove_device_from_resolving_list::Parameter {
        peer_identity_address_type,
        peer_identity_address,
    };

    remove_device_from_resolving_list::send(hi, parameter).await.unwrap();
}

async fn stop_advertising<H: HostChannelEnds>(hi: &mut Host<H>, ty: &AdvertisingType) {
    // This does not panic as some times Controllers do not
    // like for the current advertising state to be written
    // to the controller (btw there is no Spec. reason for
    // this). For purposes of stopping advertising it
    // doesn't really matter.
    bo_tie::hci::commands::le::set_advertising_enable::send(hi, false)
        .await
        .ok();

    if let AdvertisingType::Resolvable(keys) = ty {
        remove_from_resolving_list(hi, keys).await;
    }
}

async fn wait_for_connection<H: HostChannelEnds>(
    hi: &mut Host<H>,
) -> bo_tie::hci::Connection<H::ConnectionChannelEnds> {
    use bo_tie::hci::Next;

    let connection = if let Next::NewConnection(connection) = hi.next().await.unwrap() {
        connection
    } else {
        unreachable!("unexpected disconnect event?")
    };

    connection
}

async fn on_encryption_change<C, Q>(
    ed: &bo_tie::hci::events::parameters::EncryptionChangeV1Data,
    le_connection_channel: &C,
    security_manager: &mut bo_tie::host::sm::responder::SecurityManager,
    gatt_server: &mut bo_tie::host::gatt::Server<Q>,
) where
    C: bo_tie::host::l2cap::ConnectionChannel,
    Q: bo_tie::host::att::server::QueuedWriter,
{
    use bo_tie::host::att::{AttributePermissions, AttributeRestriction, EncryptionKeySize};

    let is_encrypted = ed.encryption_enabled.get_for_le().is_aes_ccm();

    security_manager.set_encrypted(is_encrypted);

    if is_encrypted {
        gatt_server.give_permissions_to_client(AttributePermissions::Read(AttributeRestriction::Encryption(
            EncryptionKeySize::Bits128,
        )));

        // Send the local IRK if has not been sent yet.
        if let None = security_manager.get_keys().unwrap().get_irk() {
            // Distribute the irk (using `None` means the
            // security manager will generate the key).
            security_manager.send_irk(le_connection_channel, None).await.unwrap();

            // The identity address should not matter here,
            // but for some devices it does. This is not a
            // Bluetooth issue, its an issue with devices
            // not updating the access list to match this
            // identity address, so he address used for
            // pairing must be the one used sent as the
            // identity address.
            security_manager
                .send_identity(le_connection_channel, None)
                .await
                .unwrap();
        } else {
            gatt_server.revoke_permissions_of_client(AttributePermissions::Read(AttributeRestriction::Encryption(
                EncryptionKeySize::Bits128,
            )));
        }
    }
}

/// Server loop handles the data processing of
async fn server_loop<C>(
    mut connection: bo_tie::hci::Connection<C>,
    ltk_sender: tokio::sync::mpsc::Sender<Option<u128>>,
    local_name: &'static str,
    own_address: AddressInfo,
    bonding_keys: Option<Keys>,
) -> Result<Keys, &'static str>
where
    C: bo_tie::hci::ConnectionChannelEnds,
{
    use bo_tie::hci::events::{EventsData, LeMetaData};
    use bo_tie::host::l2cap::{ChannelIdentifier, ConnectionChannelExt, LeUserChannelIdentifier};
    use bo_tie::host::{att, gatt, sm};

    let peer_address = AddressInfo {
        address: connection.get_peer_address(),
        is_pub: !connection.is_address_random(),
    };

    let mut event_receiver = connection.take_event_receiver().unwrap();

    let mut le_connection_channel = connection.try_into_le().unwrap();

    let gsb = gatt::GapServiceBuilder::new(local_name, None);

    let queue_writer = att::server::BasicQueuedWriter::new(1024);

    let mut gatt_server = gatt::ServerBuilder::from(gsb).make_server(queue_writer);

    gatt_server.give_permissions_to_client(att::AttributePermissions::Read(att::AttributeRestriction::None));

    let security_manager_builder = sm::responder::SecurityManagerBuilder::new(
        peer_address.address,
        own_address.address,
        !peer_address.is_pub,
        !own_address.is_pub,
    );

    let mut security_manager = if let Some(keys) = bonding_keys {
        // no pairing (and bonding) is to be done as the keys were already generate
        security_manager_builder.set_already_paired(keys).unwrap().build()
    } else {
        // !!! The security manager must be set to distribute and accept bonding keys !!!
        security_manager_builder
            .enable_number_comparison()
            .enable_passkey()
            .sent_bonding_keys(|sent| sent.enable_irk())
            .accepted_bonding_keys(|accepted| accepted.enable_irk())
            .build()
    };

    loop {
        tokio::select! {
            l2cap_packets = le_connection_channel.receive_b_frame() => {
                for packet in l2cap_packets.ok().into_iter().flatten() {
                    match packet.get_channel_id() {
                        ChannelIdentifier::Le(LeUserChannelIdentifier::AttributeProtocol) => {
                            gatt_server
                                .process_acl_data(&mut le_connection_channel, &packet)
                                .await
                                .unwrap()
                        }
                        ChannelIdentifier::Le(LeUserChannelIdentifier::SecurityManagerProtocol) => {
                            security_manager
                                .process_command(&le_connection_channel, &packet)
                                .await
                                .unwrap();
                        }
                        _ => println!("received unexpected channel identifier"),
                    }
                }
            }
            event_data = event_receiver.recv() => match event_data {
                Some(EventsData::EncryptionChangeV1(ed) )=> {
                    on_encryption_change(&ed, &le_connection_channel, &mut security_manager, &mut gatt_server).await;
                }
                Some(EventsData::LeMeta(LeMetaData::LongTermKeyRequest(_))) => {
                    let opt_ltk = security_manager.get_keys().and_then(|keys| keys.get_ltk());

                    ltk_sender.send(opt_ltk).await.unwrap();
                }
                Some(EventsData::DisconnectionComplete(_)) | None => break,
                _ => unreachable!(),
            }
        }
    }

    match security_manager.get_keys() {
        Some(keys) if keys.get_irk().is_some() && keys.get_peer_irk().is_some() => Ok(keys.clone()),
        Some(keys) if keys.get_irk().is_some() && keys.get_peer_irk().is_none() => {
            Err("bonding failed, the central device did not distribute an IRK")
        }
        Some(_) => Err("devices disconnected before bonding (this may be due to a failure in pairing)"),
        None => Err("client disconnected but is not bonded, exiting example"),
    }
}

async fn on_ltk_request_event<H: HostChannelEnds>(
    host: &mut Host<H>,
    connection_handle: ConnectionHandle,
    ltk: Option<u128>,
) {
    use bo_tie::hci::commands::le::{long_term_key_request_negative_reply, long_term_key_request_reply};

    match ltk {
        None => {
            long_term_key_request_negative_reply::send(host, connection_handle)
                .await
                .unwrap();
        }
        Some(ltk) => {
            long_term_key_request_reply::send(host, connection_handle, ltk)
                .await
                .unwrap();
        }
    }
}

async fn disconnect<H: HostChannelEnds>(hi: &mut Host<H>, connection_handle: Option<ConnectionHandle>) {
    use bo_tie::hci::commands::link_control::disconnect;
    use bo_tie::hci::events::Events;
    use bo_tie::hci::Next;

    macro_rules! disconnect {
        ($connection_handle:expr) => {
            async {
                let prams = disconnect::DisconnectParameters {
                    connection_handle: $connection_handle,
                    disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
                };

                // This may error if the device is
                // somehow already disconnected, and
                // if doesn't matter so the error is
                // disregarded here.
                disconnect::send(hi, prams).await.ok();
            }
        };
    }

    match connection_handle {
        Some(connection_handle) => disconnect!(connection_handle).await,
        None => {
            // race condition boilerplate
            hi.mask_events(core::iter::empty::<Events>()).await.unwrap();

            // send the disconnection if the controller did send a new connection
            while let Some(next) = hi.try_next().await.unwrap() {
                if let Next::NewConnection(connection) = next {
                    disconnect!(connection.get_handle()).await
                }
            }
        }
    }
}

async fn exit_example<H: HostChannelEnds>(
    host: &mut Host<H>,
    connection_handle: Option<ConnectionHandle>,
    adv_ty: &AdvertisingType,
) {
    stop_advertising(host, adv_ty).await;

    disconnect(host, connection_handle).await;
}

#[cfg(target_os = "linux")]
macro_rules! create_hci {
    () => {
        // By using `None` with bo_tie_linux::new, the first
        // Bluetooth adapter found is the adapter that is used
        bo_tie_linux::new(None)
    };
}

#[cfg(not(target_os = "linux"))]
macro_rules! create_hci {
    () => {
        compile_error!("unsupported target for this example")
    };
}

#[tokio::main]
async fn main() {
    use bo_tie::hci::events::{Events, LeMeta};

    #[cfg(feature = "log")]
    {
        use simplelog::{ColorChoice, Config, LevelFilter, TermLogger, TerminalMode};

        TermLogger::init(
            LevelFilter::Trace,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .unwrap();
    }

    let example_name = "bonding test";

    let exit_sig = io::setup_sig();

    let (interface, host_ends) = create_hci!();

    tokio::spawn(interface.run());

    let mut host = Host::init(host_ends).await.expect("failed to initialize host");

    // this example needs to set the routing policy to send the
    // encryption event to the connection async task.
    host.set_event_routing_policy(bo_tie::hci::EventRoutingPolicy::OnlyConnections)
        .await
        .unwrap();

    println!("beginning undirected advertising");

    let own_address_info = AddressInfo {
        address: bo_tie::BluetoothDeviceAddress::new_random_static(),
        is_pub: false,
    };

    let mut advertising_type = AdvertisingType::Undirected(example_name, own_address_info);

    let mut opt_connection_handle = None;

    let task = async {
        'task: loop {
            advertising_setup(&mut host, &advertising_type).await;

            let connection = wait_for_connection(&mut host).await;

            opt_connection_handle = connection.get_handle().into();

            // Unmask the 'LE connection complete' event as it is
            // no longer needed and enable the LongTermKeyRequest
            // and EncryptionChange events.
            host.mask_events([
                Events::DisconnectionComplete,
                Events::EncryptionChangeV1,
                Events::LeMeta(LeMeta::LongTermKeyRequest),
            ])
            .await
            .unwrap();

            stop_advertising(&mut host, &advertising_type).await;

            let (ltk_sender, mut ltk_receiver) = tokio::sync::mpsc::channel(1);

            let handle = tokio::spawn(server_loop(
                connection,
                ltk_sender,
                example_name,
                own_address_info,
                advertising_type.get_keys(),
            ));

            let keys = tokio::select!(
                opt_rslt_keys = handle => {
                    opt_connection_handle = None;

                    match opt_rslt_keys.unwrap() {
                        Ok(keys) => keys,
                        Err(e) => {
                            println!("{}", e);
                            break 'task;
                        }
                    }
                }

                _ = async { loop {
                    if let Some(opt_ltk) = ltk_receiver.recv().await {
                        on_ltk_request_event(
                            &mut host,
                            opt_connection_handle.unwrap(),
                            opt_ltk
                        ).await
                    } else {
                        // this may be reached if the `handle` is not polled first
                        core::future::pending::<()>().await;
                    }
                }} => unreachable!(),
            );

            println!("client disconnected and is bonded, beginning private directed advertising");

            // set advertising to directed
            advertising_type = AdvertisingType::Resolvable(keys);
        }
    };

    tokio::select!(
        _ = task => (),
        _ = exit_sig => (),
    );

    exit_example(&mut host, opt_connection_handle, &advertising_type).await;
}
