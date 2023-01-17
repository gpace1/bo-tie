#![doc = include_str!("../README.md")]

mod io;

use bo_tie::hci::{Host, HostChannelEnds, Next};

/// Scan for a device with the specific local name
///
/// This function will set the Bluetooth Controller into scanning mode and continue scanning until
/// it is stopped by the user with `stop`.
///
/// # Note
/// There is no difference between this method and the method `scan_for_devices` in the example
/// 'le-central'
///
/// # Error
/// An error is returned if the future `stop` outputs false.
async fn scan_for_devices<H, C, Fun, Fut>(
    host: &mut Host<H>,
    on_result: C,
    stop: Fun,
) -> Result<Vec<(bo_tie::hci::events::parameters::LeAdvertisingReportData, String)>, &'static str>
where
    H: HostChannelEnds,
    C: Fn(usize, &str),
    Fun: FnOnce() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    use bo_tie::hci::commands::le::{set_scan_enable, set_scan_parameters};
    use bo_tie::hci::events::{Events, EventsData, LeMeta, LeMetaData};
    use bo_tie::host::gap::assigned::local_name::LocalName;

    let mut devices = Vec::new();

    let mut scan_prams = set_scan_parameters::ScanningParameters::default();

    scan_prams.scan_type = set_scan_parameters::LeScanType::PassiveScanning;
    scan_prams.scanning_filter_policy = set_scan_parameters::ScanningFilterPolicy::AcceptAll;

    host.mask_events([Events::LeMeta(LeMeta::AdvertisingReport)])
        .await
        .unwrap();

    set_scan_parameters::send(host, scan_prams).await.unwrap();

    set_scan_enable::send(host, true, true).await.unwrap();

    let task = async {
        let mut count = 0;

        loop {
            if let Next::Event(EventsData::LeMeta(LeMetaData::AdvertisingReport(reports))) = host.next().await.unwrap()
            {
                for report in reports.iter().filter_map(|rslt_report| rslt_report.as_ref().ok()) {
                    if let Some(name) = report
                        .iter()
                        .filter_map(|rslt| rslt.ok())
                        .find_map(|ad_struct| ad_struct.try_into::<LocalName<_, _>>().ok())
                    {
                        count += 1;

                        on_result(count, name.as_str());

                        devices.push((report.clone(), name.to_string()));
                    }
                }
            }
        }
    };

    let stop_status = tokio::select! {
        _ = task => unreachable!(),
        status = stop() => status,
    };

    set_scan_enable::send(host, false, false).await.unwrap();

    host.mask_events(core::iter::empty::<Events>()).await.unwrap();

    return stop_status.then_some(devices).ok_or("exited by user");
}

/// Connect to the advertising device
///
/// Connecting is done two different ways depending on the bonding state.
///
/// When no device is bonded then a connection is made based on an advertising report. This
/// procedure is no different from the method `connect` within the example 'le-central'.
///
/// Once a device is bonded, the identity address of the peripheral device will be used to generate
/// a resolvable private address to reconnect to the device.
async fn connect<H: HostChannelEnds>(
    host: &mut Host<H>,
    report: &bo_tie::hci::events::parameters::LeAdvertisingReportData,
) -> bo_tie::hci::LeL2cap<H::ConnectionChannelEnds> {
    use bo_tie::hci::commands::le::create_connection;
    use bo_tie::hci::events::{Events, LeMeta};
    use std::time::Duration;

    // This device is not part of the whitelist, so
    // the whitelist is ignored here.
    let connection_parameters = create_connection::ConnectionParameters::new_without_whitelist(
        create_connection::ScanningInterval::default(),
        create_connection::ScanningWindow::default(),
        report.address_type,
        report.address,
        Default::default(),
        TryFrom::try_from((Duration::from_millis(10), Duration::from_millis(40))).unwrap(),
        TryFrom::try_from(0).unwrap(),
        TryFrom::try_from(Duration::from_secs(5)).unwrap(),
        Default::default(),
    );

    // enable the LE Connection Complete and Disconnection Complete events
    host.mask_events([
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::DisconnectionComplete,
    ])
    .await
    .unwrap();

    // create the connection
    create_connection::send(host, connection_parameters).await.unwrap();

    if let Next::NewConnection(connection) = host.next().await.unwrap() {
        // disable the LE Connection Complete event but keep Disconnection Complete enabled
        host.mask_events([Events::DisconnectionComplete]).await.unwrap();

        connection.try_into_le().expect("failed to create connection")
    } else {
        unreachable!("no events except for Connection Complete are enabled")
    }
}

/// Cancel the connection
///
/// This will cancel the connection if there is a pending.
///
/// # Note
/// This method assumes that only the connection complete and disconnection complete events are
/// masked on the controller.
async fn cancel_connect<H: HostChannelEnds>(host: &mut Host<H>) {
    match bo_tie::hci::commands::le::create_connection_cancel::send(host)
        .await
        .map_err(|e| e.try_into().unwrap())
    {
        Ok(_) => (),
        Err(bo_tie::Error::CommandDisallowed) => {
            // Command disallowed can be sent by the controller if
            // the connection was made before the connection cancel
            // command was sent. Simply dropping the HCI connection
            // object will cause the HCI interface async task to send
            // the disconnection.
            host.next().await.unwrap();
        }
        Err(e) => panic!("{}", e),
    }
}

/// Disconnect the peripheral device
async fn disconnect<H>(host: &mut Host<H>, connection_handle: bo_tie::hci::ConnectionHandle)
where
    H: HostChannelEnds,
{
    use bo_tie::hci::commands::link_control::disconnect;
    use bo_tie::hci::events::Events;

    host.mask_events(core::iter::empty::<Events>()).await.unwrap();

    let disconnection_parameters = disconnect::DisconnectParameters {
        connection_handle,
        disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(host, disconnection_parameters).await.unwrap();
}

/// Pair with a connected device
async fn pair<C>(connection_channel: &mut C, sm: &mut bo_tie::host::sm::initiator::SecurityManager) -> u128
where
    C: bo_tie::host::l2cap::ConnectionChannel,
{
    use bo_tie::host::l2cap::ConnectionChannelExt;
    use bo_tie::host::sm::initiator::Status;

    let mut number_comparison = None;
    let mut passkey_input = None;

    sm.start_pairing(connection_channel).await.unwrap();

    'outer: loop {
        tokio::select! {
            frames = connection_channel.receive_b_frame() => for basic_frame in frames.unwrap() {
                // All data that is not Security Manager related is ignored for this example, the
                // peripheral device should not be sending anything to this device other than
                // Security Manager packets.
                if basic_frame.get_channel_id() == bo_tie::host::sm::L2CAP_CHANNEL_ID {
                    match sm.continue_pairing(connection_channel, &basic_frame).await.unwrap() {
                        Status::PairingComplete => {
                            break 'outer sm.get_keys().unwrap().get_ltk().unwrap()
                        },
                        Status::NumberComparison(n) => {
                            println!(
                                "To proceed with pairing, compare this number ({n}) with the \
                                number displayed on the other device"
                            );
                            println!("Does {n} match the number on the other device? [y/n]");

                            number_comparison = Some(n);
                        },
                        Status::PasskeyOutput(o) => {
                            println!("enter this passkey on the other device: {o}")
                        },
                        Status::PasskeyInput(i) => {
                            io::passkey_input_message(&i);

                            passkey_input = Some(i);
                        },
                        Status::PairingFailed(reason) => {
                            eprintln!("pairing failed: {reason}");
                            number_comparison = None;
                            passkey_input = None;
                        },
                        _ => (),
                    }
                }
            },

            is_accepted = io::number_comparison(&mut number_comparison) => if is_accepted {
                number_comparison.take().unwrap().yes(sm, connection_channel).await.unwrap();
            } else {
                number_comparison.take().unwrap().no(sm, connection_channel).await.unwrap();
            },

            passkey = io::get_passkey(passkey_input.is_none()) => if let Some(input) = io::process_passkey(passkey) {
                passkey_input.as_mut().unwrap().write(input).unwrap();

                passkey_input.take().unwrap().complete(sm, connection_channel).await.unwrap();
            } else {
                passkey_input.take().unwrap().fail(sm, connection_channel).await.unwrap();
            },
        }
    }
}

/// Complete encryption with a device
async fn encrypt<H: HostChannelEnds>(
    host: &mut Host<H>,
    connection_handle: bo_tie::hci::ConnectionHandle,
    long_term_key: u128,
) -> Result<(), &'static str> {
    use bo_tie::hci::commands::le::enable_encryption;
    use bo_tie::hci::events::{Events, EventsData};

    host.mask_events([
        Events::DisconnectionComplete,
        Events::EncryptionChangeV1,
        Events::EncryptionChangeV2,
    ])
    .await
    .unwrap();

    let parameter = enable_encryption::Parameter::new_sc(connection_handle, long_term_key);

    enable_encryption::send(host, parameter).await.unwrap();

    match host.next().await.unwrap() {
        Next::Event(events_data) => match events_data {
            EventsData::EncryptionChangeV1(e) => e
                .encryption_enabled
                .get_for_le()
                .is_aes_ccm()
                .then_some(())
                .expect("encryption failed"),
            EventsData::EncryptionChangeV2(e) => e
                .encryption_enabled
                .get_for_le()
                .is_aes_ccm()
                .then_some(())
                .expect("encryption failed"),
            EventsData::DisconnectionComplete(d) => {
                if d.connection_handle == connection_handle {
                    return Err("peer device disconnected".into());
                }
            }
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };

    Ok(())
}

/// Bond with a paired device
///
/// # Note
/// This must be called after method `encrypt`
async fn bond<C>(connection_channel: &mut C, sm: &mut bo_tie::host::sm::initiator::SecurityManager)
where
    C: bo_tie::host::l2cap::ConnectionChannel,
{
    use bo_tie::host::l2cap::ConnectionChannelExt;

    sm.set_encrypted(true);

    'outer: loop {
        for basic_frame in connection_channel.receive_b_frame().await.unwrap() {
            // All data that is not Security Manager related is ignored for this example
            if basic_frame.get_channel_id() == bo_tie::host::sm::L2CAP_CHANNEL_ID {
                if sm.process_bonding(&basic_frame).await.unwrap() {
                    // once the peripheral has sent its bonding
                    // information then this bonding information
                    // is sent to the device.

                    sm.send_irk(connection_channel, None).await.unwrap();
                    sm.send_identity(connection_channel, None).await.unwrap();
                    break 'outer;
                }
            }
        }
    }
}

/// Query the services for the GATT server
///
/// # Note
/// If there is not GATT server, then this will print out a messages stating as such
async fn query_gatt_services<C>(connection: &mut C)
where
    C: bo_tie::host::l2cap::ConnectionChannel,
{
    use bo_tie::host::att::client::ConnectClient;
    use bo_tie::host::gatt::Client;
    use std::time::Duration;
    use tokio::time::timeout;

    // Normally you can assume that there exists a
    // GATT server on the peer device (I think it is
    // part of the Bluetooth certification process for
    // every LE device to have some basic GATT server
    // or client), but here it is not assumed.
    let gatt_client: Client = match timeout(Duration::from_secs(5), ConnectClient::connect(connection, 64)).await {
        Err(_timeout) => {
            println!("failed to connect to GATT (timeout)");
            return;
        }
        Ok(Err(e)) => {
            println!("failed to connect to GATT ({:?})", e);
            return;
        }
        Ok(Ok(att_client)) => att_client.into(),
    };

    let mut querier = gatt_client.query_services(connection);

    let mut services = Vec::new();

    while let Some(service) = querier.query_next().await.unwrap() {
        services.push(service);
    }

    if services.is_empty() {
        println!("no services found on connected device")
    } else {
        println!("found services:");

        for service in services {
            println!("\t{:#x}", service.get_uuid())
        }
    }
}

/// Set the peer device to be reconnected
///
/// Once bonding is completed, the peer device needs to be added to both the filter list and
/// resolving list.
async fn setup_reconnect<H: HostChannelEnds>(host: &mut Host<H>, keys: &bo_tie::host::sm::Keys) {
    use bo_tie::hci::commands::le::{
        add_device_to_filter_list, add_device_to_resolving_list, set_address_resolution_enable, set_privacy_mode,
        FilterListAddressType, PeerIdentityAddressType,
    };

    let peer_identity_info = keys.get_peer_identity().unwrap();

    let filter_list_address_type = if peer_identity_info.is_public() {
        FilterListAddressType::PublicDeviceAddress
    } else {
        FilterListAddressType::RandomDeviceAddress
    };

    let peer_identity_address_type = if peer_identity_info.is_public() {
        PeerIdentityAddressType::PublicIdentityAddress
    } else {
        PeerIdentityAddressType::RandomStaticIdentityAddress
    };

    let resolving_list_parameters = add_device_to_resolving_list::Parameter {
        peer_identity_address_type,
        peer_identity_address: peer_identity_info.get_address(),
        local_irk: keys.get_irk().unwrap(),
        peer_irk: keys.get_irk().unwrap(),
    };

    let privacy_mode_parameters = set_privacy_mode::Parameter {
        peer_identity_address_type,
        peer_identity_address: peer_identity_info.get_address(),
        privacy_mode: set_privacy_mode::PrivacyMode::NetworkPrivacy,
    };

    add_device_to_filter_list::send(host, filter_list_address_type, peer_identity_info.get_address())
        .await
        .unwrap();

    add_device_to_resolving_list::send(host, resolving_list_parameters)
        .await
        .unwrap();

    set_address_resolution_enable::send(host, true).await.unwrap();

    set_privacy_mode::send(host, privacy_mode_parameters).await.unwrap();
}

async fn reconnect<H: HostChannelEnds>(host: &mut Host<H>) -> bo_tie::hci::LeL2cap<H::ConnectionChannelEnds> {
    use bo_tie::hci::commands::le::{create_connection, OwnAddressType};
    use bo_tie::hci::events::{Events, LeMeta};
    use std::time::Duration;

    let create_connection_parameters = create_connection::ConnectionParameters::new_with_filter_list(
        Default::default(),
        Default::default(),
        OwnAddressType::RpaFromLocalIrkOrPublicAddress,
        TryFrom::try_from((Duration::from_millis(10), Duration::from_millis(40))).unwrap(),
        TryFrom::try_from(0).unwrap(),
        TryFrom::try_from(Duration::from_secs(5)).unwrap(),
        Default::default(),
    );

    host.mask_events([
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::DisconnectionComplete,
    ])
    .await
    .unwrap();

    create_connection::send(host, create_connection_parameters)
        .await
        .unwrap();

    match host.next().await.unwrap() {
        Next::NewConnection(connection) => connection.try_into_le().unwrap(),
        _ => unreachable!(),
    }
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

macro_rules! await_or_exit {
    ($host:expr, $connection:expr, $task:expr) => {
        loop {
            tokio::select! {
                next = $host.next() => {
                    if let bo_tie::hci::Next::Event(bo_tie::hci::events::EventsData::DisconnectionComplete(_)) = next.unwrap() {
                        return Err("peer device disconnected")
                    }
                }
                _ = io::exit_signal() => {
                    disconnect(&mut $host, $connection.get_handle()).await;

                    return Ok(())
                }
                ret = $task => break ret
            }
        }
    };
}

#[tokio::main]
async fn main() -> Result<(), &'static str> {
    println!(r#"press "ctrl" + "c" anytime to exit this example"#);

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

    let (interface, host_ends) = create_hci!();

    tokio::spawn(interface.run());

    let mut host = Host::init(host_ends).await.expect("failed to initialize host");

    println!("scanning for connectible devices with a complete local name");

    let mut responses = scan_for_devices(&mut host, io::on_advertising_result, io::detect_escape)
        .await
        .unwrap();

    if responses.is_empty() {
        return Err("no devices to connect to");
    }

    let report = if responses.len() == 1 {
        responses.remove(0)
    } else {
        let selected = io::select_device(1..=responses.len())
            .await
            .ok_or("exited by user")
            .unwrap();

        responses.remove(selected - 1)
    };

    println!("connecting to '{}'", report.1);

    let mut connection = tokio::select! {
        connection = connect(&mut host, &report.0) => connection,
        _ = io::exit_signal() => {
            cancel_connect(&mut host).await;

            return Ok(())
        }
    };

    println!("pairing and bonding with {}", report.1);

    let mut security_manager = bo_tie::host::sm::initiator::SecurityManagerBuilder::new(
        report.0.address,
        bo_tie::hci::commands::info_params::read_bd_addr::send(&mut host)
            .await
            .unwrap(),
        !report.0.address_type.is_public(),
        false,
    )
    .build();

    let long_term_key = await_or_exit!(host, connection, pair(&mut connection, &mut security_manager));

    println!("pairing completed");

    encrypt(&mut host, connection.get_handle(), long_term_key).await?;

    println!("encryption established");

    await_or_exit!(host, connection, bond(&mut connection, &mut security_manager));

    println!("bonding completed");

    setup_reconnect(&mut host, security_manager.get_keys().unwrap()).await;

    loop {
        host.mask_events([bo_tie::hci::events::Events::DisconnectionComplete])
            .await
            .unwrap();

        query_gatt_services(&mut connection).await;

        println!("press 'escape' to disconnect peripheral device");

        tokio::select! {
            _ = host.next() => {
                println!("peer device disconnected")
            },
            _ = io::exit_signal() => {
                disconnect(&mut host, connection.get_handle()).await;

                return Ok(())
            }
            _ = io::detect_escape() => (),
        }

        println!(
            "to reconnect, have the peripheral device perform directed \
            advertising for this device using private resolvable addresses"
        );

        tokio::select! {
            new_conneciton = reconnect(&mut host) => connection = new_conneciton,
            _ = io::exit_signal() => {
                cancel_connect(&mut host).await;

                return Ok(())
            }
        }
    }
}
