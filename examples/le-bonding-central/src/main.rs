#![doc = include_str!("../README.md")]

mod io;
mod privacy;

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
    let connection_parameters = create_connection::ConnectionParameters::new_without_filter_list(
        create_connection::ScanningInterval::default(),
        create_connection::ScanningWindow::default(),
        report.address_type,
        report.address,
        Default::default(),
        TryFrom::try_from((Duration::from_millis(10), Duration::from_millis(40))).unwrap(),
        TryFrom::try_from(1).unwrap(),
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

    host.mask_events([Events::DisconnectionComplete]).await.unwrap();

    let disconnection_parameters = disconnect::DisconnectParameters {
        connection_handle,
        disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(host, disconnection_parameters).await.unwrap();

    // Await for the disconnection complete event
    host.next().await.unwrap();
}

/// Pair with a connected device
async fn pair<C>(connection_channel: &mut C, sm: &mut bo_tie::host::sm::initiator::SecurityManager) -> Option<u128>
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
                            break 'outer sm.get_keys().unwrap().get_ltk().unwrap().into()
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
                            return None;
                        },
                        _ => (),
                    }
                }
            },

            user_auth = io::user_authentication_input(&number_comparison, &passkey_input) => {
                match user_auth {
                    io::UserAuthentication::NumberComparison(is_accepted) => if is_accepted {
                        number_comparison.take().unwrap().yes(sm, connection_channel).await.unwrap();
                    } else {
                        number_comparison.take().unwrap().no(sm, connection_channel).await.unwrap();
                    },
                    io::UserAuthentication::PasskeyInput(passkey) =>if let Some(input) = io::process_passkey(passkey) {
                passkey_input.as_mut().unwrap().write(input).unwrap();

                passkey_input.take().unwrap().complete(sm, connection_channel).await.unwrap();
            } else {
                passkey_input.take().unwrap().fail(sm, connection_channel).await.unwrap();
            },
                    io::UserAuthentication::Exit => break None,
                }
            }
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

    host.mask_events([Events::DisconnectionComplete, Events::EncryptionChangeV1])
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
            EventsData::DisconnectionComplete(_) => {
                return Err("peer device disconnected".into());
            }
            e => unreachable!("unexpected event: {:?}", e),
        },
        _ => unreachable!(),
    };

    Ok(())
}

/// Bond with a paired device
///
/// # Note
/// This must be called after method `encrypt`
async fn bond<C>(connection_channel: &mut C, sm: &mut bo_tie::host::sm::initiator::SecurityManager) -> Option<()>
where
    C: bo_tie::host::l2cap::ConnectionChannel,
{
    use bo_tie::host::l2cap::ConnectionChannelExt;

    sm.set_encrypted(true);

    'outer: loop {
        for basic_frame in connection_channel.receive_b_frame().await.unwrap() {
            // All data that is not Security Manager related is ignored for this example
            if basic_frame.get_channel_id() == bo_tie::host::sm::L2CAP_CHANNEL_ID {
                if sm.process_bonding(connection_channel, &basic_frame).await.unwrap() {
                    // once the peripheral has sent its bonding
                    // information then this bonding information
                    // is sent to the device.
                    break 'outer Some(());
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
async fn setup_reconnect<H: HostChannelEnds>(
    host: &mut Host<H>,
    privacy: &mut privacy::Privacy,
    keys: &bo_tie::host::sm::Keys,
) {
    privacy.clear_resolving_list(host).await;

    privacy.add_device_to_resolving_list(host, keys).await;
}

async fn reconnect<H: HostChannelEnds>(
    host: &mut Host<H>,
    privacy: &mut privacy::Privacy,
) -> bo_tie::hci::LeL2cap<H::ConnectionChannelEnds> {
    let connection = privacy.reconnect(host).await;

    connection.try_into_le().unwrap()
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

macro_rules! await_or_disconnect {
    ($host:expr, $connection:expr, $task:expr) => {
        loop {
            tokio::select! {
                next = $host.next() => {
                    if let bo_tie::hci::Next::Event(bo_tie::hci::events::EventsData::DisconnectionComplete(_)) = next.unwrap() {
                        return Err("peer device disconnected")
                    }
                }

                ret = $task => match ret {
                    None => {
                        disconnect(&mut $host, $connection.get_handle()).await;

                        return Ok(());
                    }
                    Some(val) => break val,
                },
            }
        }
    };
}

macro_rules! await_or_exit {
    ($host:expr, $connection:expr, $task:expr) => {
        loop {
            tokio::select! {
                ret = $task => match ret {
                    Err(e) => {
                        disconnect(&mut $host, $connection.get_handle()).await;

                        return Err(e);
                    }
                    Ok(val) => break val,
                },

                _ = io::exit_signal() => {
                    disconnect(&mut $host, $connection.get_handle()).await;

                    return Ok(())
                }
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
    println!("press enter to stop scanning");

    let mut responses = scan_for_devices(&mut host, io::on_advertising_result, io::detect_enter)
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

    let this_address = bo_tie::hci::commands::info_params::read_bd_addr::send(&mut host)
        .await
        .unwrap();

    let mut security_manager = bo_tie::host::sm::initiator::SecurityManagerBuilder::new(
        report.0.address,
        this_address,
        !report.0.address_type.is_public(),
        false,
    )
    .distributed_bonding_keys(|sent| sent.enable_id())
    .accepted_bonding_keys(|accepted| accepted.enable_id())
    .enable_number_comparison()
    .build();

    let long_term_key = await_or_disconnect!(host, connection, pair(&mut connection, &mut security_manager));

    println!("pairing completed");

    await_or_exit!(
        host,
        connection,
        encrypt(&mut host, connection.get_handle(), long_term_key)
    );

    println!("encryption established");

    await_or_disconnect!(host, connection, bond(&mut connection, &mut security_manager));

    println!("bonding completed");

    let mut privacy = privacy::Privacy::new(&mut host).await;

    setup_reconnect(&mut host, &mut privacy, security_manager.get_keys().unwrap()).await;

    loop {
        host.mask_events([bo_tie::hci::events::Events::DisconnectionComplete])
            .await
            .unwrap();

        query_gatt_services(&mut connection).await;

        println!("press 'enter' to disconnect peripheral device and reconnect using 'privacy'");

        tokio::select! {
            _ = host.next() => {
                println!("peer device disconnected")
            },
            is_enter = io::detect_enter() => if is_enter {
                disconnect(&mut host, connection.get_handle()).await;
            } else { // this branch is ctrl-c
                disconnect(&mut host, connection.get_handle()).await;

                return Ok(())
            }
        }

        println!(
            "to reconnect, have the peripheral device perform directed \
            advertising for this device using private resolvable addresses"
        );

        tokio::select! {
            new_conneciton = reconnect(&mut host, &mut privacy) => connection = new_conneciton,
            _ = io::exit_signal() => {
                cancel_connect(&mut host).await;

                return Ok(())
            }
        }

        println!("reconnected");
    }
}
