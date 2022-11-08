#![doc = include_str!("../README.md")]

mod io;

use bo_tie::hci::events::parameters::LeAdvertisingReportData;
use bo_tie::hci::{ConnectionHandle, Host, HostChannelEnds, LeL2cap, Next};

/// Scan for a device with the specific local name
///
/// This function will set the Bluetooth Controller into scanning mode and continue scanning until
/// it is stopped by the user with `stop`.
///
/// # Error
/// An error is returned if the future `stop` outputs false.
async fn scan_for_devices<H, C, F>(
    hi: &mut Host<H>,
    on_result: C,
    stop: F,
) -> Result<Vec<LeAdvertisingReportData>, &'static str>
where
    H: HostChannelEnds,
    C: Fn(usize, &str),
    F: std::future::Future<Output = bool>,
{
    use bo_tie::hci::commands::le::{set_scan_enable, set_scan_parameters};
    use bo_tie::hci::events::{Events, EventsData, LeMeta, LeMetaData};
    use bo_tie::host::gap::assigned::local_name::LocalName;

    let mut devices = Vec::new();

    let mut scan_prams = set_scan_parameters::ScanningParameters::default();

    scan_prams.scan_type = set_scan_parameters::LeScanType::PassiveScanning;
    scan_prams.scanning_filter_policy = set_scan_parameters::ScanningFilterPolicy::AcceptAll;

    hi.mask_events([Events::LeMeta(LeMeta::AdvertisingReport)])
        .await
        .unwrap();

    set_scan_parameters::send(hi, scan_prams).await.unwrap();

    set_scan_enable::send(hi, true, true).await.unwrap();

    let task = async {
        let mut count = 0;

        loop {
            if let Next::Event(EventsData::LeMeta(LeMetaData::AdvertisingReport(reports))) = hi.next().await.unwrap() {
                for report in reports.iter().filter_map(|rslt_report| rslt_report.as_ref().ok()) {
                    if let Some(name) = report
                        .iter()
                        .filter_map(|rslt| rslt.ok())
                        .find_map(|ad_struct| ad_struct.try_into::<LocalName<_, _>>().ok())
                    {
                        count += 1;

                        on_result(count, name.as_str());

                        devices.push(report.clone());
                    }
                }
            }
        }
    };

    let stop_status = tokio::select! {
        _ = task => unreachable!(),
        status = stop => status,
    };

    set_scan_enable::send(hi, false, false).await.unwrap();

    hi.mask_events(core::iter::empty::<Events>()).await.unwrap();

    return stop_status.then_some(devices).ok_or("exited by user");
}

/// Connect to the advertising device
async fn connect<H: HostChannelEnds>(
    hi: &mut Host<H>,
    report: LeAdvertisingReportData,
) -> LeL2cap<H::ConnectionChannelEnds> {
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
    hi.mask_events([
        Events::LeMeta(LeMeta::ConnectionComplete),
        Events::DisconnectionComplete,
    ])
    .await
    .unwrap();

    // create the connection
    create_connection::send(hi, connection_parameters).await.unwrap();

    if let Next::NewConnection(connection) = hi.next().await.unwrap() {
        // disable the LE Connection Complete event but keep Disconnection Complete enabled
        hi.mask_events([Events::DisconnectionComplete]).await.unwrap();

        connection.try_into_le().expect("failed to create connection")
    } else {
        unreachable!("no events except for Connection Complete are enabled")
    }
}

/// Cancel the connection
///
/// This will cancel the connection if there is a pending
async fn cancel_connect<H: HostChannelEnds>(hi: &mut Host<H>) -> bool {
    // cancel the connection
    //
    // If this command fails with 'command disallowed',
    // then there is no pending connection event, which
    // achieves the purpose of cancel_connect anyways.
    match bo_tie::hci::commands::le::create_connection_cancel::send(hi)
        .await
        .map_err(|e| e.try_into().unwrap())
    {
        Ok(_) => true,
        Err(bo_tie::Error::CommandDisallowed) => false,
        Err(e) => panic!("{}", e),
    }
}

/// Disconnect the peripheral device
async fn disconnect<H, C>(hi: &mut Host<H>, connection_handle: C)
where
    H: HostChannelEnds,
    C: Into<Option<ConnectionHandle>>,
{
    use bo_tie::hci::commands::link_control::disconnect;
    use bo_tie::hci::events::Events;

    let connection_handle = match connection_handle.into() {
        Some(handle) => handle,
        None => {
            if cancel_connect(hi).await {
                return;
            } else {
                if let Some(Next::NewConnection(connection)) = hi.try_next().await.unwrap() {
                    connection.get_handle()
                } else {
                    return;
                }
            }
        }
    };

    hi.mask_events(core::iter::empty::<Events>()).await.unwrap();

    let disconnection_parameters = disconnect::DisconnectParameters {
        connection_handle,
        disconnect_reason: disconnect::DisconnectReason::RemoteUserTerminatedConnection,
    };

    disconnect::send(hi, disconnection_parameters).await.unwrap();
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
async fn main() -> Result<(), &'static str> {
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

    let mut responses = scan_for_devices(&mut host, io::on_advertising_result, io::detect_escape()).await?;

    if responses.is_empty() {
        return Err("no devices to connect to");
    }

    let response = if responses.len() == 1 {
        responses.remove(0)
    } else {
        let selected = io::select_device(1..=responses.len()).await.ok_or("exited by user")?;

        responses.remove(selected - 1)
    };

    let connection_handle = tokio::select! {
        connection = connect(&mut host, response) => connection.get_handle(),
        _ = io::exit_signal() => {
            disconnect(&mut host, None).await;

            return Ok(())
        }
    };

    io::exit_signal().await;

    disconnect(&mut host, connection_handle).await;

    Ok(())
}
