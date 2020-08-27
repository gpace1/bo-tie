extern crate bo_tie;

use bo_tie::hci;
use bo_tie::hci::events::EventsData;
use std::time::Duration;

fn is_desired_device<T> (expcted: T, to_compare: T ) -> bool where T: PartialEq + ::std::fmt::Display {
    if expcted == to_compare {
        println!("Found the device");
        true
    }
    else {
        println!(r#"Found a device with local name "{}", expected "{}""#, to_compare, expcted);
        false
    }
}

async fn remove_from_white_list(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    address: bo_tie::BluetoothDeviceAddress)
{
    use bo_tie::hci::le::mandatory::remove_device_from_white_list::send;
    use bo_tie::hci::le::common::AddressType::RandomDeviceAddress;

    send(&hi, RandomDeviceAddress, address).await.unwrap();
}

async fn scan_for_local_name<'a>(
    hi: &'a hci::HostInterface<bo_tie_linux::HCIAdapter>,
    name: &'a str )
    -> Option<Box<::bo_tie::hci::events::LEAdvertisingReportData>>
{
    use bo_tie::gap::advertise::{local_name, TryFromRaw};
    use bo_tie::hci::events::{Events, LEMeta, LEMetaData};
    use bo_tie::hci::le::mandatory::set_event_mask;
    use bo_tie::hci::le::receiver::{ set_scan_parameters, set_scan_enable };

    let mut scan_prms = set_scan_parameters::ScanningParameters::default();

    scan_prms.scan_type = set_scan_parameters::LEScanType::PassiveScanning;
    scan_prms.scanning_filter_policy = set_scan_parameters::ScanningFilterPolicy::AcceptAll;

    let le_event = LEMeta::AdvertisingReport;

    set_scan_enable::send(&hi, false, false).await.unwrap();

    set_event_mask::send(&hi, &[le_event]).await.unwrap();

    set_scan_parameters::send(&hi, scan_prms).await.unwrap();

    set_scan_enable::send(&hi, true, true).await.unwrap();

    let awaited_event = Some(Events::from(le_event));

    // This will stop 15 seconds after the last advertising packet is received
    while let Ok(event) = hi.wait_for_event( awaited_event).await
    {
        if let EventsData::LEMeta(LEMetaData::AdvertisingReport(reports)) = event {
            for report_result in reports.iter() {
                match report_result {
                    Ok(report) => {
                        for data_rsl in report.data_iter() {
                            if let Ok(local_name) = local_name::LocalName::try_from_raw(data_rsl.unwrap())
                            {
                                if is_desired_device( name, local_name.as_ref()) {
                                    set_scan_enable::send(&hi, false, false).await.unwrap();
                                    return Some(Box::new(report.clone()));
                                }
                            }
                        }
                    },
                    Err(err_msg) => println!("Bad advertising data: {}", err_msg),
                }
            }
        }
    }

    set_scan_enable::send(&hi, false, false).await.unwrap();
    println!("Couldn't find the device");

    None
}

async fn connect(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    address: bo_tie::BluetoothDeviceAddress)
    -> Result<EventsData, impl std::fmt::Debug>
{
    use bo_tie::hci::common;
    use bo_tie::hci::events::{Events, LEMeta};
    use bo_tie::hci::le::common::{OwnAddressType, ConnectionEventLength};
    use bo_tie::hci::le::connection;
    use bo_tie::hci::le::connection::create_connection;
    use bo_tie::hci::le::mandatory::set_event_mask;

    let connect_event = LEMeta::ConnectionComplete;

    let min_connection_interval = Duration::from_millis(10);
    let max_connection_interval = Duration::from_millis(40);
    let slave_latency = 0;
    let supervision_timeout = Duration::from_secs(5);

    let parameters = create_connection::ConnectionParameters::new_without_whitelist(
        create_connection::ScanningInterval::default(),
        create_connection::ScanningWindow::default(),
        common::LEAddressType::RandomDeviceAddress,
        address,
        OwnAddressType::default(),
        connection::ConnectionIntervalBounds::try_from(
            connection::ConnectionInterval::try_from_duration(min_connection_interval).unwrap(),
            connection::ConnectionInterval::try_from_duration(max_connection_interval).unwrap(),
        ).unwrap(),
        common::ConnectionLatency::try_from(slave_latency).unwrap(),
        common::SupervisionTimeout::try_from_duration(supervision_timeout).unwrap(),
        ConnectionEventLength::default(),
    );

    // enable the LEConnectionComplete event
    set_event_mask::send(&hi, &[connect_event]).await.unwrap();

    // create the connection
    create_connection::send(&hi, parameters).await.unwrap();

    let awaited_event = Some(Events::from(connect_event));

    // wait for the LEConnectionUpdate event
    hi.wait_for_event(awaited_event).await
}

async fn cancel_connect(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter> ) {
    use bo_tie::hci::le::connection::create_connection_cancel;

    create_connection_cancel::send(&hi).await.unwrap();
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

    disconnect::send(&hi, prams).await.unwrap();
}

fn main() {
    use std::io::stdin;
    use std::io::BufRead;
    use bo_tie::hci::events::{LEMetaData};
    use futures::executor;

    let host_interface = hci::HostInterface::default();

    let mut name = String::new();

    println!("Enter local name of device to connect to");

    let stdin = stdin();

    stdin.lock().read_line(&mut name).expect("Couldn't read input from terminal");

    name = name.trim().to_string();

    // executor::block_on(scan_for_local_name(&host_interface, &name));

    if let Some(adv_report) = executor::block_on(scan_for_local_name(&host_interface, &name)) {
        let address = adv_report.address;

        // Since the example uses `new_whithout_whitelist` (in function `connect`) it needs to be
        // removed from the whitelist in case it is already in the whitelist
        executor::block_on(remove_from_white_list(&host_interface, address));

        match executor::block_on(connect(&host_interface, address)) {
            Ok(EventsData::LEMeta(LEMetaData::ConnectionComplete(data))) =>  {

                println!("Connected! ... waiting 5 seconds then disconnecting");

                ::std::thread::sleep(::std::time::Duration::from_secs(5));

                executor::block_on(disconnect(&host_interface, data.connection_handle));

                // its weird to remove the device from the white list here, but because this is an example
                // and you're probably connecting with some tests device you don't probably want this
                // device in your whitelist.
                executor::block_on(remove_from_white_list(&host_interface, address));
            }
            Err(e) => {
                executor::block_on(cancel_connect(&host_interface));
                println!("Couldn't connect: {:?}", e);
            }
            Ok(_) => println!("Any other event should never be returned"),
        }
    }
}
