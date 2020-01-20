use std::time::Duration;
use bo_tie::hci;

/// Scan for a specific address
async fn start_scanning_for_addr(
    hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>,
    addr: &bo_tie::BluetoothDeviceAddress,
) {
    use bo_tie::hci::cb::set_event_mask::{self,EventMask};
    use bo_tie::hci::events::{LEMeta, EventsData, LEMetaData};
    use bo_tie::hci::le::receiver::{set_scan_parameters,set_scan_enable};
    use bo_tie::hci::le::mandatory::set_event_mask as le_set_event_mask;
    use bo_tie::hci::events::LEEventType;

    set_scan_enable::send(hi, false, false).await.unwrap();

    set_event_mask::send(hi, &[EventMask::DisconnectionComplete, EventMask::LEMeta]).await.unwrap();

    set_event_mask::send(hi, &[LEMeta::AdvertisingReport]).await.unwrap();

    set_scan_parameters::send(hi, set_scan_parameters::ScanningParameters::default()).await.unwrap();

    set_scan_enable::send(hi, true, true).await.unwrap();

    let report_data = loop {
        match hi.wait_for_event(LEMeta::AdvertisingReport.into(), None).await.unwrap() {
            EventsData::LEMeta(LEMetaData::AdvertisingReport(reports)) => for report in reports {
                if report.
            },
            e => panic!("Received unexpected event data: {:?}", e),
        }
    };
}