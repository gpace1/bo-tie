use std::time::Duration;
use bo_tie::hci;

async fn start_scanning(hi: &hci::HostInterface<bo_tie_linux::HCIAdapter>) {
    use bo_tie::hci::le::receiver::{set_scan_parameters,set_scan_enable};
    bo_tie::hci::le::common::OwnAddressType;

    set_scan_enable::send(hi, false, false).await.unwrap();

    set_scan_parameters::send(hi, set_scan_parameters::ScanningParameters::default()).await.unwrap()


}