//! Privacy implemented by the Host
//!
//! When the Bluetooth Controller does not support the feature *LL Privacy*, the host must implement
//! the feature in order to support privacy.

use bo_tie::hci::{Connection, Host, HostChannelEnds};
use bo_tie::host::sm::{IdentityAddress, Keys};
use bo_tie::BluetoothDeviceAddress;

#[derive(Copy, Clone, PartialEq)]
struct ResolvingInformation {
    identity: IdentityAddress,
    peer_identity: IdentityAddress,
    irk: u128,
    peer_irk: u128,
}

pub struct HostPrivacy {
    // for simplicity this list consists of only one entry
    resolving_list: Option<ResolvingInformation>,
}

impl HostPrivacy {
    pub fn new() -> Self {
        let resolving_list = None;

        HostPrivacy { resolving_list }
    }

    /// Add to the hosts resolving list
    pub fn add_to_resolving_list(&mut self, keys: &Keys) {
        let identity = keys.get_identity().unwrap();
        let irk = keys.get_irk().unwrap();
        let peer_identity = keys.get_peer_identity().unwrap();
        let peer_irk = keys.get_peer_irk().unwrap();

        let resolve_info = ResolvingInformation {
            identity,
            peer_identity,
            irk,
            peer_irk,
        };

        self.resolving_list = Some(resolve_info);
    }

    /// Clear the resolving list information in the Host
    pub fn clear_resolving_list(&mut self) {
        self.resolving_list = None;
    }

    /// Check a Advertising Report
    ///
    /// This checks if the report contains an advertising address that is resolvable. If this report
    /// is for a directed advertising, then the target address is also verified.
    pub fn rpa_check_report(&self, report: &bo_tie::hci::events::parameters::LeAdvertisingReportData) -> bool {
        let info = self.resolving_list.unwrap();

        report.address.resolve(info.peer_irk)
    }

    async fn scan_for_rpa<H: HostChannelEnds>(
        &self,
        host: &mut Host<H>,
    ) -> bo_tie::hci::events::parameters::LeAdvertisingReportData {
        use bo_tie::hci::commands::le::{set_scan_enable, set_scan_parameters};
        use bo_tie::hci::events::{Events, EventsData, LeMeta, LeMetaData};
        use bo_tie::hci::Next;

        let mut scan_prams = set_scan_parameters::ScanningParameters::default();

        scan_prams.scan_type = set_scan_parameters::LeScanType::PassiveScanning;
        scan_prams.scanning_filter_policy = set_scan_parameters::ScanningFilterPolicy::AcceptAll;

        host.mask_events([Events::LeMeta(LeMeta::AdvertisingReport)])
            .await
            .unwrap();

        set_scan_parameters::send(host, scan_prams).await.unwrap();

        set_scan_enable::send(host, true, true).await.unwrap();

        let report = 'report: loop {
            match host.next().await.unwrap() {
                Next::Event(EventsData::LeMeta(LeMetaData::AdvertisingReport(reports))) => {
                    for report_result in reports {
                        let report = report_result.unwrap();

                        if self.rpa_check_report(&report) {
                            break 'report report;
                        }
                    }
                }
                _ => (),
            }
        };

        set_scan_enable::send(host, false, false).await.unwrap();

        report
    }

    pub async fn reconnect<H: HostChannelEnds>(&self, host: &mut Host<H>) -> Connection<H::ConnectionChannelEnds> {
        use bo_tie::hci::commands::le::create_connection::{
            self, ConnectionParameters, ScanningInterval, ScanningWindow,
        };
        use bo_tie::hci::commands::le::set_random_address;
        use bo_tie::hci::commands::le::{
            ConnectionEventLength, ConnectionIntervalBounds, ConnectionLatency, OwnAddressType, SupervisionTimeout,
        };
        use bo_tie::hci::events::{Events, LeMeta};
        use bo_tie::hci::Next;
        use std::time::Duration;

        let random_address = BluetoothDeviceAddress::new_resolvable(self.resolving_list.as_ref().unwrap().irk);

        set_random_address::send(host, random_address).await.unwrap();

        let report = self.scan_for_rpa(host).await;

        let parameters = ConnectionParameters::new_without_whitelist(
            ScanningInterval::default(),
            ScanningWindow::default(),
            report.address_type,
            report.address,
            OwnAddressType::RandomDeviceAddress,
            ConnectionIntervalBounds::try_from_bounds(Duration::from_millis(100), Duration::from_secs(200)).unwrap(),
            ConnectionLatency::try_from(10).unwrap(),
            SupervisionTimeout::try_from(Duration::from_secs(5)).unwrap(),
            ConnectionEventLength::new(0, 10),
        );

        host.mask_events([Events::LeMeta(LeMeta::ConnectionComplete)])
            .await
            .unwrap();

        create_connection::send(host, parameters).await.unwrap();

        match host.next().await.unwrap() {
            Next::NewConnection(connection) => connection,
            _ => unreachable!(),
        }
    }
}
