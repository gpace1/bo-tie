//! Privacy in the Bluetooth Controller

use bo_tie::hci::{Host, HostChannelEnds};
use bo_tie::host::sm::{IdentityAddress, Keys};

pub struct Controller {
    peer_identity: Option<IdentityAddress>,
}

impl Controller {
    pub fn new() -> Self {
        let peer_identity = None;

        Controller { peer_identity }
    }

    /// Add a device to the resolving list when using the Bluetooth Controller for privacy
    pub async fn add_device_resolving_list<H: HostChannelEnds>(&mut self, host: &mut Host<H>, keys: &Keys) {
        use bo_tie::hci::commands::le::{
            add_device_to_resolving_list, set_address_resolution_enable, set_privacy_mode,
            set_resolvable_private_address_timeout, PeerIdentityAddressType,
        };

        self.peer_identity = keys.get_peer_identity();

        let peer_identity_address_type = if keys.get_peer_identity().unwrap().is_public() {
            PeerIdentityAddressType::PublicIdentityAddress
        } else {
            PeerIdentityAddressType::RandomStaticIdentityAddress
        };

        let peer_identity_address = self.peer_identity.unwrap().get_address();

        let peer_irk = keys.get_peer_irk().unwrap();

        let local_irk = keys.get_irk().unwrap();

        let parameter = add_device_to_resolving_list::Parameter {
            peer_identity_address_type,
            peer_identity_address,
            peer_irk,
            local_irk,
        };

        add_device_to_resolving_list::send(host, parameter).await.unwrap();

        let privacy_mode = set_privacy_mode::PrivacyMode::NetworkPrivacy;

        let parameter = set_privacy_mode::Parameter {
            peer_identity_address_type,
            peer_identity_address,
            privacy_mode,
        };

        // This is a 5.0+ command so it may not be available.
        // That is fine as 4.2 only supports the equivalent
        // of `NetworkPrivacy`.
        set_privacy_mode::send(host, parameter).await.ok();

        set_resolvable_private_address_timeout::send(host, std::time::Duration::from_secs(900))
            .await
            .unwrap();

        set_address_resolution_enable::send(host, true).await.unwrap();
    }

    /// Clear the resolving list on the Controller
    pub async fn clear_resolving_list<H: HostChannelEnds>(host: &mut Host<H>) {
        bo_tie::hci::commands::le::clear_resolving_list::send(host)
            .await
            .unwrap()
    }

    pub async fn reconnect<H: HostChannelEnds>(
        host: &mut Host<H>,
    ) -> bo_tie::hci::Connection<H::ConnectionChannelEnds> {
        use bo_tie::hci::commands::le::create_connection::{self, ScanningInterval, ScanningWindow};
        use bo_tie::hci::commands::le::{
            ConnectionEventLength, ConnectionIntervalBounds, ConnectionLatency, OwnAddressType, SupervisionTimeout,
        };
        use bo_tie::hci::events::{Events, LeMeta};
        use bo_tie::hci::Next;
        use std::time::Duration;

        // The only important thing here is that the own
        // address is `RpaFromLocalIrkOrRandomAddress`,
        // everything else can be customized to fit your
        // needs if you want to recycle this example.

        let parameters = create_connection::ConnectionParameters::new_with_filter_list(
            ScanningInterval::default(),
            ScanningWindow::default(),
            OwnAddressType::RpaFromLocalIrkOrRandomAddress,
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
