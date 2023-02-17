//! Privacy implemented by the Host
//!
//! When the Bluetooth Controller does not support the feature *LL Privacy*, the host must implement
//! the feature in order to support privacy.

use bo_tie::hci::{Connection, Host, HostChannelEnds};
use bo_tie::host::sm::{IdentityAddress, Keys};
use bo_tie::BluetoothDeviceAddress;

#[derive(Copy, Clone, PartialEq)]
struct ResolvingInformation {
    // this flag is used to skip this information if the device is already connected
    connected: bool,
    peer_identity: IdentityAddress,
    peer_irk: u128,
}

pub struct HostPrivacy {
    // This is a list sorted by the peer identity
    resolving_list: Vec<ResolvingInformation>,
}

impl HostPrivacy {
    /// The maximum number of entries within the resolving list
    ///
    /// This example uses `None` as there is no limit, but for a more practical use case this should
    /// be set to some value (if you want to re-use this code).
    const MAX_COUNT: Option<usize> = None;

    pub fn new() -> Self {
        let resolving_list = Vec::new();

        HostPrivacy { resolving_list }
    }

    fn set_connected(&mut self, peer_identity: &IdentityAddress, is_connected: bool) {
        let index = self
            .resolving_list
            .binary_search_by(|entry| entry.peer_identity.cmp(&peer_identity))
            .expect("no information found for peer identity");

        self.resolving_list[index].connected = is_connected
    }

    /// Add to the hosts resolving list
    pub fn add_to_resolving_list(&mut self, keys: &Keys) {
        let peer_identity = keys.get_peer_identity().unwrap();
        let peer_irk = keys.get_peer_irk().unwrap();

        match self
            .resolving_list
            .binary_search_by(|entry| entry.peer_identity.cmp(&peer_identity))
        {
            Err(index) => {
                let resolve_info = ResolvingInformation {
                    connected: false,
                    peer_identity,
                    peer_irk,
                };

                self.resolving_list.insert(index, resolve_info);
            }
            Ok(index) => {
                let entry = &mut self.resolving_list[index];

                entry.peer_identity = peer_identity;
                entry.peer_irk = peer_irk;
            }
        }
    }

    /// Clear the resolving list information in the Host
    pub fn clear_resolving_list(&mut self) {
        self.resolving_list.clear();
    }

    pub fn set_timeout(&mut self, timeout: std::time::Duration) -> RpaInterval {
        RpaInterval {
            interval: tokio::time::interval_at(tokio::time::Instant::now() + timeout, timeout),
        }
    }

    /// Configure advertising when the host is performing Privacy
    pub async fn start_private_advertising<H: HostChannelEnds>(&mut self, host: &mut Host<H>) {
        set_advertising_parameters_private(host).await
    }

    /// Validate the Connection
    ///
    /// The connecting device must have a valid resolvable private address. Because the Controller
    /// does not perform private address resolving, any device can form a connection to this device
    /// in the controller.
    pub fn validate_connection<C>(&mut self, connection: &Connection<C>) -> Option<IdentityAddress> {
        for info in self.resolving_list.iter_mut() {
            if info.connected {
                continue;
            }

            if connection.get_peer_address().resolve(info.peer_irk) {
                info.connected = true;

                return Some(info.peer_identity);
            }
        }

        None
    }

    pub fn disconnect(&mut self, identity: IdentityAddress) {
        if let Ok(index) = self
            .resolving_list
            .binary_search_by(|entry| entry.peer_identity.cmp(&identity))
        {
            self.resolving_list[index].connected = false
        }
    }
}

async fn set_advertising_parameters_private<H: HostChannelEnds>(host: &mut Host<H>) {
    use bo_tie::hci::commands::le::{
        set_advertising_data, set_advertising_parameters, set_random_address, set_scan_response_data, OwnAddressType,
    };

    let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

    let own_address = BluetoothDeviceAddress::new_resolvable(crate::security::KeysStore::IRK);

    adv_prams.advertising_type =
        set_advertising_parameters::AdvertisingType::ConnectableAndScannableUndirectedAdvertising;

    adv_prams.peer_address_type = set_advertising_parameters::PeerAddressType::RandomAddress;

    adv_prams.own_address_type = OwnAddressType::RandomDeviceAddress;

    bo_tie::hci::commands::le::set_advertising_enable::send(host, false)
        .await
        .ok();

    set_advertising_data::send(host, None).await.unwrap();

    set_scan_response_data::send(host, None).await.unwrap();

    set_random_address::send(host, own_address).await.unwrap();

    set_advertising_parameters::send(host, adv_prams).await.unwrap();

    bo_tie::hci::commands::le::set_advertising_enable::send(host, true)
        .await
        .unwrap();
}

pub struct RpaInterval {
    interval: tokio::time::Interval,
}

impl RpaInterval {
    pub async fn tick(&mut self) -> RegenRpa {
        self.interval.tick().await;

        RegenRpa
    }
}

pub struct RegenRpa;

impl RegenRpa {
    pub async fn regen<H: HostChannelEnds>(self, host: &mut Host<H>) {
        set_advertising_parameters_private(host).await;
    }
}
