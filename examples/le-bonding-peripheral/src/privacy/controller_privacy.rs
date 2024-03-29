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

        set_resolvable_private_address_timeout::send(host, std::time::Duration::from_secs(60 * 4))
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

    pub async fn set_timeout<H: HostChannelEnds>(host: &mut Host<H>, timeout: std::time::Duration) {
        bo_tie::hci::commands::le::set_resolvable_private_address_timeout::send(host, timeout)
            .await
            .unwrap();
    }

    /// Configure the advertising parameters for when the Bluetooth Controller generates resolvable
    /// private addresses.
    pub async fn set_advertising_parameters<H: HostChannelEnds>(&self, host: &mut Host<H>) {
        use bo_tie::hci::commands::le::{set_advertising_parameters, OwnAddressType};

        let mut adv_prams = set_advertising_parameters::AdvertisingParameters::default();

        adv_prams.advertising_type =
            set_advertising_parameters::AdvertisingType::ConnectableAndScannableUndirectedAdvertising;

        // This is directed advertising with a resolvable private
        // address so the peer identity address is needed.
        adv_prams.peer_address = self.peer_identity.unwrap().get_address();

        adv_prams.peer_address_type = if self.peer_identity.unwrap().is_public() {
            set_advertising_parameters::PeerAddressType::PublicAddress
        } else {
            set_advertising_parameters::PeerAddressType::RandomAddress
        };

        // this is the key for advertising with a resolvable private address
        adv_prams.own_address_type = OwnAddressType::RpaFromLocalIrkOrRandomAddress;

        set_advertising_parameters::send(host, adv_prams).await.unwrap();
    }
}
