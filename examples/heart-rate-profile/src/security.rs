//! Security Setup for the heart-rate-profile example
//!
//! This implementation of a heart-rate-profile will not allow for access to heart rate data without
//! first establishing an authentication, encrypted connection. Since this example uses Bluetooth LE,
//! encryption and authentication is set up between the two devices using the Security Manager
//! protocol. The example must use a responding [`SecurityManager`] in order to process Security
//! Manager protocol commands from the client. Furthermore bonding is used to distribute the
//! identification and signing keys.
//!
//! ## `SecurityManager` Setup
//! The `SecurityManager` is built using a [`SecurityMangerBuilder`] which is used to configure how
//! the Security Manager is to operate. The builder is used for setting up how the `SecurityManager`
//! both pairs and bonds to a client device. For pairing, this example requires that a client be
//! authenticated before it can configure the server, and for bonding this example will use ID keys
//! and a signing key.
//!
//! #### Authentication
//! The builder is configured to disable 'just works'. Any other form of pairing is fine, but 'just
//! works' provides no man-in-the-middle protection so it cannot be used to authenticate a client.
//! This is easily done by calling the method [`disable_just_works`] and then calling one or more
//! methods to enable a different pairing method. This example uses a terminal so it supports both
//! number comparison and passkey entry, which are enabled with the methods
//! [`enable_number_comparison`] and [`enable_passkey`], respectively.
//!
//! #### Bonding Keys
//! The default configuration of a `SecurityManager` is to not support any key distributions between
//! the the initiating and responding (a.k.a the central and peripheral) devices. The method
//! [`distributed_bonding_keys`] is used to configure what keys are sent from this device as part of
//! bonding, and the method [`accepted_bonding_keys`] are the keys that this `SecurityManager` can
//! accept from the initiating `SecurityManager`. Do note, these methods do not ensure that these
//! keys are distributed, the initiating device also has a list of keys distributed and accepted.
//! The actual list of keys sent between the two devices is an intersection of the keys supported by
//! the initiating and responding Security Managers. This is something that should be noted when
//! choosing a device to connect with the device running this example.
//!
//! The example is configured to distribute and accept a Identity Resolving Key (IRK) and an
//! Identity address. These are used to support 'privacy' between the two previously connected
//! devices. The IRK exchange allows for both devices to reconnect with authentication. This works
//! by the devices using resolvable private addresses in both the advertising and connection
//! indication packets that can be resolved to prove the identification of each device.
//!
//! [`SecurityManager`]: SecurityManager
//! [`SecurityManagerBuilder`]: SecurityManagerBuilder
//! [`disable_just_works`]: SecurityManagerBuilder::disable_just_works
//! [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
//! [`enable_passkey`]: SecurityManagerBuilder::enable_passkey
//! [`distributed_bonding_keys`]: SecurityManagerBuilder::distributed_bonding_keys
//! [`accepted_bonding_keys`]: SecurityManagerBuilder::accepted_bonding_keys

use crate::AuthenticationInput;
use bo_tie::host::l2cap::pdu::BasicFrame;
use bo_tie::host::l2cap::{BasicFrameChannel, LogicalLink};
use bo_tie::host::sm::pairing::{PairingFailed, PairingFailedReason};
use bo_tie::host::sm::responder::{NumberComparison, PasskeyInput, SecurityManager, SecurityManagerBuilder, Status};
use bo_tie::host::sm::{IdentityAddress, Keys};
use bo_tie::BluetoothDeviceAddress;
use std::sync::Arc;
use tokio::sync::Mutex;

#[derive(serde::Serialize, serde::Deserialize)]
pub struct BondedDeviceInfo {
    keys: Keys,
    notifications_enabled: bool,
}

impl BondedDeviceInfo {
    pub fn get_keys(&self) -> &Keys {
        &self.keys
    }

    pub fn is_notification_enabled(&self) -> bool {
        self.notifications_enabled
    }

    pub fn set_notification_enabled(&mut self, is_enabled: bool) {
        self.notifications_enabled = is_enabled
    }
}

impl std::ops::Deref for BondedDeviceInfo {
    type Target = Keys;

    fn deref(&self) -> &Self::Target {
        &self.keys
    }
}

impl std::ops::DerefMut for BondedDeviceInfo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.keys
    }
}

/// Type for Storing the Security Manager Keys
#[derive(Clone)]
pub struct Store(Arc<Mutex<Vec<BondedDeviceInfo>>>);

impl Store {
    /// This uses a single IRK for all devices that connect to it. This is not necessary to do, and
    /// unique IRK's could be distributed to each connected device instead of using a singular IRK.
    pub const IRK: u128 = 0x1e0777f16bc56c4eb20065118adae9bf;

    /// The identity address for a device should always be constant. This helps the peer devices
    /// to *update* security information (instead of creating a new entry) if bonding or pairing
    /// reoccurs.
    pub const IDENTITY: IdentityAddress =
        IdentityAddress::StaticRandom(BluetoothDeviceAddress([0x83, 0xfd, 0x5d, 0x9f, 0x35, 0xdb]));

    const FILE_NAME: &'static str = "heart-rate-profile.keys";

    const DIR_NAME: &'static str = "bo-tie_hart-rate-profile_example";

    /// Initialize a `KeyStore`
    ///
    /// This should only be called when `load_keys` returns false.
    pub fn init() -> Self {
        Store(Default::default())
    }

    /// Load keys from 'heart-rate-profile.key' in the config dir
    pub fn load_keys() -> Option<Self> {
        let mut config_dir_path = dirs::config_dir().unwrap();

        config_dir_path.push(Self::DIR_NAME);
        config_dir_path.push(Self::FILE_NAME);

        if let Ok(file) = std::fs::File::open(config_dir_path) {
            let info: Vec<BondedDeviceInfo> = serde_yaml::from_reader(file).unwrap();

            Some(Store(Arc::new(Mutex::new(info))))
        } else {
            None
        }
    }

    /// Save keys to the file 'heart-rate-profile.key' in the config dir
    pub async fn save_keys(&self) {
        let mut config_dir_path = dirs::config_dir().unwrap();

        config_dir_path.push(Self::DIR_NAME);

        if !config_dir_path.exists() {
            std::fs::create_dir_all(config_dir_path.clone()).unwrap();
        }

        config_dir_path.push(Self::FILE_NAME);

        let file = std::fs::File::create(config_dir_path).unwrap();

        serde_yaml::to_writer(file, &*self.0.lock().await).unwrap();
    }

    pub async fn add(&mut self, keys: Keys) {
        let mut guard = self.0.lock().await;

        match guard.binary_search_by(|entry| entry.keys.cmp(&keys)) {
            Ok(index) => {
                *guard.get_mut(index).unwrap() = BondedDeviceInfo {
                    keys,
                    notifications_enabled: false,
                };
            }
            Err(index) => {
                guard.insert(
                    index,
                    BondedDeviceInfo {
                        keys,
                        notifications_enabled: false,
                    },
                );
            }
        }
    }

    pub async fn get(&self, peer: IdentityAddress) -> Option<tokio::sync::MappedMutexGuard<'_, BondedDeviceInfo>> {
        let guard = self.0.lock().await;

        let index = guard
            .binary_search_by(|entry| entry.keys.get_peer_identity().cmp(&Some(peer)))
            .ok()?;

        tokio::sync::MutexGuard::map(guard, |entries| &mut entries[index]).into()
    }

    pub async fn get_all_keys(&self) -> tokio::sync::MutexGuard<'_, Vec<impl std::ops::DerefMut<Target = Keys>>> {
        self.0.lock().await
    }

    pub async fn clear_all_keys(&self) {
        self.0.lock().await.clear()
    }

    pub async fn delete_key(&self, identity: IdentityAddress) -> bool {
        let mut guard = self.0.lock().await;

        guard
            .binary_search_by(|entry| entry.keys.get_peer_identity().cmp(&Some(identity)))
            .map(|index| guard.remove(index))
            .is_ok()
    }

    pub async fn is_empty(&self) -> bool {
        self.0.lock().await.is_empty()
    }
}

/// The two kinds of Devices that connect
///
/// The device is either a `New` device or an `Identified` device. `New` devices are devices that
/// have not previously bonded and connect when the example is discoverable. An `Identified`
/// connection is one where the peer device has connected with a resolved resolvable private
/// address.
///
/// For a newly connected device, the Security Manager requires the advertising address of this
/// device and the address of the peer within the connection indication LE link layer packet. The
/// advertising address is always random in this example, but the peer device may use a random
/// address or its public address.
pub enum ConnectionKind {
    New {
        advertising_address: BluetoothDeviceAddress,
        peer_address: BluetoothDeviceAddress,
        peer_is_random: bool,
    },
    Identified(Keys),
}

/// The `Security` type
///
/// This is a connection specific security implementation. Every time a connection is formed, a new
/// `Security` is created and the lifetime of the `Security` will last until the
pub struct Security {
    security_manager: SecurityManager,
    store: Store,
    keys: Option<Keys>,
    is_encrypted: bool,
    pairing_request: Option<BasicFrame<Vec<u8>>>,
    authentication: Option<Authentication>,
}

impl Security {
    /// Create a new `Security`
    ///
    /// This requires the addresses of both this device and the connected peer device. The
    /// `this_is_random` and `peer_is_random` inputs is are for indicating if the respective address
    /// is random or public.
    ///
    /// # Error
    /// If `discoverable_address` is `None` and either the peer address within `connection` is not
    /// resolvable or no address
    pub fn new(keys_store: Store, connection: ConnectionKind) -> Self {
        let (security_manager, keys) = match connection {
            ConnectionKind::New {
                advertising_address,
                peer_address,
                peer_is_random,
            } => {
                let security_manager =
                    SecurityManagerBuilder::new(peer_address, advertising_address, peer_is_random, true)
                        .disable_just_works()
                        .enable_number_comparison()
                        .enable_passkey()
                        .accepted_bonding_keys(|accepted| accepted.enable_id())
                        .distributed_bonding_keys(|distributed| {
                            distributed
                                .enable_id()
                                .set_irk(Store::IRK)
                                .set_identity(Store::IDENTITY)
                        })
                        .build();

                (security_manager, None)
            }
            ConnectionKind::Identified(keys) => {
                let security_manager = SecurityManagerBuilder::new_already_paired(keys).unwrap().build();

                (security_manager, keys.into())
            }
        };

        let is_encrypted = false;

        let pairing_request = None;

        let authentication = None;

        Security {
            security_manager,
            store: keys_store,
            keys,
            is_encrypted,
            pairing_request,
            authentication,
        }
    }

    /// Process a L2CAP packet from the initiating Security Manager
    ///
    /// The return is a boolean indicating if the client sent a pairing request message (while the
    /// connection is unencrypted). This is used to signal the connection async task to send a
    /// `ConnectionToMain` message to alert the user that a device is
    pub async fn process<L>(
        &mut self,
        sm_channel: &mut BasicFrameChannel<'_, L>,
        pdu: &mut BasicFrame<Vec<u8>>,
    ) -> Option<SecurityStage>
    where
        L: LogicalLink,
    {
        use bo_tie::host::sm::CommandType;

        if let Ok(CommandType::PairingRequest) = (&*pdu).try_into() {
            let pairing_request = pdu.clone();

            self.pairing_request = Some(pairing_request);

            return Some(SecurityStage::AwaitUserAcceptPairingRequest);
        }

        let status = self.security_manager.process_command(sm_channel, pdu).await.unwrap();

        if let Ok(CommandType::PairingRequest) = (&*pdu).try_into() {
            Some(SecurityStage::AwaitUserAcceptPairingRequest)
        } else {
            self.process_status(status).await
        }
    }

    async fn process_status(&mut self, status: Status) -> Option<SecurityStage> {
        match status {
            Status::BondingComplete => {
                self.keys = self.security_manager.get_keys().copied();

                self.store.add(self.keys.unwrap()).await;

                self.store.save_keys().await;

                let identity = self.keys.unwrap().get_peer_identity().unwrap();

                Some(SecurityStage::BondingComplete(identity))
            }
            Status::PairingComplete => {
                self.pairing_request.take();

                Some(SecurityStage::PairingComplete)
            }
            Status::PairingFailed(reason) => {
                self.pairing_request.take();
                self.authentication.take();

                Some(SecurityStage::PairingFailed(reason))
            }
            Status::NumberComparison(number_comparison) => {
                let displayed = number_comparison.to_string();

                self.authentication = Authentication::NumberComparison(number_comparison).into();

                Some(SecurityStage::AuthenticationNumberComparison(displayed))
            }
            Status::PasskeyInput(passkey_input) => {
                self.authentication = Authentication::PasskeyInput(passkey_input).into();

                Some(SecurityStage::AuthenticationPasskeyInput)
            }
            Status::PasskeyOutput(passkey_output) => {
                self.authentication = Authentication::PasskeyOutput.into();

                Some(SecurityStage::AuthenticationPasskeyOutput(passkey_output.to_string()))
            }
            _ => None,
        }
    }

    /// Called when encryption is established between the two devices
    pub async fn on_encryption<L>(&mut self, sm_channel: &mut BasicFrameChannel<'_, L>)
    where
        L: LogicalLink,
    {
        self.is_encrypted = true;

        self.security_manager.set_encrypted(true);

        // self.keys is only `Some(_)` when bonding has
        // completed (at some point) between the two devices.
        if self.keys.is_none() {
            if self.security_manager.start_bonding(sm_channel).await.unwrap() {
                // The only time `start_bonding` returns `true` is
                // when the initiator does not have any keys to send
                self.keys = self.security_manager.get_keys().copied();
            }
        }
    }

    /// Called when encryption is disabled between to devices
    pub fn on_unsecured(&mut self) {
        self.security_manager.set_encrypted(false)
    }

    /// Get the LTK
    pub fn get_ltk(&mut self) -> Option<u128> {
        self.security_manager.get_keys().and_then(|keys| keys.get_ltk())
    }

    pub async fn allow_pairing<L>(&mut self, connection_channel: &mut BasicFrameChannel<'_, L>)
    where
        L: LogicalLink,
    {
        let pairing_message = match self.pairing_request.take() {
            Some(pairing_message) => pairing_message,
            None => return,
        };

        self.security_manager
            .process_command(connection_channel, &pairing_message)
            .await
            .unwrap();
    }

    pub async fn reject_pairing<L>(&mut self, connection_channel: &mut BasicFrameChannel<'_, L>)
    where
        L: LogicalLink,
    {
        if self.pairing_request.take().is_none() {
            return;
        }

        // the failure reason doesn't really matter, but this
        // error should stop any automatic (not user initiated)
        // retries by a peer device.
        let reason = PairingFailedReason::RepeatedAttempts;

        let sm_command = PairingFailed::new(reason);

        sm_command.send(connection_channel).await.unwrap();
    }

    pub async fn process_authentication<L>(
        &mut self,
        connection_channel: &mut BasicFrameChannel<'_, L>,
        authentication: AuthenticationInput,
    ) -> Option<SecurityStage>
    where
        L: LogicalLink,
    {
        match (authentication, self.authentication.take()) {
            (_, None) => None, // pairing probably failed
            (AuthenticationInput::Yes, Some(Authentication::NumberComparison(n))) => {
                let status = n.yes(&mut self.security_manager, connection_channel).await.unwrap();

                self.process_status(status).await
            }
            (AuthenticationInput::No, Some(Authentication::NumberComparison(n))) => {
                let status = n.no(&mut self.security_manager, connection_channel).await.unwrap();

                self.process_status(status).await
            }
            (AuthenticationInput::Passkey(passkey), Some(Authentication::PasskeyInput(mut p))) => {
                p.write(passkey).unwrap();

                let status = p
                    .complete(&mut self.security_manager, connection_channel)
                    .await
                    .unwrap();

                self.process_status(status).await
            }
            _ => unreachable!("unexpected authentication"),
        }
    }

    /// Get the bonding information
    pub async fn get_bonding_info(&self) -> Option<tokio::sync::MappedMutexGuard<'_, BondedDeviceInfo>> {
        if let Some(identity) = self.keys.and_then(|keys| keys.get_peer_identity()) {
            self.store.get(identity).await
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub enum SecurityStage {
    AwaitUserAcceptPairingRequest,
    AuthenticationNumberComparison(String),
    AuthenticationPasskeyInput,
    AuthenticationPasskeyOutput(String),
    BondingComplete(IdentityAddress),
    PairingComplete,
    PairingFailed(PairingFailedReason),
}

enum Authentication {
    NumberComparison(NumberComparison),
    PasskeyInput(PasskeyInput),
    PasskeyOutput,
}
