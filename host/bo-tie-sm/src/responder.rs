//! Responder side of the Security Manager
//!
//! A responder is used by the peripheral device to to 'respond' to the security manager requests of
//! an initiating device.
//!
//! # Builder
//! A responding [`SecurityManger`] must be created from the builder [`SecurityManagerBuilder`]. The
//! builder is used to configure the type of pairing performed and the bonding keys that allowed for
//! distribution by the security manager.  The default configuration is to distribute the identity
//! resolving key during bonding and use *just works* man in the middle (MITM) protection.
//! Unfortunately other forms of MITM protection require access to things outside the scope of the
//! implementation of this library.
//!
//! ```
#![cfg_attr(
    botiedocs,
    doc = r##"
# mod bo_tie::sm {
#    pub use bo_tie_sm::*;
# }
use bo_tie::responder::SecurityManagerBuilder;
"##
)]
#![cfg_attr(
    not(botiedocs),
    doc = r##"
use bo_tie_sm::responder::SecurityManagerBuilder;
"##
)]
//! # use bo_tie_util::BluetoothDeviceAddress;
//! # let this_address = BluetoothDeviceAddress::zeroed();
//! # let peer_address = BluetoothDeviceAddress::zeroed();
//!
//! let security_manager = SecurityManagerBuilder::new(this_address, peer_address, true, true)
//!     .build();
//! ```
//!
//! ### Bonding Keys
//! The responder can distribute and accept an identity resolving key (IRK) and a
//! Connection Signature Resolving Key (CSRK) during bonding. However, the default is to only
//! distribute an IRK and accept no keys from the initiator.
//!
//! The IRK is used for generating a resolvable private address and the CSRK is for signing data
//! that is part of an unencrypted advertising packet, so the only need to accept keys from the
//! initiator is if the roles of the devices could switch.
//!
//! ```
//! # use bo_tie_sm::responder::SecurityManagerBuilder;
//! # use bo_tie_util::BluetoothDeviceAddress;
//! let security_manager_builder = SecurityManagerBuilder::new(BluetoothDeviceAddress::zeroed(), BluetoothDeviceAddress::zeroed(), false, false);
//!
//! // create a security manager that will send an
//! // IRK and CSRK during bonding but only accept
//! // an IRK from the initiator.
//! security_manager_builder.sent_bonding_keys(|keys| {
//!     keys.enable_irk();
//!     keys.enable_csrk();
//! })
//! .accepted_bonding_keys(|keys| {
//!     keys.enable_irk();
//! })
//! .build()
//! # ;
//! ```
//!
//! ### Man in the Middle Protection
//! The builder is used for selecting what MITM protection is supported by the responder. All forms
//! except for just works (which is the same as having no MITM protection) require some form of user
//! or external system input.
//!
//! # Out of Band
//! The out of band MITM protection is the same process as just works, but it uses a secure tunnel
//! outside the Bluetooth connection between the two devices to transfer some of the pairing
//! information. In order for out of band to work it requires the method to also be MITM protected.
//! Using another communication protocol, such as [near field communication], is a common way to
//! perform out of band.
//!
//! In order to use out of band with this security manager, the methods of transferring data must
//! be set as part of the builder pattern of `SecurityManagerBuilder`. The methods
//! [`set_oob_sender`] and [`set_oob_receiver`] are used to register the means to send and receive
//! out of band data by the security manager.
//!
//! ```
//! # use bo_tie_util::BluetoothDeviceAddress;
//! # let this_addr = BluetoothDeviceAddress::zeroed();
//! # let remote_addr = BluetoothDeviceAddress::zeroed();
//! # let security_manager_builder = bo_tie_sm::responder::SecurityManagerBuilder::new(this_addr, remote_addr, false, false);
//! # async fn send_over_nfc(_: &[u8]) {}
//! # async fn receive_from_nfc() -> Vec<u8> { Vec::new() }
//!
//! let security_manager = security_manager_builder
//!     .set_oob_sender(|data: &[u8]| async { send_over_nfc(data).await })
//!     .set_oob_receiver(|| async { receive_from_nfc().await })
//!     .build()
//! # ;
//! ```

use crate::l2cap::ConnectionChannel;
use crate::oob::{sealed_receiver_type::OobReceiverTypeVariant, OobDirection};
use crate::pairing::{KeyPressNotification, PairingFailedReason};
use crate::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, GetXOfP256Key, PairingData,
    PairingMethod, PasskeyDirection,
};
use crate::{EnabledBondingKeysBuilder, SecurityManagerError};
use alloc::vec::Vec;
use bo_tie_util::buffer::stack::LinearBuffer;

macro_rules! error {
    ($a:ty) => {
        crate::SecurityManagerError<
            <<$a>::YesNoInput as crate::io::YesNoInput>::Error,
            <<$a>::KeyboardInput as crate::io::KeyboardInput>::Error
        >
    }
}

/// A builder for a [`SlaveSecurityManager`]
///
/// This is used to construct a `SlaveSecurityManager`. However building requires the
///
/// ## Bonding
/// By default, bonding is configured to be done with the peer device. If bonding support is not
/// desired, it can be disabled with the method `no_boding`.
///
/// ## Man In The Middle protection
/// By default, a Security Manager created by this builder does not have MITM protection, and will
/// only support the "just works" pairing. In order for Man in the Middle (MITM) protection to be
/// supported by the built Security Manager, at least one kind of operation to prevent MITM
/// protection must be enabled.
///
/// #### Disabling Just Works
/// Just works can be disabled via the method `no_just_works`, however another pairing method must
/// be enabled or `build` will panic.
///
/// #### Out of Band Support
/// Out of Band (OOB) requires the usage of external types to facilitate the passing of out of band
/// data. When a `SecurityManagerBuilder` is created with `new`, OOB functionality is set to be
/// unsupported. At least one of the methods `set_oob_sender` and `set_oob_receiver` must be called
/// to enable the usage of OOB MITM protection.
///
/// The level of security that the OOB method uses is completely out of scope of this builder to be
/// verified by it. You must ensure that the out of band transport used has sufficient MITM
/// protection to provide a successful Authorization.
pub struct SecurityManagerBuilder {
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: crate::BluetoothDeviceAddress,
    this_address: crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
    enable_just_works: bool,
    enable_number_comparison: bool,
    enable_passkey: bool,
    can_bond: bool,
    distribute_irk: bool,
    distribute_csrk: bool,
    accept_irk: bool,
    accept_csrk: bool,
    prior_keys: Option<super::Keys>,
    assert_check_mode_one: Option<bo_tie_gap::security::LeSecurityModeOne>,
    assert_check_mode_two: Option<bo_tie_gap::security::LeSecurityModeTwo>,
}

impl SecurityManagerBuilder
{
    /// Create a new `SlaveSecurityManagerBuilder`
    pub fn new(
        connected_device_address: crate::BluetoothDeviceAddress,
        this_device_address: crate::BluetoothDeviceAddress,
        is_connected_devices_address_random: bool,
        is_this_device_address_random: bool,
    ) -> Self {
        Self {
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
            enable_just_works: true,
            can_bond: true,
            distribute_irk: true,
            distribute_csrk: false,
            accept_irk: true,
            accept_csrk: false,
            prior_keys: None,
            assert_check_mode_one: None,
            assert_check_mode_two: None,
        }
    }
}

impl SecurityManagerBuilder
{
    /// Set the keys to the peer device if it is already paired
    ///
    /// This assigns the keys that were previously generated after a successful pair and bonding.
    /// This method should only be called after the identity of the peer and associated long term
    /// key (LTK) is known. Usually this is through successful resolving the resolvable private
    /// address *of the* peer device.
    pub fn set_already_paired(mut self, keys: super::Keys) -> Result<Self, &'static str> {
        if keys.get_ltk().is_some() {
            self.prior_keys = Some(keys);

            Ok(self)
        } else {
            Err("missing long term key")
        }
    }

    /// Use GAP's Security Mode One to Ensure the Configuration of the Security Manager
    ///
    /// This method ensures that the Security Manager meets the requirements of the specified level
    /// for Security Mode One. The Security Manager will not be able to be built if it is not
    /// configured to meet the requirements of the specified level.
    ///
    /// Security Mode One defines the requirements for authentication and encryption for data
    /// transfer within a connection. This affects the pairing mode requirements of the Security
    /// Manager for establishing encryption.
    ///
    /// ### `Level1` and `Level2`
    /// Level one corresponds to no security and Level two corresponds to unauthenticated pairing.
    /// As far as creating a Security Manager is concerned these levels are equivalent (level one
    /// just means that use of a Security Manager is optional). When using either enum the Security
    /// Manager will be configured to allow just works pairing.
    ///
    /// ### `Level3` and `Level4`
    /// Level three and level four are equivalent for this implementation of a Security Manager.
    /// Level three requires authenticated pairing with encryption, and level four requires the same
    /// using LE Secure Connections. Since only Secure Connections is implemented, both enums
    /// `Level3` and `Level4` have the same result.
    ///
    /// Both these enums disable 'just works'. This means that the method [`build`] will panic if
    /// another pairing method is not enabled. todo mention methods to call...
    ///
    /// [`build`]
    pub fn ensure_security_mode_one(mut self, mode: bo_tie_gap::security::LeSecurityModeOne) -> Self {
        self.assert_check_mode_one = mode.into();
        self
    }

    /// Use GAP's Security Mode Two to Ensure the Configuration the Security Manager
    ///
    /// This method ensures that the Security Manager meets the requirements fo the specified level
    /// for Security Mode Two. The Security Manager will not be able to be built if it is not
    /// configured to meet the requirements of the specified level.
    ///
    /// Security Mode two defines the security aspects of signed data. For the Security Manager this
    /// sets the requirements for how the Connection Signature Resolving Key (CSRK) is distributed
    ///
    /// ### Level 1
    /// If the CSRK is configured to be sent by the method [`sent_bonding_keys`], it will always be
    /// sent regardless of the pairing method.
    ///
    /// ### Level 2
    /// If the CSRK is configured to be sent by the method [`sent_bonding_keys`], the pairing method
    /// 'just works' must be disabled before the Security Method is build. If not then the method
    /// [`build`] will panic.
    ///
    /// [`sent_bonding_keys`]: SecurityManagerBuilder::sent_bonding_keys
    /// [`build`]: SecurityManagerBuilder::build
    pub fn ensure_security_mode_two(mut self, mode: bo_tie_gap::security::LeSecurityModeTwo) -> Self {
        self.assert_check_mode_two = mode.into();
        self
    }

    /// EDisable 'Just Works' Pairing
    ///
    /// Just works pairing requires no authentication to establish encryption. Disabling 'just
    /// works' requires the enabling of either passkey or number comparison pairing.
    pub fn disable_just_works(mut self) -> Self {
        self.enable_just_works = false;
        self
    }

    /// Enable 'Number Comparison' Pairing.
    ///
    /// Number Comparison requires the Bluetooth application user to confirm that numbers displayed
    /// on both devices are equivalent. This should only be enabled if this device as some way to
    /// have the user input the equivalent of 'yes' and 'no' along with the ability to display six
    /// digits (base 10).
    pub fn enable_number_comparison(mut self) -> Self {
        self.enable_number_comparison = true;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// Passkey entry usually requires the Bluetooth application user to enter the same passcode on
    /// one device that is displayed on the other device. The other way for passkey to work is when
    /// the user inputs the same passkey (chosen by them) on both devices. The first way requires
    /// one device to have the ability to display six digits and the other device able to input six
    /// digits. The other passkey entry method requires both devices to be able to input six digits.
    pub fn enable_passcode_entry(mut self) -> Self {
        self.enable_passkey = true;
        self
    }

    /// Disable Bonding
    ///
    /// This creates a Security Manager that will not bond with the peer device after pairing is
    /// completed.
    pub fn disable_bonding(mut self) -> Self {
        self.can_bond = false;
        self
    }

    /// Set the bonding keys to be distributed by the responder
    ///
    /// When this method is called, the default configuration for key distribution is overwritten to
    /// disable the distribution of all bonding keys. The return must then be used to selectively
    /// enable what keys are sent by the security manager when bonding.
    ///
    /// By default only the Identity Resolving Key (IRK) is distributed to the initiator. This
    /// method does not need to be called if the default key configuration is desired.
    ///
    /// # Note
    /// This method has no affect if the Security Manager is built without bonding support.
    pub fn sent_bonding_keys<F>(mut self, f: F) -> Self
        where
            F: FnOnce(&mut EnabledBondingKeysBuilder) -> &mut EnabledBondingKeysBuilder,
    {
        let mut enabled_bonding_keys = EnabledBondingKeysBuilder::new();

        f(&mut enabled_bonding_keys);

        self.distribute_irk = enabled_bonding_keys.irk;
        self.distribute_csrk = enabled_bonding_keys.csrk;

        self
    }

    /// Set the bonding keys to be accepted by this initiator
    ///
    /// When this method is called, the default configuration for key distribution is overwritten to
    /// not accept all bonding all keys. The return must then be used to selectively enable
    /// what keys are sent by the security manager when bonding.
    ///
    /// By default only the Identity Resolving Key (IRK) is accepted from the initiator. This
    /// method does not need to be called if the default key configuration is desired.
    ///
    /// # Note
    /// This method has no affect if the Security Manager is built without bonding support.
    pub fn accepted_bonding_keys<F>(mut self, f: F) -> Self
        where
            F: FnOnce(&mut EnabledBondingKeysBuilder) -> &mut EnabledBondingKeysBuilder,
    {
        let mut enabled_bonding_keys = EnabledBondingKeysBuilder::new();

        f(&mut enabled_bonding_keys);

        self.accept_irk = enabled_bonding_keys.irk;
        self.accept_csrk = enabled_bonding_keys.csrk;

        self
    }

    /// Create the Authentication Requirements
    ///
    /// # Panic
    /// If the user disallows "just works" and no other paring method can be used.
    fn create_auth_req(
        &self,
    ) -> Result<LinearBuffer<{ encrypt_info::AuthRequirements::full_depth() }, encrypt_info::AuthRequirements>, crate::SecurityManagerBuilderError> {
        let mut auth_req = LinearBuffer::new();

        // mandatory as only Secure Connections (not legacy) is supported
        auth_req.try_push(encrypt_info::AuthRequirements::Sc).unwrap();

        if self.can_bond {
            auth_req.try_push(encrypt_info::AuthRequirements::Bonding).unwrap();
        }

        if self.enable_number_comparison || self.enable_passkey {
            auth_req
                .try_push(encrypt_info::AuthRequirements::ManInTheMiddleProtection)
                .unwrap();
        } else if !self.enable_just_works {
            return Err(crate::SecurityManagerBuilderError::NoPairingMethodSet)
        }

        if self.enable_passkey {
            auth_req.try_push(encrypt_info::AuthRequirements::KeyPress).unwrap();
        }

        Ok(auth_req)
    }

    /// Create the [`SecurityManager`]
    ///
    /// This will create a `SecurityManager` from the configuration provided
    /// # Panic
    /// If an

    /// Try to create the `SlaveSecurityManager`
    pub fn try_build(self) -> Result<SecurityManager, crate::SecurityManagerBuilderError> {
        let initiator_key_distribution = super::get_keys(self.accept_irk, self.accept_csrk);

        let responder_key_distribution = super::get_keys(self.distribute_irk, self.distribute_csrk);

        let io_capability = pairing::IOCapability::map(Y::can_read(), K::can_read(), O::can_write());

        let auth_req = self.create_auth_req();

        let authentication = crate::Authentication {
            yes_no_input: self.yes_no_input,
            keyboard_input: self.passkey_input,
            output: self.output,
            oob_sender: self.oob_sender,
            oob_receiver: self.oob_receiver,
        };

        SecurityManager {
            io_capability,
            authentication,
            auth_req,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            initiator_key_distribution,
            responder_key_distribution,
            initiator_address: self.remote_address,
            responder_address: self.this_address,
            initiator_address_is_random: self.remote_address_is_random,
            responder_address_is_random: self.this_address_is_random,
            pairing_data: None,
            keys: self.prior_keys,
            link_encrypted: false,
        }
    }
}

pub struct SecurityManager {
    io_capability: pairing::IOCapability,
    auth_req: LinearBuffer<{ encrypt_info::AuthRequirements::full_depth() }, encrypt_info::AuthRequirements>,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_key_distribution: &'static [pairing::KeyDistributions],
    responder_key_distribution: &'static [pairing::KeyDistributions],
    initiator_address: crate::BluetoothDeviceAddress,
    responder_address: crate::BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    keys: Option<super::Keys>,
    link_encrypted: bool,
}

impl SecurityManager {
    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `SlaveSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    pub fn set_encrypted(&mut self, is_encrypted: bool) {
        self.link_encrypted = is_encrypted
    }

    /// Get the encryption keys
    ///
    /// This returns the encryption keys, if they exist. Keys will exist after they're generated
    /// once pairing completes, until then this method will return `None`.
    pub fn get_keys(&self) -> Option<&super::Keys> {
        self.keys.as_ref()
    }

    /// Send the Identity Resolving Key
    ///
    /// This will add the IRK to the cypher keys and send it to the other device if the internal
    /// encryption flag is set to true (by the method
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted)) and pairing
    /// has completed.
    ///
    /// If the input `irk` evaluates to `None` then an IRK is generated before being added and sent.
    ///
    /// The IRK is returned if it was successfully sent to the other device
    pub async fn send_irk<C, Irk>(&mut self, connection_channel: &C, irk: Irk) -> Result<u128, error!(A)>
    where
        C: ConnectionChannel,
        Irk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let irk = irk.into().unwrap_or_else(|| toolbox::rand_u128());

            if let Some(super::Keys {
                irk: ref mut irk_opt, ..
            }) = self.keys
            {
                *irk_opt = Some(irk)
            }

            self.send(connection_channel, encrypt_info::IdentityInformation::new(irk))
                .await?;

            Ok(irk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    /// Send the Connection Signature Resolving Key
    ///
    /// This will add the CSRK to the cypher keys and send it to the other device if the internal
    /// encryption flag is set to true (by the method
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted)) and pairing
    /// has completed.
    ///
    /// If the input `csrk` evaluates to `None` then a CSRK is generated before being added and
    /// sent.
    ///
    /// The CSRK is returned if it was successfully sent to the other device
    ///
    /// # Note
    /// There is no input for the sign counter as the CSRK is considered a new value, and thus the
    /// sign counter within the CSRK will always be 0.
    pub async fn send_csrk<C, Csrk>(&mut self, connection_channel: &C, csrk: Csrk) -> Result<u128, error!(A)>
    where
        C: ConnectionChannel,
        Csrk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let csrk = csrk.into().unwrap_or_else(|| toolbox::rand_u128());

            if let Some(super::Keys {
                csrk: ref mut csrk_opt, ..
            }) = self.keys
            {
                *csrk_opt = Some((csrk, 0));
            }

            self.send(connection_channel, encrypt_info::SigningInformation::new(csrk))
                .await?;

            Ok(csrk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    /// Send the identity address to the peer Device.
    ///
    /// This will send the `identity` address of this device to the peer Device if the internal
    /// encryption flag is set to true by [`set_encrypted`]. If `identity` is `None` then the
    /// address sent will fall back to either the identity within the cypher keys or the address
    /// used when pairing the devices, in that order.
    ///
    /// The identity address will be set in the cypher keys if the cypher keys exist within this
    /// security manager.
    ///
    /// The return is the identity address information sent to the peer device.
    ///
    /// # Error
    /// An error will occur if the encryption flag is not set or an error occurs trying to send the
    /// message to the peer device.
    ///
    /// [`set_encrypted`]: crate::sm::responder::SecurityManager::set_encrypted
    pub async fn send_identity<C, I>(
        &mut self,
        connection_channel: &C,
        identity: I,
    ) -> Result<crate::IdentityAddress, error!(A)>
    where
        C: ConnectionChannel,
        I: Into<Option<crate::IdentityAddress>>,
    {
        let identity = match identity.into() {
            Some(identity) => identity,
            None => {
                if let Some(super::Keys {
                    identity: Some(identity),
                    ..
                }) = self.keys
                {
                    identity
                } else {
                    if self.responder_address_is_random {
                        crate::IdentityAddress::StaticRandom(self.responder_address)
                    } else {
                        crate::IdentityAddress::Public(self.responder_address)
                    }
                }
            }
        };

        if self.link_encrypted {
            self.send(
                connection_channel,
                match identity {
                    crate::IdentityAddress::Public(addr) => encrypt_info::IdentityAddressInformation::new_pub(addr),
                    crate::IdentityAddress::StaticRandom(addr) => {
                        encrypt_info::IdentityAddressInformation::new_static_rand(addr)
                    }
                },
            )
            .await?;

            if let Some(super::Keys {
                identity: ref mut identity_opt,
                ..
            }) = self.keys
            {
                *identity_opt = Some(identity);
            }

            Ok(identity)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    async fn send<C, Cmd, P>(&self, connection_channel: &C, command: Cmd) -> Result<(), error!(A)>
    where
        C: ConnectionChannel,
        Cmd: Into<Command<P>>,
        P: CommandData,
    {
        use crate::l2cap::BasicInfoFrame;

        let acl_data = BasicInfoFrame::new(command.into().into_command_format().to_vec(), super::L2CAP_CHANNEL_ID);

        connection_channel
            .send(acl_data)
            .await
            .map_err(|e| Error::DataSend(alloc::format!("{:?}", e)).into())
    }

    async fn send_err<C>(
        &mut self,
        connection_channel: &C,
        fail_reason: pairing::PairingFailedReason,
    ) -> Result<(), error!(A)>
    where
        C: ConnectionChannel,
    {
        self.pairing_data = None;

        self.send(connection_channel, pairing::PairingFailed::new(fail_reason))
            .await
    }

    /// Process an

    /// Process a request from the initiating SecurityManager
    ///
    /// This will return a response to a valid request that can be sent to the Master device.
    /// Errors will be returned if the request is not something that can be processed by the slave
    /// or there was something wrong with the request message.
    ///
    /// This function will return a ['Keys'](crate::sm::Keys) with the newly generated
    /// Long Term Key (LTK). **This key information will only last as long as the master does not
    /// retry pairing or the master causes this responder to return a pairing error to the master**.
    /// *After pairing is complete*, the returned `Keys` will only contain the LTK and the
    /// peer address used during pairing as the peer identity address. The return will be updated
    /// further with peer keys only when `set_encryption` is used to indicate that the connection
    /// is encrypted.
    ///
    /// It is recommended to always keep processing Bluetooth Security Manager packets as the
    /// responder. The host can at any point decide to restart encryption using different keys or
    /// send a `PairingFailed` to indicate that the prior pairing process failed.
    pub async fn process_command<C>(
        &mut self,
        connection_channel: &C,
        acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        let command = match CommandType::try_from(acl_data) {
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;
                return Err(e.into());
            }
            Ok(cmd) => cmd,
        };

        let payload = &acl_data.get_payload()[1..];

        match command {
            CommandType::PairingRequest => self.p_pairing_request(connection_channel, payload).await,
            CommandType::PairingConfirm => self.p_pairing_confirm(connection_channel, payload).await,
            CommandType::PairingPublicKey => self.p_pairing_public_key(connection_channel, payload).await,
            CommandType::PairingRandom => self.p_pairing_random(connection_channel, payload).await,
            CommandType::PairingFailed => self.p_pairing_failed(connection_channel, payload).await,
            CommandType::PairingDHKeyCheck => self.p_pairing_dh_key_check(connection_channel, payload).await,
            CommandType::IdentityInformation => self.p_identity_info(connection_channel, payload).await,
            CommandType::IdentityAddressInformation => self.p_identity_address_info(connection_channel, payload).await,
            CommandType::SigningInformation => self.p_signing_info(connection_channel, payload).await,
            cmd @ CommandType::MasterIdentification | // Legacy SM, not supported
            cmd @ CommandType::EncryptionInformation | // Legacy SM, not supported
            cmd => self.p_command_not_supported(connection_channel, cmd).await,
        }
    }

    /// Send the OOB confirm information
    ///
    /// This will create the confirm information and send it to the initiator if the out of band
    /// send function was set. If no sender was set, this method does nothing.
    ///
    /// # Notes
    /// * This method does nothing if OOB sending is not enabled.
    /// * The information generated is wrapped in a OOB data block and then sent to the initiator.
    ///
    /// # Panic
    /// This method will panic if the pairing information and public keys were not already generated
    /// in the pairing process.
    async fn send_oob(&mut self) {
        use crate::oob::OutOfBandSend;
        use bo_tie_gap::assigned::{
            le_device_address::LeDeviceAddress, le_role::LeRole, sc_confirm_value::ScConfirmValue,
            sc_random_value::ScRandomValue, Sequence,
        };

        if <A::OobSender as crate::oob::OutOfBandSend>::can_send() {
            let data = &mut [0u8; LeDeviceAddress::STRUCT_SIZE
                + LeRole::STRUCT_SIZE
                + ScRandomValue::STRUCT_SIZE
                + ScConfirmValue::STRUCT_SIZE];

            let ra = toolbox::rand_u128();

            let paring_data = self.pairing_data.as_ref().unwrap();

            let pka = GetXOfP256Key::x(&paring_data.public_key);

            let address = LeDeviceAddress::from(self.initiator_address);

            let role = LeRole::OnlyPeripheral;

            let random = ScRandomValue::new(ra);

            let confirm = ScConfirmValue::new(toolbox::f4(pka, pka, ra, 0));

            let mut sequence = Sequence::new(data);

            sequence.try_add(&address).unwrap();
            sequence.try_add(&role).unwrap();
            sequence.try_add(&random).unwrap();
            sequence.try_add(&confirm).unwrap();

            self.authentication
                .get_mut_oob_sender()
                .send(sequence.into_inner())
                .await;
        }
    }

    /// Receive OOB information by its type
    ///
    /// This will do one of two things depending on the type of receiver.
    ///
    /// For the `Internal` type of receiver it will await the data and send the nonce once it
    /// receives and validated the OOB data.
    ///
    /// For the `External` it will just return Ok as the user needs to provide the OOB data with
    /// the method `received_oob_data`.
    ///
    /// # Panic
    /// This method will panic if `DoesNotExist` is the receiver type or `pairing_data` is `None`
    async fn by_oob_receiver_type<C>(&mut self, connection_channel: &C) -> Result<(), error!(A)>
    where
        C: ConnectionChannel,
    {
        match <A::OobReceiver as crate::oob::sealed_receiver_type::SealedTrait>::receiver_type() {
            OobReceiverTypeVariant::Internal => {
                let confirm_result = self.receive_oob().await;

                self.oob_confirm_result(connection_channel, confirm_result).await
            }
            OobReceiverTypeVariant::External => Ok(()),
            OobReceiverTypeVariant::DoesNotExist => unreachable!(),
        }
    }

    /// Function for the validation result of the confirm value with an OOB data.
    ///
    /// # Panic
    /// Member `pairing_data` must be `Some(_)`.
    async fn oob_confirm_result<C>(&mut self, connection_channel: &C, confirm_result: bool) -> Result<(), error!(A)>
    where
        C: ConnectionChannel,
    {
        if confirm_result {
            match self.pairing_data {
                Some(PairingData {
                    pairing_method: PairingMethod::Oob(_),
                    ref mut external_oob_confirm_valid,
                    ..
                }) => {
                    *external_oob_confirm_valid = true;

                    Ok(())
                }
                None => unreachable!("Pairing Data cannot be None"),
                _ => Ok(()), // Other pairing methods
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::ConfirmValueFailed)
                .await
        }
    }

    /// Receive OOB information from the initiator
    ///
    /// This will await for the OOB data block containing the initiator's confirm information and
    /// return a boolean indicating if the information was verified. If no receive function was set,
    /// this method will return true.
    ///
    /// # Error
    /// An error is returned if the initiator's random and confirm values cannot be converted
    ///
    /// # Panic
    /// This method will panic if the pairing information and public keys were not already generated
    /// in the pairing process.
    async fn receive_oob(&mut self) -> bool {
        use crate::oob::sealed_receiver_type::SealedTrait;
        use core::borrow::Borrow;

        let data = self.authentication.get_mut_oob_receiver().receive().await;

        self.process_received_oob(data.borrow())
    }

    /// Process the received OOB
    ///
    /// This will check the OOB to determine the validity of the raw data and the confirm within the
    /// raw data. True is returned if everything within `raw` is validated.
    fn process_received_oob(&self, raw: &[u8]) -> bool {
        use bo_tie_gap::assigned::{sc_confirm_value, sc_random_value, AssignedTypes, EirOrAdIterator, TryFromStruct};

        let mut ra = None;
        let mut ca = None;

        for ad in EirOrAdIterator::new(raw).silent() {
            const RANDOM_TYPE: u8 = AssignedTypes::LESecureConnectionsRandomValue.val();
            const CONFIRM_TYPE: u8 = AssignedTypes::LESecureConnectionsConfirmationValue.val();

            match ad.get_type() {
                RANDOM_TYPE => ra = sc_random_value::ScRandomValue::try_from_struct(ad).ok(),
                CONFIRM_TYPE => ca = sc_confirm_value::ScConfirmValue::try_from_struct(ad).ok(),
                _ => (),
            }
        }

        if let (Some(ra), Some(ca)) = (ra, ca) {
            let paring_data = self.pairing_data.as_ref().unwrap();

            let pka = GetXOfP256Key::x(paring_data.peer_public_key.as_ref().unwrap());

            if ca.0 == toolbox::f4(pka, pka, ra.0, 0) {
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    async fn p_command_not_supported<C>(
        &mut self,
        connection_channel: &C,
        cmd: CommandType,
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        self.send_err(connection_channel, pairing::PairingFailedReason::CommandNotSupported)
            .await?;

        Err(Error::IncorrectCommand(cmd).into())
    }

    async fn p_pairing_request<C>(
        &mut self,
        connection_channel: &C,
        data: &[u8],
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing request");

        let request = match pairing::PairingRequest::try_from_command_format(data) {
            Ok(request) => request,
            Err(_) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::IncorrectCommand(CommandType::PairingPublicKey).into());
            }
        };

        if request.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(connection_channel, pairing::PairingFailedReason::EncryptionKeySize)
                .await?;

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize).into())
        } else {
            let response = pairing::PairingResponse::new(
                self.io_capability,
                if <A::OobReceiver as crate::oob::sealed_receiver_type::SealedTrait>::can_receive() {
                    pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
                } else {
                    pairing::OOBDataFlag::AuthenticationDataNotPresent
                },
                self.auth_req.clone(),
                self.encryption_key_size_max,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            );

            let pairing_method = PairingMethod::determine_method(
                request.get_oob_data_flag(),
                response.get_oob_data_flag(),
                request.get_io_capability(),
                response.get_io_capability(),
                false,
            );

            let initiator_io_cap = request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            self.send(connection_channel, response).await?;

            let (private_key, public_key) = toolbox::ecc_gen();

            log::info!("(SM) pairing Method: {:?}", pairing_method);

            self.pairing_data = Some(PairingData {
                pairing_method,
                public_key,
                private_key: Some(private_key),
                initiator_io_cap,
                responder_io_cap,
                nonce: toolbox::nonce(),
                peer_public_key: None,
                secret_key: None,
                peer_nonce: None,
                responder_pairing_confirm: None,
                mac_key: None,
                external_oob_confirm_valid: false,
            });

            Ok(None)
        }
    }

    async fn p_pairing_public_key<C>(
        &mut self,
        connection_channel: &C,
        data: &[u8],
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing public Key");

        let initiator_pub_key = match pairing::PairingPubKey::try_from_command_format(data) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: ref key_gen_method,
                ref public_key,
                ref nonce,
                ref mut private_key,
                ref mut peer_public_key,
                ref mut secret_key,
                ..
            }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_command_format();

                    let mut raw_key = [0u8; 64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                let remote_public_key = initiator_pub_key.get_key();

                log::trace!("(SM) remote public key: {:x?}", remote_public_key.as_ref());

                let peer_pub_key = match toolbox::PubKey::try_from_command_format(&remote_public_key) {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                            .await?;

                        return Err(e.into());
                    }
                };

                // Calculate the shared secret key
                let private_key = private_key.take().expect("Private key doesn't exist");

                *secret_key = toolbox::ecdh(private_key, &peer_pub_key).into();

                let confirm_value =
                    toolbox::f4(GetXOfP256Key::x(public_key), GetXOfP256Key::x(&peer_pub_key), *nonce, 0);

                *peer_public_key = peer_pub_key.into();

                // Send the public key of this device
                self.send(connection_channel, pairing::PairingPubKey::new(raw_pub_key))
                    .await?;

                // Process what to do next based on the key generation method
                match key_gen_method {
                    PairingMethod::JustWorks | PairingMethod::NumbComp => {
                        // Send the confirm value
                        self.send(connection_channel, pairing::PairingConfirm::new(confirm_value))
                            .await?;
                    }
                    PairingMethod::Oob(OobDirection::OnlyResponderSendsOob) => {
                        self.send_oob().await;
                    }
                    PairingMethod::Oob(OobDirection::BothSendOob) => {
                        self.send_oob().await;

                        self.by_oob_receiver_type(connection_channel).await?;
                    }
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) => {
                        self.by_oob_receiver_type(connection_channel).await?;
                    }
                    PairingMethod::PassKeyEntry(direction) => match direction {
                        PasskeyDirection::InitiatorDisplaysResponderInputs
                        | PasskeyDirection::InitiatorAndResponderInput => {
                            let mut key = self.authentication.passkey_input().next_passkey(true).await?;

                            loop {
                                self.send(connection_channel, key).await?;

                                if key == KeyPressNotification::PasskeyEntryCompleted {
                                    break;
                                }

                                key = self.authentication.passkey_input().next_passkey(true).await?;
                            }
                        }
                        _ => (),
                    },
                }

                Ok(None)
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::IncorrectCommand(CommandType::PairingPublicKey).into())
            }
        }
    }

    async fn send_passkey<C>(&mut self, connection_channel: &C, direction: &PasskeyDirection) -> Result<(), error!(A)> {
        Ok(())
    }

    async fn p_pairing_confirm<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing confirm");

        let _initiator_confirm = match pairing::PairingConfirm::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data.as_ref() {
            // Only the pairing method Passkey will have confirm values sent through the logical
            // link
            Some(PairingData {
                pairing_method: PairingMethod::PassKeyEntry | PairingMethod::NumbComp | PairingMethod::Oob(_),
                ..
            }) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason).into())
            }
            _ => {
                // Neither the Just Works method, Number Comparison, or out of band should have the
                // responder receiving the pairing confirm PDU.
                self.send_err(connection_channel, pairing::PairingFailedReason::InvalidParameters)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::InvalidParameters).into())
            }
        }
    }

    async fn p_pairing_random<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing random");

        let initiator_random = match pairing::PairingRandom::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks,
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(None)
            }
            Some(PairingData {
                pairing_method: PairingMethod::NumbComp,
                ref mut peer_nonce,
                nonce,
                public_key,
                peer_public_key: Some(peer_public_key),
                ..
            }) => {
                let initiator_nonce = initiator_random.get_value();

                *peer_nonce = initiator_nonce.into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                let pka = GetXOfP256Key::x(&peer_public_key);

                let pkb = GetXOfP256Key::x(&public_key);

                let na = initiator_nonce;

                let nb = nonce;

                let vb = toolbox::g2(pka, pkb, na, nb);

                match self.authentication.yes_no_input(crate::io::CompareValue(vb)).await {
                    Err(e) => {
                        self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                            .await?;

                        Err(e)
                    }
                    Ok(false) => {
                        self.send_err(connection_channel, PairingFailedReason::NumericComparisonFailed)
                            .await?;

                        Ok(None)
                    }
                    Ok(true) => Ok(None),
                }
            }
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) | PairingMethod::Oob(OobDirection::BothSendOob),
                external_oob_confirm_valid,
                ..
            }) if OobReceiverTypeVariant::External
                == <A::OobReceiver as crate::oob::sealed_receiver_type::SealedTrait>::receiver_type()
                && !external_oob_confirm_valid =>
            {
                self.send_err(connection_channel, pairing::PairingFailedReason::OOBNotAvailable)
                    .await?;

                Err(Error::ExternalOobNotProvided.into())
            }
            Some(PairingData {
                pairing_method: PairingMethod::Oob(_),
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(None)
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::UnsupportedFeature.into())
            }
        }
    }

    async fn p_pairing_failed<'z, C>(
        &'z mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&'z super::Keys>, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing failed");

        let initiator_fail = match pairing::PairingFailed::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        self.pairing_data = None;

        Err(Error::PairingFailed(initiator_fail.get_reason()).into())
    }

    async fn p_pairing_dh_key_check<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing pairing dh key check");

        let initiator_dh_key_check = match pairing::PairingDHKeyCheck::try_from_command_format(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        let pd = self.pairing_data.as_ref();

        match pd {
            Some(PairingData {
                secret_key: Some(dh_key),
                nonce,
                peer_nonce: Some(peer_nonce),
                initiator_io_cap,
                responder_io_cap,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                log::trace!("(SM) secret key: {:x?}", dh_key);
                log::trace!("(SM) remote nonce: {:x?}", peer_nonce);
                log::trace!("(SM) this nonce: {:x?}", nonce);
                log::trace!("(SM) remote address: {:x?}", a_addr);
                log::trace!("(SM) this address: {:x?}", b_addr);

                let (mac_key, ltk) = toolbox::f5(*dh_key, *peer_nonce, *nonce, a_addr.clone(), b_addr.clone());

                log::trace!("(SM) mac_key: {:x?}", mac_key);
                log::trace!("(SM) ltk: {:x?}", ltk);
                log::trace!("(SM) initiator_io_cap: {:x?}", initiator_io_cap);

                let ea = toolbox::f6(
                    mac_key,
                    *peer_nonce,
                    *nonce,
                    0,
                    *initiator_io_cap,
                    a_addr.clone(),
                    b_addr.clone(),
                );

                let received_ea = initiator_dh_key_check.get_key_check();

                if received_ea == ea {
                    log::trace!("(SM) responder_io_cap: {:x?}", responder_io_cap);

                    let eb = toolbox::f6(mac_key, *nonce, *peer_nonce, 0, *responder_io_cap, b_addr, a_addr);

                    self.send(connection_channel, pairing::PairingDHKeyCheck::new(eb))
                        .await?;

                    let keys = &mut self.keys;

                    *keys = super::Keys {
                        is_authenticated: todo!(),
                        ltk: ltk.into(),
                        irk: None,
                        csrk: None,
                        peer_irk: None,
                        peer_identity: if self.initiator_address_is_random {
                            super::IdentityAddress::StaticRandom(self.initiator_address)
                        } else {
                            super::IdentityAddress::Public(self.initiator_address)
                        }
                        .into(),
                        peer_csrk: None,
                        identity: if self.responder_address_is_random {
                            super::IdentityAddress::StaticRandom(self.responder_address)
                        } else {
                            super::IdentityAddress::Public(self.responder_address)
                        }
                        .into(),
                    }
                    .into();

                    Ok(keys.as_ref())
                } else {
                    self.send_err(connection_channel, pairing::PairingFailedReason::DHKeyCheckFailed)
                        .await?;

                    log::trace!("(SM) received ea: {:x?}", received_ea);
                    log::trace!("(SM) calculated ea: {:x?}", ea);

                    Err(Error::PairingFailed(pairing::PairingFailedReason::DHKeyCheckFailed).into())
                }
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                Err(Error::UnsupportedFeature.into())
            }
        }
    }

    async fn p_identity_info<'z, C>(
        &'z mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&'z super::Keys>, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer IRK");

        let identity_info = match encrypt_info::IdentityInformation::try_from_command_format(payload) {
            Ok(ii) => ii,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_irk = Some(identity_info.get_irk());

                Ok(Some(keys))
            } else {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason).into());
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted.into());
        }
    }

    async fn p_identity_address_info<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<SecurityManagerStage, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer address info");

        let identity_addr_info = match encrypt_info::IdentityAddressInformation::try_from_command_format(payload) {
            Ok(iai) => iai,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_identity = Some(identity_addr_info.into());

                Ok(Some(keys))
            } else {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason).into());
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted.into());
        }
    }

    async fn p_signing_info<'z, C>(
        &'z mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Option<&'z super::Keys>, error!(A)>
    where
        C: ConnectionChannel,
    {
        log::info!("(SM) processing peer signing info (CSRK)");

        let signing_info = match encrypt_info::SigningInformation::try_from_command_format(payload) {
            Ok(si) => si,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_csrk = Some((signing_info.get_signature_key(), 0));

                Ok(Some(keys))
            } else {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason).into());
            }
        } else {
            self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                .await?;

            return Err(Error::UnknownIfLinkIsEncrypted.into());
        }
    }
}

impl<A> SecurityManager<A>
where
    A: crate::AuthenticationCapabilities<OobReceiver = crate::oob::Unsupported>,
{
    /// Set the received out of band data
    ///
    /// This method is required to be called when the OOB receiver type is `ExternalOobReceiver`.
    /// Obviously it is not needed if the receiver type something other than `ExternalOobReceiver`
    /// because you cannot call this method.
    ///
    /// This method is tricky as it may only be called at the correct time during the pairing
    /// process with OOB, but the method
    /// [`expecting_oob_data`](SlaveSecurityManager::expecting_oob_data) can be used to get the
    /// correct time to call this method. If any other pairing process is being used, or this is
    /// called at the incorrect time, pairing is canceled and must be restarted by the initiator.
    /// The initiator is also sent the error `OOBNotAvailable`.
    ///
    /// This method must be called after the initiator's pairing public key message is *processed*
    /// but before the pairing random message is *processed*. Note *processed*, it is ok for this
    /// device to receive the pairing random message, but do not call the method
    /// [`process_command`](SlaveSecurityManager::process_command) with the message until after this
    /// method is called. The easiest way to know when this occurs is to call the method
    /// `expecting_oob_data` after processing every security manager message.
    ///
    /// ```
    /// # use std::error::Error;
    /// # use bo_tie_sm::oob::ExternalOobReceiver;
    /// # use std::future::Future;
    /// # use bo_tie_l2cap::{BasicInfoFrame, ChannelIdentifier, ConnectionChannel, ConnectionChannelExt, L2capFragment, LeUserChannelIdentifier};
    /// # use bo_tie_sm::responder::SecurityManagerBuilder;
    /// # use bo_tie_util::BluetoothDeviceAddress;
    /// # let mut security_manager_builder = SecurityManagerBuilder::new(BluetoothDeviceAddress::zeroed(), BluetoothDeviceAddress::zeroed(), false, false);
    /// # struct StubConnectionChannel;
    /// # impl ConnectionChannel for StubConnectionChannel {
    /// #     type SendBuffer = Vec<u8>;
    /// #     type SendFut<'a> = std::pin::Pin<Box<dyn Future<Output=Result<(), bo_tie_l2cap::send_future::Error<Self::SendFutErr>>>>>;
    /// #     type SendFutErr = usize;
    /// #     type RecvBuffer = Vec<u8>;
    /// #     type RecvFut<'a> = std::pin::Pin<Box<dyn Future<Output=Option<Result<L2capFragment<Self::RecvBuffer>, bo_tie_l2cap::BasicFrameError<<Self::RecvBuffer as bo_tie_util::buffer::TryExtend<u8>>::Error>>>>>>;
    /// #     fn send(&self, data: BasicInfoFrame<Vec<u8>>) -> Self::SendFut<'_> { unimplemented!() }
    /// #     fn set_mtu(&mut self,mtu: u16) { unimplemented!() }
    /// #     fn get_mtu(&self) -> usize { unimplemented!() }
    /// #     fn max_mtu(&self) -> usize { unimplemented!() }
    /// #     fn min_mtu(&self) -> usize { unimplemented!() }
    /// #     fn receive(&mut self) -> Self::RecvFut<'_> { unimplemented!() }
    /// # }
    /// # let mut connection_channel = StubConnectionChannel;
    /// # let oob_data = &[];
    /// # async {
    /// # let _r: Result<(), Box<dyn Error>> = async {
    /// const SM_CHANNEL_ID: ChannelIdentifier = ChannelIdentifier::Le(
    ///     LeUserChannelIdentifier::SecurityManagerProtocol
    /// );
    ///    
    /// let mut security_manager = security_manager_builder
    ///     .set_oob_receiver(ExternalOobReceiver)
    ///     .build();
    ///
    /// loop {
    ///     for b_frame in connection_channel.receive_b_frame().await? {
    ///         match b_frame.get_channel_id() {
    ///             SM_CHANNEL_ID => {
    ///                 security_manager.process_command(
    ///                     &connection_channel,
    ///                     &b_frame
    ///                 ).await?;
    ///
    ///                 if security_manager.expecting_oob_data() {
    ///                     security_manager.received_oob_data(
    ///                         &connection_channel,
    ///                         oob_data
    ///                     ).await?;
    ///                 }  
    ///             }
    ///             _ => { /* process other protocols */ }   
    ///         }
    ///     }
    /// }
    /// # Ok(())
    /// # }.await;
    /// # };
    /// ```
    /// # Note
    /// The error `ConfirmValueFailed` can also be returned, but that means that the method was
    /// called at the correct time, just that pairing was going to fail because of the confirm value
    /// check failing.
    pub async fn received_oob_data<C>(&mut self, connection_channel: &C, data: &[u8]) -> Result<(), error!(A)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::BothSendOob) | PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
                private_key: Some(_),
                peer_public_key: Some(_),
                secret_key: Some(_),
                peer_nonce: None,
                external_oob_confirm_valid: false,
                ..
            }) => {
                self.oob_confirm_result(connection_channel, self.process_received_oob(data))
                    .await
            }
            _ => {
                self.send_err(connection_channel, pairing::PairingFailedReason::OOBNotAvailable)
                    .await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason).into())
            }
        }
    }

    /// Query the security manager if it is expecting some received OOB data
    ///
    /// This can be used to find the correct time to call the method `received_oob_data`. It is
    /// recommended to call this after every processed security manager message to know the
    /// correct time to call `received_oob_data`.
    pub fn expecting_oob_data(&self) -> bool {
        match self.pairing_data {
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::BothSendOob) | PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob),
                private_key: Some(_),
                peer_public_key: Some(_),
                secret_key: Some(_),
                peer_nonce: None,
                external_oob_confirm_valid: false,
                ..
            }) => true,
            _ => false,
        }
    }
}

/// The input of method `process`
pub struct Input<'a>(InputInner<'a>);

enum InputInner<'a> {
    AclData(&'a crate::l2cap::BasicInfoFrame<Vec<u8>>),
    YesNoInput(),
}

/// The return of method `process_command`
///
/// See the method [`SecurityManager::process_command`] for the use of this enum.
pub enum SecurityManagerStage {
    Pairing,
    RequiresYesNoInput,
    RequiresPasskeyInput,
    RequiresOobData,
    PairingComplete,
    BondingComplete,
}
