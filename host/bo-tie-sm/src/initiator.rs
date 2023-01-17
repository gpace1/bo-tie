//! Initiating side of the Security Manager
//!
//! The security manager used by the initiator begins the processing of pairing between the two
//! devices.
//!
//! # Builder
//! An initiating [`SecurityManger`] must be created from the builder [`SecurityManagerBuilder`].
//! The builder is used to configure the type of pairing performed and the bonding keys that allowed
//! for distribution by the security manager. The default builder does not distribute the identity
//! resolving key during bonding and use *just works* man in the middle (MITM) protection.
//! Unfortunately other forms of MITM protection require access to things outside the scope of the
//! implementation of this library.
//!
//! ```
#![cfg_attr(
    botiedocs,
    doc = r##"
# mod bo_tie {
#    mod sm {
#        pub use bo_tie_sm::*;
#    }
# }
use bo_tie::sm::initiator::SecurityManagerBuilder;
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
use super::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, GetXOfP256Key, PairingData, PairingMethod,
};
use crate::encrypt_info::AuthRequirements;
use crate::l2cap::ConnectionChannel;
use crate::pairing::{IOCapability, KeyDistributions, PairingFailedReason};
use crate::{
    EnabledBondingKeysBuilder, IdentityAddress, OobDirection, PasskeyAbility, PasskeyDirection, SecurityManagerError,
};
use alloc::vec::Vec;
use bo_tie_util::buffer::stack::LinearBuffer;
use bo_tie_util::BluetoothDeviceAddress;

macro_rules! error {
    ($connection_channel:ty) => {
        crate::SecurityManagerError<bo_tie_l2cap::send_future::Error<
            <$connection_channel as bo_tie_l2cap::ConnectionChannel>::SendFutErr>
        >
    }
}

/// Used to generate the r value for passkey entry
///
/// See rai/rbi in the toolbox function [`f4`]
///
/// [`f4`]: toolbox::f4
macro_rules! passkey_r {
    ($passkey:expr, $passkey_round:expr) => {
        if 0 == $passkey & (1 << $passkey_round) {
            0x80
        } else {
            0x81
        }
    };
}

pub struct SecurityManagerBuilder {
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: BluetoothDeviceAddress,
    this_address: BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
    enable_just_works: bool,
    enable_number_comparison: bool,
    enable_passkey: PasskeyAbility,
    oob: Option<OobDirection>,
    can_bond: bool,
    distribute_irk: bool,
    distribute_csrk: bool,
    accept_irk: bool,
    accept_csrk: bool,
    prior_keys: Option<super::Keys>,
    assert_check_mode_one: Option<bo_tie_gap::security::LeSecurityModeOne>,
    assert_check_mode_two: Option<bo_tie_gap::security::LeSecurityModeTwo>,
}

impl SecurityManagerBuilder {
    /// Create a new `MasterSecurityManagerBuilder`
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
            enable_number_comparison: false,
            enable_passkey: PasskeyAbility::None,
            oob: None,
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

impl SecurityManagerBuilder {
    /// Set the keys to the peer device if it is already paired
    ///
    /// This assigns the keys that were previously generated after a successful pair and bonding.
    /// This method should only be called after the identity of the peer and associated long term
    /// key (LTK) is known. Usually this is through successful resolving the resolvable private
    /// address *by the* peer device.
    pub fn set_already_paired(mut self, keys: super::Keys) -> Result<Self, &'static str> {
        if keys.get_ltk().is_some() {
            self.prior_keys = Some(keys);

            Ok(self)
        } else {
            Err("missing long term key")
        }
    }

    /// Use GAP's Security Mode One for the Configuration of the Security Manager
    ///
    /// This method ensures that the Security Manager meets the requirements of the `level` for
    /// Security Mode One. Security Mode One defines the requirements for authentication and
    /// encryption for data transfer within a connection.
    ///
    /// ### `Level1` and `Level2`
    /// Level one corresponds to no security and Level two corresponds to unauthenticated pairing.
    /// As far as creating a Security Manager is concerned these levels are equivalent (level one
    /// just means that use of a Security Manager is optional). When using either enum the Security
    /// Manager will be configured to allow just works pairing.
    ///
    /// If you only want to use `Level1`, then do not use a Security Manager.
    ///
    /// ### `Level3` and `Level4`
    /// Level three and level four are equivalent for this implementation of a Security Manager,
    /// because only Secure Connections is implemented. Level three requires authenticated pairing
    /// with encryption, and level four requires the same security but only using LE Secure
    /// Connections.
    ///
    /// Both these enums disable 'just works'. This means that the method [`build`] will panic if
    /// another pairing method is not enabled.
    ///
    /// [`build`]: SecurityManagerBuilder::build
    /// [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
    /// [`enable_passcode_entry`]: SecurityManagerBuilder::enable_passcode_entry
    /// [`enable_number_comparison`]
    pub fn ensure_security_mode_one(mut self, level: bo_tie_gap::security::LeSecurityModeOne) -> Self {
        self.assert_check_mode_one = level.into();
        self
    }

    /// Use GAP's Security Mode Two for the Configuration the Security Manager
    ///
    /// This method ensures that the Security Manager meets the requirements fo the `level` for
    /// Security Mode Two.
    ///
    /// Security Mode two defines the security aspects of signed data. For the Security Manager this
    /// sets the requirements for how the Connection Signature Resolving Key (CSRK) is distributed.
    ///
    /// ### Level 1
    /// No affect on the pairing requirements of the Security Manager.
    ///
    /// ### Level 2
    /// If the CSRK is configured to be sent by the method [`sent_bonding_keys`] or received by
    /// [`accepted_bonding_keys`], the pairing method 'just works' will be disabled. Either
    /// [`enable_number_comparison`] or [`enable_passcode_entry`] be called to set the pairing
    /// method, or the method [`build`] will panic.
    ///
    /// If a CSRK is neither sent nor accepted, then this level has no affect on the pairing
    /// requirements of the Security Manager.
    ///
    /// [`sent_bonding_keys`]: SecurityManagerBuilder::sent_bonding_keys
    /// [`accepted_bonding_keys`]: SecurityManagerBuilder::accepted_bonding_keys
    /// [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
    /// [`enable_passcode_entry`]: SecurityManagerBuilder::enable_passcode_entry
    /// [`build`]: SecurityManagerBuilder::build
    pub fn ensure_security_mode_two(mut self, mode: bo_tie_gap::security::LeSecurityModeTwo) -> Self {
        self.assert_check_mode_two = mode.into();
        self
    }

    /// Disable 'Just Works' Pairing
    ///
    /// Just works pairing requires no authentication to establish encryption. Disabling 'just
    /// works' requires the enabling of either passkey or number comparison pairing (see
    /// [`enable_number_comparison`] or [`enable_passcode_entry`]).
    ///
    /// [`enable_number_comparison`]: SecurityManagerBuilder::enable_number_comparison
    /// [`enable_passcode_entry`]: SecurityManagerBuilder::enable_passcode_entry
    pub fn disable_just_works(mut self) -> Self {
        self.enable_just_works = false;
        self
    }

    /// Enable 'Number Comparison' Pairing.
    ///
    /// Number Comparison requires the Bluetooth application user to confirm that numbers displayed
    /// on both devices are equivalent. This should only be enabled if this device can display six
    /// digits (base 10) and has some way for the user input the equivalent of 'yes' and 'no'.
    pub fn enable_number_comparison(mut self) -> Self {
        self.enable_number_comparison = true;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// This enabled passkey entry for a device that can both display and input six digits
    /// (base 10). Calling this means passkey entry is enabled for pairing where one device
    /// displays the passkey and the other device has the user inputs the passkey.
    ///
    /// # Notes
    /// * If the initiator has the ability to input a passkey, then this device will be used to
    ///   display the passkey.
    /// * This method overwrites the configuration set by [`enable_passkey_entry`] and
    ///   [`enable_passkey_display`]
    ///
    /// [`enable_passkey_entry`]: SecurityManagerBuilder::enable_passkey_entry
    /// [`enable_passkey_display`]: SecurityManagerBuilder::enable_passkey_display
    pub fn enable_passkey(mut self) -> Self {
        self.enable_passkey = PasskeyAbility::DisplayWithInput;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// Enable the input of a passkey `entry`. This should be used whenever a passkey can be entered
    /// but six digits (base 10) cannot be displayed.
    ///
    /// # Note
    /// This method overwrites the configuration set by [`enable_passkey`] and
    /// [`enable_passkey_display`]
    ///
    /// [`enable_passkey`]: SecurityManagerBuilder::enable_passkey
    /// [`enable_passkey_display`]: SecurityManagerBuilder::enable_passkey_display
    pub fn enable_passkey_entry(mut self) -> Self {
        self.enable_passkey = PasskeyAbility::InputOnly;
        self
    }

    /// Enable 'Passkey Entry' Pairing.
    ///
    /// Enable the display of a passkey `entry`. This should be used whenever six digits (base 10)
    /// can be displayed but digits cannot be input by the user.
    ///
    /// # Note
    /// This method overwrites the configuration set by [`enable_passkey_entry`] and
    /// [`enable_passkey_display`]
    ///
    /// [`enable_passkey_entry`]: SecurityManagerBuilder::enable_passkey_entry
    /// [`enable_passkey_display`]: SecurityManagerBuilder::enable_passkey_display
    pub fn enable_passkey_display(mut self) -> Self {
        self.enable_passkey = PasskeyAbility::DisplayOnly;
        self
    }

    /// Enable `Out of Band` Pairing
    ///
    /// This will enable the usage of out of band (OOB) pairing. The input `direction` is used for
    /// indicating the direction that OOB data can be sent.
    pub fn enable_oob(mut self, direction: OobDirection) -> Self {
        self.oob = Some(direction);
        self
    }

    /// Disable Bonding
    ///
    /// This creates a Security Manager that will not bond with the peer device after pairing is
    /// completed. Configuration set by [`sent_bonding_keys`] and [`accepted_bonding_keys`] will be
    /// ignored.
    ///
    /// [`sent_bonding_keys`]: SecurityManagerBuilder::sent_bonding_keys
    /// [`accepted_bonding_keys`]: SecurityManagerBuilder::accepted_bonding_keys
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
    ) -> Result<LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>, crate::SecurityManagerBuilderError>
    {
        let mut auth_req = LinearBuffer::new();

        // mandatory as only Secure Connections (not legacy) is supported
        auth_req.try_push(AuthRequirements::Sc).unwrap();

        if self.can_bond {
            auth_req.try_push(AuthRequirements::Bonding).unwrap();
        }

        if self.enable_number_comparison || self.enable_passkey.is_enabled() || self.oob.is_some() {
            auth_req.try_push(AuthRequirements::ManInTheMiddleProtection).unwrap();
        } else if !self.enable_just_works {
            return Err(crate::SecurityManagerBuilderError);
        }

        if self.enable_passkey.is_enabled() {
            auth_req.try_push(AuthRequirements::KeyPress).unwrap();
        }

        Ok(auth_req)
    }

    /// Create the [`SecurityManager`]
    ///
    /// This will create a `SecurityManager`.
    ///
    /// # Panic
    /// `build` will panic if the configuration does not enable any form of pairing.
    pub fn build(self) -> SecurityManager {
        self.try_build().unwrap()
    }

    /// Try to create the `SlaveSecurityManager`
    ///
    /// This equivalent to [`build`] except an error is returned instead of panicking.
    pub fn try_build(self) -> Result<SecurityManager, crate::SecurityManagerBuilderError> {
        let initiator_key_distribution = super::get_keys(self.accept_irk, self.accept_csrk);

        let responder_key_distribution = super::get_keys(self.distribute_irk, self.distribute_csrk);

        let io_capability = match (self.enable_number_comparison, self.enable_passkey) {
            (_, PasskeyAbility::DisplayWithInput) => IOCapability::KeyboardDisplay,
            (true, _) => IOCapability::DisplayWithYesOrNo,
            (false, PasskeyAbility::DisplayOnly) => IOCapability::DisplayOnly,
            (false, PasskeyAbility::InputOnly) => IOCapability::KeyboardOnly,
            (false, PasskeyAbility::None) => IOCapability::NoInputNoOutput,
        };

        if !self.enable_just_works && io_capability.no_io_capability() {
            return Err(crate::SecurityManagerBuilderError);
        }

        let auth_req = self.create_auth_req()?;

        Ok(SecurityManager {
            io_capability,
            oob: self.oob,
            auth_req,
            allow_just_works: self.enable_just_works,
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
            pairing_expected_cmd: None,
        })
    }
}

pub struct SecurityManager {
    io_capability: IOCapability,
    oob: Option<OobDirection>,
    auth_req: LinearBuffer<{ AuthRequirements::full_depth() }, AuthRequirements>,
    allow_just_works: bool,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_key_distribution: &'static [KeyDistributions],
    responder_key_distribution: &'static [KeyDistributions],
    initiator_address: BluetoothDeviceAddress,
    responder_address: BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    keys: Option<super::Keys>,
    link_encrypted: bool,
    pairing_expected_cmd: Option<super::CommandType>,
}

macro_rules! check_channel_id_and {
    ($data:expr, async $job:block ) => {
        if $data.get_channel_id() == super::L2CAP_CHANNEL_ID {
            $job
        } else {
            Err(Error::IncorrectL2capChannelId.into())
        }
    };
}

impl SecurityManager {
    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `MasterSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    pub fn set_encrypted(&mut self, is_encrypted: bool) {
        self.link_encrypted = is_encrypted
    }

    /// Get the pairing keys
    ///
    /// Pairing must be completed before these keys are generated
    pub fn get_keys(&self) -> Option<&super::Keys> {
        self.keys.as_ref()
    }

    async fn send<C, Cmd, P>(&self, connection_channel: &C, command: Cmd) -> Result<(), error!(C)>
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
            .map_err(|e| SecurityManagerError::Sender(e))
    }

    async fn send_err<C>(&mut self, connection_channel: &C, fail_reason: PairingFailedReason) -> Result<(), error!(C)>
    where
        C: ConnectionChannel,
    {
        self.pairing_data = None;

        self.pairing_expected_cmd = None;

        self.send(connection_channel, pairing::PairingFailed::new(fail_reason))
            .await
    }

    /// Send the Identity Resolving Key
    ///
    /// This will add the IRK to the cypher keys and send it to the other device if the internal
    /// encryption flag is set to true (by the method [`set_encrypted`]) and pairing has completed.
    ///
    /// If the input `irk` evaluates to `None` then an IRK is generated before being added and sent.
    ///
    /// The IRK is returned if it was successfully sent to the other device.
    ///
    /// [`set_encrypted`]: bo_tie_sm::initiator::SecurityManager::set_encrypted
    pub async fn send_irk<C, Irk>(&mut self, connection_channel: &C, irk: Irk) -> Result<u128, error!(C)>
    where
        C: ConnectionChannel,
        Irk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let irk = irk.into().unwrap_or(toolbox::rand_u128());

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
    /// encryption flag is set to true (by the method [`set_encrypted`]) and pairing has completed.
    ///
    /// If the input `csrk` evaluates to `None` then a CSRK is generated before being added and
    /// sent.
    ///
    /// The CSRK is returned if it was successfully sent to the other device
    ///
    /// # Note
    /// There is no input for the sign counter as the CSRK is considered a new value, and thus the
    /// sign counter within the CSRK will always be 0.
    ///
    /// [`set_encrypted`]: bo_tie_sm::initiator::SecurityManager::set_encrypted
    pub async fn send_csrk<C, Csrk>(&mut self, connection_channel: &C, csrk: Csrk) -> Result<u128, error!(C)>
    where
        C: ConnectionChannel,
        Csrk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            let csrk = csrk.into().unwrap_or(toolbox::rand_u128());

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

    /// Creating a Pairing Instance Identifier
    ///
    /// This returns a unique identifier used for a single pairing execution.
    fn new_instance() -> usize {
        static INSTANCE: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

        INSTANCE.fetch_add(1, core::sync::atomic::Ordering::Relaxed)
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
    /// # Error
    /// An error will occur if the encryption flag is not set or an error occurs trying to send the
    /// message to the peer device.
    ///
    /// [`set_encrypted`]: crate::sm::initiator::SecurityManager::set_encrypted
    pub async fn send_identity<C, I>(&mut self, connection_channel: &C, identity: I) -> Result<(), error!(C)>
    where
        C: ConnectionChannel,
        I: Into<Option<IdentityAddress>>,
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
                        IdentityAddress::StaticRandom(self.responder_address)
                    } else {
                        IdentityAddress::Public(self.responder_address)
                    }
                }
            }
        };

        if self.link_encrypted {
            self.send(
                connection_channel,
                match identity {
                    IdentityAddress::Public(addr) => encrypt_info::IdentityAddressInformation::new_pub(addr),
                    IdentityAddress::StaticRandom(addr) => {
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

            Ok(())
        } else {
            Err(Error::UnknownIfLinkIsEncrypted.into())
        }
    }

    /// Send the Pairing Request to the slave device
    ///
    /// This sends the pairing request security manage PDU to the slave which will initiate the
    /// pairing process
    async fn send_pairing_request<C>(&mut self, connection_channel: &C) -> Result<(), error!(C)>
    where
        C: ConnectionChannel,
    {
        self.pairing_data = None;

        let oob_data_flag = match self.oob {
            Some(OobDirection::BothSendOob | OobDirection::OnlyInitiatorSendsOob) => {
                pairing::OobDataFlag::AuthenticationDataFromRemoteDevicePresent
            }
            _ => pairing::OobDataFlag::AuthenticationDataNotPresent,
        };

        let pairing_request = pairing::PairingRequest::new(
            self.io_capability,
            oob_data_flag,
            self.auth_req.clone(),
            self.encryption_key_size_max,
            self.initiator_key_distribution,
            self.responder_key_distribution,
        );

        self.send(connection_channel, pairing_request).await
    }

    async fn process_pairing_response<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let response = match pairing::PairingResponse::try_from_command_format(payload) {
            Ok(response) => response,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        if response.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(connection_channel, PairingFailedReason::EncryptionKeySize)
                .await?;

            Ok(Status::PairingFailed(PairingFailedReason::EncryptionKeySize))
        } else {
            let oob_data_flag = match self.oob {
                Some(OobDirection::BothSendOob | OobDirection::OnlyInitiatorSendsOob) => {
                    pairing::OobDataFlag::AuthenticationDataFromRemoteDevicePresent
                }
                _ => pairing::OobDataFlag::AuthenticationDataNotPresent,
            };

            let pairing_method = PairingMethod::determine_method(
                oob_data_flag,
                response.get_oob_data_flag(),
                self.io_capability,
                response.get_io_capability(),
                false,
            );

            if pairing_method.is_just_works() && !self.allow_just_works {
                self.send_err(connection_channel, PairingFailedReason::AuthenticationRequirements)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::AuthenticationRequirements))
            } else {
                log::info!("(SM) pairing Method: {:?}", pairing_method);

                let initiator_io_cap = pairing::convert_io_cap(&self.auth_req, oob_data_flag, self.io_capability);
                let responder_io_cap = response.get_io_cap();

                let (private_key, public_key) = toolbox::ecc_gen();

                self.pairing_data = Some(PairingData {
                    instance: Self::new_instance(),
                    pairing_method,
                    public_key,
                    private_key: Some(private_key),
                    initiator_io_cap,
                    responder_io_cap,
                    nonce: toolbox::nonce(),
                    peer_public_key: None,
                    secret_key: None,
                    peer_nonce: None,
                    responder_random: 0,
                    mac_key: None,
                    ltk: None,
                    passkey: None,
                    initiator_random: 0,
                    peer_confirm: None,
                    passkey_round: 0,
                    number_comp_validated: false,
                    initiator_dh_key_check: None,
                });

                self.pairing_expected_cmd = CommandType::PairingPublicKey.into();

                self.send_pairing_pub_key(connection_channel).await?;

                Ok(Status::None)
            }
        }
    }

    /// Send the pairing pub key
    ///
    /// This must be called only after the pairing response is received from the responder Security
    /// Manager.
    ///
    /// # Panic
    /// This will panic if the pairing data has not already been created and the public/private keys
    /// were not generated.
    async fn send_pairing_pub_key<C>(&mut self, connection_channel: &C) -> Result<(), error!(C)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData { ref public_key, .. }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_command_format();

                    let mut raw_key = [0u8; 64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                self.send(connection_channel, pairing::PairingPubKey::new(raw_pub_key))
                    .await?;

                Ok(())
            }
            _ => unreachable!(),
        }
    }

    /// Process the responders public key
    ///
    /// This should be received after this sends its public key to the responder Security Manager.
    ///
    /// # Error
    /// If this is received out of the expected order.
    ///
    /// # Panic
    /// This will panic  
    async fn process_responder_pub_key<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let peer_pub_key = match pairing::PairingPubKey::try_from_command_format(payload) {
            Ok(public_key) => public_key,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method,
                ref mut private_key,
                ref mut peer_public_key,
                ref mut secret_key,
                ..
            }) => {
                let remote_pub_key = match toolbox::PubKey::try_from_command_format(&peer_pub_key.get_key()) {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                            .await?;

                        return Err(e.into());
                    }
                };

                let this_pri_key = private_key.take().unwrap();

                *secret_key = toolbox::ecdh(this_pri_key, &remote_pub_key).into();

                *peer_public_key = remote_pub_key.into();

                match pairing_method {
                    PairingMethod::JustWorks | PairingMethod::NumbComp => {
                        self.pairing_expected_cmd = CommandType::PairingConfirm.into();

                        Ok(Status::None)
                    }
                    PairingMethod::Oob(direction) => {
                        self.pairing_expected_cmd = None;

                        match direction {
                            OobDirection::OnlyInitiatorSendsOob => {
                                Ok(Status::OutOfBandOutput(OutOfBandOutput::new(self)))
                            }
                            OobDirection::OnlyResponderSendsOob => Ok(Status::OutOfBandInput(OutOfBandInput)),
                            OobDirection::BothSendOob => {
                                Ok(Status::OutOfBandInputOutput(OutOfBandInput, OutOfBandOutput::new(self)))
                            }
                        }
                    }
                    PairingMethod::PassKeyEntry(direction) => match direction {
                        PasskeyDirection::ResponderDisplaysInitiatorInputs => {
                            self.pairing_expected_cmd = None;

                            let input = PasskeyInput::new(self, connection_channel, false).await?;

                            Ok(Status::PasskeyInput(input))
                        }
                        PasskeyDirection::InitiatorAndResponderInput => {
                            self.pairing_expected_cmd = CommandType::PairingKeyPressNotification.into();

                            let input = PasskeyInput::new(self, connection_channel, true).await?;

                            Ok(Status::PasskeyInput(input))
                        }
                        PasskeyDirection::InitiatorDisplaysResponderInputs => {
                            self.pairing_expected_cmd = CommandType::PairingKeyPressNotification.into();

                            Ok(Status::PasskeyOutput(PasskeyOutput::new(self)))
                        }
                    },
                }
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Process the responders confirm
    ///
    /// When this is received depends on the pairing procedure (in phase 2).
    /// * For just works or number comparison this is received after the responder Security
    ///   Manager sends its public key.
    /// * For Passkey this is received after this Security Manager sends its confirm, and this is
    ///   done twenty times (as the passkey process repeats twenty times).
    /// * This is **not** received with out of band pairing
    ///
    /// # Panic
    /// This will panic if pairing data is not set.
    async fn process_responder_confirm<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let responder_confirm = match pairing::PairingConfirm::try_from_command_format(payload) {
            Ok(public_key) => public_key,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks | PairingMethod::NumbComp | PairingMethod::PassKeyEntry(_),
                ref mut peer_confirm,
                nonce,
                ..
            }) => {
                *peer_confirm = responder_confirm.get_value().into();

                log::trace!("(SM) initiator nonce: {:?}", nonce);

                self.pairing_expected_cmd = CommandType::PairingRandom.into();

                self.send(connection_channel, pairing::PairingRandom::new(nonce))
                    .await?;

                Ok(Status::None)
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason).into())
            }
        }
    }

    /// Process the Responders Nonce
    ///
    /// This is received after this Security Manager sends its nonce to the responding Security
    /// Manager, for every pairing method. For passkey though, this is received twenty times.
    ///
    /// # Return
    /// A status is returned as pairing can fail. The status returned is either `None` or
    /// `PairingFailed(PairingFailedReason::ConfirmValueFailed)`.
    async fn process_responder_random<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let responder_nonce = match pairing::PairingRandom::try_from_command_format(payload) {
            Ok(pairing_random) => pairing_random.get_value(),
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        log::trace!("(SM) responder Nonce: {:?}", responder_nonce);

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks,
                ref mut peer_nonce,
                peer_public_key: Some(ref peer_public_key),
                ref public_key,
                peer_confirm: Some(responder_confirm),
                ..
            }) => {
                let pka = GetXOfP256Key::x(public_key);

                let pkb = GetXOfP256Key::x(peer_public_key);

                let calculated_confirm = toolbox::f4(pka, pkb, responder_nonce, 0);

                if responder_confirm == calculated_confirm {
                    *peer_nonce = responder_nonce.into();

                    self.pairing_expected_cmd = CommandType::PairingDHKeyCheck.into();

                    self.send_initiator_dh_key_check(connection_channel).await
                } else {
                    self.send_err(connection_channel, PairingFailedReason::ConfirmValueFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::ConfirmValueFailed))
                }
            }
            Some(PairingData {
                pairing_method: PairingMethod::NumbComp,
                nonce,
                ref mut peer_nonce,
                peer_public_key: Some(ref peer_public_key),
                ref public_key,
                peer_confirm: Some(responder_confirm),
                ..
            }) => {
                let pka = GetXOfP256Key::x(public_key);

                let pkb = GetXOfP256Key::x(peer_public_key);

                let calculated_confirm = toolbox::f4(pka, pkb, responder_nonce, 0);

                if responder_confirm == calculated_confirm {
                    *peer_nonce = responder_nonce.into();

                    let na = nonce;

                    let nb = responder_nonce;

                    let v = toolbox::g2(pka, pkb, na, nb);

                    Ok(Status::NumberComparison(NumberComparison::new(self, v)))
                } else {
                    self.send_err(connection_channel, PairingFailedReason::ConfirmValueFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::ConfirmValueFailed))
                }
            }
            Some(PairingData {
                pairing_method: PairingMethod::PassKeyEntry(_),
                ref mut peer_nonce,
                peer_public_key: Some(ref peer_public_key),
                ref public_key,
                peer_confirm: Some(responder_confirm),
                passkey: Some(passkey),
                ref mut passkey_round,
                ..
            }) => {
                *peer_nonce = responder_nonce.into();

                let pka = GetXOfP256Key::x(public_key);

                let pkb = GetXOfP256Key::x(peer_public_key);

                let r = passkey_r!(passkey, *passkey_round);

                if responder_confirm == toolbox::f4(pkb, pka, responder_nonce, r) {
                    *passkey_round += 1;

                    if *passkey_round < 20 {
                        self.send_passkey_confirm(connection_channel).await
                    } else {
                        self.pairing_expected_cmd = CommandType::PairingDHKeyCheck.into();

                        self.send_initiator_dh_key_check(connection_channel).await
                    }
                } else {
                    self.send_err(connection_channel, PairingFailedReason::ConfirmValueFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::ConfirmValueFailed))
                }
            }
            Some(PairingData {
                pairing_method: PairingMethod::Oob(_),
                ref mut peer_nonce,
                ..
            }) => {
                *peer_nonce = responder_nonce.into();

                self.pairing_expected_cmd = CommandType::PairingDHKeyCheck.into();

                self.send_initiator_dh_key_check(connection_channel).await
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn send_initiator_dh_key_check<C>(&mut self, connection_channel: &C) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData {
                secret_key: Some(ref dh_key),
                nonce,
                peer_nonce: Some(ref peer_nonce),
                initiator_io_cap,
                responder_random,
                ref mut mac_key,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                log::trace!("(SM) secret key: {:x?}", dh_key);
                log::trace!("(SM) remote nonce: {:x?}", peer_nonce);
                log::trace!("(SM) this nonce: {:x?}", nonce);
                log::trace!("(SM) remote address: {:x?}", a_addr);
                log::trace!("(SM) this address: {:x?}", b_addr);

                let (gen_mac_key, ltk) = toolbox::f5(*dh_key, nonce, *peer_nonce, a_addr.clone(), b_addr.clone());

                log::trace!("(SM) mac_key: {:x?}", gen_mac_key);
                log::trace!("(SM) ltk: {:x?}", ltk);
                log::trace!("(SM) initiator_io_cap: {:x?}", initiator_io_cap);

                let ea = toolbox::f6(
                    gen_mac_key,
                    nonce,
                    *peer_nonce,
                    responder_random,
                    initiator_io_cap,
                    a_addr,
                    b_addr,
                );

                let mut keys = crate::Keys::new();

                keys.ltk = Some(ltk);

                self.keys = Some(keys);

                *mac_key = gen_mac_key.into();

                self.send(connection_channel, pairing::PairingDhKeyCheck::new(ea))
                    .await?;

                Ok(Status::None)
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn process_responder_dh_key_check<C>(
        &mut self,
        connection_channel: &C,
        payload: &[u8],
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let eb = match pairing::PairingDhKeyCheck::try_from_command_format(payload) {
            Ok(dh_key_check) => dh_key_check,
            Err(e) => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match self.pairing_data.take() {
            Some(PairingData {
                nonce,
                peer_nonce: Some(peer_nonce),
                responder_io_cap,
                initiator_random,
                mac_key: Some(mac_key),
                ltk: ltk @ Some(_),
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(&self.initiator_address, self.initiator_address_is_random);

                let b_addr = toolbox::PairingAddress::new(&self.responder_address, self.responder_address_is_random);

                let calc_eb = toolbox::f6(
                    mac_key,
                    peer_nonce,
                    nonce,
                    initiator_random,
                    responder_io_cap,
                    b_addr,
                    a_addr,
                );

                if eb.get_key_check() == calc_eb {
                    self.keys = Some(crate::Keys {
                        is_authenticated: !self.allow_just_works,
                        ltk,
                        csrk: None,
                        irk: None,
                        identity: if self.responder_address_is_random {
                            IdentityAddress::StaticRandom(self.responder_address)
                        } else {
                            IdentityAddress::Public(self.responder_address)
                        }
                        .into(),
                        peer_csrk: None,
                        peer_irk: None,
                        peer_identity: if self.initiator_address_is_random {
                            IdentityAddress::StaticRandom(self.initiator_address)
                        } else {
                            IdentityAddress::Public(self.initiator_address)
                        }
                        .into(),
                    });

                    self.pairing_expected_cmd = None;

                    Ok(Status::PairingComplete)
                } else {
                    self.send_err(connection_channel, PairingFailedReason::DhKeyCheckFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::DhKeyCheckFailed))
                }
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn process_keypress<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let kp = match pairing::KeyPressNotification::try_from_command_format(payload) {
            Ok(responder_confirm) => responder_confirm,
            Err(e) => {
                self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Err(e.into());
            }
        };

        match kp {
            pairing::KeyPressNotification::PasskeyEntryCompleted => self.send_passkey_confirm(connection_channel).await,
            pairing::KeyPressNotification::PasskeyEntryStarted => Ok(Status::None),
            _ => {
                /* todo: reset security manager timeout */
                Ok(Status::None)
            }
        }
    }

    /// Begin Pairing to the Peripheral
    ///
    /// This begins the pairing process by sending the request for the peripheral's pairing
    /// information. This function is required to be called before `continue_pairing` can be used to
    /// process and send further Security Manager PDU's to the slave.
    pub async fn start_pairing<C>(&mut self, connection_channel: &C) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        self.pairing_expected_cmd = CommandType::PairingResponse.into();

        self.send_pairing_request(connection_channel).await?;

        Ok(Status::None)
    }

    /// Continue Pairing
    ///
    /// This is used to continue pairing until pairing is either complete, fails, or user input
    /// is required for authentication. It must be called for every received Security Manager ACL
    /// data. The returned `Status` is used to indicate the next step in the procedure.
    pub async fn continue_pairing<C>(
        &mut self,
        connection_channel: &C,
        acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        check_channel_id_and!(acl_data, async {
            let (d_type, payload) = acl_data.get_payload().split_at(1);

            match CommandType::try_from_val(d_type[0]) {
                Ok(CommandType::PairingFailed) => {
                    self.pairing_data = None;

                    self.pairing_expected_cmd = super::CommandType::PairingFailed.into();

                    Ok(Status::PairingFailed(
                        pairing::PairingFailed::try_from_command_format(payload)?.get_reason(),
                    ))
                }
                Ok(cmd) if Some(cmd) == self.pairing_expected_cmd => self.next_step(connection_channel, payload).await,
                Ok(cmd) => {
                    self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                        .await?;

                    Err(Error::IncorrectCommand {
                        expected: self.pairing_expected_cmd,
                        received: cmd,
                    }
                    .into())
                }
                Err(e) => {
                    self.send_err(connection_channel, pairing::PairingFailedReason::UnspecifiedReason)
                        .await?;

                    Err(e.into())
                }
            }
        })
    }

    async fn next_step<C>(&mut self, connection_channel: &C, payload: &[u8]) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        let status_rslt = match self.pairing_expected_cmd {
            Some(CommandType::PairingKeyPressNotification) => self.process_keypress(connection_channel, payload).await,
            Some(CommandType::PairingResponse) => self.process_pairing_response(connection_channel, payload).await,
            Some(CommandType::PairingPublicKey) => self.process_responder_pub_key(connection_channel, payload).await,
            Some(CommandType::PairingConfirm) => self.process_responder_confirm(connection_channel, payload).await,
            Some(CommandType::PairingRandom) => self.process_responder_random(connection_channel, payload).await,
            Some(CommandType::PairingDHKeyCheck) => {
                self.process_responder_dh_key_check(connection_channel, payload).await
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        };

        if let Ok(Status::PairingFailed(_)) | Err(_) = status_rslt {
            self.pairing_expected_cmd = None;
        };

        status_rslt
    }

    /// Process "bonding" packets
    ///
    /// Bonding keys are sent from the peer device (hopefully) as soon as encryption is first
    /// established between it and this device. After pairing is completed, any received security
    /// manager packets need to be processed by this method.
    ///
    /// This method is used for processing bonding packets, but only when the link is encrypted. The
    /// method [`set_encrypted`] needs to be called to indicate the link is encrypted before this
    /// method can be called without it returning an error.
    ///
    /// # Return
    /// The return is boolean to indicate that bonding is completed. `true` is returned once all
    /// keys of the peer device are received as determined by the pairing request/response exchange.
    ///
    /// # Errors
    ///
    /// ### Always Errors
    /// An error is always returned if any of the pairing specific or legacy key Security Manager
    /// messages are processed by this method (only secure connections is supported by this
    /// library). Trying to process any of following will always cause an error to be returned.
    /// * [`set_encrypted`]
    /// * [`PairingRequest`]
    /// * [`PairingResponse`]
    /// * [`PairingConfirm`]
    /// * [`PairingRandom`]
    /// * [`PairingFailed`]
    /// * [`EncryptionInformation`]
    /// * [`MasterIdentification`]
    /// * [`PairingPublicKey`]
    /// * [`PairingDHKeyCheck`]
    /// * [`SecurityRequest`]
    ///
    /// ### Require Encryption
    /// The following Security Manager messages will have this method return an error unless the
    /// internal encryption flag is set with method `set_encrypted`.
    /// * [`IdentityInformation`]
    /// * [`IdentityAddressInformation`]
    /// * [`SigningInformation`]
    ///
    /// [`set_encrypted`]: SecurityManager::set_encrypted
    /// [`PairingRequest`]: CommandType::PairingRequest
    /// [`PairingResponse`]: CommandType::PairingResponse
    /// [`PairingConfirm`]: CommandType::PairingConfirm
    /// [`PairingRandom`]: CommandType::PairingRandom
    /// [`PairingFailed`]: CommandType::PairingFailed
    /// [`EncryptionInformation`]: CommandType::EncryptionInformation
    /// [`MasterIdentification`]: CommandType::MasterIdentification
    /// [`PairingPublicKey`]: CommandType::PairingPublicKey
    /// [`PairingDHKeyCheck`]: CommandType::PairingDHKeyCheck
    /// [`PairingKeyPressNotification`]: CommandType::PairingKeyPressNotification
    /// [`IdentityInformation`]: CommandType::IdentityInformation
    /// [`IdentityAddressInformation`]: CommandType::IdentityAddressInformation
    /// [`SigningInformation`]: CommandType::SigningInformation
    pub async fn process_bonding(&mut self, acl_data: &crate::l2cap::BasicInfoFrame<Vec<u8>>) -> Result<bool, Error> {
        macro_rules! set_peer_key {
            ($this:expr, $key_val: expr, $key:ident) => {
                match ($this.link_encrypted, $this.keys.is_some()) {
                    (true, true) => {
                        *$this.keys.as_mut().and_then(|keys| keys.$key.as_mut()).unwrap() = $key_val;

                        for key_kind in $this.responder_key_distribution {
                            match key_kind {
                                $crate::pairing::KeyDistributions::EncKey => (),
                                $crate::pairing::KeyDistributions::IdKey => {
                                    if $this
                                        .keys
                                        .as_ref()
                                        .and_then(|keys| keys.peer_irk.as_ref())
                                        .is_none()
                                    {
                                        return Ok(false);
                                    }
                                }
                                $crate::pairing::KeyDistributions::SignKey => {
                                    if $this
                                        .keys
                                        .as_ref()
                                        .and_then(|keys| keys.peer_csrk.as_ref())
                                        .is_none()
                                    {
                                        return Ok(false);
                                    }
                                }
                            }
                        }

                        Ok(true)
                    }
                    (false, _) => Err(Error::UnknownIfLinkIsEncrypted.into()),
                    (_, false) => Err(Error::OperationRequiresPairing.into()),
                }
            };
        }

        check_channel_id_and!(acl_data, async {
            let (d_type, payload) = acl_data.get_payload().split_at(1);

            match CommandType::try_from_val(d_type[0])? {
                CommandType::IdentityInformation => {
                    let irk = encrypt_info::IdentityInformation::try_from_command_format(payload)?.get_irk();

                    set_peer_key!(self, irk, peer_irk)
                }
                CommandType::SigningInformation => {
                    let csrk = encrypt_info::SigningInformation::try_from_command_format(payload)?.get_signature_key();

                    set_peer_key!(self, (csrk, 0), peer_csrk)
                }
                CommandType::IdentityAddressInformation => {
                    let identity = encrypt_info::IdentityAddressInformation::try_from_command_format(payload)?.into();

                    set_peer_key!(self, identity, peer_identity)
                }
                c => Err(Error::IncorrectCommand {
                    expected: None,
                    received: c,
                }
                .into()),
            }
        })
    }

    async fn process_number_comparison<C>(
        &mut self,
        connection_channel: &C,
        accepted: bool,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        if accepted {
            self.send_err(connection_channel, PairingFailedReason::NumericComparisonFailed)
                .await?;

            Ok(Status::PairingFailed(PairingFailedReason::NumericComparisonFailed))
        } else {
            match &self.pairing_data {
                Some(PairingData {
                    pairing_method: PairingMethod::NumbComp,
                    ..
                }) => self.send_initiator_dh_key_check(connection_channel).await,
                _ => {
                    self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
                }
            }
        }
    }

    async fn process_input_passkey<C>(&mut self, connection_channel: &C, passkey_val: u32) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData { ref mut passkey, .. }) => {
                *passkey = passkey_val.into();

                self.send_passkey_confirm(connection_channel).await
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn process_input_oob<C>(
        &mut self,
        connection_channel: &C,
        _address: BluetoothDeviceAddress,
        random: u128,
        confirm: u128,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData {
                peer_public_key: Some(ref peer_public_key),
                ref mut nonce,
                ..
            }) => {
                let pkb = GetXOfP256Key::x(peer_public_key);

                if confirm == toolbox::f4(pkb, pkb, random, 0) {
                    *nonce = toolbox::nonce();

                    let pairing_random = pairing::PairingRandom::new(*nonce);

                    self.send(connection_channel, pairing_random).await?;

                    self.pairing_expected_cmd = CommandType::PairingRandom.into();

                    Ok(Status::None)
                } else {
                    self.send_err(connection_channel, PairingFailedReason::ConfirmValueFailed)
                        .await?;

                    Ok(Status::PairingFailed(PairingFailedReason::ConfirmValueFailed))
                }
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn send_passkey_confirm<C>(&mut self, connection_channel: &C) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        match self.pairing_data {
            Some(PairingData {
                ref public_key,
                peer_public_key: Some(ref peer_public_key),
                ref mut nonce,
                passkey: Some(passkey),
                passkey_round,
                ..
            }) => {
                let pka = GetXOfP256Key::x(public_key);

                let pkb = GetXOfP256Key::x(peer_public_key);

                *nonce = toolbox::nonce();

                let ra0 = passkey_r!(passkey, passkey_round);

                let confirm = pairing::PairingConfirm::new(toolbox::f4(pka, pkb, *nonce, ra0));

                self.send(connection_channel, confirm).await?;

                self.pairing_expected_cmd = CommandType::PairingConfirm.into();

                Ok(Status::None)
            }
            _ => {
                self.send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason))
            }
        }
    }
}

pub enum Status {
    None,
    PairingFailed(PairingFailedReason),
    PairingComplete,
    BondingComplete,
    NumberComparison(NumberComparison),
    PasskeyInput(PasskeyInput),
    PasskeyOutput(PasskeyOutput),
    OutOfBandInput(OutOfBandInput),
    OutOfBandOutput(OutOfBandOutput),
    OutOfBandInputOutput(OutOfBandInput, OutOfBandOutput),
}

macro_rules! security_manager_check {
    ($sm:expr, $instance:expr) => {
        match $sm.pairing_data.as_ref() {
            None => return Err(InputError::NotPairing.into()),
            Some(pd) => {
                if pd.instance != $instance {
                    return Err(InputError::InstanceNoLongerValid.into());
                }
            }
        }
    };
}

/// Input related error
///
/// Returned as part of the error type for methods of the user input authentication types.
#[derive(Debug)]
enum InputError<E> {
    NotPairing,
    InstanceNoLongerValid,
    SecurityManager(E),
}

impl<E> core::fmt::Display for InputError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            InputError::NotPairing => f.write_str("devices are no longer pairing"),
            InputError::InstanceNoLongerValid => f.write_str("used by a prior pairing attempt"),
            InputError::SecurityManager(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for InputError<E> where E: std::error::Error {}

/// User Input and Output for Number Comparison
///
/// This is returned by [`process_command`] when the Security Manager reaches the point in pairing
/// where it requires the application user to perform number comparison.
///
/// The value can be shown to the application user via the implementation of `Display`.
///
/// ## Pairing Process Instanced
/// A `NumberComparison` is tied to a single pairing instance. If pairing fails or stops for any
/// reason, then the `NumberComparison` that was created for it should be dropped. Methods [`yes`]
/// and [`no`] will return an error if the specific pairing process that created a
/// `NumberComparison` is no longer executing.
///
/// [`process`]: SecurityManager::process
/// [`yes`]: NumberComparison::yes
/// [`no`]: NumberComparison::no
pub struct NumberComparison {
    instance: usize,
    val: u32,
}

impl NumberComparison {
    /// Create a new `NumberComparison`
    ///
    /// Input `val` is the passcode value to be displayed to application user.
    ///
    /// # Panic
    /// `security_manager` must have its field `pairing_data` as `Some(_)`
    fn new(security_manager: &SecurityManager, val: u32) -> Self {
        let instance = security_manager.pairing_data.as_ref().unwrap().instance;

        // displayed values are only 6 digits
        let val = val % 1_000_000;

        Self { instance, val }
    }

    /// Yes Confirmation From the Application User
    ///
    /// This should be called once the user has confirmed the number comparison value.
    pub async fn yes<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, NumberComparisonError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        security_manager
            .process_number_comparison(connection_channel, true)
            .await
            .map_err(|e| InputError::SecurityManager(e).into())
    }

    /// Yes Confirmation From the Application User
    ///
    /// This should be called once the user has denied the validity of the number comparison value.
    pub async fn no<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, NumberComparisonError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        security_manager
            .process_number_comparison(connection_channel, false)
            .await
            .map_err(|e| InputError::SecurityManager(e).into())
    }
}

impl core::fmt::Display for NumberComparison {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:06}", self.val)
    }
}

/// Error for [`NumberComparison`]
///
/// This is returned by the methods [`yes`] and [`no`] of `NumberComparison`
///
/// [`yes`]: NumberComparison::yes
/// [`no`]: NumberComparison::no
pub struct NumberComparisonError<E>(InputError<E>);

impl<E> core::fmt::Debug for NumberComparisonError<E>
where
    E: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        core::fmt::Debug::fmt(&self.0, f)
    }
}

impl<E> core::fmt::Display for NumberComparisonError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self.0 {
            InputError::InstanceNoLongerValid => f.write_str(
                "this instance of a \
                `NumberComparison` no longer valid and it should be dropped",
            ),
            _ => core::fmt::Display::fmt(&self.0, f),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for NumberComparisonError<E> where E: std::error::Error {}

impl<E> From<InputError<E>> for NumberComparisonError<E> {
    fn from(e: InputError<E>) -> Self {
        NumberComparisonError(e)
    }
}

/// Passkey Input
///
/// This is returned by the Security Manager's [`process_command`] method when it requires a passkey
/// input from the application user.
///
/// ## Pairing Process Instanced
/// A `PasskeyInput` is tied to a single pairing instance. If pairing fails or stops for any
/// reason, then the `PasskeyInput` that was created for it should be dropped. Methods of a
/// `PasskeyInput` will return an error if the specific pairing process that created a
/// `PasskeyInput` is no longer executing.
pub struct PasskeyInput {
    instance: usize,
    passkey: [char; 6],
    key_count: usize,
    both: bool,
}

impl PasskeyInput {
    /// Create a new `PasscodeInput`
    ///
    /// This sends the keypress notification *passkey entry started* before a `PasscodeInput` is
    /// returned.
    ///
    /// # Panic
    /// `security_manager` must have its field `pairing_data` as `Some(_)`
    async fn new<C>(
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        both_enter: bool,
    ) -> Result<Self, error!(C)>
    where
        C: ConnectionChannel,
    {
        let instance = security_manager.pairing_data.as_ref().unwrap().instance;

        security_manager
            .send(connection_channel, pairing::KeyPressNotification::PasskeyEntryStarted)
            .await?;

        Ok(Self {
            instance,
            passkey: Default::default(),
            key_count: 0,
            both: both_enter,
        })
    }

    /// Check if the Application User is to input a passkey on both devices
    ///
    /// This is a check to see if the user will need to input the same passkey on both devices.
    pub fn is_passkey_input_on_both(&self) -> bool {
        self.both
    }

    /// Get the number of digits
    ///
    /// This returns the number of digits that are currently within this `PasscodeInput`.
    pub fn count(&self) -> usize {
        self.key_count
    }

    /// Add a Character to the Passkey
    ///
    /// This adds a digit character to the passkey. The `security_manager` will send a keypress
    /// notification to the peer device's Security Manager containing *passkey digit entered*.
    ///
    /// # Errors
    /// 1) `digit` must be a base 10 digit character and there must be less than six digits within
    ///    this passcode.
    /// 2) The `connection_channel` is closed and the `security_manager` fails to send the keypress
    ///    notification because.
    pub async fn add<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        digit: char,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        if self.key_count >= 6 {
            Err(PasscodeInputError::TooManyDigits)
        } else if !digit.is_digit(10) {
            Err(PasscodeInputError::NotADigit)
        } else {
            self.passkey[self.key_count] = digit;

            self.key_count += 1;

            security_manager
                .send(connection_channel, pairing::KeyPressNotification::PasskeyDigitErased)
                .await
                .map_err(|e| PasscodeInputError::SecurityManager(e))?;

            Ok(())
        }
    }

    /// Insert a Character Into the Passkey
    ///
    /// This inserts a digit character to the passkey. The digit is inserted at the position
    /// `index`. `index` must less than or equal to the current number of passkey digits within this
    /// `PasskeyInput`. The `security_manager` will send a keypress notification to the peer
    /// device's Security Manager containing *passkey digit entered*.
    ///
    /// # Errors
    /// 1) `digit` must be a base 10 digit character and there must be less than six digits within
    ///    this passcode.
    /// 2) `index` must be a valid position to insert `digit` into the passcode.
    /// 3) The `connection_channel` is closed and the `security_manager` fails to send the keypress
    ///    notification because.
    pub async fn insert<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        digit: char,
        index: usize,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        if self.key_count >= 6 {
            Err(PasscodeInputError::TooManyDigits)
        } else if !digit.is_digit(10) {
            Err(PasscodeInputError::NotADigit)
        } else if index > self.key_count {
            Err(PasscodeInputError::IndexOutOfBounds)
        } else {
            self.key_count += 1;

            self.passkey[index..self.key_count].rotate_right(1);

            self.passkey[index] = digit;

            security_manager
                .send(connection_channel, pairing::KeyPressNotification::PasskeyDigitEntered)
                .await
                .map_err(|e| PasscodeInputError::SecurityManager(e))?;

            Ok(())
        }
    }

    /// Remove a Character From the Passkey
    ///
    /// This is used to remove a character from the passkey. This should be called whenever the user
    /// deletes a single character of the passkey. `index` is the position of the digit that was
    /// deleted by the user. The `security_manager` will send a keypress notification to the peer
    /// device's Security Manager containing *passkey digit erased*.
    ///
    /// # Errors
    /// 1) 'index' must be a valid position to remove a `digit` of the passcode
    /// 2) The `connection_channel` is closed and the `security_manager` fails to send the keypress
    ///    notification because.
    pub async fn remove<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        index: usize,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        if index >= self.key_count {
            Err(PasscodeInputError::IndexOutOfBounds)
        } else {
            self.passkey[index..self.key_count].rotate_left(1);

            self.key_count -= 1;

            security_manager
                .send(connection_channel, pairing::KeyPressNotification::PasskeyDigitErased)
                .await
                .map_err(|e| PasscodeInputError::SecurityManager(e))?;

            Ok(())
        }
    }

    /// Clear the passcode
    ///
    /// All digits within this `PasscodeInput` are cleared. The `security_manager` will send a
    /// keypress notification to the peer device's Security Manager containing *passkey cleared*.
    ///
    /// # Error
    /// The `connection_channel` is closed and the `security_manager` fails to send the keypress
    /// notification because.
    pub async fn clear<C>(
        &mut self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        self.passkey = Default::default();
        self.key_count = 0;

        security_manager
            .send(connection_channel, pairing::KeyPressNotification::PasskeyCleared)
            .await
            .map_err(|e| PasscodeInputError::SecurityManager(e))?;

        Ok(())
    }

    /// Complete the passcode
    ///
    /// After the user has entered in all six digits and is satisfied with the input, this method
    /// is used to complete the passcode entry. The `security_manager` will send a keypress
    /// notification to the peer device's Security Manager containing *passkey completed*.
    pub async fn complete<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        if self.key_count != 6 {
            Err(PasscodeInputError::NotComplete)
        } else {
            let mut passkey_val = 0;
            let mut mul = 100_000;

            for i in 0..6 {
                passkey_val += self.passkey[i].to_digit(10).unwrap() * mul;

                mul /= 10;
            }

            security_manager
                .send(connection_channel, pairing::KeyPressNotification::PasskeyEntryCompleted)
                .await
                .map_err(|e| PasscodeInputError::SecurityManager(e))?;

            security_manager
                .process_input_passkey(connection_channel, passkey_val)
                .await
                .map_err(|e| PasscodeInputError::SecurityManager(e))
        }
    }

    /// Write the Passcode to this input.
    ///
    /// When the user is able to easily manipulate a passcode it can be easier to set the entire
    /// passcode instead of dealing with individual digits. The application should still send
    /// keypress notifications with the method [`send_notification`].
    ///
    /// [`send_notification`]: PasskeyInput::send_notification
    pub fn write(&mut self, passcode: [char; 6]) -> Result<(), PasscodeInputError<()>> {
        if passcode.iter().find(|key| !key.is_digit(10)).is_some() {
            Err(PasscodeInputError::NotADigit)
        } else {
            self.passkey = passcode;
            self.key_count = 6;
            Ok(())
        }
    }

    /// Send a keystroke entry notification
    ///
    /// This will send a keystroke entry notification without adding a digit to this `PasskeyInput`
    pub async fn send_key_entry<C>(
        &self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        security_manager
            .send(connection_channel, pairing::KeyPressNotification::PasskeyDigitEntered)
            .await
            .map_err(|e| PasscodeInputError::SecurityManager(e))
    }

    /// Send a keystroke erase notification
    ///
    /// This will send a keystroke erase notification without removing a digit to this `PasskeyInput`
    pub async fn send_key_erase<C>(
        &self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        security_manager
            .send(connection_channel, pairing::KeyPressNotification::PasskeyDigitErased)
            .await
            .map_err(|e| PasscodeInputError::SecurityManager(e))?;

        Ok(())
    }

    /// Send a keystroke erase notification
    ///
    /// This will send a keystroke clear notification without clearing a digit to this `PasskeyInput`
    pub async fn send_key_clear<C>(
        &self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<(), PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        security_manager
            .send(connection_channel, pairing::KeyPressNotification::PasskeyCleared)
            .await
            .map_err(|e| PasscodeInputError::SecurityManager(e))
    }

    /// Passkey failure
    ///
    /// This sends the passkey entry failed error to the device
    pub async fn fail<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, PasscodeInputError<error!(C)>>
    where
        C: ConnectionChannel,
    {
        security_manager_check!(security_manager, self.instance);

        security_manager
            .send_err(connection_channel, PairingFailedReason::PasskeyEntryFailed)
            .await
            .map_err(|e| PasscodeInputError::SecurityManager(e))?;

        Ok(Status::PairingFailed(PairingFailedReason::PasskeyEntryFailed))
    }
}

/// Error for [`PasskeyInput`]
///
/// This is error returned by methods of `PasskeyInput`
#[derive(Debug)]
pub enum PasscodeInputError<E> {
    InstanceNoLongerValid,
    SecurityManager(E),
    TooManyDigits,
    NotADigit,
    IndexOutOfBounds,
    NotPairing,
    NotComplete,
}

impl<E> core::fmt::Display for PasscodeInputError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match &self {
            PasscodeInputError::InstanceNoLongerValid => {
                f.write_str("this instance of a `PasscodeInput` no longer valid and it should be dropped")
            }
            PasscodeInputError::SecurityManager(e) => core::fmt::Display::fmt(e, f),
            PasscodeInputError::TooManyDigits => f.write_str("too many digits"),
            PasscodeInputError::NotADigit => f.write_str("character(s) other than digits in passkey"),
            PasscodeInputError::IndexOutOfBounds => f.write_str("index out of bounds"),
            PasscodeInputError::NotPairing => f.write_str("the security manager is no longer pairing"),
            PasscodeInputError::NotComplete => f.write_str("not complete"),
        }
    }
}

impl<E> From<InputError<E>> for PasscodeInputError<E> {
    fn from(e: InputError<E>) -> Self {
        match e {
            InputError::NotPairing => Self::NotPairing,
            InputError::InstanceNoLongerValid => Self::InstanceNoLongerValid,
            InputError::SecurityManager(e) => Self::SecurityManager(e),
        }
    }
}

/// Passcode Output
///
/// This is returned by the Security Manager's [`process_command`] method when a passkey is to be
/// displayed on this device to the application user.
pub struct PasskeyOutput(u32);

impl PasskeyOutput {
    /// Create a new `PasskeyOutput`
    ///
    /// # Panic
    /// Pairing data must exist
    fn new(security_manager: &mut SecurityManager) -> PasskeyOutput {
        let passkey = toolbox::new_passkey();

        security_manager.pairing_data.as_mut().unwrap().passkey = Some(passkey);

        PasskeyOutput(passkey)
    }
}

impl core::fmt::Display for PasskeyOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:06}", self.0)
    }
}

/// Out of Band Output
///
/// This is output that is to be sent through the out of band medium to the peer's Security Manager.
/// It contains the minimum required Security Manager types that must be sent to the peer's Security
/// Manager. More types can be added by pushing the type to this Out of Band input, but there is a
/// total buffer limit of 64 bytes.
///
/// The out of band data always contains the Security Manager types for the Bluetooth address, a
/// random, and a confirm value. Legacy pairing is not implemented so out of band data within an
/// `OutOfBandOutput` will always be these values by default (in legacy pairing the out of band
/// data is just the temporary key).
///
/// # Security Manager Type and Structures
/// A security manager types and structures are no different from the advertising data types and
/// structures listed within the assigned types and Core Specification Supplement.
///
/// # Note
/// The method used for sending out of band data may have requirements for Security Manager types
/// that are not included in the default out of band output. For example [`NFC`] requires the
/// Bluetooth device address and role data types to be part of the Oot of band data.
///
/// [`NFC`]: https://members.nfc-forum.org/apps/group_public/download.php/18688/NFCForum-AD-BTSSP_1_1.pdf
pub struct OutOfBandOutput([u8; 64], usize);

impl OutOfBandOutput {
    /// Create a new `OutOfBandOutput`
    ///
    /// # Panic
    /// This will panic if `security_manager` is not ready to create the out of band data
    fn new(security_manager: &mut SecurityManager) -> Self {
        use bo_tie_gap::assigned::{
            le_device_address::LeDeviceAddress, sc_confirm_value::ScConfirmValue, sc_random_value::ScRandomValue,
            Sequence,
        };

        let mut data = [0u8; 64];

        let pairing_data = security_manager.pairing_data.as_mut().unwrap();

        let rb = toolbox::rand_u128();

        pairing_data.responder_random = rb;

        let pkb = GetXOfP256Key::x(&pairing_data.public_key);

        let address = LeDeviceAddress::from(security_manager.responder_address);

        let random = ScRandomValue::new(rb);

        let confirm = ScConfirmValue::new(toolbox::f4(pkb, pkb, rb, 0));

        let mut sequence = Sequence::new(&mut data);

        sequence.try_add(&address).unwrap();
        sequence.try_add(&random).unwrap();
        sequence.try_add(&confirm).unwrap();

        let len = sequence.count();

        Self(data, len)
    }

    /// Add the role security manager structure to the out of band data
    ///
    /// This is not necessary as far as the Security Manager, but it may be necessary for the
    /// transport that the out of band data is sent through. This is the most commonly required
    /// Security Manager structure so it gets its own method.
    ///
    /// # Error
    /// There must be enough room within the buffer otherwise an error is returned. The value of the
    /// error is the size of the role Security Manager structure.
    pub fn add_role(&mut self) -> Result<(), usize> {
        let mut sequence = self.as_sequence();

        let role = bo_tie_gap::assigned::le_role::LeRole::OnlyPeripheral;

        sequence
            .try_add(&role)
            .map_err(|_| bo_tie_gap::assigned::le_role::LeRole::STRUCT_SIZE)
    }

    /// Get this `OutOfBandOutput` as a [`Sequence`]
    ///
    /// A sequence can be used to add more security manager types to the out of band output.
    ///
    /// [`Sequence`]: bo_tie_gap::assigned::Sequence
    pub fn as_sequence(&mut self) -> bo_tie_gap::assigned::Sequence<'_> {
        bo_tie_gap::assigned::Sequence::new(&mut self.0[self.1..])
    }

    /// Convert the underlying buffer to a `SequenceVec`
    ///
    /// This is necessary if there needs to be more than 64 bytes of data within the out of band
    /// output. A `SequenceVec` can contain
    pub fn to_sequence_vec(self) -> bo_tie_gap::assigned::SequenceVec {
        bo_tie_gap::assigned::SequenceVec::from(self.0)
    }
}

impl core::ops::Deref for OutOfBandOutput {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0[..self.1]
    }
}

/// Out of Band Input
///
/// This is a marker type for inputting out of band data from the peer device's Security Manager
/// into this Security Manager.
pub struct OutOfBandInput;

impl OutOfBandInput {
    /// Input the Out of Band Data into the Security Manager
    pub async fn input_oob<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
        oob_data: &[u8],
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        use bo_tie_gap::assigned::{
            le_device_address, sc_confirm_value, sc_random_value, AssignedTypes, TryFromStruct,
        };

        macro_rules! error {
            () => {{
                security_manager
                    .send_err(connection_channel, PairingFailedReason::UnspecifiedReason)
                    .await?;

                return Ok(Status::PairingFailed(PairingFailedReason::UnspecifiedReason));
            }};
        }

        let mut address = None;
        let mut random = None;
        let mut confirm = None;

        for rslt_struct in bo_tie_gap::assigned::EirOrAdIterator::new(oob_data) {
            match rslt_struct {
                Ok(sm_struct) => {
                    if sm_struct.is_assigned_type(AssignedTypes::LEBluetoothDeviceAddress) {
                        match le_device_address::LeDeviceAddress::try_from_struct(sm_struct) {
                            Ok(sm_address) => address = sm_address.into_inner().into(),
                            Err(_) => error!(),
                        }
                    } else if sm_struct.is_assigned_type(AssignedTypes::LESecureConnectionsRandomValue) {
                        match sc_random_value::ScRandomValue::try_from_struct(sm_struct) {
                            Ok(sm_random) => random = sm_random.into_inner().into(),
                            Err(_) => error!(),
                        }
                    } else if sm_struct.is_assigned_type(AssignedTypes::LESecureConnectionsConfirmationValue) {
                        match sc_confirm_value::ScConfirmValue::try_from_struct(sm_struct) {
                            Ok(sm_confirm) => confirm = sm_confirm.into_inner().into(),
                            Err(_) => error!(),
                        }
                    }
                }
                Err(_) => error!(),
            }
        }

        if let (Some(address), Some(random), Some(confirm)) = (address, random, confirm) {
            security_manager
                .process_input_oob(connection_channel, address, random, confirm)
                .await
        } else {
            error!()
        }
    }

    /// Out of Band Data is Unavailable
    ///
    /// This method should be called whenever the OOB data cannot be acquired by this device.
    pub async fn unavailable<C>(
        self,
        security_manager: &mut SecurityManager,
        connection_channel: &C,
    ) -> Result<Status, error!(C)>
    where
        C: ConnectionChannel,
    {
        security_manager
            .send_err(connection_channel, PairingFailedReason::OobNotAvailable)
            .await?;

        Ok(Status::PairingFailed(PairingFailedReason::OobNotAvailable))
    }
}
