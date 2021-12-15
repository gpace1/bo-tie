//! Responder side of the Security Manager
//!
//! A responder is used by a device to to 'respond' to the security manager requests of an
//! initiating device.

use super::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, GetXOfP256Key, PairingData, PairingMethod,
};
use crate::l2cap::ConnectionChannel;
use crate::sm::oob::{
    sealed_receiver_type::OobReceiverTypeVariant, BuildOutOfBand, ExternalOobReceiver, OobDirection, OobReceiverType,
    OutOfBandMethodBuilder, OutOfBandSend,
};
use alloc::vec::Vec;

/// A builder for a [`SlaveSecurityManager`]
///
/// This is used to construct a `SlaveSecurityManager`. However building requires the
///
/// # Out of Band Support
/// A `SlaveSecurityManager` will only support OOB if method `use_oob` of this build is called. It
///
pub struct SlaveSecurityManagerBuilder<'a, C> {
    connection_channel: &'a C,
    io_capabilities: pairing::IOCapability,
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: &'a crate::BluetoothDeviceAddress,
    this_address: &'a crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
    distribute_ltk: bool,
    distribute_csrk: bool,
    accept_ltk: bool,
    accept_csrk: bool,
    prior_keys: Option<super::Keys>,
}

impl<'a, C> SlaveSecurityManagerBuilder<'a, C>
where
    C: ConnectionChannel,
{
    /// Create a new SlaveSecurityManagerBuilder
    pub fn new(
        connection_channel: &'a C,
        connected_device_address: &'a crate::BluetoothDeviceAddress,
        this_device_address: &'a crate::BluetoothDeviceAddress,
        is_connected_devices_address_random: bool,
        is_this_device_address_random: bool,
    ) -> Self {
        Self {
            connection_channel,
            io_capabilities: pairing::IOCapability::NoInputNoOutput,
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
            distribute_ltk: true,
            distribute_csrk: false,
            accept_ltk: false,
            accept_csrk: false,
            prior_keys: None,
        }
    }

    /// Set the keys if the devices are already paired
    ///
    /// Assigns the keys that were previously generated after a successful pair. The long term key
    /// must be present within `keys`. *This method allows for bonding keys to be distributed
    /// without having to go through pairing.
    pub fn set_already_paired<K: Into<Option<super::Keys>>>(&mut self, keys: K) -> Result<(), &'static str> {
        self.prior_keys = keys
            .into()
            .map(|keys| {
                if keys.get_ltk().is_some() {
                    Ok(keys)
                } else {
                    Err("Missing LTK")
                }
            })
            .transpose()?;

        Ok(())
    }

    /// Set the bonding keys to be distributed by the responder
    ///
    /// This is used to specify within the pairing request packet what bonding keys are going to be
    /// distributed by the responder security manager.
    ///
    /// # Note
    /// By default only the Identity Resolving Key (IRK) is distributed by the initiator. This
    /// method does not need to be called if the default key configuration is desired.
    pub fn sent_bonding_keys(
        &'a mut self,
    ) -> impl super::EnabledBondingKeys<'a, SlaveSecurityManagerBuilder<'a, C>> + 'a {
        self.distribute_ltk = false;
        self.distribute_csrk = false;

        struct SentKeys<'z, C>(&'z mut SlaveSecurityManagerBuilder<'z, C>);

        impl<'z, C> super::EnabledBondingKeys<'z, SlaveSecurityManagerBuilder<'z, C>> for SentKeys<'z, C> {
            fn distribute_ltk(&mut self) -> &mut Self {
                self.0.distribute_ltk = true;
                self
            }

            fn distribute_csrk(&mut self) -> &mut Self {
                self.0.distribute_csrk = true;
                self
            }

            fn finish_keys(self) -> &'z mut SlaveSecurityManagerBuilder<'z, C> {
                self.0
            }

            fn default(self) -> &'z mut SlaveSecurityManagerBuilder<'z, C> {
                self.0.distribute_ltk = true;
                self.0.distribute_csrk = false;
                self.0
            }
        }

        SentKeys(self)
    }

    /// Set the bonding keys to be accepted by this initiator
    ///
    /// This is used to specify within the pairing request packet what bonding keys can be received
    /// by the initiator security manager.
    ///
    /// # Note
    /// By default no bonding keys are accepted by this initiator. This method does not need to
    /// be called if the default key configuration is desired.
    pub fn accepted_bonding_keys(
        &'a mut self,
    ) -> impl super::EnabledBondingKeys<'a, SlaveSecurityManagerBuilder<'a, C>> + 'a {
        self.accept_ltk = false;
        self.accept_csrk = false;

        struct ReceivedKeys<'z, C>(&'z mut SlaveSecurityManagerBuilder<'z, C>);

        impl<'z, C> super::EnabledBondingKeys<'z, SlaveSecurityManagerBuilder<'z, C>> for ReceivedKeys<'z, C> {
            fn distribute_ltk(&mut self) -> &mut Self {
                self.0.accept_ltk = true;
                self
            }

            fn distribute_csrk(&mut self) -> &mut Self {
                self.0.accept_csrk = true;
                self
            }

            fn finish_keys(self) -> &'z mut SlaveSecurityManagerBuilder<'z, C> {
                self.0
            }

            fn default(self) -> &'z mut SlaveSecurityManagerBuilder<'z, C> {
                self.0.accept_ltk = false;
                self.0.accept_csrk = false;
                self.0
            }
        }

        ReceivedKeys(self)
    }

    /// Use or support an out-of-band (OOB) method for pairing
    ///
    /// This creates an implementor of `BuildOutOfBand` for creating a `SlaveSecurityManager` that
    /// will support OOB data transfer. This method requires the ways to send and receive
    pub fn use_oob<'b: 'a, S, R>(
        self,
        send: S,
        receive: R,
    ) -> impl BuildOutOfBand<
        Builder = SlaveSecurityManagerBuilder<'a, C>,
        SecurityManager = SlaveSecurityManager<'a, C, S, R>,
    > + 'a
    where
        S: for<'i> OutOfBandSend<'i> + 'b,
        R: OobReceiverType + 'b,
    {
        OutOfBandMethodBuilder::new(self, send, receive)
    }

    /// Create the `SlaveSecurityManager`
    ///
    /// # Note
    /// This will create a `SlaveSecurityManager` that does not support the out of band pairing
    /// method.
    pub fn build(self) -> SlaveSecurityManager<'a, C, (), ()> {
        self.make((), ())
    }

    /// Method for making a `SlaveSecurityManager`
    ///
    /// This is here to facilitate the tricks done around OOB type implementations.
    fn make<S, R>(self, oob_send: S, oob_receive: R) -> SlaveSecurityManager<'a, C, S, R>
    where
        S: OutOfBandSend<'a>,
        R: OobReceiverType,
    {
        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let initiator_key_distribution = super::get_keys(self.accept_ltk, self.accept_csrk);

        let responder_key_distribution = super::get_keys(self.distribute_ltk, self.distribute_csrk);

        SlaveSecurityManager {
            connection_channel: self.connection_channel,
            io_capability: self.io_capabilities,
            oob_send,
            oob_receive,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            auth_req,
            initiator_key_distribution,
            responder_key_distribution,
            initiator_address: *self.remote_address,
            responder_address: *self.this_address,
            initiator_address_is_random: self.remote_address_is_random,
            responder_address_is_random: self.this_address_is_random,
            pairing_data: None,
            keys: self.prior_keys,
            link_encrypted: false,
        }
    }
}

impl<'a, C, S, R> BuildOutOfBand for OutOfBandMethodBuilder<SlaveSecurityManagerBuilder<'a, C>, S, R>
where
    C: ConnectionChannel,
    S: for<'i> OutOfBandSend<'i>,
    R: OobReceiverType,
{
    type Builder = SlaveSecurityManagerBuilder<'a, C>;
    type SecurityManager = SlaveSecurityManager<'a, C, S, R>;

    fn build(self) -> Self::SecurityManager {
        let oob_send = self.send_method;
        let oob_receive = self.receive_method;
        self.builder.make(oob_send, oob_receive)
    }
}

pub struct SlaveSecurityManager<'a, C, S, R> {
    connection_channel: &'a C,
    io_capability: pairing::IOCapability,
    oob_send: S,
    oob_receive: R,
    auth_req: Vec<encrypt_info::AuthRequirements>,
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

impl<C, S, R> SlaveSecurityManager<'_, C, S, R> {
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
}

impl<'a, C, S, R> SlaveSecurityManager<'a, C, S, R>
where
    C: ConnectionChannel,
{
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
    pub async fn send_irk<Irk>(&mut self, irk: Irk) -> Result<u128, Error>
    where
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

            self.send(encrypt_info::IdentityInformation::new(irk)).await?;

            Ok(irk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted)
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
    pub async fn send_csrk<Csrk>(&mut self, csrk: Csrk) -> Result<u128, Error>
    where
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

            self.send(encrypt_info::SigningInformation::new(csrk)).await?;

            Ok(csrk)
        } else {
            Err(Error::UnknownIfLinkIsEncrypted)
        }
    }

    /// Send the public address to the Master Device.
    ///
    /// This will send `addr` as a Public Device Address to the Master Device if the internal
    /// encryption flag is set to true by
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted).
    /// If the function returns false then `addr` isn't sent to the Master Device.
    pub async fn send_pub_addr(&self, addr: crate::BluetoothDeviceAddress) -> Result<bool, Error> {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr))
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Send the static random address to the Master Device.
    ///
    /// This will send `addr` as a Static Random Device Address to the Master Device if the internal
    /// encryption flag is set to true by
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted).
    /// If the function returns false then `addr` isn't sent to the Master Device.
    ///
    /// # Warning
    /// This function doesn't validate that `address` is a valid static device address. The format
    /// of a static random device address can be found in the Bluetooth Specification (v5.0 | Vol 6,
    /// Part B, section 1.3.2.1).
    pub async fn send_static_rand_addr(&self, addr: crate::BluetoothDeviceAddress) -> Result<bool, Error> {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr))
                .await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    async fn send<Cmd, P>(&self, command: Cmd) -> Result<(), Error>
    where
        Cmd: Into<Command<P>>,
        P: CommandData,
    {
        use crate::l2cap::AclData;

        let acl_data = AclData::new(command.into().into_icd(), super::L2CAP_CHANNEL_ID);

        self.connection_channel
            .send(acl_data)
            .await
            .map_err(|e| Error::DataSend(alloc::format!("{:?}", e)))
    }

    async fn send_err(&mut self, fail_reason: pairing::PairingFailedReason) -> Result<(), Error> {
        self.pairing_data = None;

        self.send(pairing::PairingFailed::new(fail_reason)).await
    }
}

impl<'a, C, S, R> SlaveSecurityManager<'a, C, S, R>
where
    C: ConnectionChannel,
    S: for<'i> OutOfBandSend<'i>,
    R: OobReceiverType,
{
    /// Process a request from a MasterSecurityManager
    ///
    /// This will return a response to a valid request that can be sent to the Master device.
    /// Errors will be returned if the request is not something that can be processed by the slave
    /// or there was something wrong with the request message.
    ///
    /// This function will return a ['KeyDBEntry'](crate::sm::KeyDBEntry) with the newly generated
    /// Long Term Key (LTK). **This key information will only last as long as the master does not
    /// retry pairing or the master causes this responder to return a pairing error to the master**.
    /// *After pairing is complete*, the returned `KeyDBEntry` will only contain the LTK and the
    /// peer address used during pairing as the peer identity address. The return will be updated
    /// further with peer keys only when `set_encryption` is used to indicate that the connection
    /// is encrypted.
    ///
    /// It is recommended to always keep processing Bluetooth Security Manager packets as the
    /// responder. The host can at any point decide to restart encryption using different keys or
    /// send a `PairingFailed` to indicate that the prior pairing process failed.
    pub async fn process_command(&mut self, acl_data: &crate::l2cap::AclData) -> Result<Option<&super::Keys>, Error> {
        use core::convert::TryFrom;

        let command = match CommandType::try_from(acl_data) {
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;
                return Err(e);
            }
            Ok(cmd) => cmd,
        };

        let payload = &acl_data.get_payload()[1..];

        match command {
            CommandType::PairingRequest => self.p_pairing_request(payload).await,
            CommandType::PairingConfirm => self.p_pairing_confirm(payload).await,
            CommandType::PairingPublicKey => self.p_pairing_public_key(payload).await,
            CommandType::PairingRandom => self.p_pairing_random(payload).await,
            CommandType::PairingFailed => self.p_pairing_failed(payload).await,
            CommandType::PairingDHKeyCheck => self.p_pairing_dh_key_check(payload).await,
            CommandType::IdentityInformation => self.p_identity_info(payload).await,
            CommandType::IdentityAddressInformation => self.p_identity_address_info(payload).await,
            CommandType::SigningInformation => self.p_signing_info(payload).await,
            cmd @ CommandType::MasterIdentification | // Legacy SM, not supported
            cmd @ CommandType::EncryptionInformation | // Legacy SM, not supported
            cmd => self.p_command_not_supported(cmd).await,
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
        use crate::gap::{
            assigned::{sc_confirm_value, sc_random_value, IntoRaw},
            oob_block,
        };

        if S::can_send() {
            // doing things this way so the future returned by send_oob implements `Send`
            let oob_block = {
                let rb = toolbox::rand_u128();

                let paring_data = self.pairing_data.as_ref().unwrap();

                let pkb = GetXOfP256Key::x(&paring_data.public_key);

                let address = self.responder_address;

                let random = &sc_random_value::ScRandomValue::new(rb);

                let confirm = &sc_confirm_value::ScConfirmValue::new(toolbox::f4(pkb, pkb, rb, 0));

                let items: &[&dyn IntoRaw] = &[random, confirm];

                oob_block::OobDataBlockBuilder::new(address).build(items)
            };

            self.oob_send.send(&oob_block).await;
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
    async fn by_oob_receiver_type(&mut self) -> Result<(), Error> {
        match R::receiver_type() {
            OobReceiverTypeVariant::Internal => {
                let confirm_result = self.receive_oob().await;

                self.oob_confirm_result(confirm_result).await
            }
            OobReceiverTypeVariant::External => Ok(()),
            OobReceiverTypeVariant::DoesNotExist => unreachable!(),
        }
    }

    /// Function for the validation result of the confirm value with an OOB data.
    ///
    /// # Panic
    /// Member `pairing_data` must be `Some(_)`.
    async fn oob_confirm_result(&mut self, confirm_result: bool) -> Result<(), Error> {
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
            self.send_err(pairing::PairingFailedReason::ConfirmValueFailed).await
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
        let data = self.oob_receive.receive().await;

        self.process_received_oob(data)
    }

    /// Process the received OOB
    ///
    /// This will check the OOB to determine the validity of the raw data and the confirm within the
    /// raw data. True is returned if everything within `raw` is validated.
    fn process_received_oob(&self, raw: Vec<u8>) -> bool {
        use crate::gap::{
            assigned::{sc_confirm_value, sc_random_value, AssignedTypes, TryFromRaw},
            oob_block,
        };

        let oob_info = oob_block::OobDataBlockIter::new(raw);

        let mut ra = None;
        let mut ca = None;

        for (ty, data) in oob_info.iter() {
            const RANDOM_TYPE: u8 = AssignedTypes::LESecureConnectionsRandomValue.val();
            const CONFIRM_TYPE: u8 = AssignedTypes::LESecureConnectionsConfirmationValue.val();

            match ty {
                RANDOM_TYPE => ra = sc_random_value::ScRandomValue::try_from_raw(data).ok(),
                CONFIRM_TYPE => ca = sc_confirm_value::ScConfirmValue::try_from_raw(data).ok(),
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

    async fn p_command_not_supported(&mut self, cmd: CommandType) -> Result<Option<&super::Keys>, Error> {
        self.send_err(pairing::PairingFailedReason::CommandNotSupported).await?;

        Err(Error::IncorrectCommand(cmd))
    }

    async fn p_pairing_request(&mut self, data: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing pairing request");

        let request = match pairing::PairingRequest::try_from_icd(data) {
            Ok(request) => request,
            Err(_) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::IncorrectCommand(CommandType::PairingPublicKey));
            }
        };

        if request.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(pairing::PairingFailedReason::EncryptionKeySize).await?;

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize))
        } else {
            let response = pairing::PairingResponse::new(
                self.io_capability,
                if R::can_receive() {
                    pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
                } else {
                    pairing::OOBDataFlag::AuthenticationDataNotPresent
                },
                self.auth_req.clone(),
                self.encryption_key_size_max,
                self.initiator_key_distribution,
                self.responder_key_distribution,
            );

            let pairing_method = PairingMethod::determine_method_secure_connection(
                request.get_oob_data_flag(),
                response.get_oob_data_flag(),
                request.get_io_capability(),
                response.get_io_capability(),
                false,
            );

            let initiator_io_cap = request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            self.send(response).await?;

            let (private_key, public_key) = toolbox::ecc_gen().expect("Failed to fill bytes for generated random");

            log::info!("Pairing Method: {:?}", pairing_method);

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

    async fn p_pairing_public_key(&mut self, data: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing pairing public Key");

        let initiator_pub_key = match pairing::PairingPubKey::try_from_icd(data) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
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
                    let key_bytes = public_key.clone().into_icd();

                    let mut raw_key = [0u8; 64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                let remote_public_key = initiator_pub_key.get_key();

                log::trace!("remote public key: {:x?}", remote_public_key.as_ref());

                let peer_pub_key = match toolbox::PubKey::try_from_icd(&remote_public_key) {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                        return Err(e);
                    }
                };

                // Calculate the shared secret key
                let private_key = private_key.take().expect("Private key doesn't exist");

                *secret_key = toolbox::ecdh(private_key, &peer_pub_key).into();

                let confirm_value =
                    toolbox::f4(GetXOfP256Key::x(public_key), GetXOfP256Key::x(&peer_pub_key), *nonce, 0);

                *peer_public_key = peer_pub_key.into();

                // Send the public key of this device
                self.send(pairing::PairingPubKey::new(raw_pub_key)).await?;

                // Process what to do next based on the key generation method
                match key_gen_method {
                    PairingMethod::JustWorks | PairingMethod::NumbComp => {
                        // Send the confirm value
                        self.send(pairing::PairingConfirm::new(confirm_value)).await?;
                    }
                    PairingMethod::Oob(OobDirection::OnlyResponderSendsOob) => {
                        self.send_oob().await;
                    }
                    PairingMethod::Oob(OobDirection::BothSendOob) => {
                        self.send_oob().await;

                        self.by_oob_receiver_type().await?;
                    }
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) => {
                        self.by_oob_receiver_type().await?;
                    }
                    PairingMethod::PassKeyEntry => {
                        todo!("Key generation method 'Pass Key Entry' is not supported yet")
                    }
                }

                Ok(None)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::IncorrectCommand(CommandType::PairingPublicKey))
            }
        }
    }

    async fn p_pairing_confirm(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing pairing confirm");

        let _initiator_confirm = match pairing::PairingConfirm::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        match self.pairing_data.as_ref() {
            // Only the pairing method Passkey will have confirm values sent through the logical
            // link
            Some(PairingData {
                pairing_method: PairingMethod::PassKeyEntry | PairingMethod::NumbComp | PairingMethod::Oob(_),
                ..
            }) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
            _ => {
                // Neither the Just Works method, Number Comparison, or out of band should have the
                // responder receiving the pairing confirm PDU.
                self.send_err(pairing::PairingFailedReason::InvalidParameters).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::InvalidParameters))
            }
        }
    }

    async fn p_pairing_random(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing pairing random");

        let initiator_random = match pairing::PairingRandom::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        match self.pairing_data {
            Some(PairingData {
                pairing_method: PairingMethod::JustWorks | PairingMethod::NumbComp,
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(pairing::PairingRandom::new(nonce)).await?;

                Ok(None)
            }
            Some(PairingData {
                pairing_method:
                    PairingMethod::Oob(OobDirection::OnlyInitiatorSendsOob) | PairingMethod::Oob(OobDirection::BothSendOob),
                external_oob_confirm_valid,
                ..
            }) if OobReceiverTypeVariant::External == R::receiver_type() && !external_oob_confirm_valid => {
                self.send_err(pairing::PairingFailedReason::OOBNotAvailable).await?;

                Err(Error::ExternalOobNotProvided)
            }
            Some(PairingData {
                pairing_method: PairingMethod::Oob(_),
                ref mut peer_nonce,
                nonce,
                ..
            }) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send(pairing::PairingRandom::new(nonce)).await?;

                Ok(None)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::UnsupportedFeature)
            }
        }
    }

    async fn p_pairing_failed(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing pairing failed");

        let initiator_fail = match pairing::PairingFailed::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        self.pairing_data = None;

        Err(Error::PairingFailed(initiator_fail.get_reason()))
    }

    async fn p_pairing_dh_key_check(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing pairing dh key check");

        let initiator_dh_key_check = match pairing::PairingDHKeyCheck::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
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

                log::trace!("secret key: {:x?}", dh_key);
                log::trace!("remote nonce: {:x?}", peer_nonce);
                log::trace!("this nonce: {:x?}", nonce);
                log::trace!("remote address: {:x?}", a_addr);
                log::trace!("this address: {:x?}", b_addr);

                let (mac_key, ltk) = toolbox::f5(*dh_key, *peer_nonce, *nonce, a_addr.clone(), b_addr.clone());

                log::trace!("mac_key: {:x?}", mac_key);
                log::trace!("ltk: {:x?}", ltk);
                log::trace!("initiator_io_cap: {:x?}", initiator_io_cap);

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
                    log::trace!("responder_io_cap: {:x?}", responder_io_cap);

                    let eb = toolbox::f6(mac_key, *nonce, *peer_nonce, 0, *responder_io_cap, b_addr, a_addr);

                    self.send(pairing::PairingDHKeyCheck::new(eb)).await?;

                    let keys = &mut self.keys;

                    *keys = super::Keys {
                        ltk: ltk.into(),
                        irk: None,
                        csrk: None,
                        peer_irk: None,
                        peer_addr: if self.initiator_address_is_random {
                            super::BluAddr::StaticRandom(self.initiator_address)
                        } else {
                            super::BluAddr::Public(self.initiator_address)
                        }
                        .into(),
                        peer_csrk: None,
                    }
                    .into();

                    Ok(keys.as_ref())
                } else {
                    self.send_err(pairing::PairingFailedReason::DHKeyCheckFailed).await?;

                    log::trace!("received ea: {:x?}", received_ea);
                    log::trace!("calculated ea: {:x?}", ea);

                    Err(Error::PairingFailed(pairing::PairingFailedReason::DHKeyCheckFailed))
                }
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::UnsupportedFeature)
            }
        }
    }

    async fn p_identity_info(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let identity_info = match encrypt_info::IdentityInformation::try_from_icd(payload) {
            Ok(ii) => ii,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_irk = Some(identity_info.get_irk());

                Ok(Some(keys))
            } else {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }

    async fn p_identity_address_info(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing peer address info");

        let identity_addr_info = match encrypt_info::IdentityAddressInformation::try_from_icd(payload) {
            Ok(iai) => iai,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_addr = Some(identity_addr_info.into());

                Ok(Some(keys))
            } else {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }

    async fn p_signing_info(&mut self, payload: &[u8]) -> Result<Option<&super::Keys>, Error> {
        log::trace!("(SM) Processing peer signing info (CSRK)");

        let signing_info = match encrypt_info::SigningInformation::try_from_icd(payload) {
            Ok(si) => si,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            if let Some(ref mut keys) = self.keys {
                keys.peer_csrk = Some((signing_info.get_signature_key(), 0));

                Ok(Some(keys))
            } else {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }
}

impl<'a, C, S> SlaveSecurityManager<'a, C, S, ExternalOobReceiver>
where
    C: ConnectionChannel,
    S: for<'i> OutOfBandSend<'i>,
{
    /// Set the received out of band data
    ///
    /// This method is required to be called when the OOB receiver type is `ExternalOobReceiver`.
    /// Obviously it is not needed if the receiver type something other than `ExternalOobReceiver`
    /// because you cannot call this method.
    ///
    /// This method is tricky as it may only be called at the correct time during the pairing
    /// process with OOB, but he method
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
    /// `expecting_oob_data` after processing every security manager message, although this
    /// procedure can be stopped after this method is called.
    ///
    /// # Note
    /// The error `ConfirmValueFailed` can also be returned, but that means that the method was
    /// called at the correct time, just that pairing was going to fail because of the confirm value
    /// check failing.
    pub async fn received_oob_data(&mut self, data: Vec<u8>) -> Result<(), Error> {
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
            }) => self.oob_confirm_result(self.process_received_oob(data)).await,
            _ => {
                self.send_err(pairing::PairingFailedReason::OOBNotAvailable).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
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

// pub struct AsyncMasterSecurityManager<'a, HCI, C> {
//     sm: &'a SecurityManager,
//     hci: &'a HostInterface<HCI>,
//     connection_channel: &'a C,
// }
//
// impl<'a, HCI, C> AsyncMasterSecurityManager<'a, HCI, C> {
//     fn new( sm: &'a SecurityManager, hci: &'a HostInterface<HCI>, connection_channel: &'a C ) -> Self {
//         Self { sm, hci, connection_channel }
//     }
// }
//
// pub struct AsyncSlaveSecurityManager<'a, HCI, C> {
//     sm: &'a SecurityManager,
//     hci: &'a HostInterface<HCI>,
//     connection_channel: &'a C,
// }
//
// impl<'a, HCI, C> AsyncSlaveSecurityManager<'a, HCI, C> {
//     fn new( sm: &'a SecurityManager, hci: &'a HostInterface<HCI>, connection_channel: &'a C ) -> Self {
//         Self { sm, hci, connection_channel }
//     }
// }
