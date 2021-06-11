//! Responder side of the Security Manager
//!
//! A responder is used by a device to to 'respond' to the security manager requests of an
//! initiating device.

use super::{
    encrypt_info, pairing, toolbox, Command, CommandData, CommandType, Error, GetXOfP256Key, KeyGenerationMethod,
    PairingData,
};
use crate::l2cap::ConnectionChannel;
use alloc::vec::Vec;

/// A builder for a [`SlaveSecurityManager`]
pub struct SlaveSecurityManagerBuilder<'a, C> {
    connection_channel: &'a C,
    io_capabilities: pairing::IOCapability,
    oob: bool,
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: &'a crate::BluetoothDeviceAddress,
    this_address: &'a crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
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
            oob: false,
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
        }
    }

    /// Use an out-of-band method for pairing
    ///
    /// This takes
    pub fn use_oob<S, R>(&'a mut self) -> OutOfBandMethod<'a, C, S, R> {
        self.oob = true;

        OutOfBandMethod::new(self)
    }

    pub fn build(&self) -> SlaveSecurityManager<'a, C> {
        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let key_dist = alloc::vec![pairing::KeyDistributions::IdKey,];

        SlaveSecurityManager {
            connection_channel: self.connection_channel,
            io_capability: self.io_capabilities,
            oob: self.oob,
            // passkey: None,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            auth_req,
            initiator_key_distribution: key_dist.clone(),
            responder_key_distribution: key_dist,
            initiator_address: *self.remote_address,
            responder_address: *self.this_address,
            initiator_address_is_random: self.remote_address_is_random,
            responder_address_is_random: self.this_address_is_random,
            pairing_data: None,
            link_encrypted: false,
        }
    }
}

pub struct SlaveSecurityManager<'a, C> {
    connection_channel: &'a C,
    io_capability: pairing::IOCapability,
    oob: bool,
    auth_req: Vec<encrypt_info::AuthRequirements>,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_key_distribution: Vec<pairing::KeyDistributions>,
    responder_key_distribution: Vec<pairing::KeyDistributions>,
    initiator_address: crate::BluetoothDeviceAddress,
    responder_address: crate::BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    link_encrypted: bool,
}

impl<'a, C> SlaveSecurityManager<'a, C>
where
    C: ConnectionChannel,
{
    /// Save the key details to `security_manager``
    ///
    /// If the `SlaveSecurityManager` did not contain any key information , then this function will
    /// do nothing to `security_manager`. Also key information will not be added to `security_manager`
    /// if it doesn't contain the required keys (either peer_irk or peer_addr)
    pub fn save_to_security_manager(&self, security_manager: &mut super::SecurityManager) {
        match self.pairing_data {
            Some(PairingData {
                db_keys: Some(ref db_keys),
                ..
            }) => {
                security_manager.add_keys(db_keys.clone());
            }
            _ => {}
        }
    }

    // pub fn set_oob_data(&mut self, val: u128) { self.oob_data = Some(val) }

    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `SlaveSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    pub fn set_encrypted(&mut self, is_encrypted: bool) {
        self.link_encrypted = is_encrypted
    }

    /// Send a new Identity Resolving Key to the Master Device
    ///
    /// This function will generate and send a new CSRK to the master device if the internal
    /// encryption flag is set to true by
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted).
    ///
    /// An IRK is generated if input `irk` is `None`.
    ///
    /// # Return
    /// If the encryption flag is true, the return value is either input `irk` or the generated IRK.
    /// `None` is returned if the encryption flag is not set and an error is returned when sending
    /// the PDU fails.
    pub async fn send_new_irk<Irk>(&mut self, irk: Irk) -> Result<Option<u128>, Error>
    where
        Irk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            // using or_else because it will only generate a random number if needed
            let irk_opt = irk.into().or_else(|| Some(toolbox::rand_u128()));

            if let Some(PairingData {
                db_keys: Some(super::KeyDBEntry { ref mut irk, .. }),
                ..
            }) = self.pairing_data
            {
                *irk = irk_opt
            }

            self.send(encrypt_info::IdentityInformation::new(irk_opt.unwrap()))
                .await?;

            Ok(irk_opt)
        } else {
            Ok(None)
        }
    }

    /// Send a new Connection Signature Resolving Key to the Master Device
    ///
    /// This function will generate and send a new CSRK to the master device if the internal
    /// encryption flag is set to true by
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted).
    ///
    /// A CSRK is generated if input `csrk` is `None`. There is no input for the sign counter as
    /// the CSRK is considered a new value, thus the sign counter is 0.
    ///
    /// # Return
    /// If the encryption flag is true, the return value is either input 'csrk' the generated CSRK.
    /// `None` is returned if the encryption flag is not set and an error is returned when sending
    /// the PDU fails.
    pub async fn send_new_csrk<Csrk>(&mut self, csrk: Csrk) -> Result<Option<u128>, Error>
    where
        Csrk: Into<Option<u128>>,
    {
        if self.link_encrypted {
            // using or_else because it will only generate a random number if needed
            let csrk_opt = csrk.into().or_else(|| Some(toolbox::rand_u128()));

            if let Some(PairingData {
                db_keys: Some(super::KeyDBEntry { ref mut csrk, .. }),
                ..
            }) = self.pairing_data
            {
                *csrk = csrk_opt.map(|csrk| (csrk, 0));
            }

            self.send(encrypt_info::SigningInformation::new(csrk_opt.unwrap()))
                .await?;

            Ok(csrk_opt)
        } else {
            Ok(None)
        }
    }

    /// Resend the Identity Resolving Key to the Master Device
    ///
    /// This function will send the IRK to the master device if the internal encryption flag is set
    /// to true by [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted)
    /// and an IRK has been generated. An IRK is generated once
    /// [`process_command`](SlaveSecurityManager::process_command)
    /// returns a reference to a [`KeyDBEntry`](super::KeyDBEntry), however, since the return is a
    /// mutable, you can replace the IRK with `None` which would also cause this function to
    /// return false. If the function returns false then the IRK isn't sent to the Master Device.
    pub async fn resend_irk(&self) -> Result<bool, Error> {
        if self.link_encrypted {
            if let Some(irk) = self
                .pairing_data
                .as_ref()
                .and_then(|pd| pd.db_keys.as_ref())
                .and_then(|db_key| db_key.irk.clone())
            {
                self.send(encrypt_info::IdentityInformation::new(irk)).await?;

                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
        }
    }

    /// Resend the Connection Signature Resolving Key to the Master Device
    ///
    /// This function will send the CSRK to the master device if the internal encryption flag is set
    /// to true by [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted)
    /// and an CSRK has been generated. An CSRK is generated once
    /// [`process_command`](SlaveSecurityManager::process_command)
    /// returns a reference to a [`KeyDBEntry`](super::KeyDBEntry), however, since the return is a
    /// mutable, you can replace the CSRK with `None` which would also cause this function to
    /// return false. If the function returns false then the CSRK isn't sent to the Master Device.
    pub async fn resend_csrk(&self) -> Result<bool, Error> {
        if self.link_encrypted {
            if let Some(csrk) = self
                .pairing_data
                .as_ref()
                .and_then(|pd| pd.db_keys.as_ref())
                .and_then(|db_key| db_key.csrk.clone())
            {
                self.send(encrypt_info::SigningInformation::new(csrk.0)).await?;

                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            Ok(false)
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
    pub async fn process_command<'s>(
        &'s mut self,
        acl_data: &'s crate::l2cap::AclData,
    ) -> Result<Option<&'s mut super::KeyDBEntry>, Error> {
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

    async fn p_command_not_supported(&mut self, cmd: CommandType) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        self.send_err(pairing::PairingFailedReason::CommandNotSupported).await?;

        Err(Error::IncorrectCommand(cmd))
    }

    async fn p_pairing_request<'z>(&'z mut self, data: &'z [u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
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
                if self.oob {
                    pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
                } else {
                    pairing::OOBDataFlag::AuthenticationDataNotPresent
                },
                self.auth_req.clone(),
                self.encryption_key_size_max,
                self.initiator_key_distribution.clone(),
                self.responder_key_distribution.clone(),
            );

            let pairing_method = KeyGenerationMethod::determine_method(
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
                key_gen_method: pairing_method,
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
                db_keys: None,
            });

            Ok(None)
        }
    }

    async fn p_pairing_public_key(&mut self, data: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
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
                let secret_key_rslt =
                    toolbox::ecdh(private_key.take().expect("Private key doesn't exist"), &peer_pub_key);

                match secret_key_rslt {
                    Ok(key) => {
                        *secret_key = Some(key);

                        let confirm_value =
                            toolbox::f4(GetXOfP256Key::x(public_key), GetXOfP256Key::x(&peer_pub_key), *nonce, 0);

                        *peer_public_key = peer_pub_key.into();

                        // Send the public key of this device
                        self.send(pairing::PairingPubKey::new(raw_pub_key)).await?;

                        // Send the confirm value
                        self.send(pairing::PairingConfirm::new(confirm_value)).await?;

                        Ok(None)
                    }
                    Err(e) => {
                        // Generating the dh key failed

                        log::error!("(SM) Secret Key failed, '{:?}'", e);

                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                        Err(Error::Value)
                    }
                }
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::IncorrectCommand(CommandType::PairingPublicKey))
            }
        }
    }

    async fn p_pairing_confirm(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing pairing confirm");

        let _initiator_confirm = match pairing::PairingConfirm::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        match self.pairing_data.as_ref() {
            Some(PairingData {
                key_gen_method: KeyGenerationMethod::JustWorks,
                ..
            })
            | Some(PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                ..
            }) =>
            /* Just Works or Number Comparison */
            {
                // Neither the Just Works method or Number Comparison should have the responder
                // receiving the pairing confirm PDU
                self.send_err(pairing::PairingFailedReason::InvalidParameters).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::InvalidParameters))
            }
            // The pairing methods OOB and Passkey are not supported yet
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    async fn p_pairing_random(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
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
                key_gen_method: KeyGenerationMethod::JustWorks,
                ref mut peer_nonce,
                nonce,
                ..
            })
            | Some(PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
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

    async fn p_pairing_failed(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
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

    async fn p_pairing_dh_key_check(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
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

                    let db_keys = &mut self.pairing_data.as_mut().unwrap().db_keys;

                    *db_keys = super::KeyDBEntry {
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

                    Ok(db_keys.as_mut())
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

    async fn p_identity_info(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let identity_info = match encrypt_info::IdentityInformation::try_from_icd(payload) {
            Ok(ii) => ii,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            match self.pairing_data {
                Some(PairingData {
                    db_keys: Some(ref mut db_key),
                    ..
                }) => {
                    db_key.peer_irk = Some(identity_info.get_irk());

                    Ok(Some(db_key))
                }
                _ => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                    return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
                }
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }

    async fn p_identity_address_info(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let identity_addr_info = match encrypt_info::IdentityAddressInformation::try_from_icd(payload) {
            Ok(iai) => iai,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            match self.pairing_data {
                Some(PairingData {
                    db_keys: Some(ref mut db_key),
                    ..
                }) => {
                    db_key.peer_addr = Some(identity_addr_info.into());

                    Ok(Some(db_key))
                }
                _ => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                    return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
                }
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }

    async fn p_signing_info(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let signing_info = match encrypt_info::SigningInformation::try_from_icd(payload) {
            Ok(si) => si,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                return Err(e);
            }
        };

        if self.link_encrypted {
            match self.pairing_data {
                Some(PairingData {
                    db_keys: Some(ref mut db_key),
                    ..
                }) => {
                    db_key.peer_csrk = Some((signing_info.get_signature_key(), 0));

                    Ok(Some(db_key))
                }
                _ => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

                    return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
                }
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await?;

            return Err(Error::UnknownIfLinkIsEncrypted);
        }
    }
}

/// Out of Band pairing method setup
///
/// Things that implement this trait can be used as the out-of-band (OOB) process for pairing. Any
/// communication process that is outside of the direct Bluetooth communication between the two
/// pairing devices can be considered a valid OOB. However the OOB must have no man-in-the-middle in
/// order for OOB to be secure form of pairing.
///
/// The methods [`set_send_method`] and [`set_receive_method`] determine how data is sent and
/// received through the OOB interface. At least one of them must be called before an
/// [`OutOfBandSlaveSecurityManager`] can be built (with [`build`]). When `set_send_method` the
/// responder will send OOB data to the initiator, and if `set_receive_method` is called then this
/// responder will await for an OOB message from the initiator. It is recommended to match the
/// methods to the capability of the OOB interface.
pub struct OutOfBandMethod<'a, C, S, R> {
    builder: &'a mut SlaveSecurityManagerBuilder<'a, C>,
    send_method: core::cell::Cell<Option<S>>,
    receive_method: core::cell::Cell<Option<R>>,
}

impl<'a, C, S, R> OutOfBandMethod<'a, C, S, R>
where
    C: ConnectionChannel,
{
    fn new(builder: &'a mut SlaveSecurityManagerBuilder<'a, C>) -> Self {
        OutOfBandMethod {
            builder,
            send_method: core::cell::Cell::new(None),
            receive_method: core::cell::Cell::new(None),
        }
    }

    /// Set the method for sending
    ///
    /// Input `send_method` is a function for generating a future used for sending data across the
    /// OOB interface. The purpose of the future is to allow for situations where sending may
    /// be an asynchronous process.
    pub fn set_send_method<F>(&mut self, send_method: S) -> &mut Self
    where
        S: Fn(&[u8]) -> F,
        F: core::future::Future,
    {
        self.send_method.set(Some(send_method));

        self
    }

    /// Set the method for receiving
    ///
    /// Input `send_method` is a function for generating a future for receiving over the OOB
    /// interface.
    pub fn set_receive_method<F>(&mut self, receive_method: R) -> &mut Self
    where
        R: Fn() -> F,
        F: core::future::Future<Output = Vec<u8>>,
    {
        self.receive_method.set(Some(receive_method));

        self
    }

    pub fn build(&self) -> Result<OutOfBandSlaveSecurityManager<'a, C, S, R>, OobBuildError> {
        let send_method = self.send_method.take();

        let receive_method = self.receive_method.take();

        Ok(OutOfBandSlaveSecurityManager::new(
            self.builder.build(),
            send_method,
            receive_method,
        ))
    }
}

impl<'a, C, S, R> core::ops::Deref for OutOfBandMethod<'a, C, S, R> {
    type Target = SlaveSecurityManagerBuilder<'a, C>;

    fn deref(&self) -> &Self::Target {
        &self.builder
    }
}

#[derive(Debug)]
pub struct OobBuildError;

impl core::fmt::Display for OobBuildError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        f.write_str("No send or receive methods were set for OOB data")
    }
}

/// A slave security manager that uses an out-of-band process of pairing
pub struct OutOfBandSlaveSecurityManager<'a, C, S, R> {
    sm: SlaveSecurityManager<'a, C>,
    send_method: Option<S>,
    receive_method: Option<R>,
}

impl<'a, C, S, R> OutOfBandSlaveSecurityManager<'a, C, S, R> {
    fn new(sm: SlaveSecurityManager<'a, C>, send_method: Option<S>, receive_method: Option<R>) -> Self {
        OutOfBandSlaveSecurityManager {
            sm,
            send_method,
            receive_method,
        }
    }
}

impl<'a, C, S, R, F> OutOfBandSlaveSecurityManager<'a, C, S, R>
where
    S: Fn(&[u8]) -> F,
    F: core::future::Future,
{
    /// Send the OOB confirm information if sending is enabled
    ///
    /// This will create the confirm information and send the information to the initiator if the
    /// sender function was set. If no sender was set, this method does nothing.
    ///
    /// # Note
    /// The information generated is wrapped in a OOB data block and then sent to the initiator.
    ///
    /// # Panic
    /// This method will panic if the pairing information and public keys were not already generated
    /// in the pairing process.
    async fn send(&self) {
        use crate::gap::{
            assigned::{sc_confirm_value, sc_random_value, IntoRaw},
            oob_block,
        };

        if let Some(sender) = self.send_method.as_ref() {
            let rb = toolbox::rand_u128();

            let paring_data = self.sm.pairing_data.as_ref().unwrap();

            let pka = GetXOfP256Key::x(paring_data.peer_public_key.as_ref().unwrap());

            let pkb = GetXOfP256Key::x(&paring_data.public_key);

            let address = self.sm.responder_address;

            let random = &sc_random_value::ScRandomValue::new(rb) as &dyn IntoRaw;

            let confirm = &sc_confirm_value::ScConfirmValue::new(toolbox::f4(pka, pkb, rb, 0)) as &dyn IntoRaw;

            let oob_block = oob_block::OobDataBlockBuilder::new(address).build(&[random, confirm]);

            sender(&oob_block).await;
        }
    }
}

impl<'a, C, S, R, F> OutOfBandSlaveSecurityManager<'a, C, S, R>
where
    R: Fn() -> F,
    F: core::future::Future<Output = Vec<u8>>,
{
    /// Receive OOB information from the initiator
    ///
    /// This will await for the OOB data block containing the initiator's confirm information and
    /// return a boolean indicating if the information was verified. If no receive function was set,
    /// this method will return true.
    ///
    /// # Panic
    /// This method will panic if the pairing information and public keys were not already generated
    /// in the pairing process.
    async fn receive(&self) -> bool {
        use crate::gap::{
            assigned::{sc_confirm_value, sc_random_value, AssignedTypes, IntoRaw},
            oob_block,
        };

        if let Some(receive) = self.receive_method.as_ref() {
            let oob_info = oob_block::OobDataBlockIter::new(receive().await);

            for (ty, data) in oob_info.iter() {
                const RANDOM_TYPE: u8 = AssignedTypes::LESecureConnectionsRandomValue.val();
                const CONFIRM_TYPE: u8 = AssignedTypes::LESecureConnectionsConfirmationValue.val();

                match ty {
                    RANDOM_TYPE => todo!(),
                    CONFIRM_TYPE => todo!(),
                    _ => (),
                }
            }

            true
        } else {
            true
        }
    }
}

impl<'a, C, S, R> core::ops::Deref for OutOfBandSlaveSecurityManager<'a, C, S, R> {
    type Target = SlaveSecurityManager<'a, C>;

    fn deref(&self) -> &Self::Target {
        &self.sm
    }
}

impl<'a, C, S, R> core::ops::DerefMut for OutOfBandSlaveSecurityManager<'a, C, S, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.sm
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
