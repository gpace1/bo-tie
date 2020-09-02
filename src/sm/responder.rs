/// Responder side of the Security Manager
///
/// A responder is used by a device to to 'respond' to the security manager requests of an
/// initiating device.

use alloc::vec::Vec;
use crate::l2cap::ConnectionChannel;
use super::{
    Command,
    CommandData,
    CommandType,
    encrypt_info,
    Error,
    KeyGenerationMethod,
    pairing,
    PairingData,
    toolbox,
};

pub struct SlaveSecurityManagerBuilder<'a, C> {
    connection_channel: &'a C,
    io_capabilities: pairing::IOCapability,
    oob_data: Option<u128>,
    encryption_key_min: usize,
    encryption_key_max: usize,
    remote_address: &'a crate::BluetoothDeviceAddress,
    this_address: &'a crate::BluetoothDeviceAddress,
    remote_address_is_random: bool,
    this_address_is_random: bool,
}

impl<'a,C> SlaveSecurityManagerBuilder<'a,C>
where C: ConnectionChannel
{
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
            oob_data: None,
            encryption_key_min: super::ENCRYPTION_KEY_MAX_SIZE,
            encryption_key_max: super::ENCRYPTION_KEY_MAX_SIZE,
            remote_address: connected_device_address,
            this_address: this_device_address,
            remote_address_is_random: is_connected_devices_address_random,
            this_address_is_random: is_this_device_address_random,
        }
    }

    pub fn build(&self) -> SlaveSecurityManager<'a, C> {

        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let key_dist = alloc::vec![
            pairing::KeyDistributions::IdKey,
        ];

        SlaveSecurityManager {
            connection_channel: self.connection_channel,
            io_capability: self.io_capabilities,
            oob_data: self.oob_data,
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
            link_encrypted: false
        }
    }
}

pub struct SlaveSecurityManager<'a,  C> {
    connection_channel: &'a C,
    io_capability: pairing::IOCapability,
    oob_data: Option<u128>,
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
    link_encrypted: bool
}

impl<'a, C> SlaveSecurityManager<'a, C>
where C: ConnectionChannel,
{
    /// Save the key details to `security_manager``
    ///
    /// If the `SlaveSecurityManager` did not contain any key information , then this function will
    /// do nothing to `security_manager`. Also key information will not be added to `security_manager`
    /// if it doesn't contain the required keys (either peer_irk or peer_addr)
    pub fn save_to_security_manager(&self, security_manager: &mut super::SecurityManager) {
        match self.pairing_data {
            Some( PairingData{
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
    pub fn set_encrypted(&mut self, is_encrypted: bool) { self.link_encrypted = is_encrypted }

    /// Send a new Identity Resolving Key to the Master Device
    ///
    /// This function will generate and send a new CSRK to the master device if the internal
    /// encryption flag is set to true by
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted).
    ///
    /// An IRK is generated if input `irk` is `None`.
    ///
    /// If the encryption flag is true, the return value is either input `irk` or the generated IRK.
    pub async fn send_new_irk<Irk>(&mut self, irk: Irk) -> Option<u128> where Irk: Into<Option<u128>>{
        if self.link_encrypted {

            // using or_else because it will only generate a random number if needed
            let irk_opt = irk.into().or_else(|| Some(toolbox::rand_u128()) );

            if let Some( PairingData { db_keys: Some( super::KeyDBEntry { ref mut irk, ..}), .. }) = self.pairing_data {
                *irk = irk_opt
            }

            self.send(encrypt_info::IdentityInformation::new(irk_opt.unwrap())).await;

            irk_opt
        } else {
            None
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
    /// If the encryption flag is true, the return value is either input 'csrk' the generated CSRK.
    pub async fn send_new_csrk<Csrk>(&mut self, csrk: Csrk) -> Option<u128> where Csrk: Into<Option<u128>> {
        if self.link_encrypted {

            // using or_else because it will only generate a random number if needed
            let csrk_opt = csrk.into().or_else(|| Some(toolbox::rand_u128()) );

            if let Some( PairingData { db_keys: Some( super::KeyDBEntry { ref mut csrk, ..}), .. }) = self.pairing_data {
                *csrk = csrk_opt.map(|csrk| (csrk, 0) );
            }

            self.send(encrypt_info::SigningInformation::new(csrk_opt.unwrap())).await;

            csrk_opt
        } else {
            None
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
    pub async fn resend_irk(&self) -> bool {
        if self.link_encrypted {
            if let Some(irk) = self.pairing_data.as_ref()
                .and_then(|pd| pd.db_keys.as_ref() )
                .and_then(|db_key| db_key.irk.clone() )
            {
                self.send(encrypt_info::IdentityInformation::new(irk)).await;

                true
            } else {
                false
            }
        } else {
            false
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
    pub async fn resend_csrk(&self) -> bool {
        if self.link_encrypted {
            if let Some(csrk) = self.pairing_data.as_ref()
                .and_then(|pd| pd.db_keys.as_ref() )
                .and_then(|db_key| db_key.csrk.clone() )
            {
                self.send(encrypt_info::SigningInformation::new(csrk.0)).await;

                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Send the public address to the Master Device.
    ///
    /// This will send `addr` as a Public Device Address to the Master Device if the internal
    /// encryption flag is set to true by
    /// [`set_encrypted`](crate::sm::responder::SlaveSecurityManager::set_encrypted).
    /// If the function returns false then `addr` isn't sent to the Master Device.
    pub async fn send_pub_addr(&self, addr: crate::BluetoothDeviceAddress) -> bool {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr)).await;
            true
        } else {
            false
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
    pub async fn send_static_rand_addr(&self, addr: crate::BluetoothDeviceAddress) -> bool {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr)).await;
            true
        } else {
            false
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
    pub async fn process_command<'s>(&'s mut self, acl_data: &'s crate::l2cap::AclData )
    -> Result<Option<&'s mut super::KeyDBEntry>, Error>
    {
        use core::convert::TryFrom;

        let command = match CommandType::try_from(acl_data) {
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;
                return Err(e);
            },
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

    async fn send<Cmd,P>(&self, command: Cmd)
        where Cmd: Into<Command<P>>,
              P: CommandData
    {
        use crate::l2cap::AclData;

        let acl_data = AclData::new( command.into().into_icd(), super::L2CAP_CHANNEL_ID);

        self.connection_channel.send(acl_data).await;
    }

    async fn send_err(&mut self, fail_reason: pairing::PairingFailedReason) {
        self.pairing_data = None;

        self.send(pairing::PairingFailed::new(fail_reason)).await;
    }

    async fn p_command_not_supported(&mut self, cmd: CommandType) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        self.send_err(pairing::PairingFailedReason::CommandNotSupported).await;

        Err(Error::IncorrectCommand(cmd))
    }

    async fn p_pairing_request<'z>(&'z mut self, data: &'z [u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {

        log::trace!("(SM) Processing pairing request");

        let request = match pairing::PairingRequest::try_from_icd(data) {
            Ok(request) => request,
            Err(_) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(Error::IncorrectCommand(CommandType::PairingPublicKey))
            }
        };

        if request.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(pairing::PairingFailedReason::EncryptionKeySize).await;

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize))
        } else {

            let response = pairing::PairingResponse::new(
                self.io_capability,
                if self.oob_data.is_some() {
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
                false
            );

            let initiator_io_cap = request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            self.send(response).await;

            let (private_key, public_key) = toolbox::ecc_gen()
                .expect("Failed to fill bytes for generated random");

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

        use super::GetXOfP256Key;

        log::trace!("(SM) Processing pairing public Key");

        let initiator_pub_key = match pairing::PairingPubKey::try_from_icd(data) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
            }
        };

        match self.pairing_data {
            Some( PairingData{
                ref public_key,
                ref nonce,
                ref mut private_key,
                ref mut peer_public_key,
                ref mut secret_key,
                ..
            }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_icd();

                    let mut raw_key = [0u8;64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                let remote_public_key = initiator_pub_key.get_key();

                log::trace!("remote public key: {:x?}", remote_public_key.as_ref());

                let peer_pub_key = match toolbox::PubKey::try_from_icd(&remote_public_key)
                {
                    Ok(k) => k,
                    Err(e) => {
                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                        return Err(e)
                    }
                };

                // Calculate the shared secret key
                let secret_key_rslt = toolbox::ecdh(
                    private_key.take().expect("Private key doesn't exist"),
                    &peer_pub_key
                );

                match secret_key_rslt {
                    Ok(key) => {
                        *secret_key = Some(key);

                        let confirm_value = toolbox::f4(
                            public_key.x(),
                            peer_pub_key.x(),
                            *nonce,
                            0
                        );

                        *peer_public_key = peer_pub_key.into();

                        // Send the public key of this device
                        self.send(pairing::PairingPubKey::new(raw_pub_key)).await;

                        // Send the confirm value
                        self.send(pairing::PairingConfirm::new(confirm_value)).await;

                        Ok(None)
                    },
                    Err(e) => {
                        // Generating the dh key failed

                        log::error!("(SM) Secret Key failed, '{:?}'", e);

                        self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                        Err(Error::Value)
                    }
                }
            },
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                Err(Error::IncorrectCommand(CommandType::PairingPublicKey))
            }
        }
    }

    async fn p_pairing_confirm(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {

        log::trace!("(SM) Processing pairing confirm");

        let _initiator_confirm = match pairing::PairingConfirm::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
            }
        };

        match self.pairing_data.as_ref() {
            Some( PairingData{
                key_gen_method: KeyGenerationMethod::JustWorks,
                ..
            }) |
            Some( PairingData{
                key_gen_method: KeyGenerationMethod::NumbComp,
                ..
            }) => /* Just Works or Number Comparison */
            {
                // Neither the Just Works method or Number Comparison should have the responder
                // receiving the pairing confirm PDU
                self.send_err(pairing::PairingFailedReason::InvalidParameters).await;

                Err(Error::PairingFailed(pairing::PairingFailedReason::InvalidParameters))
            },
            // The pairing methods OOB and Passkey are not supported yet
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            },
        }
    }

    async fn p_pairing_random(&mut self, payload: &[u8])
    -> Result<Option<&mut super::KeyDBEntry>, Error>
    {
        log::trace!("(SM) Processing pairing random");

        let initiator_random = match pairing::PairingRandom::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
            }
        };

        match self.pairing_data {
            Some( PairingData {
                key_gen_method: KeyGenerationMethod::JustWorks,
                ref mut peer_nonce,
                nonce,
                ..
            } ) |
            Some( PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                ref mut peer_nonce,
                nonce,
                ..
            } ) => {
                *peer_nonce = initiator_random.get_value().into();

                self.send( pairing::PairingRandom::new(nonce) ).await;

                Ok(None)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                Err(Error::UnsupportedFeature)
            }
        }
    }

    async fn p_pairing_failed(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing pairing failed");

        let initiator_fail = match pairing::PairingFailed::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
            }
        };

        self.pairing_data = None;

        Err(Error::PairingFailed(initiator_fail.get_reason()))
    }

    async fn p_pairing_dh_key_check(&mut self, payload: &[u8])
    -> Result<Option<&mut super::KeyDBEntry>, Error>
    {

        log::trace!("(SM) Processing pairing dh key check");

        let initiator_dh_key_check = match pairing::PairingDHKeyCheck::try_from_icd(payload) {
            Ok(request) => request,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
            }
        };

        let pd = self.pairing_data.as_ref();

        match pd {
            Some( PairingData {
                secret_key: Some( dh_key ),
                nonce,
                peer_nonce: Some( peer_nonce ),
                initiator_io_cap,
                responder_io_cap,
                ..
            }) => {

                let a_addr = toolbox::PairingAddress::new(
                    &self.initiator_address,
                    self.initiator_address_is_random
                );

                let b_addr = toolbox::PairingAddress::new(
                    &self.responder_address,
                    self.responder_address_is_random
                );

                log::trace!("secret key: {:x?}", dh_key);
                log::trace!("remote nonce: {:x?}", peer_nonce);
                log::trace!("this nonce: {:x?}", nonce);
                log::trace!("remote addr: {:x?}", a_addr);
                log::trace!("this addr: {:x?}", b_addr);

                let (mac_key, ltk) = toolbox::f5(
                    *dh_key,
                    *peer_nonce,
                    *nonce,
                    a_addr.clone(),
                    b_addr.clone(),
                );

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

                    let eb = toolbox::f6(
                        mac_key,
                        *nonce,
                        *peer_nonce,
                        0,
                        *responder_io_cap,
                        b_addr,
                        a_addr,
                    );

                    self.send(pairing::PairingDHKeyCheck::new(eb)).await;

                    let db_keys = &mut self.pairing_data.as_mut().unwrap().db_keys;

                    *db_keys = super::KeyDBEntry{
                        ltk: ltk.into(),
                        irk: None,
                        csrk: None,
                        peer_irk: None,
                        peer_addr: if self.initiator_address_is_random {
                                super::BluAddr::StaticRandom(self.initiator_address)
                            } else {
                                super::BluAddr::Public(self.initiator_address)
                            }.into(),
                        peer_csrk: None,
                    }.into();

                    Ok( db_keys.as_mut() )

                } else {
                    self.send_err(pairing::PairingFailedReason::DHKeyCheckFailed).await;

                    log::trace!("received ea: {:x?}", received_ea);
                    log::trace!("calculated ea: {:x?}", ea);

                    Err(Error::PairingFailed(pairing::PairingFailedReason::DHKeyCheckFailed))
                }
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                Err(Error::UnsupportedFeature)
            }
        }
    }

    async fn p_identity_info(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let identity_info = match encrypt_info::IdentityInformation::try_from_icd(payload) {
            Ok(ii) => ii,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
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
                },
                _ => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                    return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
                }
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

            return Err(Error::UnknownIfLinkIsEncrypted)
        }
    }

    async fn p_identity_address_info(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let identity_addr_info = match encrypt_info::IdentityAddressInformation::try_from_icd(payload) {
            Ok(iai) => iai,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
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
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                    return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
                }
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

            return Err(Error::UnknownIfLinkIsEncrypted)
        }
    }

    async fn p_signing_info(&mut self, payload: &[u8]) -> Result<Option<&mut super::KeyDBEntry>, Error> {
        log::trace!("(SM) Processing peer IRK");

        let signing_info = match encrypt_info::SigningInformation::try_from_icd(payload) {
            Ok(si) => si,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                return Err(e)
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
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

                    return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
                }
            }
        } else {
            self.send_err(pairing::PairingFailedReason::UnspecifiedReason).await;

            return Err(Error::UnknownIfLinkIsEncrypted)
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
