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

pub struct MasterSecurityManagerBuilder<'a, C> {
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

impl<'a, C> MasterSecurityManagerBuilder<'a, C> {

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

    pub fn build(self) -> MasterSecurityManager<'a, C> {

        let auth_req = alloc::vec![
            encrypt_info::AuthRequirements::Bonding,
            encrypt_info::AuthRequirements::ManInTheMiddleProtection,
            encrypt_info::AuthRequirements::Sc,
        ];

        let key_dist = alloc::vec![
            pairing::KeyDistributions::IdKey,
        ];

        let pairing_request = pairing::PairingRequest::new(
            self.io_capabilities,
            if self.oob_data.is_some() {
                pairing::OOBDataFlag::AuthenticationDataFromRemoteDevicePresent
            } else {
                pairing::OOBDataFlag::AuthenticationDataNotPresent
            },
            auth_req,
            self.encryption_key_max,
            key_dist.clone(),
            key_dist,
        );

        MasterSecurityManager {
            connection_channel: self.connection_channel,
            // oob_data: self.oob_data,
            // passkey: None,
            encryption_key_size_min: self.encryption_key_min,
            encryption_key_size_max: self.encryption_key_max,
            pairing_request,
            initiator_address: self.this_address,
            responder_address: self.remote_address,
            initiator_address_is_random: self.this_address_is_random,
            responder_address_is_random: self.remote_address_is_random,
            pairing_data: None,
            link_encrypted: false
        }
    }
}

pub trait ResponseProcessor {
    type Output;

    fn process(self, l2cap_data: crate::l2cap::AclData) -> Result<Self::Output, super::Error>;

    fn expected(&self) -> super::CommandType;
}

struct Processor<'i, J, C> {
    msm: &'i mut MasterSecurityManager<'i, C>,
    expected: super::CommandType,
    job: J
}

impl<'i, J, C, O> Processor<'i, J, C>
where J: for<'d> core::ops::FnOnce(&'i mut MasterSecurityManager<'i, C>, &'d [u8]) -> Result<O, super::Error>,
      C: ConnectionChannel,
{
    fn proc_data(mut self, received_data: &[u8]) -> Result<O, super::Error> {

        let (d_type, payload) = received_data.split_at(1);

        match CommandType::try_from_val(d_type[0]) {
            Err(e) => {
                self.msm.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                Err(e)
            },

            Ok(cmd) if cmd == self.expected => (self.job)(self.msm, payload),

            Ok(cmd) if cmd == CommandType::PairingFailed => {
                self.msm.pairing_data = None;

                Err(Error::PairingFailed( pairing::PairingFailed::try_from_icd(payload)?.get_reason() ))
            },

            Ok(cmd) => {
                self.msm.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                Err(Error::IncorrectCommand(cmd))
            },
        }
    }
}

impl<'i, J, C, O> ResponseProcessor for Processor<'i, J, C>
where J: for<'d> core::ops::FnOnce(&'i mut MasterSecurityManager<'i, C>, &'d [u8]) -> Result<O, super::Error>,
      C: ConnectionChannel,
{
    type Output = O;

    fn process(self, l2cap_data: crate::l2cap::AclData) -> Result<Self::Output, super::Error> {
        if l2cap_data.get_channel_id() == super::SECURITY_MANAGER_L2CAP_CHANNEL_ID {
            self.proc_data(l2cap_data.get_payload())
        } else {
            Err(Error::IncorrectL2capChannelId)
        }
    }

    fn expected(&self) -> super::CommandType { self.expected }
}

pub struct MasterSecurityManager<'a, C> {
    connection_channel: &'a C,
    // oob_data: Option<u128>,
    pairing_request: pairing::PairingRequest,
    encryption_key_size_min: usize,
    encryption_key_size_max: usize,
    initiator_address: &'a crate::BluetoothDeviceAddress,
    responder_address: &'a crate::BluetoothDeviceAddress,
    initiator_address_is_random: bool,
    responder_address_is_random: bool,
    pairing_data: Option<PairingData>,
    link_encrypted: bool
}

impl<'a, C> MasterSecurityManager<'a, C>
where C: ConnectionChannel
{
    fn send<Cmd,P>(&self, command: Cmd)
    where Cmd: Into<Command<P>>,
            P: CommandData
    {
        use crate::l2cap::AclData;

        let acl_data = AclData::new( command.into().into_icd(), super::SECURITY_MANAGER_L2CAP_CHANNEL_ID);

        self.connection_channel.send((acl_data, super::L2CAP_LEGACY_MTU));
    }

    fn send_err(&mut self, fail_reason: pairing::PairingFailedReason) {
        self.pairing_data = None;

        self.send(pairing::PairingFailed::new(fail_reason));
    }

    fn send_pairing_request(&'a mut self)
    -> Processor<'a, fn(&'a mut MasterSecurityManager<'a, C>, &[u8]) -> Result<Option<&'a mut super::KeyDBEntry>, Error>, C>
    {
        self.send(self.pairing_request.clone());

        Processor {
            msm: self,
            expected: CommandType::PairingResponse,
            job: Self::process_pairing_response,
        }
    }

    fn process_pairing_response(&'a mut self, payload: &[u8])
    -> Result<Option<&'a mut super::KeyDBEntry>, Error>
    {
        let response = pairing::PairingResponse::try_from_icd(payload)?;

        if response.get_max_encryption_size() < self.encryption_key_size_min {
            self.send_err(pairing::PairingFailedReason::EncryptionKeySize);

            Err(Error::PairingFailed(pairing::PairingFailedReason::EncryptionKeySize))
        } else {
            let pairing_method = KeyGenerationMethod::determine_method(
                self.pairing_request.get_oob_data_flag(),
                response.get_oob_data_flag(),
                self.pairing_request.get_io_capability(),
                response.get_io_capability(),
                false
            );

            let initiator_io_cap = self.pairing_request.get_io_cap();
            let responder_io_cap = response.get_io_cap();

            let (private_key, public_key) = toolbox::ecc_gen()
                .expect("Failed to fill bytes for generated random");

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

    /// Send the pairing pub key
    ///
    /// After the pairing pub key PDU is sent to the slave, a `ResponseProcessor` is returned that
    /// can be used to process the acl data returned by the server.
    fn send_pairing_pub_key(&'a mut self)
    -> Result<Processor<'a, fn(&'a mut MasterSecurityManager<'a, C>, &[u8]) -> Result<Option<&'a mut super::KeyDBEntry>, Error>, C>, Error>
    {
        match self.pairing_data {
            Some( PairingData {
                ref public_key,
                ..
            }) => {
                let raw_pub_key = {
                    let key_bytes = public_key.clone().into_icd();

                    let mut raw_key = [0u8;64];

                    raw_key.copy_from_slice(&key_bytes);

                    raw_key
                };

                self.send(pairing::PairingPubKey::new(raw_pub_key));

                Ok( Processor {
                    msm: self,
                    expected: CommandType::PairingPublicKey,
                    job: Self::process_responder_pub_key
                } )
            }
            _ => {
                Err(Error::IncorrectCommand(CommandType::PairingPublicKey))
            }
        }
    }

    fn process_responder_pub_key(&'a mut self, payload: &[u8])
    -> Result<Option<&'a mut super::KeyDBEntry>, Error>
    {
        let pub_key = pairing::PairingPubKey::try_from_icd(payload);

        match (&pub_key, &mut self.pairing_data) {
            (
                Ok(peer_pub_key_pdu),
                Some(PairingData {
                    private_key: private_key @ Some(_),
                    peer_public_key,
                    secret_key,
                    ..
                })
            ) => {
                let remote_pub_key = match toolbox::PeerKey::try_from_icd( &peer_pub_key_pdu.get_key() )
                    {
                        Ok(k) => k,
                        Err(e) => {
                            self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                            return Err(e)
                        }
                    };

                let this_pri_key = private_key.take().unwrap();

                *secret_key = toolbox::ecdh(this_pri_key, &remote_pub_key).ok();

                *peer_public_key = remote_pub_key.into();

                Ok(None)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    fn get_responder_commitment(&'a mut self)
    -> Processor<'a, fn(&'a mut MasterSecurityManager<'a, C>, &[u8]) -> Result<Option<&'a mut super::KeyDBEntry>, Error>, C>
    {
        Processor {
            msm: self,
            expected: CommandType::PairingConfirm,
            job: Self::process_responder_commitment,
        }
    }

    /// Wait for responder check
    fn process_responder_commitment(&'a mut self, payload: &[u8])
    -> Result<Option<&'a mut super::KeyDBEntry>, Error>
    {
        match (&pairing::PairingConfirm::try_from_icd(payload), &mut self.pairing_data) {
            (
                Ok(responder_confirm),
                Some(PairingData {
                    key_gen_method: KeyGenerationMethod::JustWorks,
                    responder_pairing_confirm,
                    ..
                })
            ) |
            (
                Ok(responder_confirm),
                Some(PairingData {
                    key_gen_method: KeyGenerationMethod::NumbComp,
                    responder_pairing_confirm,
                    ..
                })
            ) => {
                *responder_pairing_confirm = responder_confirm.get_value().into();

                Ok(None)
            },
            (Err(_), _) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                Err(Error::Value)
            }
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        }
    }

    /// Send the Nonce
    ///
    /// # Panics
    /// This will panic if the pairing response has not been received yet
    fn send_pairing_random(&'a mut self)
    -> Result<Processor<'a, fn(&'a mut MasterSecurityManager<'a, C>, &[u8]) -> Result<Option<&'a mut super::KeyDBEntry>, Error>, C>, Error>
    {
        match self.pairing_data {
            Some( PairingData {
                key_gen_method: KeyGenerationMethod::JustWorks,
                nonce,
                ..
            }) |
            Some( PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                nonce,
                ..
            }) => {
                self.send(pairing::PairingRandom::new(nonce));

                Ok(Processor{
                    msm: self,
                    expected: CommandType::PairingRandom,
                    job: Self::process_responder_random,
                })
            }
            _ => {
                return Err(Error::UnsupportedFeature)
            }
        }
    }

    fn process_responder_random(&'a mut self, payload: &[u8])
    -> Result<Option<&'a mut super::KeyDBEntry>, Error>
    {
        use super::GetXOfP256Key;

        let responder_random = pairing::PairingRandom::try_from_icd(payload);

        let check_result = match (&responder_random, &mut self.pairing_data)
            {
                (
                    Ok(random_pdu),
                    Some( PairingData {
                        key_gen_method: KeyGenerationMethod::JustWorks,
                        nonce,
                        peer_nonce,
                        peer_public_key: Some(peer_public_key),
                        public_key,
                        responder_pairing_confirm: Some(responder_confirm),
                        ..
                      })
                ) | (
                    Ok(random_pdu),
                    Some( PairingData {
                        key_gen_method: KeyGenerationMethod::NumbComp,
                        nonce,
                        peer_nonce,
                        peer_public_key: Some(peer_public_key),
                        public_key,
                        responder_pairing_confirm: Some(responder_confirm),
                        ..
                    })
                ) => {
                    let responder_nonce = random_pdu.get_value();

                    let initiator_confirm = toolbox::f4(
                        public_key.x(),
                        peer_public_key.x(),
                        *nonce,
                        0
                    );

                    *peer_nonce = responder_nonce.into();

                    *responder_confirm == initiator_confirm
                }
                ( Err(_), _) => {
                    self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                    return Err(Error::Value)
                }
                _ => {
                    let reason = pairing::PairingFailedReason::UnspecifiedReason;

                    self.send_err(reason);

                    return Err(Error::PairingFailed(reason))
                }
            };

        if check_result {
            Ok(None)
        } else {
            let reason = pairing::PairingFailedReason::ConfirmValueFailed;

            self.send_err(reason);

            Err(Error::PairingFailed(reason))
        }
    }

    fn send_initiator_dh_key_check(&'a mut self)
    -> Result<Processor<'a, fn(&'a mut MasterSecurityManager<'a, C>, &[u8]) -> Result<Option<&'a mut super::KeyDBEntry>, Error>, C>, Error>
    {
        let ltk = match self.pairing_data {
            Some( PairingData{
                key_gen_method: KeyGenerationMethod::JustWorks,
                secret_key: Some( ref dh_key ),
                ref nonce,
                peer_nonce: Some( ref peer_nonce ),
                ref initiator_io_cap,
                ref mut mac_key,
                ..
            }) |
            Some( PairingData{
                key_gen_method: KeyGenerationMethod::NumbComp,
                secret_key: Some( ref dh_key ),
                ref nonce,
                peer_nonce: Some( ref peer_nonce ),
                ref initiator_io_cap,
                ref mut mac_key,
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(
                    self.initiator_address,
                    self.initiator_address_is_random
                );

                let b_addr = toolbox::PairingAddress::new(
                    self.responder_address,
                    self.responder_address_is_random
                );

                let (gen_mac_key, ltk) = toolbox::f5(
                    *dh_key,
                    *nonce,
                    *peer_nonce,
                    a_addr.clone(),
                    b_addr.clone(),
                );

                let ea = toolbox::f6(
                    gen_mac_key,
                    *nonce,
                    *peer_nonce,
                    0,
                    *initiator_io_cap,
                    a_addr,
                    b_addr,
                );

                *mac_key = gen_mac_key.into();

                self.send(pairing::PairingDHKeyCheck::new(ea));

                ltk
            }
            _ => {
                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason))
            }
        };

        self.pairing_data.as_mut().unwrap().db_keys = Some( super::KeyDBEntry {
            ltk: ltk.into(),
            csrk: (toolbox::rand_u128(), 0 ).into(),
            irk: toolbox::rand_u128().into(),
            peer_csrk: None,
            peer_irk: None,
            peer_addr: None,
        });

        Ok( Processor {
            msm: self,
            expected: CommandType::PairingDHKeyCheck,
            job: Self::process_responder_dh_key_check,
        } )
    }
    
    fn process_responder_dh_key_check(&'a mut self, payload: &[u8])
    -> Result<Option<&'a mut super::KeyDBEntry>, Error> {

        let eb = match pairing::PairingDHKeyCheck::try_from_icd(payload) {
            Ok(responder_confirm) => responder_confirm,
            Err(e) => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                return Err(e)
            }
        };

        let check = match self.pairing_data {
            Some( PairingData {
                key_gen_method: KeyGenerationMethod::JustWorks,
                ref nonce,
                peer_nonce: Some( ref peer_nonce ),
                ref responder_io_cap,
                mac_key: Some(ref mac_key),
                ..
            }) |
            Some( PairingData {
                key_gen_method: KeyGenerationMethod::NumbComp,
                ref nonce,
                peer_nonce: Some( ref peer_nonce ),
                ref responder_io_cap,
                mac_key: Some(ref mac_key),
                ..
            }) => {
                let a_addr = toolbox::PairingAddress::new(
                    self.initiator_address,
                    self.initiator_address_is_random
                );

                let b_addr = toolbox::PairingAddress::new(
                    self.responder_address,
                    self.responder_address_is_random
                );

                let calc_eb = toolbox::f6(
                    *mac_key,
                    *peer_nonce,
                    *nonce,
                    0,
                    *responder_io_cap,
                    b_addr,
                    a_addr,
                );

                eb.get_key_check() == calc_eb
            },
            _ => {
                self.send_err(pairing::PairingFailedReason::UnspecifiedReason);

                return Err(Error::PairingFailed(pairing::PairingFailedReason::UnspecifiedReason));
            }
        };

        if check {
            Ok( self.pairing_data.as_mut().unwrap().db_keys.as_mut() )
        } else {
            self.send_err(pairing::PairingFailedReason::DHKeyCheckFailed);

            Err(Error::PairingFailed(pairing::PairingFailedReason::DHKeyCheckFailed))
        }
    }

    /// Start Pairing
    ///
    /// This creates an pairing stepper that acts much like an iterator to go through the process of
    /// pairing with the slave device. When the iteration is complete, pairing is complete. However,
    /// this doesn't complete the process of bonding, the link needs to first be encrypted
    /// (initiated by this device if it stays as the master) and the IRK, address, and CSRK can be
    /// exchanged with the other device.
    ///
    /// The `Item` returned implements [`ResponseProcessor`] which is used to process the next
    /// pairing PDU from the responder.
    pub fn start_pairing(&'a mut self)
    -> impl PairingStep<Item = impl ResponseProcessor<Output=Option<&'a mut super::KeyDBEntry>> + 'a>
    {
        PairingProcess::new(self)
    }

    /// Indicate if the connection is encrypted
    ///
    /// This is used to indicate to the `MasterSecurityManager` that it is safe to send a Key to the
    /// peer device. This is a deliberate extra step to ensure that the functions `send_irk`,
    /// `send_csrk`, `send_pub_addr`, and `send_rand_addr` are only used when the link is encrypted.
    pub fn set_encrypted(&mut self, is_encrypted: bool) { self.link_encrypted = is_encrypted }

    /// Send the Identity Resolving Key to the Master Device
    ///
    /// This function will send the IRK to the master device if the internal encryption flag is set
    /// to true by [`set_encrypted`](MasterSecurityManager::set_encrypted)
    /// and an IRK has been generated. An IRK is generated once the return of
    /// [`start_pairing`](MasterSecurityManager::start_pairing)
    /// returns a reference to a [`KeyDBEntry`](super::KeyDBEntry). However, since the return is a
    /// mutable, you can replace the IRK with `None` which would also cause this function to
    /// return false. If the function returns false then the IRK isn't sent to the Master Device.
    pub fn send_irk(&self) -> bool {
        if self.link_encrypted {
            if let Some(irk) = self.pairing_data.as_ref()
                .and_then(|pd| pd.db_keys.as_ref() )
                .and_then(|db_key| db_key.irk.clone() )
            {
                self.send(encrypt_info::IdentityInformation::new(irk));

                true
            } else {
                false
            }
        } else {
            false
        }
    }

    /// Send the Connection Signature Resolving Key to the Master Device
    ///
    /// This function will send the CSRK to the master device if the internal encryption flag is set
    /// to true by [`set_encrypted`](MasterSecurityManager::set_encrypted)
    /// and an CSRK has been generated. An IRK is generated once the return of
    /// [`start_pairing`](MasterSecurityManager::start_pairing)
    /// returns a reference to a [`KeyDBEntry`](super::KeyDBEntry). However, since the return is a
    /// mutable, you can replace the IRK with `None` which would also cause this function to
    /// return false. If the function returns false then the IRK isn't sent to the Master Device.
    pub fn send_csrk(&self) -> bool {
        if self.link_encrypted {
            if let Some(csrk) = self.pairing_data.as_ref()
                .and_then(|pd| pd.db_keys.as_ref() )
                .and_then(|db_key| db_key.csrk.clone() )
            {
                self.send(encrypt_info::SigningInformation::new(csrk.0));

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
    /// encryption flag is set to true by [`set_encrypted`](MasterSecurityManager::set_encrypted).
    pub fn send_pub_addr(&self, addr: crate::BluetoothDeviceAddress) -> bool {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr));
            true
        } else {
            false
        }
    }

    /// Send the static random address to the Master Device.
    ///
    /// This will send `addr` as a Static Random Device Address to the Master Device if the internal
    /// encryption flag is set to true by [`set_encrypted`](MasterSecurityManager::set_encrypted).
    ///
    /// # Warning
    /// This function doesn't validate that `address` is a valid static device address. The format
    /// of a static random device address can be found in the Bluetooth Specification (v5.0 | Vol 6,
    /// Part B, section 1.3.2.1).
    pub fn send_static_rand_addr(&self, addr: crate::BluetoothDeviceAddress) -> bool {
        if self.link_encrypted {
            self.send(encrypt_info::IdentityAddressInformation::new_pub(addr));
            true
        } else {
            false
        }
    }
}

/// An iterator-like pairing process
///
/// This trait is designed to step through the pairing process with the responder. When the process
/// is done, the function `next` will return `None` just like `Iterator`.
pub trait PairingStep<'a> {
    type Item;

    fn next(&'a mut self) -> Option<Self::Item>;

    /// Pairing process fail reason
    ///
    /// If the pairing process fails due to... well you or my implementation... this will return the
    /// reason for the error. This will not return an error caused by the responder or some
    /// initiator-responder process such as the pairing confirm check failing.
    ///
    /// This returns `None` if there was no initiator caused pairing error.
    fn initiator_fail_reason(&self) -> Option<&Error>;
}

enum PairingStage {
    Start,
    WaitPairingResponse,
    WaitPairingPubKey,
    WaitPairingConfirm,
    WaitPairingRandom,
    WaitDhKeyCheck,
}

struct PairingProcess<'a, C> {
    stage: PairingStage,
    msm: &'a mut MasterSecurityManager<'a, C>,
    ifr: Option<Error>,
}

impl<'a,C> PairingProcess<'a,C> {
    fn new(msm: &'a mut  MasterSecurityManager<'a, C>) -> Self {
        Self {
            stage: PairingStage::Start,
            msm,
            ifr: None,
        }
    }
}

impl <'a, C> PairingStep<'a> for PairingProcess<'a, C> where C: crate::l2cap::ConnectionChannel {
    type Item = Processor<'a, fn(&'a mut MasterSecurityManager<'a, C>, &[u8]) -> Result<Option<&'a mut super::KeyDBEntry>, Error>, C>;

    fn next(&'a mut self) -> Option<Self::Item> {
        match self.stage {
            PairingStage::Start => {
                self.stage = PairingStage::WaitPairingResponse;

                Some(self.msm.send_pairing_request())
            },
            PairingStage::WaitPairingResponse => {
                self.stage = PairingStage::WaitPairingPubKey;

                match self.msm.send_pairing_pub_key() {
                    Ok(job) => Some(job),
                    Err(e) => {
                        self.ifr = e.into();
                        None
                    }
                }
            },
            PairingStage::WaitPairingPubKey => {
                self.stage = PairingStage::WaitPairingConfirm;

                Some(self.msm.get_responder_commitment())
            },
            PairingStage::WaitPairingConfirm => {
                self.stage = PairingStage::WaitPairingRandom;

                match self.msm.send_pairing_random() {
                    Ok(job) => Some(job),
                    Err(e) => {
                        self.ifr = e.into();
                        None
                    }
                }
            },
            PairingStage::WaitPairingRandom => {
                self.stage = PairingStage::WaitDhKeyCheck;
                
                match self.msm.send_initiator_dh_key_check() {
                    Ok(job) => Some(job),
                    Err(e) => {
                        self.ifr = e.into();
                        None
                    }
                }
            },
            PairingStage::WaitDhKeyCheck => {
                None
            }
        }
    }

    fn initiator_fail_reason(&self) -> Option<&Error> { self.ifr.as_ref() }
}