//! Characteristic client configuration descriptor implementation

use crate::characteristic::{AddCharacteristicComponent, VecArray};
use bo_tie_att::server::{AccessValue, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
use bo_tie_core::buffer::stack::LinearBuffer;
use core::borrow::Borrow;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// UUID of a client configuration descriptor
pub(crate) const TYPE: bo_tie_host_util::Uuid = crate::uuid::CLIENT_CHARACTERISTIC_CONFIGURATION;

type ClientConfigVec = VecArray<{ ClientConfiguration::full_depth() }, ClientConfiguration>;

/// Constructor of the client configuration descriptor
pub struct ClientConfigurationBuilder<T> {
    enabled_config: LinearBuffer<{ ClientConfiguration::full_depth() }, ClientConfiguration>,
    init_config: LinearBuffer<{ ClientConfiguration::full_depth() }, ClientConfiguration>,
    on_write: T,
    write_restrictions: LinearBuffer<{ AttributeRestriction::full_depth() }, AttributeRestriction>,
}

impl ClientConfigurationBuilder<SetClientConfiguration> {
    pub(crate) fn new() -> Self {
        ClientConfigurationBuilder {
            enabled_config: LinearBuffer::new(),
            init_config: LinearBuffer::new(),
            on_write: SetClientConfiguration,
            write_restrictions: LinearBuffer::new(),
        }
    }
}

impl ClientConfigurationBuilder<SetClientConfiguration> {
    /// Set the configuration that can be enabled by the client
    ///
    /// The client will be able to set these client configuration parameters (if the client has
    /// write access). The client will get an error if it tries to write any configuration not
    /// within `config`.
    pub fn set_config<C>(mut self, config: C) -> ClientConfigurationBuilder<ReadOnlyClientConfiguration>
    where
        C: Borrow<[ClientConfiguration]>,
    {
        self.enabled_config.clear();

        unique_only!(self.enabled_config, config.borrow());

        ClientConfigurationBuilder {
            enabled_config: self.enabled_config,
            init_config: self.init_config,
            on_write: ReadOnlyClientConfiguration,
            write_restrictions: self.write_restrictions,
        }
    }
}

impl ClientConfigurationBuilder<ReadOnlyClientConfiguration> {
    /// Set the initial configuration
    ///
    /// This will set the initial client configuration upon creation of the ATT server.
    ///
    /// # Note
    /// If any config parameters within the input are not enabled by [`set_config`], they are
    /// ignored.
    ///
    /// [`set_config`]: ClientConfigurationBuilder::set_config  
    pub fn init_config<C>(mut self, config: C) -> Self
    where
        C: Borrow<[ClientConfiguration]>,
    {
        self.init_config.clear();

        unique_only!(self.init_config, config.borrow());

        self
    }

    /// Set a callback for a write operation
    ///
    /// Whenever a client writes to this descriptor, this `callback` will be called. Calling this
    /// method also enables adding the write attribute permissions to this descriptor. By default,
    /// writes are permitted only to clients that have been granted a write permission with either
    /// the restriction [authenticated] or [authorized]. If these write restrictions are not
    /// appropriate for the application they can be changed by calling the method
    /// [`set_write_restrictions`].
    ///
    /// [`Authenticated`]: AttributeRestriction::Authentication
    /// [`Authorized`]: AttributeRestriction::Authorization
    /// [`set_write_restrictions`]: ClientConfigurationBuilder::set_write_restrictions
    pub fn set_write_callback<Fun, Fut>(mut self, callback: Fun) -> ClientConfigurationBuilder<Fun>
    where
        Fun: FnMut(SetClientConfig) -> Fut + Send + 'static,
        Fut: Future + Send,
    {
        if self.write_restrictions.len() == 0 {
            self.write_restrictions
                .try_push(AttributeRestriction::Authentication)
                .unwrap();
            self.write_restrictions
                .try_push(AttributeRestriction::Authorization)
                .unwrap();
        }

        ClientConfigurationBuilder {
            enabled_config: self.enabled_config,
            init_config: self.init_config,
            on_write: callback,
            write_restrictions: self.write_restrictions,
        }
    }
}

impl<Fun, Fut> ClientConfigurationBuilder<Fun>
where
    Fun: FnMut(SetClientConfig) -> Fut + Send + 'static,
    Fut: Future + Send,
{
    /// Set the restrictions for writing to the client configuration
    ///
    /// By default, writes are allowed only for authenticated and authorized clients. This method
    /// is used to customize the restrictions from their default.
    pub fn set_write_restrictions<R>(mut self, restrictions: R) -> Self
    where
        R: Borrow<[AttributeRestriction]>,
    {
        self.write_restrictions.clear();

        unique_only!(self.write_restrictions, restrictions.borrow());

        self
    }
}

impl AddCharacteristicComponent for ClientConfigurationBuilder<SetClientConfiguration> {
    fn push_to(self, _: &mut ServerAttributes, _: &[AttributeRestriction]) -> bool {
        false
    }
}

impl AddCharacteristicComponent for ClientConfigurationBuilder<ReadOnlyClientConfiguration> {
    fn push_to(self, sa: &mut ServerAttributes, restrictions: &[AttributeRestriction]) -> bool {
        let mut init_config: ClientConfigVec = VecArray(LinearBuffer::new());

        let mut attribute_permissions = LinearBuffer::<{ AttributePermissions::full_depth() }, _>::new();

        for config in self.enabled_config.iter() {
            if self.init_config.contains(config) {
                init_config.0.try_push(*config).unwrap();
            }
        }

        map_restrictions!(restrictions => Read => attribute_permissions);

        let value = ClientConfigurationAccessor {
            config_mask: self.enabled_config,
            config: init_config,
            write_callback: self.on_write,
        };

        let attribute = Attribute::new(TYPE, attribute_permissions, value);

        sa.push_accessor(attribute);

        true
    }
}

impl<Fun, Fut> AddCharacteristicComponent for ClientConfigurationBuilder<Fun>
where
    Fun: for<'a> FnMut(SetClientConfig) -> Fut + Send + 'static,
    Fut: Future + Send,
{
    fn push_to(self, sa: &mut ServerAttributes, restrictions: &[AttributeRestriction]) -> bool {
        let mut init_config: ClientConfigVec = VecArray(LinearBuffer::new());

        let mut attribute_permissions = LinearBuffer::<{ AttributePermissions::full_depth() }, _>::new();

        for config in self.enabled_config.iter() {
            if self.init_config.contains(config) {
                init_config.0.try_push(*config).unwrap();
            }
        }

        map_restrictions!(self.write_restrictions => Write => attribute_permissions);

        map_restrictions!(restrictions => Read => attribute_permissions);

        let value = ClientConfigurationAccessor {
            config_mask: self.enabled_config,
            config: init_config,
            write_callback: self.on_write,
        };

        let attribute = Attribute::new(TYPE, attribute_permissions, value);

        sa.push_accessor(attribute);

        true
    }
}

/// Marker type for an unused client configuration
pub struct SetClientConfiguration;

/// Marker type for a client configuration that is read only
pub struct ReadOnlyClientConfiguration;

/// The client configuration
struct ClientConfigurationAccessor<F> {
    config_mask: LinearBuffer<{ ClientConfiguration::full_depth() }, ClientConfiguration>,
    config: ClientConfigVec,
    write_callback: F,
}

impl AccessValue for ClientConfigurationAccessor<ReadOnlyClientConfiguration> {
    type ReadValue = ClientConfigVec;
    type ReadGuard<'a> = &'a ClientConfigVec where Self: 'a;
    type Read<'a> = core::future::Ready<Self::ReadGuard<'a>> where Self: 'a;
    type WriteValue = ClientConfigVec;
    type Write<'a> = core::future::Ready<Result<(), bo_tie_att::pdu::Error>>;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(&self.config)
    }

    fn write(&mut self, client_config: Self::WriteValue) -> Self::Write<'_> {
        self.config = client_config;

        core::future::ready(Ok(()))
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

impl<Fun, Fut> AccessValue for ClientConfigurationAccessor<Fun>
where
    Fun: FnMut(SetClientConfig) -> Fut + Send + 'static,
    Fut: Future + Send,
{
    type ReadValue = ClientConfigVec;
    type ReadGuard<'a> = &'a ClientConfigVec where Self: 'a;
    type Read<'a> = core::future::Ready<Self::ReadGuard<'a>> where Self: 'a;
    type WriteValue = ClientConfigVec;
    type Write<'a> = WriteAccessor<'a, Fun, Fut> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        core::future::ready(&self.config)
    }

    fn write(&mut self, config: Self::WriteValue) -> Self::Write<'_> {
        WriteAccessor {
            accessor: self,
            future: None,
            value: Some(config),
        }
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_mut_any(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

struct WriteAccessor<'a, Fun, Fut> {
    accessor: &'a mut ClientConfigurationAccessor<Fun>,
    future: Option<Fut>,
    value: Option<ClientConfigVec>,
}

impl<Fun, Fut> Future for WriteAccessor<'_, Fun, Fut>
where
    Fun: for<'z> FnMut(SetClientConfig) -> Fut + Send,
    Fut: Future + Send,
{
    type Output = Result<(), crate::att::pdu::Error>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = unsafe { self.get_unchecked_mut() };

        loop {
            match this.future.as_mut().take() {
                None => {
                    let mut new_config: ClientConfigVec = VecArray(LinearBuffer::new());

                    for config in this.value.take().unwrap().0.iter() {
                        if this.accessor.config_mask.contains(config) {
                            new_config.0.try_push(*config).unwrap()
                        }
                    }

                    this.accessor.config = new_config;

                    let callback_config = SetClientConfig {
                        config: this.accessor.config.0.clone(),
                    };

                    this.future = Some((this.accessor.write_callback)(callback_config))
                }
                Some(future) => break unsafe { Pin::new_unchecked(future).poll(cx).map(|_| Ok(())) },
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, bo_tie_macros::DepthCount)]
pub enum ClientConfiguration {
    Notification,
    Indication,
}

impl ClientConfiguration {
    /// Convert to native-endian bits
    fn to_bits(config: &[ClientConfiguration]) -> u16 {
        config.iter().fold(0u16, |bits, cfg| {
            bits | match cfg {
                ClientConfiguration::Notification => 1 << 0,
                ClientConfiguration::Indication => 1 << 1,
            }
        })
    }

    /// Convert from native-endian bits
    ///
    /// Bits that are specification defined as reserved are ignored
    fn from_bits(bits: u16) -> ClientConfigVec {
        let v = (0..ClientConfiguration::full_depth())
            .filter_map(|bit| match bits & 1 << bit {
                0x1 => Some(ClientConfiguration::Notification),
                0x2 => Some(ClientConfiguration::Indication),
                _ => None,
            })
            .fold(LinearBuffer::new(), |mut lb, cc| {
                lb.try_push(cc).unwrap();
                lb
            });

        VecArray(v)
    }
}

/// The client configuration set by the Client
///
/// This is passed to the callback whenever the Client writes to the associated client
/// configuration. This dereferences to a slice of the client configuration parameters set by the
/// client. See [`set_write_callback`].
///
/// [`set_write_callback`]: ClientConfigurationBuilder::set_write_callback
pub struct SetClientConfig {
    config: LinearBuffer<{ ClientConfiguration::full_depth() }, ClientConfiguration>,
}

impl core::ops::Deref for SetClientConfig {
    type Target = [ClientConfiguration];

    fn deref(&self) -> &Self::Target {
        &*self.config
    }
}

impl bo_tie_att::TransferFormatInto for ClientConfigVec {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&ClientConfiguration::to_bits(&*self.0).to_le_bytes())
    }
}

impl bo_tie_att::TransferFormatTryFrom for ClientConfigVec {
    fn try_from(raw: &[u8]) -> Result<Self, bo_tie_att::TransferFormatError> {
        if raw.len() == 2 {
            Ok(ClientConfiguration::from_bits(<u16>::from_le_bytes([raw[0], raw[1]])))
        } else {
            Err(bo_tie_att::TransferFormatError::bad_size(
                stringify!(ClientConfiguration),
                2,
                raw.len(),
            ))
        }
    }
}

impl bo_tie_att::TransferFormatInto for ClientConfiguration {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        let val: u16 = match *self {
            ClientConfiguration::Notification => 0x1,
            ClientConfiguration::Indication => 0x2,
        };

        into_ret.copy_from_slice(&val.to_le_bytes())
    }
}

/// A trait to mark that the client configuration characteristic is complete
pub trait ClientConfigComplete {}

impl ClientConfigComplete for ReadOnlyClientConfiguration {}

impl<Fun, Fut> ClientConfigComplete for Fun
where
    Fun: for<'a> FnMut(SetClientConfig) -> Fut + Send + 'static,
    Fut: Future + Send,
{
}
