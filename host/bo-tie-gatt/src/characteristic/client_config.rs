//! Characteristic client configuration descriptor implementation

use crate::characteristic::{AddCharacteristicComponent, VecArray};
use bo_tie_att::server::access_value::{ReadReady, WriteReady};
use bo_tie_att::server::{AccessValue, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
use bo_tie_util::buffer::stack::LinearBuffer;
use core::borrow::Borrow;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

/// UUID of a client configuration descriptor
pub(crate) const TYPE: bo_tie_host_util::Uuid = bo_tie_host_util::Uuid::from_u16(2902);

/// Default permissions of an client configuration descriptor
const DEFAULT_PERMISSIONS: [AttributePermissions; 6] = bo_tie_att::FULL_READ_PERMISSIONS;

type ClientConfigVec = VecArray<{ ClientConfiguration::full_depth() }, ClientConfiguration>;

/// Constructor of the client configuration descriptor
pub struct ClientConfigurationBuilder<T> {
    enabled_config: LinearBuffer<{ ClientConfiguration::full_depth() }, ClientConfiguration>,
    init_config: LinearBuffer<{ ClientConfiguration::full_depth() }, ClientConfiguration>,
    on_write: T,
    permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,
}

impl ClientConfigurationBuilder<ReadOnlyClientConfiguration> {
    pub(crate) fn new() -> Self {
        ClientConfigurationBuilder {
            enabled_config: LinearBuffer::new(),
            init_config: LinearBuffer::new(),
            on_write: ReadOnlyClientConfiguration,
            permissions: LinearBuffer::new(),
        }
    }
}

impl<T> ClientConfigurationBuilder<T> {
    /// Set the configuration that the client can enabled
    ///
    /// The client will be able to set these client configuration parameters (if the client has
    /// write access). The client will get an error if it tries to write any configuration not
    /// within `config`.
    pub fn set_config<C>(mut self, config: C) -> Self
    where
        C: Borrow<[ClientConfiguration]>,
    {
        self.enabled_config.clear();

        unique_only!(self.enabled_config, config.borrow());

        self
    }

    /// Set the initial initial configuration
    ///
    /// This will set the client configuration upon creation of the ATT server.
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
    /// writes are permitted only to clients that are either authenticated or authorized, but
    /// these restrictions can be changed by calling the method [`set_write_restrictions`].
    ///
    /// [`set_write_restrictions`]: ClientConfigurationBuilder::set_write_restrictions
    pub fn set_write_callback<Fun, Fut>(mut self, callback: Fun) -> ClientConfigurationBuilder<Fun>
    where
        Fun: FnMut(SetClientConfig) -> Fut + Send + Sync + 'static,
        Fut: Future + Send + Sync,
    {
        if self.permissions.len() == 0 {
            self.permissions
                .try_push(AttributePermissions::Write(AttributeRestriction::Authentication))
                .unwrap();
            self.permissions
                .try_push(AttributePermissions::Write(AttributeRestriction::Authorization))
                .unwrap();
        }

        ClientConfigurationBuilder {
            enabled_config: self.enabled_config,
            init_config: self.init_config,
            on_write: callback,
            permissions: self.permissions,
        }
    }

    /// Set the restrictions for writing to the client configuration
    ///
    /// By default, writes are allowed only for authenticated and authorized clients. This method
    /// is used to customize the restrictions from their default. This method has no effect on the
    /// permissions if method [`set_write_callback`] is not also called.
    ///
    /// [`set_write_callback`]: ClientConfigurationBuilder::set_write_callback
    pub fn set_write_restrictions<R>(mut self, restrictions: R) -> Self
    where
        R: Borrow<[AttributeRestriction]>,
    {
        let attribute_permissions = restrictions
            .borrow()
            .iter()
            .map(|restriction| AttributePermissions::Write(*restriction));

        self.permissions.clear();

        unique_only_owned!(self.permissions, attribute_permissions);

        self
    }
}

impl AddCharacteristicComponent for ClientConfigurationBuilder<ReadOnlyClientConfiguration> {
    fn push_to(self, _: &mut ServerAttributes) -> bool {
        false
    }
}

impl<Fun, Fut> AddCharacteristicComponent for ClientConfigurationBuilder<Fun>
where
    Fun: for<'a> FnMut(SetClientConfig) -> Fut + Send + Sync + 'static,
    Fut: Future + Send + Sync,
{
    fn push_to(mut self, sa: &mut ServerAttributes) -> bool {
        let mut init_config: ClientConfigVec = VecArray(LinearBuffer::new());

        for config in self.enabled_config.iter() {
            if self.init_config.contains(config) {
                init_config.0.try_push(*config).unwrap();
            }
        }

        for permission in DEFAULT_PERMISSIONS {
            self.permissions.try_push(permission).unwrap();
        }

        let value = ClientConfigurationAccessor {
            config_mask: self.enabled_config,
            config: init_config,
            write_callback: self.on_write,
        };

        let attribute = Attribute::new(TYPE, self.permissions, value);

        sa.push_accessor(attribute);

        true
    }
}

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
    type Read<'a> = ReadReady<Self::ReadGuard<'a>> where Self: 'a;
    type WriteValue = ClientConfigVec;
    type Write<'a> = WriteReady<'a, ClientConfigVec> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadReady::new(&self.config)
    }

    fn write(&mut self, client_config: Self::WriteValue) -> Self::Write<'_> {
        WriteReady::new(&mut self.config, client_config)
    }
}

impl<Fun, Fut> AccessValue for ClientConfigurationAccessor<Fun>
where
    Fun: for<'z> FnMut(SetClientConfig) -> Fut + Send + Sync,
    Fut: Future + Send + Sync,
{
    type ReadValue = ClientConfigVec;
    type ReadGuard<'a> = &'a ClientConfigVec where Self: 'a;
    type Read<'a> = ReadReady<Self::ReadGuard<'a>> where Self: 'a;
    type WriteValue = ClientConfigVec;
    type Write<'a> = WriteAccessor<'a, Fun, Fut> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadReady::new(&self.config)
    }

    fn write(&mut self, config: Self::WriteValue) -> Self::Write<'_> {
        WriteAccessor {
            accessor: self,
            future: None,
            value: Some(config),
        }
    }
}

struct WriteAccessor<'a, Fun, Fut> {
    accessor: &'a mut ClientConfigurationAccessor<Fun>,
    future: Option<Fut>,
    value: Option<ClientConfigVec>,
}

impl<Fun, Fut> Future for WriteAccessor<'_, Fun, Fut>
where
    Fun: for<'z> FnMut(SetClientConfig) -> Fut + Send + Sync,
    Fut: Future + Send + Sync,
{
    type Output = Fut::Output;

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
                Some(future) => break unsafe { Pin::new_unchecked(future).poll(cx) },
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
