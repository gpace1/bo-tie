//! Server Configuration Descriptor implementation

use crate::characteristic::{AddCharacteristicComponent, VecArray};
use bo_tie_att::server::{AccessValue, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions};
use bo_tie_util::buffer::stack::LinearBuffer;
use core::borrow::Borrow;

/// UUID of a server configuration descriptor
pub(crate) const TYPE: bo_tie_host_util::Uuid = bo_tie_host_util::Uuid::from_u16(0x2903);

/// Default permissions of an server configuration descriptor
const DEFAULT_PERMISSIONS: [AttributePermissions; 6] = bo_tie_att::FULL_READ_PERMISSIONS;

/// Builder of a server configuration descriptor
#[derive(Clone)]
pub struct ServerConfigurationBuilder<T> {
    current: T,
}

impl ServerConfigurationBuilder<SetConfiguration> {
    /// Create a new `ServerConfigurationBuilder`
    pub fn new() -> Self {
        ServerConfigurationBuilder {
            current: SetConfiguration,
        }
    }

    /// Set the value of the server configuration
    ///
    /// The server configuration is shared by all clients, both currently connected and not
    /// connected but bonded. The accessor `A` should be a mutex like structure to share access to
    /// the same server configuration on all servers that use this characteristic.
    ///
    /// # Note
    /// Generic parameter `A` must implement [`Clone`] if this `ServerConfigurationBuilder` is to be
    /// used by multiple instance of the same Characteristic.
    pub fn set_config<A>(self, server_configuration: A) -> ServerConfigurationBuilder<SetPermissions<A>>
    where
        A: AccessValue<ReadValue = ServerConfiguration, WriteValue = ServerConfiguration> + 'static,
    {
        let current = SetPermissions {
            config: server_configuration,
        };

        ServerConfigurationBuilder { current }
    }
}

impl<A> ServerConfigurationBuilder<SetPermissions<A>> {
    /// Set the write attribute restrictions
    ///
    /// This sets restrictions for writing the server configuration *for this client only*.
    pub fn set_permissions<P>(self, permissions: P) -> ServerConfigurationBuilder<Complete<A>>
    where
        P: Borrow<[AttributePermissions]>,
    {
        let mut attribute_permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions> =
            LinearBuffer::new();

        unique_only!(attribute_permissions, permissions.borrow());

        unique_only_owned!(attribute_permissions, DEFAULT_PERMISSIONS);

        let current = Complete {
            config: self.current.config,
            permissions: attribute_permissions,
        };

        ServerConfigurationBuilder { current }
    }
}

impl AddCharacteristicComponent for ServerConfigurationBuilder<SetConfiguration> {
    fn push_to(self, _: &mut ServerAttributes) -> bool {
        false
    }
}

impl<A> AddCharacteristicComponent for ServerConfigurationBuilder<Complete<A>>
where
    A: AccessValue<ReadValue = ServerConfiguration, WriteValue = ServerConfiguration> + 'static,
{
    fn push_to(self, sa: &mut ServerAttributes) -> bool {
        let attribute = Attribute::new(TYPE, self.current.permissions, self.current.config);

        sa.push_accessor(attribute);

        true
    }
}

/// `ServerConfigurationBuilder` marker type
///
/// This marker type is used for enabling the method [`ServerConfigurationBuilder::set_value`]
#[derive(Clone)]
pub struct SetConfiguration;

/// `ServerConfigurationBuilder` marker type
///
/// This marker type is used for enabling the method [`ServerConfigurationBuilder::set_value`]
#[derive(Clone)]
pub struct SetPermissions<A> {
    config: A,
}

/// `ServerConfigurationBuilder` marker type
///
/// This marks that a `ValueBuilder` is complete.
#[derive(Clone)]
pub struct Complete<A> {
    config: A,
    permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,
}

/// The server configuration descriptor value
#[derive(Copy, Clone, PartialEq, bo_tie_macros::DepthCount)]
enum ServerConfigurationKind {
    Broadcast,
}

impl ServerConfigurationKind {
    /// Convert to native-endian bits
    fn to_bits(config: &[ServerConfigurationKind]) -> u16 {
        config.iter().fold(0u16, |bits, cfg| {
            bits | match cfg {
                ServerConfigurationKind::Broadcast => 1 << 0,
            }
        })
    }

    /// Convert from native-endian bits
    ///
    /// Bits that are specification defined as reserved are ignored
    fn from_bits(bits: u16) -> VecArray<{ ServerConfigurationKind::full_depth() }, ServerConfigurationKind> {
        let lb = (0..ServerConfigurationKind::full_depth())
            .filter_map(|bit| match bits & 1 << bit {
                0x1 => Some(ServerConfigurationKind::Broadcast),
                _ => None,
            })
            .fold(LinearBuffer::new(), |mut lb, sc| {
                lb.try_push(sc).unwrap();
                lb
            });

        VecArray(lb)
    }
}

/// The server configuration descriptor value
#[derive(PartialEq)]
pub struct ServerConfiguration {
    config: VecArray<{ ServerConfigurationKind::full_depth() }, ServerConfigurationKind>,
}

impl ServerConfiguration {
    /// Create a new `ServerConfiguration`
    ///
    /// This can be useful for creating the initial server configuration. But the return should be
    /// shared by all clients who have access the characteristic that owns this
    /// `ServerConfiguration`.
    pub fn new() -> ServerConfiguration {
        ServerConfiguration {
            config: VecArray(LinearBuffer::new()),
        }
    }

    /// Set the broadcast flag
    ///
    /// This sets the broadcast flag within the server configuration
    pub fn set_broadcast(&mut self) {
        if !self.config.0.contains(&ServerConfigurationKind::Broadcast) {
            self.config.0.try_push(ServerConfigurationKind::Broadcast).unwrap();
        }
    }

    /// Clear the broadcast flag
    ///
    /// This clears the broadcast flag within the server configuration
    pub fn clear_broadcast(&mut self) {
        if let Some(index) = self
            .config
            .0
            .iter()
            .position(|kind| kind == &ServerConfigurationKind::Broadcast)
        {
            self.config.0.try_remove(index).unwrap();
        }
    }
}

impl bo_tie_att::TransferFormatInto for ServerConfiguration {
    fn len_of_into(&self) -> usize {
        2
    }

    fn build_into_ret(&self, into_ret: &mut [u8]) {
        into_ret.copy_from_slice(&ServerConfigurationKind::to_bits(&self.config.0).to_le_bytes())
    }
}

impl bo_tie_att::TransferFormatTryFrom for ServerConfiguration {
    fn try_from(raw: &[u8]) -> Result<Self, bo_tie_att::TransferFormatError> {
        if raw.len() == 2 {
            let config = ServerConfigurationKind::from_bits(<u16>::from_le_bytes([raw[0], raw[1]]));

            Ok(ServerConfiguration { config })
        } else {
            Err(bo_tie_att::TransferFormatError::bad_size(
                stringify!(ClientConfiguration),
                2,
                raw.len(),
            ))
        }
    }
}
