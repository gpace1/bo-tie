//! Characteristic user description descriptor implementation

use crate::characteristic::AddCharacteristicComponent;
use bo_tie_att::server::access_value::Trivial;
use bo_tie_att::server::{AccessReadOnly, AccessValue, ServerAttributes};
use bo_tie_att::{Attribute, AttributePermissions, AttributeRestriction};
use bo_tie_util::buffer::stack::LinearBuffer;
use core::borrow::Borrow;
use core::future::Future;
use core::ops::Deref;
use core::pin::Pin;
use core::task::{Context, Poll};

/// UUID for a user description descriptor
pub(crate) const TYPE: crate::Uuid = crate::Uuid::from_u16(0x2901);

pub struct UserDescriptionBuilder<T> {
    current: T,
}

impl UserDescriptionBuilder<SetDescription> {
    pub(crate) fn new() -> Self {
        UserDescriptionBuilder {
            current: SetDescription,
        }
    }

    /// Make the user description read-only
    ///
    /// This allows for `&'static str` and other immutable types to be used for the user
    /// description.
    pub fn read_only(self) -> UserDescriptionBuilder<SetReadOnlyDescription> {
        UserDescriptionBuilder {
            current: SetReadOnlyDescription,
        }
    }

    /// Set the user description
    pub fn set_description<S>(self, description: S) -> UserDescriptionBuilder<SetPermissions<Trivial<S>>>
    where
        S: Borrow<str> + From<alloc::string::String> + Send + Sync,
    {
        let current = SetPermissions {
            description: UserDescription(Trivial(description)),
        };

        UserDescriptionBuilder { current }
    }

    /// Set an accessible description
    pub fn set_accessible_description<A>(self, accessor: A) -> UserDescriptionBuilder<SetPermissions<A>>
    where
        A: AccessValue + 'static,
        A::ReadValue: Borrow<str>,
        A::WriteValue: From<alloc::string::String>,
    {
        let current = SetPermissions {
            description: UserDescription(accessor),
        };

        UserDescriptionBuilder { current }
    }
}

impl<A> UserDescriptionBuilder<SetPermissions<A>> {
    /// Set the Attribute permissions of the user description descriptor
    pub fn set_permissions<P>(self, permissions: P) -> UserDescriptionBuilder<Complete<UserDescription<A>>>
    where
        P: Borrow<[AttributePermissions]>,
    {
        let mut attribute_permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions> =
            LinearBuffer::new();

        unique_only!(attribute_permissions, permissions.borrow());

        let current = Complete::ReadWrite {
            description: self.current.description,
            permissions: attribute_permissions,
        };

        UserDescriptionBuilder { current }
    }
}

impl UserDescriptionBuilder<SetReadOnlyDescription> {
    /// Set a description that can only be read from by a Client
    pub fn set_read_only_description<S>(self, description: S) -> UserDescriptionBuilder<SetReadOnlyPermissions<S>>
    where
        S: Borrow<str> + Send + Sync + 'static,
    {
        let current = SetReadOnlyPermissions {
            description: Trivial(description),
        };

        UserDescriptionBuilder { current }
    }
}

impl<S> UserDescriptionBuilder<SetReadOnlyPermissions<S>> {
    /// Set the permission restrictions for read access by a Client
    pub fn set_read_only_restrictions<R>(
        self,
        restrictions: R,
    ) -> UserDescriptionBuilder<Complete<RoUserDescription<Trivial<S>>>>
    where
        R: Borrow<[AttributeRestriction]>,
    {
        let attribute_permissions = restrictions
            .borrow()
            .iter()
            .map(|restriction| AttributePermissions::Read(*restriction));

        let mut permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions> =
            LinearBuffer::new();

        unique_only_owned!(permissions, attribute_permissions);

        let current = Complete::ReadOnly {
            description: RoUserDescription(self.current.description),
            permissions,
        };

        UserDescriptionBuilder { current }
    }
}

impl AddCharacteristicComponent for UserDescriptionBuilder<SetDescription> {
    fn push_to(self, _: &mut ServerAttributes, _: &[AttributeRestriction]) -> bool {
        false
    }
}

impl<A> AddCharacteristicComponent for UserDescriptionBuilder<Complete<UserDescription<A>>>
where
    A: AccessValue + 'static,
    A::ReadValue: Borrow<str>,
    A::WriteValue: From<alloc::string::String>,
{
    fn push_to(self, sa: &mut ServerAttributes, _: &[AttributeRestriction]) -> bool {
        match self.current {
            Complete::ReadWrite {
                description,
                permissions,
            } => {
                let attribute = Attribute::new(TYPE, permissions, description);

                sa.push_accessor(attribute);

                true
            }
            _ => unreachable!(),
        }
    }
}

impl<S> AddCharacteristicComponent for UserDescriptionBuilder<Complete<RoUserDescription<S>>>
where
    S: AccessReadOnly + 'static,
    S::Value: Borrow<str>,
{
    fn push_to(self, sa: &mut ServerAttributes, _: &[AttributeRestriction]) -> bool {
        match self.current {
            Complete::ReadOnly {
                description,
                permissions,
            } => {
                let attribute = Attribute::new(TYPE, permissions, description);

                sa.push_read_only(attribute);

                true
            }
            _ => unreachable!(),
        }
    }
}

/// `UserDescriptionBuilder` marker type
///
/// This marker type is used for enabling the method [`UserDescriptionBuilder::read_only`],
/// [`UserDescriptionBuilder::read_only`], and [`UserDescriptionBuilder::read_only`].
///
/// [`UserDescriptionBuilder::read_only`]: UserDescriptionBuilder::<SetDescription>::read_only
/// [`UserDescriptionBuilder::set_description`]: UserDescriptionBuilder::<SetDescription>::set_description
/// [`UserDescriptionBuilder::set_accessible_description`]: UserDescriptionBuilder::<SetDescription>::set_accessible_description
pub struct SetDescription;

/// `UserDescriptionBuilder` marker type
///
/// This marker type is used for enabling the method [`UserDescriptionBuilder::set_permissions`].
///
/// [`UserDescriptionBuilder::set_permissions`]: UserDescriptionBuilder::<SetReadOnlyDescription>::set_permissions
pub struct SetReadOnlyDescription;

/// `UserDescriptionBuilder` marker type
///
/// This marker type is used for enabling the method [`UserDescriptionBuilder::set_read_only_restrictions`].
///
/// [`UserDescriptionBuilder::set_read_only_restrictions`]: UserDescriptionBuilder::<SetReadOnlyPermissions>::set_read_only_restrictions
pub struct SetReadOnlyPermissions<S> {
    description: Trivial<S>,
}

/// `UserDescriptionBuilder` marker type
///
/// This marker type is used for enabling the method [`UserDescriptionBuilder::set_permissions`].
///
/// [`UserDescriptionBuilder::set_permissions`]: UserDescriptionBuilder::<SetPermissions>::set_permissions
pub struct SetPermissions<S> {
    description: UserDescription<S>,
}

/// `UserDescriptionBuilder` marker type
///
/// This marks that a `UserDescriptionBuilder` is complete.
pub enum Complete<S> {
    ReadWrite {
        description: S,
        permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,
    },
    ReadOnly {
        description: S,
        permissions: LinearBuffer<{ AttributePermissions::full_depth() }, AttributePermissions>,
    },
}

/// The user description
///
/// The main purpose of this wrapper is to enforce the usage of `utf8` as the transfer format for
/// the user description.
pub struct UserDescription<A>(A);

impl<A> AccessValue for UserDescription<A>
where
    A: AccessValue,
    A::ReadValue: Borrow<str>,
    A::WriteValue: From<alloc::string::String>,
{
    type ReadValue = str;
    type ReadGuard<'a> = ReadGuard<A::ReadGuard<'a>> where Self: 'a;
    type Read<'a> = ReadUserDescription<A::Read<'a>> where Self: 'a;
    type WriteValue = alloc::string::String;
    type Write<'a> = A::Write<'a> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadUserDescription { future: self.0.read() }
    }

    fn write(&mut self, v: Self::WriteValue) -> Self::Write<'_> {
        self.0.write(<A::WriteValue as From<alloc::string::String>>::from(v))
    }
}

pub struct ReadGuard<T>(T);

impl<T> Deref for ReadGuard<T>
where
    T: Deref,
    T::Target: Borrow<str>,
{
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.deref().borrow()
    }
}

pub struct ReadUserDescription<F> {
    future: F,
}

impl<F> Future for ReadUserDescription<F>
where
    F: Future,
    F::Output: Deref,
    <F::Output as Deref>::Target: Borrow<str>,
{
    type Output = ReadGuard<F::Output>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        unsafe {
            self.map_unchecked_mut(|this| &mut this.future)
                .poll(cx)
                .map(|output| ReadGuard(output))
        }
    }
}

/// A read only user description
///
/// The main purpose of this wrapper is to enforce the usage of `utf8` as the transfer format for
/// the user description. This
pub struct RoUserDescription<S>(S);

impl<S> AccessReadOnly for RoUserDescription<S>
where
    S: AccessReadOnly,
    S::Value: Borrow<str>,
{
    type Value = str;
    type ReadGuard<'a> = ReadGuard<S::ReadGuard<'a>> where Self: 'a;
    type Read<'a> = ReadUserDescription<S::Read<'a>> where Self: 'a;

    fn read(&self) -> Self::Read<'_> {
        ReadUserDescription { future: self.0.read() }
    }
}
