//! Trait for I/O functionality
//!
//! A Security Manager requires I/O functionality for most of the Man In The Middle Protection
//! methods. In order to provide that functionality the library user must provide methods to access

use core::future::Future;

/// Trait for a Yes/No input
///
/// This is used when the device has the capability of sending the equivalent of yes or no from the
/// user to the Security Manager.
///
/// When the Security Manager wants to acquire verification of successful authentication from the
/// user, it will call `read` and await `YesNoFuture` until it it polls to completion. The
/// successful output is a boolean indicating if the user replied with yes (`true`) or no (`false`).
pub trait YesNoInput {
    type Error;
    type YesNoFuture<'a>: Future<Output = Result<bool, Self::Error>>
    where
        Self: 'a;

    fn can_read() -> bool;

    fn read(&mut self) -> Self::YesNoFuture<'_>;
}

impl<T, F, E> YesNoInput for T
where
    T: FnMut() -> F,
    F: Future<Output = Result<bool, E>>,
{
    type Error = E;
    type YesNoFuture<'a> = F where Self: 'a;

    fn can_read() -> bool {
        true
    }

    fn read(&mut self) -> Self::YesNoFuture<'_> {
        self()
    }
}

/// Enum of the kinds of Keyboard inputs
///
/// This is returned as part of the output of the future returned by the method [`read`] of the
/// trait `KeyboardInput`.
///
/// [`read`]: KeyboardInput::next
#[derive(Copy, Clone, Ord, PartialOrd, Eq, PartialEq)]
pub enum KeyInput {
    /// User input for "yes"
    Yes,
    /// User input for "no"
    No,
    /// Key entered by the user
    Entered(char),
    /// A single key erased by the user
    ///
    /// `Erased` must contains the position of the digit erased by the user
    Erased(usize),
    /// Entire passkey cleared by the user
    Cleared,
    /// Passkey completed by the user
    Completed,
}

/// Keyboard Input Kind
///
/// Keyboard input can either be Yes/No or Passkey. This cannot be determined until both the
/// initiating and responding devices have determined the method for pairing. This is used for the
/// input of the method `KeyboardInput::next`, but most implementations of the trait `KeyboardInput`
/// will use it as the input to the closure.
///
/// ### Yes/No
/// The keyboard is to be used for yes or no input values.
///
/// ### PassKey
/// The keyboard is to be used for a passkey. The field within `Passkey` is a boolean for indicating
/// that the passkey has started.
pub enum InputKind {
    YesNo,
    Passkey(bool),
}

/// Trait for Keyboard Input
///
/// This is used whenever the device has a keyboard. With a keyboard the Security Manager will
/// support both Yes/No input and Passkey pairing. The keyboard is required to have some way to
/// enter digits (zero through nine) in order for the user to enter in a passcode. There should also
/// be some way to enter yes/no.
pub trait KeyboardInput {
    type Error;
    type KeypressFuture<'a>: Future<Output = Result<KeyInput, Self::Error>>
    where
        Self: 'a;

    fn can_read() -> bool;

    fn next(&mut self, kind: InputKind) -> Self::KeypressFuture<'_>;
}

impl<T, F, E> KeyboardInput for T
where
    T: FnMut(InputKind) -> F,
    F: Future<Output = Result<KeyInput, E>>,
{
    type Error = E;
    type KeypressFuture<'a> = F where Self: 'a;

    fn can_read() -> bool {
        true
    }

    fn next(&mut self, kind: InputKind) -> Self::KeypressFuture<'_> {
        self(kind)
    }
}

#[doc(hidden)]
/// User passkey input processor
pub struct UserKeyboardInput<T> {
    source: T,
    keys: [char; 6],
    current: usize,
}

impl<T> UserKeyboardInput<T> {
    pub fn new(source: T) -> Self {
        Self {
            source,
            keys: ['0'; 6],
            current: 0usize,
        }
    }

    /// Process the next passkey key
    pub async fn next_passkey(&mut self) -> Result<crate::pairing::KeyPressNotification, KeyboardError<T::Error>>
    where
        T: KeyboardInput,
    {
        match self.source.next().await? {
            KeyInput::Entered(c) => {
                self.keys[self.current] = c;
                self.current += 1;
                Ok(crate::pairing::KeyPressNotification::PasskeyDigitEntered)
            }
            KeyInput::Erased(pos) => {
                self.keys[pos] = '0';
                self.keys[pos..self.current].rotate_left(1);
                self.current -= 1;
                Ok(crate::pairing::KeyPressNotification::PasskeyDigitErased)
            }
            KeyInput::Cleared => {
                self.keys = ['0'; 6];
                self.current = 0;
                Ok(crate::pairing::KeyPressNotification::PasskeyCleared)
            }
            KeyInput::Completed => Ok(crate::pairing::KeyPressNotification::PasskeyEntryCompleted),
            KeyInput::Yes | KeyInput::No => Err(KeyboardError::UnexpectedYesOrNo),
        }
    }

    /// Process Yes/No
    pub async fn yes_no(&mut self) -> Result<bool, KeyboardError<T::Error>>
    where
        T: KeyboardInput,
    {
        match self.source.next().await? {
            KeyInput::Yes => Ok(true),
            KeyInput::No => Ok(false),
            _ => Err(KeyboardError::ExpectedYesOrNo),
        }
    }

    pub fn get_key_count(&self) -> usize {
        self.current
    }
}

/// Output for the Security Manager
///
/// `Output` is used to provide a display or other means to output information to the device user.
pub trait Output {
    fn can_write() -> bool;

    type Error;
    type WriteFuture<'a>: Future<Output = Result<(), Self::Error>>
    where
        Self: 'a;

    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteFuture<'a>;
}

impl<T, F, E> Output for T
where
    T: FnMut(&[u8]) -> F,
    F: Future<Output = Result<(), E>>,
{
    fn can_write() -> bool {
        true
    }

    type Error = E;
    type WriteFuture<'a> = F where T: 'a;

    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        self(buf)
    }
}

#[cfg(feature = "std")]
impl Output for std::io::Stdout {
    fn can_write() -> bool {
        true
    }

    type Error = std::io::Error;
    type WriteFuture<'a> = std::future::Ready<Result<(), Self::Error>>;
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> Self::WriteFuture<'a> {
        use std::io::Write;

        std::future::ready(self.write_all(buf))
    }
}

/// Marker type for unsupported [`Input`] or [`Output`]
pub type Unsupported = ();

impl YesNoInput for Unsupported {
    type Error = core::convert::Infallible;
    type YesNoFuture<'a> = core::future::Pending<Result<bool, Self::Error>>;
    fn can_read() -> bool {
        false
    }
    fn read(&mut self) -> Self::YesNoFuture<'_> {
        unreachable!()
    }
}

impl KeyboardInput for Unsupported {
    type Error = core::convert::Infallible;
    type KeypressFuture<'a> = core::future::Pending<Result<KeyInput, Self::Error>>;

    fn can_read() -> bool {
        false
    }

    fn next(&mut self) -> Self::KeypressFuture<'_> {
        unreachable!()
    }
}

impl Output for Unsupported {
    fn can_write() -> bool {
        false
    }

    type Error = core::convert::Infallible;
    type WriteFuture<'a> = core::future::Pending<Result<(), Self::Error>>;
    fn write<'a>(&'a mut self, _: &'a [u8]) -> Self::WriteFuture<'a> {
        unreachable!()
    }
}

pub enum KeyboardError<E> {
    UnexpectedYesOrNo,
    ExpectedYesOrNo,
    NotADigit(char),
    TooManyKeys(char),
    InvalidErasurePosition(usize),
    Impl(E),
}

impl<E> From<E> for KeyboardError<E> {
    fn from(e: E) -> Self {
        KeyboardError::Impl(e)
    }
}

impl<E> core::fmt::Debug for KeyboardError<E>
where
    E: core::fmt::Debug,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            KeyboardError::UnexpectedYesOrNo => f.write_str("UnexpectedYesOrNo"),
            KeyboardError::ExpectedYesOrNo => f.write_str("ExpectedYesOrNo"),
            KeyboardError::NotADigit(c) => write!(f, "NotADigit({})", c),
            KeyboardError::TooManyKeys(c) => write!(f, "TooManyKeys({})", c),
            KeyboardError::InvalidErasurePosition(p) => write!(f, "InvalidErasurePosition({})", p),
            KeyboardError::Impl(e) => core::fmt::Debug::fmt(e, f),
        }
    }
}

impl<E> core::fmt::Display for KeyboardError<E>
where
    E: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            KeyboardError::UnexpectedYesOrNo => f.write_str("expected passkey digit, not yes or no"),
            KeyboardError::ExpectedYesOrNo => f.write_str("expected yes or no, not a passkey digit"),
            KeyboardError::NotADigit(c) => write!(f, "non-digit entered in passkey ({})", c),
            KeyboardError::TooManyKeys(c) => write!(f, "too many keys entered for passkey ({})", c),
            KeyboardError::InvalidErasurePosition(p) => write!(f, "cannot erase key at position ({})", p),
            KeyboardError::Impl(e) => core::fmt::Display::fmt(e, f),
        }
    }
}

#[cfg(feature = "std")]
impl<E> std::error::Error for KeyboardError<E> where E: std::error::Error {}
