//! Trait for I/O functionality
//!
//! A Security Manager requires I/O functionality for most of the Man In The Middle Protection
//! methods. In order to provide that functionality the library user must provide methods to access

use bo_tie_util::buffer::stack::LinearBuffer;
use core::fmt::Arguments;
use core::future::Future;

/// Input from the application user
///
/// This is used by the Security Managers to process user input.
pub struct UserInput(UserInputInner);

impl UserInput {
    fn yes() -> Self {
        UserInput(UserInputInner::Yes)
    }

    fn no() -> Self {
        UserInput(UserInputInner::No)
    }

    fn key() -> Self {
        UserInput(UserInputInner::Key)
    }

    fn key_erase() -> Self {
        UserInput(UserInputInner::KeyErase)
    }

    fn passkey_clear() -> Self {
        UserInput(UserInputInner::PasskeyClear)
    }

    fn passkey_complete(passkey: u32) -> Self {
        UserInput(UserInputInner::PasskeyComplete(passkey))
    }

    pub(crate) fn into_inner(self) -> UserInputInner {
        self.0
    }
}

pub(crate) enum UserInputInner {
    Yes,
    No,
    Key,
    KeyErase,
    PasskeyClear,
    PasskeyComplete(u32),
}

/// The compare value used for number comparison
pub struct CompareValue(pub(crate) u32);

impl core::fmt::Display for CompareValue {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:06}", self.0 % 1_000_000)
    }
}

/// Yes/No input from the application user
///
/// A `YesNoInput` is used for confirmation that a *compare value* matches on both devices of the
/// connection. The user of both devices must enter yes on both sides for pairing to be successfully
/// completed.
///
/// The compare value can be displayed to the user using the [`Display`] trait (this also means it
/// implements [`ToString`]).
/// ```
/// # use bo_tie_sm::io::{YesNoInput, UserInput};
/// fn check_compare_value(y: YesNoInput) -> UserInput {
///     println!("pairing check value: {}", y);
///     println!("does this match (y/n)?");
///
///     let mut input = String::new();
///
///     let input = std::io::stdin().read_line(&mut input);
///
///     if input == "y" {
///         y.into_yes()
///     } else {
///         y.into_no()
///     }
/// }
/// ```
///
/// The returned `UserInput` must be provided to the Security Manager to continue pairing.
///
/// [`Display`]: std::fmt::Display
pub struct YesNoInput(CompareValue);

impl YesNoInput {
    /// Convert into "yes"
    ///
    /// This converts this `YesNotInput` into a `UserInput` containing "yes".
    pub fn into_yes(self) -> UserInput {
        UserInput::yes()
    }

    /// Convert into "no"
    ///
    /// This converts this `YesNotInput` into a `UserInput` containing "no".
    pub fn into_no(self) -> UserInput {
        UserInput::no()
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

/// Passkey input from the application user
///
/// Passkeys are used for both legacy and secure connection pairing with a Security Manager. Passkey
/// entry requires the Security Manager to know every keypress of the user so that it may send a
/// keypress notification to the peer's Security Manager. Every time the user enters a passkey digit
/// this `PasskeyInput` needs to know about it. The same is true for erasing digits or clearing the
/// entire passcode.
///
/// Every time a digit is entered by the user, the method `add` should be called. *The user must
/// enter the passcode from left to right, the most significant digit must be the first digit
/// entered*. Once all six digits of the passcode, the application must call `complete` to finish
/// the passcode.
///
/// All methods of `PasskeyInput` return a `UserInput` that must be provided to the Security Manager
/// in order to continue pairing. See the respective Security Manager module ([`initiator`] or
/// [`responder`]) for example usage.
///
/// [`initiator`]: crate::initiator
/// [`responder`]: crate::responder
pub struct PasskeyInput {
    passkey: [char; 6],
    count: usize,
}

impl PasskeyInput {
    /// Add a key to the passcode
    ///
    /// # Error
    /// An error is returned if six digits are already in the passcode or input `key` is not a digit
    /// character.
    pub fn add(&mut self, key: char) -> Result<UserInput, PasskeyError> {
        if !key.is_digit(10) {
            return Err(PasskeyError::NotADigit(key));
        }

        *self.passkey.get_mut(self.count).ok_or(PasskeyError::TooManyKeys(key))? = key;

        self.count += 1;

        Ok(UserInput::key())
    }

    /// Remove a key from the passcode
    ///
    /// # Error
    /// The index must be the index of a key already added to this `PasskeyInput` or an error is
    /// returned.
    pub fn remove(&mut self, index: usize) -> Result<UserInput, PasskeyError> {
        if index < self.count {
            self.passkey[index..self.count].rotate_left(1);
            self.count -= 1;
            Ok(UserInput::key_erase())
        } else {
            Err(PasskeyError::InvalidKeyPosition(index))
        }
    }

    /// Clear the Passcode
    ///
    /// After this is called, the passcode is reset to contain zero digits
    pub fn clear(&mut self) -> UserInput {
        self.count = 0;

        UserInput::passkey_clear()
    }

    /// Passcode Completed
    ///
    /// # Error
    /// The passcode must be a complete six digit number.
    pub fn complete(self) -> Result<UserInput, PasskeyError> {
        if self.count != 6 {
            return Err(PasskeyError::PasskeyIncomplete);
        }

        let (_, val) = self
            .passkey
            .into_iter()
            .rev()
            .fold((1, 0), |(mul, sum), digit| (mul * 10, sum + digit.to_digit(10) * mul));

        Ok(UserInput::passkey_complete(val))
    }
}

/// Passkey error
#[derive(Clone, Debug)]
pub enum PasskeyError {
    UnexpectedYesOrNo,
    ExpectedYesOrNo,
    NotADigit(char),
    TooManyKeys(char),
    InvalidKeyPosition(usize),
    PasskeyIncomplete,
}

impl core::fmt::Display for PasskeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match self {
            PasskeyError::UnexpectedYesOrNo => f.write_str("expected passkey digit, not yes or no"),
            PasskeyError::ExpectedYesOrNo => f.write_str("expected yes or no, not a passkey digit"),
            PasskeyError::NotADigit(c) => write!(f, "non-digit entered in passkey ({})", c),
            PasskeyError::TooManyKeys(c) => write!(f, "too many keys entered for passkey ({})", c),
            PasskeyError::InvalidKeyPosition(p) => write!(f, "cannot erase key at position ({})", p),
            PasskeyError::PasskeyIncomplete => f.write_str("full passkey not entered"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PasskeyError {}

/// Output of a Passkey
///
/// This is returned by a Security Manager whenever a passkey is generated by it. The user will then
/// input the passkey on the other device.
///
/// The compare value can be displayed to the user using the [`Display`] trait (this also means it
/// implements [`ToString`]).
///
/// ```
/// # use bo_tie_sm::io::PasskeyOutput;
///
/// fn display_passkey(p: PasskeyOutput) {
///     println!("please enter this passkey on the other device: {}", p);
/// }
/// ```
pub struct PasskeyOutput(u32);

impl core::fmt::Display for PasskeyOutput {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{:06}", self.0 % 999_999)
    }
}
