//! What the flow needs of a security key, and which of the plugged-in ones
//! it takes.
//!
//! A trait, so the flow can be tested with a key that isn't one. The real
//! one is [`crate::device::PluggedIn`].

use anyhow::Result;
use skagent_fido::AgeCredential;
use skagent_secret::SecretBuffer;

/// Why a security key didn't do what it was asked, as far as the flow
/// treats the reasons differently.
#[derive(Debug)]
pub enum Failure {
    /// The PIN was wrong, which cost a try.
    WrongPin,
    /// Three wrong PINs in a row: the key takes none until it is unplugged
    /// and plugged in again.
    BlockedUntilReplugged,
    /// No tries left. Only a FIDO reset, which wipes the key, helps.
    PinBlocked,
    /// Nobody touched the key in time.
    NotTouched,
    /// The request was cancelled on the key, because whoever asked is gone.
    Cancelled,
    /// Anything else, in the security key's or libfido2's words.
    Other(anyhow::Error),
}

/// A security key that could hold an age identity: it speaks CTAP2, has a
/// PIN and lists what an identity's credential needs.
pub trait SecurityKey {
    /// What a person calls the key, in printable ASCII: "YubiKey 12345678",
    /// or its product name.
    fn name(&self) -> &str;

    /// The PIN tries left. Asking takes no PIN and costs no try.
    ///
    /// # Errors
    ///
    /// Returns an error if the key can't be asked.
    fn tries_left(&mut self) -> Result<u32>;

    /// The key's age credentials, listed with `pin` and without a touch.
    /// The key checks the PIN for this, so a PIN that lists them is right.
    ///
    /// # Errors
    ///
    /// Returns why the key refused; a wrong PIN is [`Failure::WrongPin`].
    fn credentials(&mut self, pin: &SecretBuffer) -> Result<Vec<AgeCredential>, Failure>;

    /// What `credential` gives for the salt of skagent's age identities:
    /// 32 bytes, the same every time. Takes `pin` and a touch, and blocks
    /// until the key is touched or gives up waiting.
    ///
    /// # Errors
    ///
    /// Returns why the key refused; a touch that didn't come is
    /// [`Failure::NotTouched`].
    fn derive(
        &mut self,
        credential: &AgeCredential,
        pin: &SecretBuffer,
    ) -> Result<SecretBuffer, Failure>;
}

/// The security key to ask, among those plugged in.
#[derive(Debug)]
pub enum Found<K> {
    /// The only one that could hold an age identity.
    One(K),
    /// None could. `unusable`: the ones plugged in that can't, each with
    /// its name and why.
    None {
        /// "NAME: why it can't hold an identity", one per device.
        unusable: Vec<String>,
    },
    /// Several could, by these names. A PIN isn't sent on a guess: it would
    /// go to a key before anything shows that it holds an identity, and a
    /// wrong guess costs that key a try.
    Several(Vec<String>),
}

/// Chooses among the plugged-in FIDO devices. Each comes with its name, and
/// with itself if it could hold an age identity, else with why it can't.
/// Only those that could count: a U2F token next to the security key
/// doesn't get in its way.
#[must_use]
pub fn select<K>(devices: Vec<(String, Result<K, String>)>) -> Found<K> {
    let mut usable = Vec::new();
    let mut unusable = Vec::new();
    for (name, device) in devices {
        match device {
            Ok(key) => usable.push((name, key)),
            Err(why) => unusable.push(format!("{name}: {why}")),
        }
    }
    if usable.len() > 1 {
        return Found::Several(usable.into_iter().map(|(name, _)| name).collect());
    }
    match usable.pop() {
        Some((_, key)) => Found::One(key),
        None => Found::None { unusable },
    }
}
