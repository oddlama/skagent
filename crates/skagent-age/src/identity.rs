//! The identity string of skagent's plugin: `AGE-PLUGIN-SKAGENT-1…`. It
//! holds no secret. It says which key to ask the agent for, and carries that
//! key's public half, so encrypting to an identity needs neither the agent
//! nor the security key.

use std::fmt;
use std::str::FromStr;

use anyhow::{Context as _, Result, bail};

use crate::encoding;
use crate::recipient::{RECIPIENT_BYTES, Recipient};

/// The plugin's name: age runs `age-plugin-skagent` for these identities.
pub const PLUGIN_NAME: &str = "skagent";

/// What an identity string starts with, before Bech32's separator.
const PREFIX: &str = "AGE-PLUGIN-SKAGENT-";

/// The first byte of an identity that names its recipient.
const VERSION_NAMED: u8 = 1;

/// Which of skagent's age identities a file is to be decrypted with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Identity {
    /// The identity on the security key at hand: what `age -j skagent`
    /// stands for. Only the agent can tell which that is.
    AtHand,
    /// The identity with this recipient.
    Named(Recipient),
}

impl Identity {
    /// An identity from the data of its string, as age hands it to a plugin.
    ///
    /// # Errors
    ///
    /// Returns an error if `data` is neither empty nor a version this code
    /// knows followed by a valid recipient.
    pub fn from_data(data: &[u8]) -> Result<Self> {
        match data.split_first() {
            None => Ok(Self::AtHand),
            Some((&VERSION_NAMED, key)) => Recipient::from_bytes(key)
                .map(Self::Named)
                .context("the identity's recipient"),
            Some((version, _)) => bail!(
                "identity version {version} is newer than this skagent; only version \
                 {VERSION_NAMED} is known"
            ),
        }
    }

    /// The data of the identity's string.
    #[must_use]
    pub fn to_data(&self) -> Vec<u8> {
        match self {
            Self::AtHand => Vec::new(),
            Self::Named(recipient) => {
                let mut data = Vec::with_capacity(RECIPIENT_BYTES.saturating_add(1));
                data.push(VERSION_NAMED);
                data.extend_from_slice(recipient.as_bytes());
                data
            }
        }
    }

    /// The recipient this identity names, if it names one.
    #[must_use]
    pub fn recipient(&self) -> Option<&Recipient> {
        match self {
            Self::AtHand => None,
            Self::Named(recipient) => Some(recipient),
        }
    }
}

impl fmt::Display for Identity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let encoded = encoding::encode(PREFIX, &self.to_data()).map_err(|_| fmt::Error)?;
        formatter.write_str(&encoded)
    }
}

impl FromStr for Identity {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self> {
        let data = encoding::decode(PREFIX, text)
            .with_context(|| format!("not an identity of skagent's age plugin ({PREFIX}1…)"))?;
        Self::from_data(&data)
    }
}
