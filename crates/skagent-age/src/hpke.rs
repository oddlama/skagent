//! HPKE's base mode (RFC 9180) for the one suite age's `mlkem768x25519`
//! stanza uses: the KEM MLKEM768-X25519 (`0x647a`), HKDF-SHA256 and
//! ChaCha20Poly1305. A stanza is a single message, so this is the key
//! schedule and the first seal or open, nothing more.

use anyhow::{Result, anyhow};
use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use hkdf::{Hkdf, HkdfExtract};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::xwing::SHARED_SECRET_BYTES;

/// `"HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`.
const SUITE_ID: [u8; 10] = [b'H', b'P', b'K', b'E', 0x64, 0x7a, 0x00, 0x01, 0x00, 0x03];
const VERSION: &[u8] = b"HPKE-v1";
/// `mode_base`.
const MODE_BASE: u8 = 0x00;

const HASH_BYTES: usize = 32;
const KEY_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;

/// `LabeledExtract(salt, label, ikm)`.
fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; HASH_BYTES]> {
    let mut extract = HkdfExtract::<Sha256>::new(Some(salt));
    extract.input_ikm(VERSION);
    extract.input_ikm(&SUITE_ID);
    extract.input_ikm(label);
    extract.input_ikm(ikm);
    let (pseudorandom_key, _) = extract.finalize();
    Zeroizing::new(pseudorandom_key.into())
}

/// `LabeledExpand(prk, label, info, L)` into `output`.
fn labeled_expand(
    pseudorandom_key: &[u8; HASH_BYTES],
    label: &[u8],
    info: &[u8],
    output: &mut [u8],
) -> Result<()> {
    let length = u16::try_from(output.len())
        .map_err(|_| anyhow!("HPKE can't expand to {} bytes", output.len()))?
        .to_be_bytes();
    Hkdf::<Sha256>::from_prk(pseudorandom_key)
        .map_err(|error| anyhow!("HPKE's pseudorandom key: {error}"))?
        .expand_multi_info(&[&length, VERSION, &SUITE_ID, label, info], output)
        .map_err(|error| anyhow!("HPKE's expand: {error}"))
}

/// Key and nonce of the first message (`KeyScheduleR` and `KeyScheduleS` are
/// the same in base mode).
struct Context {
    key: Zeroizing<[u8; KEY_BYTES]>,
    nonce: [u8; NONCE_BYTES],
}

impl Context {
    fn schedule(shared_secret: &[u8; SHARED_SECRET_BYTES], info: &[u8]) -> Result<Self> {
        let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[]);
        let info_hash = labeled_extract(&[], b"info_hash", info);
        let mut context = Vec::with_capacity(65);
        context.push(MODE_BASE);
        context.extend_from_slice(&*psk_id_hash);
        context.extend_from_slice(&*info_hash);
        // The shared secret is the salt; the (empty) pre-shared key is the input.
        let secret = labeled_extract(shared_secret, b"secret", &[]);
        let mut key = Zeroizing::new([0; KEY_BYTES]);
        labeled_expand(&secret, b"key", &context, &mut *key)?;
        let mut nonce = [0; NONCE_BYTES];
        labeled_expand(&secret, b"base_nonce", &context, &mut nonce)?;
        Ok(Self { key, nonce })
    }

    fn cipher(&self) -> ChaCha20Poly1305 {
        ChaCha20Poly1305::new(Key::from_slice(&*self.key))
    }
}

/// Seals `plaintext` under `shared_secret`, with an empty `aad`: the first
/// (and only) message of a sender's context.
pub(crate) fn seal(
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    info: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let context = Context::schedule(shared_secret, info)?;
    context
        .cipher()
        .encrypt(
            Nonce::from_slice(&context.nonce),
            Payload {
                msg: plaintext,
                aad: &[],
            },
        )
        .map_err(|_| anyhow!("sealing {} bytes with HPKE failed", plaintext.len()))
}

/// Opens `ciphertext` under `shared_secret`, with an empty `aad`. `None`
/// if it doesn't authenticate, which is what another recipient's stanza
/// looks like.
pub(crate) fn open(
    shared_secret: &[u8; SHARED_SECRET_BYTES],
    info: &[u8],
    ciphertext: &[u8],
) -> Result<Option<Zeroizing<Vec<u8>>>> {
    let context = Context::schedule(shared_secret, info)?;
    Ok(context
        .cipher()
        .decrypt(
            Nonce::from_slice(&context.nonce),
            Payload {
                msg: ciphertext,
                aad: &[],
            },
        )
        .ok()
        .map(Zeroizing::new))
}
