//! X-Wing, the hybrid KEM of age's `mlkem768x25519` recipient: ML-KEM-768
//! and X25519, combined with SHA3-256. This follows
//! [filippo.io/hpke-pq](https://filippo.io/hpke-pq) ("MLKEM768-X25519"),
//! which is what age implements.
//!
//! A private key is a 32-byte seed. It is expanded for every use and the
//! expansion is dropped right after.

use anyhow::{Context as _, Result, bail, ensure};
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768KeyPair, MlKem768PublicKey};
use zeroize::{Zeroize as _, Zeroizing};

/// A private key: the seed.
pub(crate) const SEED_BYTES: usize = 32;
/// A public key: the ML-KEM-768 encapsulation key, then the X25519 public key.
pub(crate) const PUBLIC_KEY_BYTES: usize = 1216;
/// An encapsulation: the ML-KEM-768 ciphertext, then the X25519 share.
pub(crate) const CIPHERTEXT_BYTES: usize = 1120;
/// The shared secret.
pub(crate) const SHARED_SECRET_BYTES: usize = 32;
/// Randomness of one encapsulation: 32 bytes for ML-KEM, 32 for X25519.
pub(crate) const ENCAPSULATION_RANDOM_BYTES: usize = 64;

const MLKEM_PUBLIC_KEY_BYTES: usize = 1184;
const MLKEM_CIPHERTEXT_BYTES: usize = 1088;
const MLKEM_SEED_BYTES: usize = 64;
const MLKEM_RANDOM_BYTES: usize = 32;
const X25519_BYTES: usize = 32;
/// `SHAKE256(seed)` is cut into the two seeds.
const EXPANDED_SEED_BYTES: usize = 96;

/// The generator of Curve25519 (RFC 7748, section 4.1).
const X25519_BASEPOINT: [u8; X25519_BYTES] = [
    9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

/// The label that ends the combiner's input: `\.//^\`.
const LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// A shared secret, wiped when dropped.
pub(crate) type SharedSecret = Zeroizing<[u8; SHARED_SECRET_BYTES]>;

/// What a seed expands to (`expandKey`). Our copies are wiped when dropped;
/// `libcrux-ml-kem`'s key pair has no way to be wiped.
pub(crate) struct ExpandedKey {
    mlkem: MlKem768KeyPair,
    x25519_private: Zeroizing<[u8; X25519_BYTES]>,
    x25519_public: [u8; X25519_BYTES],
}

impl ExpandedKey {
    /// Expands `seed` into the ML-KEM-768 and the X25519 key pair.
    pub(crate) fn expand(seed: &[u8; SEED_BYTES]) -> Result<Self> {
        let expanded: Zeroizing<[u8; EXPANDED_SEED_BYTES]> =
            Zeroizing::new(libcrux_sha3::shake256(seed));
        let (mlkem_seed, x25519_seed) = expanded
            .split_first_chunk::<MLKEM_SEED_BYTES>()
            .context("the expanded seed is shorter than the ML-KEM seed")?;
        // `generate_key_pair` takes its seed by value.
        let mut mlkem_seed = *mlkem_seed;
        let mlkem = mlkem768::generate_key_pair(mlkem_seed);
        mlkem_seed.zeroize();
        let x25519_private: Zeroizing<[u8; X25519_BYTES]> = Zeroizing::new(
            x25519_seed
                .try_into()
                .context("the expanded seed doesn't end in an X25519 scalar")?,
        );
        let x25519_public = x25519_dalek::x25519(*x25519_private, X25519_BASEPOINT);
        Ok(Self {
            mlkem,
            x25519_private,
            x25519_public,
        })
    }

    /// The public key (`PrivateKeyToPublicKey`).
    pub(crate) fn public_key(&self) -> Result<Box<[u8; PUBLIC_KEY_BYTES]>> {
        let mut key = Vec::with_capacity(PUBLIC_KEY_BYTES);
        key.extend_from_slice(self.mlkem.pk());
        key.extend_from_slice(&self.x25519_public);
        key.into_boxed_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("the public key doesn't have {PUBLIC_KEY_BYTES} bytes"))
    }

    /// The shared secret of `ciphertext` (`Decaps`). A ciphertext that isn't
    /// for this key gives another secret, not an error: ML-KEM rejects
    /// implicitly.
    ///
    /// # Errors
    ///
    /// Returns an error if the X25519 share is a low-order point.
    pub(crate) fn decapsulate(&self, ciphertext: &[u8; CIPHERTEXT_BYTES]) -> Result<SharedSecret> {
        let (mlkem_ciphertext, share) = split_ciphertext(ciphertext)?;
        let mlkem_secret = Zeroizing::new(mlkem768::decapsulate(
            self.mlkem.private_key(),
            &MlKem768Ciphertext::from(mlkem_ciphertext),
        ));
        let x25519_secret = exchange(&self.x25519_private, share)?;
        Ok(combine(
            &mlkem_secret,
            &x25519_secret,
            share,
            &self.x25519_public,
        ))
    }
}

/// Encapsulates to `public_key` with the given randomness (`EncapsDerand`):
/// the ciphertext and the shared secret.
///
/// # Errors
///
/// Returns an error if `public_key` isn't a valid ML-KEM-768 encapsulation
/// key followed by an X25519 public key of full order.
pub(crate) fn encapsulate(
    public_key: &[u8; PUBLIC_KEY_BYTES],
    randomness: &[u8; ENCAPSULATION_RANDOM_BYTES],
) -> Result<(Box<[u8; CIPHERTEXT_BYTES]>, SharedSecret)> {
    let (mlkem_public, x25519_public) = split_public_key(public_key)?;
    let mlkem_public = MlKem768PublicKey::from(mlkem_public);
    ensure!(
        mlkem768::validate_public_key(&mlkem_public),
        "the ML-KEM-768 part of the public key is invalid"
    );
    let (mlkem_random, x25519_random) = randomness
        .split_first_chunk::<MLKEM_RANDOM_BYTES>()
        .context("the randomness is shorter than ML-KEM's part")?;
    let ephemeral: Zeroizing<[u8; X25519_BYTES]> = Zeroizing::new(
        x25519_random
            .try_into()
            .context("the randomness doesn't end in an X25519 scalar")?,
    );

    // `encapsulate` takes its randomness by value.
    let mut mlkem_random = *mlkem_random;
    let (mlkem_ciphertext, mlkem_secret) = mlkem768::encapsulate(&mlkem_public, mlkem_random);
    mlkem_random.zeroize();
    let mlkem_secret = Zeroizing::new(mlkem_secret);

    let share = x25519_dalek::x25519(*ephemeral, X25519_BASEPOINT);
    let x25519_secret = exchange(&ephemeral, x25519_public)?;

    let mut ciphertext = Vec::with_capacity(CIPHERTEXT_BYTES);
    ciphertext.extend_from_slice(mlkem_ciphertext.as_slice());
    ciphertext.extend_from_slice(&share);
    let ciphertext = ciphertext
        .into_boxed_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("the ciphertext doesn't have {CIPHERTEXT_BYTES} bytes"))?;
    Ok((
        ciphertext,
        combine(&mlkem_secret, &x25519_secret, &share, x25519_public),
    ))
}

/// Checks what can be checked about a ciphertext without a private key: its
/// X25519 share must not be a low-order point, for which every key gives
/// the same, all-zero secret.
pub(crate) fn check_ciphertext(ciphertext: &[u8; CIPHERTEXT_BYTES]) -> Result<()> {
    let (_, share) = split_ciphertext(ciphertext)?;
    check_point(share)
}

/// Checks what can be checked about a public key without using it: the
/// ML-KEM-768 part decodes to itself, and the X25519 part has full order.
pub(crate) fn check_public_key(public_key: &[u8; PUBLIC_KEY_BYTES]) -> Result<()> {
    let (mlkem_public, x25519_public) = split_public_key(public_key)?;
    ensure!(
        mlkem768::validate_public_key(&MlKem768PublicKey::from(mlkem_public)),
        "the ML-KEM-768 part of the public key is invalid"
    );
    check_point(x25519_public)
}

fn split_ciphertext(
    ciphertext: &[u8; CIPHERTEXT_BYTES],
) -> Result<(&[u8; MLKEM_CIPHERTEXT_BYTES], &[u8; X25519_BYTES])> {
    let (mlkem, share) = ciphertext
        .split_first_chunk::<MLKEM_CIPHERTEXT_BYTES>()
        .context("the ciphertext is shorter than its ML-KEM part")?;
    let share = share
        .try_into()
        .context("the ciphertext doesn't end in an X25519 share")?;
    Ok((mlkem, share))
}

fn split_public_key(
    public_key: &[u8; PUBLIC_KEY_BYTES],
) -> Result<(&[u8; MLKEM_PUBLIC_KEY_BYTES], &[u8; X25519_BYTES])> {
    let (mlkem, x25519) = public_key
        .split_first_chunk::<MLKEM_PUBLIC_KEY_BYTES>()
        .context("the public key is shorter than its ML-KEM part")?;
    let x25519 = x25519
        .try_into()
        .context("the public key doesn't end in an X25519 public key")?;
    Ok((mlkem, x25519))
}

/// Refuses the points of low order. X25519 clamps its scalar to a multiple
/// of the cofactor, so any scalar sends exactly those points to zero.
fn check_point(point: &[u8; X25519_BYTES]) -> Result<()> {
    let mut scalar = [0_u8; X25519_BYTES];
    scalar.fill(0x42);
    exchange(&scalar, point).map(drop)
}

/// X25519, refusing the all-zero result a low-order point gives.
fn exchange(
    scalar: &[u8; X25519_BYTES],
    point: &[u8; X25519_BYTES],
) -> Result<Zeroizing<[u8; X25519_BYTES]>> {
    let secret = Zeroizing::new(x25519_dalek::x25519(*scalar, *point));
    // Whether the result is zero depends on the point alone, which is public.
    if *secret == [0; X25519_BYTES] {
        bail!("the X25519 part is a point of low order");
    }
    Ok(secret)
}

/// `SHA3-256(ss_PQ || ss_T || ct_T || ek_T || Label)`.
fn combine(
    mlkem_secret: &[u8; SHARED_SECRET_BYTES],
    x25519_secret: &[u8; X25519_BYTES],
    share: &[u8; X25519_BYTES],
    x25519_public: &[u8; X25519_BYTES],
) -> SharedSecret {
    let mut input = Zeroizing::new(Vec::with_capacity(134));
    input.extend_from_slice(mlkem_secret);
    input.extend_from_slice(x25519_secret);
    input.extend_from_slice(share);
    input.extend_from_slice(x25519_public);
    input.extend_from_slice(&LABEL);
    Zeroizing::new(libcrux_sha3::sha256(&input))
}
