# age: formats and tools for a key derived from hardware

Findings behind [`docs/age.md`](../age.md). Versions: **age 1.3.2** (Go) and **rage 0.12.1** from this repository's nixpkgs, the C2SP specifications [`age`](https://c2sp.org/age) and [`age-plugin`](https://c2sp.org/age-plugin) as of 2026-11, **agenix** at `5e5b88a` and **agenix-rekey** at `87e5d5f`. Re-check them when those move.

## age's post-quantum recipient

Native since age 1.3.0 (2025-12-27): recipients `age1pq1…`, identities `AGE-SECRET-KEY-PQ-1…`, stanza type `mlkem768x25519`.

- **Identity:** 32 random bytes.
- **Recipient:** `PrivateKeyToPublicKey(identity)`, which is the ML-KEM-768 encapsulation key (1184 bytes) followed by the X25519 public key (32 bytes). As Bech32 that is 1959 characters.
- **Stanza:** HPKE `SealBase` (RFC 9180, §6.1) of the file key, with the KEM MLKEM768-X25519 (X-Wing, KEM id `0x647a`), HKDF-SHA256, ChaCha20Poly1305, `info = "age-encryption.org/mlkem768x25519"` and an empty `aad`. Two arguments, the type and the encapsulated key `enc` (1120 bytes, base64). The body is 32 bytes: the 16-byte file key and the tag.
- **What an identity must do:** ignore stanzas of other types; reject one with another number of arguments, or an `enc` that isn't the canonical base64 of 1120 bytes; check that the body is exactly 32 bytes before decrypting, against partitioning oracles.
- **X-Wing,** as written down in [filippo.io/hpke-pq](https://filippo.io/hpke-pq):
  - `expandKey(seed)`: `SHAKE256(seed, 96)`. The first 64 bytes seed `ML-KEM.KeyGen_internal`, the last 32 are the X25519 scalar.
  - `Decaps(seed, ct)`: `ct` is the ML-KEM ciphertext (1088 bytes) and the X25519 share (32 bytes). The shared secret is `SHA3-256(ss_PQ || ss_T || ct_T || ek_T || Label)`, with the six-byte label `\.//^\` (hex `5c2e2f2f5e5c`).
- **Test vectors:** [C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/age), `age/testdata/hybrid*`. 19 cases, among them a bad tag, each half of `enc` corrupted, an extra argument, a long file key, a low-order point, non-canonical encodings and no match.
- **Strength:** the file key is 128 bits, for every recipient type. That is the ceiling, below ML-KEM-768's level.
- **No tag.** A `mlkem768x25519` stanza doesn't say whose it is. The tagged types (`p256tag`, `mlkem768p256tag`) exist for hardware that does P-256 ECDH itself, which FIDO2 doesn't offer.

## post-quantum and classic recipients don't mix

The specification says a file SHOULD NOT be encrypted to both. The clients enforce it, checked with both:

- **age:** `age -r age1pq1… -r age1…` fails with "incompatible recipients: can't mix post-quantum and classic recipients, or the file would be vulnerable to quantum computers". `HybridRecipient.WrapWithLabels` (`pq.go`) returns the label `postquantum`, and `Encrypt` (`age.go`) wants the same labels from every recipient.
- **rage:** with `age-plugin-pq`, "Cannot encrypt to a recipient with labels 'postquantum' alongside a recipient with no labels". The plugin protocol's `labels` extension carries the same rule.

SSH keys used as recipients (`ssh-ed25519`) are classic.

## plugins and native stanzas

- **A plugin may decrypt native stanzas.** age-plugin: "A plugin MAY support decrypting files encrypted to native age recipients, by including support for the `x25519` and/or `mlkem768x25519` recipient stanzas."
- **It gets them.** "When decrypting, age clients will pass all recipient stanzas to every connected plugin." Checked with a dummy plugin that logs its input: `age -d -j probe` and `rage -d -j probe` both send `add-identity AGE-PLUGIN-PROBE-1GJ2MKE` (the identity without data that `-j` stands for) and `recipient-stanza 0 mlkem768x25519 …`.
- **The stanza type never selects a plugin.** Without an identity, age stops with "the file is not passphrase-encrypted, identities are required". A plugin is chosen by the recipient's prefix when encrypting and by the identity's when decrypting.
- **Agents are the intended shape.** "The expected design is a short-lifetime plugin binary `age-plugin-NAME`, which implements the plugin protocol, and in turn connects to (or starts, if not already running) a long-lifetime agent daemon."
- **One file per process.** `identity-v1` can carry several files, but the command line tools decrypt one per run. Sparing the user work across files is up to the agent.
- **Encrypting to an identity** (`-e -i`) asks the plugin through `recipient-v1`. A plugin without it needs the recipient given with `-r`.

## tools

- **nixpkgs' `age`** ships `age-plugin-pq`, `age-plugin-tag` and `age-plugin-tagpq` next to `age`, `age-keygen` and `age-inspect`.
- **rage 0.12.1** has no native post-quantum recipient ([rage#632](https://github.com/str4d/rage/pull/632) is open). It takes `age1pq1…` for a recipient of the plugin `pq`: "Could not find 'age-plugin-pq' on the PATH". With age's `age-plugin-pq` on the `PATH` it encrypts, and age decrypts the result. Checked.
- **Rust crates** (2026-11):
  - `libcrux-ml-kem` 0.0.11 (Apache-2.0): field arithmetic, NTT, serialization and the generic high-level code are verified with hax and F\*, portable and AVX2. OpenSSH's ML-KEM is extracted from the same project (`libcrux_mlkem768_sha3.h` in 9.9 and 10.0).
  - `ml-kem` 0.3.4 and `x-wing` 0.1.1 (RustCrypto): both READMEs say "never been independently audited".
  - `hpke` 0.15.1 has X-Wing, on top of those two; no paid audit.

## agenix and agenix-rekey

- **agenix** decrypts on the host with `age.ageBin`, by default nixpkgs' `age`, and `age.identityPaths`. Its command line tool runs one `age --decrypt --identity …` per file.
- **agenix-rekey** keeps two kinds of files:
  - *Master copies*, encrypted to the master identities' public keys and `extraEncryptionPubkeys` in one file. The mixing rule applies among these.
  - *Rekeyed copies*, encrypted to one `hostPubkey` each. With `storageMode = "local"` they live in the repository, next to the master copies.
- It runs `agenix-rekey.agePackage` (rage by default) once per secret, with `age.rekey.agePlugins` appended to the `PATH`.
- A master identity file is only understood without help for `AGE-PLUGIN-YUBIKEY-` and `AGE-PLUGIN-FIDO2-HMAC-` (`nix/lib.nix` reads the recipient from a comment). Any other is passed as `-i` when encrypting, which needs `recipient-v1`. Giving `{ identity = …; pubkey = "age1pq1…"; }` avoids that.

What follows for a repository that wants post-quantum protection:

- The master copies need every recipient post-quantum: the master identity and each backup key.
- The rekeyed copies hold the same secrets. While a host's `hostPubkey` is its SSH host key, they stay classic, wherever the master copies are. Each has one recipient, so hosts can move to an `age1pq1…` key one at a time.
- Whatever was pushed before stays as it was encrypted. Only secrets created or rotated afterwards gain anything.
