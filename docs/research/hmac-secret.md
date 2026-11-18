# hmac-secret: what a security key offers for decryption

Findings behind [`docs/age.md`](../age.md). Sources: CTAP 2.0 (PS 2019-01-30), CTAP 2.1 (PS, errata 2022-06-21), CTAP 2.2 (PS 2025-07-14), **libfido2 1.17.0** and **soft-fido2 0.17**. Re-check them when those versions move.

## FIDO2 has no decryption

A credential's key pair signs, and that's all it does. The `hmac-secret` extension is the one way to get a stable secret out of an authenticator:

- At `makeCredential` with `"hmac-secret": true` the authenticator generates random 32-byte values and keeps them with the credential. CTAP 2.0 has one, `CredRandom`. CTAP 2.1 has two, `CredRandomWithUV` and `CredRandomWithoutUV` (§12.5; §12.7 in CTAP 2.2).
- At `getAssertion` the platform sends one or two 32-byte salts, encrypted with a key agreed for this request (the PIN protocol's ECDH on P-256). The authenticator answers `HMAC-SHA-256(CredRandom, salt)` for each salt, encrypted the same way, inside the signed authenticator data.
- CTAP 2.1 picks the value by the `uv` bit of the response: "If uv bit is set to 1 in the response, let CredRandom be CredRandomWithUV", else `CredRandomWithoutUV`. A request without the PIN can then never produce the output of one with it. A CTAP 2.0 key may not separate them. A credential with credProtect 3 doesn't depend on that: without the PIN it can't be used at all.
- The output is the same every time. Whoever gets it once has it for good.
- `hmac-secret-mc` (CTAP 2.2, §12.8) returns an output from `makeCredential` already, which saves the first assertion.

A public-key scheme on top therefore derives its private key from that output on the host, every time it decrypts. No YubiKey decapsulates ML-KEM itself, so any post-quantum scheme has its private key in host memory at that moment, whatever it is built on.

The key agreement that protects salt and output on the wire is P-256 ECDH. Recorded USB traffic is not protected against a future quantum computer, whatever is done with the output afterwards.

## the touch is not optional

- CTAP 2.1 and 2.2, in the extension's `getAssertion` steps: "If "up" is set to false, authenticator returns CTAP2_ERR_UNSUPPORTED_OPTION."
- CTAP 2.0 says "The authenticator waits for user consent." there, and defines `CTAP2_ERR_UP_REQUIRED` (0x3B): "User presence is required for the requested operation."
- A PIN doesn't stand in for the touch. A token obtained with the PIN starts with `beginUsingPinUvAuthToken(userIsPresent: false)`; only built-in verification such as a fingerprint may count as presence. With `up=true` and a PIN token, the authenticator asks for the touch.
- libfido2's maintainers say the same about YubiKeys ([libfido2#237](https://github.com/Yubico/libfido2/issues/237)), and systemd documented that `--fido2-with-user-presence=no` can't work for this reason ([systemd#43266](https://github.com/systemd/systemd/pull/43266)).
- Confirmed on hardware, see below.

So there is no "derive again, silently" for a batch of files. Every derivation is a touch, and a batch has to keep what the first touch produced.

## libfido2 1.17.0

- **Creating:** `fido_cred_set_extensions(FIDO_EXT_HMAC_SECRET)`, next to `fido_cred_set_prot` and `fido_cred_set_rk`.
- **Deriving:** `fido_assert_set_extensions(FIDO_EXT_HMAC_SECRET)` and `fido_assert_set_hmac_salt` with 32 or 64 bytes (anything else is `FIDO_ERR_INVALID_ARGUMENT`), then `fido_assert_hmac_secret_ptr` and `fido_assert_hmac_secret_len`.
- **Where the output lives:** `decrypt_hmac_secrets` (`src/assert.c`) puts it into the assertion's heap blob. `fido_assert_free` wipes it (`fido_blob_reset` calls `freezero`). Like libfido2's copies of the PIN, that memory isn't locked.
- **Error codes come from the key:** `FIDO_ERR_UP_REQUIRED` and `FIDO_ERR_UNSUPPORTED_OPTION` are CTAP status bytes passed through. `FIDO_ERR_UP_REQUIRED` appears in `src/fido/err.h` and `src/err.c` only; the library never produces it.
- **`hmac-secret-mc`:** `FIDO_EXT_HMAC_SECRET_MC`, `fido_cred_set_hmac_salt`, `fido_cred_hmac_secret_ptr`.

## hardware check

[`hmac-secret-check.sh`](hmac-secret-check.sh) asks a plugged-in key the questions below, with libfido2's own tools (`fido2-token`, `fido2-cred`, `fido2-assert`). It creates a discoverable credProtect 3 credential with hmac-secret under the relying party `skagent:hmac-check` and deletes it at the end. The PIN is typed five times, into those tools; three steps need a touch.

```sh
nix shell --inputs-from . nixpkgs#libfido2 -c bash docs/research/hmac-secret-check.sh
```

Run on 2026-11-18 against a YubiKey that reports `FIDO_2_0, FIDO_2_1_PRE`, PIN protocol 1 and the options `rk, up, noplat, clientPin, credentialMgmtPreview`. That is the feature set from before firmware 5.7, which moved to CTAP 2.1. The exact version isn't known: this firmware has no version in `getInfo` (`fwversion: 0x0`).

| question | answer |
|---|---|
| discoverable credential, credProtect 3, hmac-secret, relying party that is no web origin | created; the attestation (`packed`) confirms both extensions |
| derive with PIN and touch | 32 bytes |
| same salt again | same output |
| two salts in one request | 64 bytes, the second half differs from the first |
| derive with PIN and `up=false` | refused by the key: `FIDO_ERR_UP_REQUIRED` |
| plain assertion without PIN, `up=false` | `FIDO_ERR_NO_CREDENTIALS`: the credential is invisible without the PIN |
| `hmac-secret-mc` listed | no |

Not run yet: a YubiKey with firmware 5.7 or later. Expected there: the same, with `FIDO_ERR_UNSUPPORTED_OPTION` for the refusal.

## the virtual test key (soft-fido2 0.17)

The same script, run in a VM against `skagent-testkey` (which lists only `credProtect` as an extension):

- **hmac-secret works although it isn't listed.** `make_credential.rs` generates a `cred_random` whenever the request asks for the extension, and `get_assertion.rs` answers whenever the credential has one.
- **One `cred_random` per credential,** as in CTAP 2.0.
- **No touch needed.** With PIN and `up=false`, the same secret came back.

So before any VM test counts touches for decryption, the test key has to list `hmac-secret` and refuse a `getAssertion` that carries the extension with `up=false`. That belongs in front of soft-fido2, next to its other touch decisions (`src/ctap.rs`, see [`test-key.md`](test-key.md)).

## what follows for skagent

- A dedicated credential with credProtect 3 and hmac-secret gives a secret that needs the key, the PIN and a touch, on firmware old and new.
- One touch can return two outputs, for two salts.
- The output never changes, so a single derivation by someone else (a stolen PIN and one hijacked touch) is a permanent loss. With a signature it would be one signature.
- Requests never ask for `up=false`. Both refusal codes are a key saying "touch required".
- The output and everything derived from it pass through unlocked memory in libfido2. That is the same exposure as the PIN's during an assertion.
- Discoverable credentials are a limited resource. Yubico's numbers (not checked here): 25 before firmware 5.7, 100 from then on.
