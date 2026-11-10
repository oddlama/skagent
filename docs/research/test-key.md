# The virtual test key (`skagent-testkey`)

`crates/skagent-testkey` runs soft-fido2 0.17 as a uhid FIDO2 device inside the NixOS VM tests. Findings from making it behave like a YubiKey towards OpenSSH 10.6p1.

## license

- soft-fido2's README says GPL-3.0, but the `LICENSE` file shipped in the crates is the **AGPL-3.0** text, and `Cargo.toml` only points at that file. Treat it as AGPL-3.0.
- Consequence: only `skagent-testkey` depends on it. It's test-only, never a dependency of `skagent` or `skagent-secret`, and the agent binary doesn't link it.

## what works against stock OpenSSH (`checks.vm-testkey`)

- `fido2-token -L/-I` lists the device with `credProtect`, `rk`, `clientPin` and `eddsa`.
- `ssh-keygen -t ed25519-sk -O resident -O verify-required -O application=ssh:example`: enrolls with credProtect 3 (`UV_REQUIRED`) after the PIN prompt, with exactly one touch.
- `ssh-keygen -Y sign` with the stub needs the PIN plus one touch, and `-Y verify` accepts the signature.
- A wrong PIN fails the signature and costs a retry (8 → 7, visible in `fido2-token -I`).
- Stock `ssh-agent` with that key asks askpass for the PIN on **every** signature (two signatures, two prompts). That's the behavior skagent exists to fix, reproduced as a baseline.

## deviations from a YubiKey, and what the test key does about them

### PIN token counts as touch

soft-fido2 sets "user present" whenever a PIN token is valid within its usage window (`get_user_present_flag_value` in `make_credential.rs`), and then never calls `request_up`. A YubiKey asks for a touch even after a PIN, and CTAP 2.1 only lets tokens from built-in verification imply presence.

The test key therefore decides about touch itself, in front of soft-fido2 (`src/ctap.rs`):

- `makeCredential`, and `getAssertion` unless its `up` option is `false`, need a touch.
- The touch is asked for **after** the request succeeded, since a YubiKey rejects invalid requests (missing PIN, unknown credential) without blinking. OpenSSH's enrollment first tries without a PIN and retries with it; a touch before running would have counted two touches for one enrollment.
- If the touch is refused or times out, the response is replaced by `CTAP2_ERR_OPERATION_DENIED` / `CTAP2_ERR_USER_ACTION_TIMEOUT`, and credentials the request created are removed again.
- soft-fido2's own `request_up` callback always accepts.

Every touch request is logged as `touch requested`, so tests count touches in the journal. `--touch auto|deny|file` selects the policy; `file` waits up to 10 s for a trigger file and consumes it, one file per touch.

### touch selection and cancellation

libfido2 1.17's `src/touch.c` implements touch-begin/status with a dummy `makeCredential` carrying an empty `pinUvAuthParam` (not `authenticatorSelection`). CTAP requires touch before rejecting that empty parameter. The test key handles it before soft-fido2: request `select` touch, then return `PIN_AUTH_INVALID` without checking a PIN, changing retries or creating a credential. libfido2 recognizes that status as a successful selection.

The transport loop is synchronous: while waiting for a touch it cannot process a CTAPHID CANCEL. Unselected test devices therefore wait out their 10s timeout; the multi-key suite waits for that before its next operation. Production sends `fido_dev_cancel` before closing outstanding probes, but prompt hardware cancellation still needs a real-key test.

### credential management listing is incomplete

soft-fido2 0.17's `enumerateCredentialsBegin/GetNextCredential` responses carry user and credential id, but not `publicKey` (0x08) or `credProtect` (0x0A), although both keys are defined in `credential_management.rs`. libfido2 then reports key type 0, and OpenSSH skips the credential:

```
read_rks: ... user "openssh" uidlen 32 slot 0: type 0 flags 0x00 prot 0x00
read_rks: unsupported key type 0
No keys to download
```

So `ssh-keygen -K` and `ssh-add -K` don't work against the test key. VM tests load keys from the stub file written at enrollment instead. Fix before `skagent load` needs it: either patch the listing response in the test key (it has the credentials) or upstream.

### PIN

`Authenticator::set_pin_hash(sha256(pin))` presets the PIN for the next authenticator created, so the key starts with a known PIN (`--pin` / `SKAGENT_TESTKEY_PIN`). Retries are 8, like a YubiKey. State lives in memory; restarting the key resets everything.
