# skagent design

Draft. Findings this is based on: `docs/research/pin-caching.md`.

## goal

- Keys stay `ed25519-sk` with `-O resident -O verify-required` (credProtect `UV_REQUIRED`). Nothing about provisioning changes.
- The authenticator enforces a touch for every signature.
- The PIN is typed once and cached in the agent for a bounded time. It's evicted on lock, suspend, explicit request or errors.
- Drop-in: speaks the ssh-agent protocol on a unix socket. Works with ssh, git, agent forwarding and `ssh-add -K`.

Non-goals: non-sk keys (refused, see open questions), OpenPGP/PIV, non-Linux.

## threat model

Protected:

- **Lost/stolen YubiKey:** useless without the PIN (`UV_REQUIRED`, discovery needs the PIN too).
- **Leaked key handle (stub file, agent memory dump):** useless without the PIN.
- **Stolen laptop + key while the cache is empty** (locked, suspended, expired, rebooted): PIN needed.
- **Other local users:** socket is `0600` in `$XDG_RUNTIME_DIR`, and the peer uid is checked on accept (own uid or root, same as OpenSSH).
- **Forwarded agent on a hostile remote host:** every signature still needs a touch on your machine, so no silent use.
- **Core dumps / ptrace by other processes of the same user:** `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`. The PIN sits in a zeroizing, mlocked buffer.

Not protected:

- **Malware running as you in an unlocked session.** It can ask the agent for signatures and gets them whenever you touch. That's true for every ssh-agent. It can also keylog the PIN when you enter it.
- **root.**
- **A rogue USB device that claims to hold a credential.** It receives the PIN through the PIN protocol. Same exposure as OpenSSH today.

## architecture

```
ssh / git / ssh-add ── ssh-agent protocol (unix socket, peer-checked) ──> skagent
                                                                          ├─ identity store   sk public keys + key handles, in memory
                                                                          ├─ PIN cache        bounded, see rules below
                                                                          ├─ PIN prompt       pinentry (Assuan)
                                                                          └─ fido layer       libfido2 via FFI, blocking calls on spawn_blocking
```

Crates:

- `skagent`: CLI, socket and process hardening, protocol handling via `ssh-agent-lib`, identity store, cache policy. `unsafe` is forbidden.
- `skagent-fido` (planned): the only crate with `unsafe`. It's a safe wrapper over `libfido2-sys`, the same libfido2 OpenSSH uses. It provides: enumerate devices, read the PIN retry counter, assert with up/uv/pin, probe which device holds a key handle (silent assertion, `up=false`, no UV), and enumerate resident credentials (credential management, needs the PIN).

Why libfido2 and not a pure Rust CTAP stack: OpenSSH signs with exactly the libfido2 assertion semantics (raw client data, `ssh:` rp ids, credProtect), and libfido2 handles hidraw, pcsc and all PIN protocol versions. Matching OpenSSH byte for byte is the point.

## protocol surface

| message | behavior |
|---|---|
| `REQUEST_IDENTITIES` | loaded sk keys |
| `SIGN_REQUEST` | `sk-ssh-ed25519@openssh.com` only: find the device that holds the key handle, get the PIN (cache or prompt), assert with `up=true uv=true`, return `sig ‖ flags ‖ counter` |
| `ADD_IDENTITY(_CONSTRAINED)` | sk keys from `ssh-add -K` or `ssh-add <stub>`. Lifetime (`-t`) honored. Unknown or unimplemented constraints (incl. destination constraints) **refuse the key**, fail closed |
| `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES` | drop identities. Remove-all also evicts the whole PIN cache |
| `LOCK` / `UNLOCK` (`ssh-add -x/-X`) | lock evicts the PIN cache and refuses signing until unlock. Passphrase compared in constant time |
| `EXTENSION session-bind@openssh.com` | accepted and recorded per connection (needed for destination constraints and for showing the target host in the PIN prompt) |
| anything else | `FAILURE` |

Key loading: `ssh-add -K` with stock tooling works from day one, but it asks for the PIN itself, so the user types it twice. `skagent load` (later) enumerates resident credentials with one PIN entry and primes the cache with it.

## PIN cache rules

1. **Only store PINs the device accepted.** An entry is created after a successful UV assertion, never from raw user input.
2. **An entry** holds the PIN (zeroizing, mlocked), `created_at`, `last_used` and `retries_at_store`, which is the retry counter read right after the successful assertion.
3. **Retry guard.** Before using a cached PIN, read the device's retry counter (free, no attempt consumed). Use the PIN only if the counter equals `retries_at_store`. Anything lower means someone entered a wrong PIN since: evict and prompt. This is stricter than gpg's `>= 3`.
4. **PIN error from the device** (`PIN_INVALID`, `PIN_BLOCKED`, `PIN_AUTH_BLOCKED`): evict immediately and never retry with a cached PIN. Prompt again only through the user, with the remaining retries shown.
5. **Forced PIN change pending** (`PIN_POLICY_VIOLATION`): don't cache. Tell the user to run `ykman fido access change-pin`.
6. **Lifetime:** hard max since creation (default 8h, configurable down), plus an optional idle timeout since last use. There's no "forever".
7. **Evict everything on:** `ssh-add -D`, `ssh-add -x`, logind `Lock` and `PrepareForSleep(true)` over D-Bus, `skagent forget`, agent shutdown.
8. **Scope:** one entry per credential (key handle) to start with. FIDO has no portable device serial, so "per device" needs a device identity first (open question).

## prompting

- **PIN:** pinentry over Assuan, so it uses whatever the user already has (gnome3/qt/curses/tty). The description names the key (comment, e.g. `alice@example.com yubikey:12345678`) and, once session-bind is handled, the destination host. Either a tiny own Assuan client or the `pinentry` crate, to be decided.
- **Touch:** libfido2 blocks until touched. Optionally show a desktop notification (`org.freedesktop.Notifications`) while waiting.

## concurrency

- libfido2 calls block for up to the touch timeout, so they run on `spawn_blocking`.
- One operation per device at a time (per-device mutex). Other requests wait with a timeout.
- Cancel the pending assertion (`fido_dev_cancel`) when the client disconnects. Later.

## testing

- **Rust:** protocol tests against an in-process agent over a real unix socket. The cache policy is a pure state machine over an injected clock and a fake `Authenticator` trait, so retry and eviction rules are tested deterministically.
- **NixOS VM tests:** stock OpenSSH tools (`ssh-add`, `ssh`, `ssh-keygen -Y sign`) against the real binary. For FIDO inside the VM we need a virtual authenticator on `/dev/uhid`:
  - `soft-fido2` (pure Rust CTAP 2.1 with a uhid transport, EdDSA, credProtect, PIN, forcePINChange) is **AGPL-3.0**. It needs a licensing decision before we depend on it, even test-only.
  - Alternatives: a minimal uhid CTAP2 authenticator of our own that only covers what the tests need, or QEMU USB passthrough of a real key for manual hardware runs.
- Real-hardware runs stay manual with a documented checklist.

## open questions

- License of the virtual authenticator for VM tests.
- Device identity for a per-device PIN cache.
- Non-sk keys: refuse (current plan) or pass through to an upstream agent.
- systemd user unit with socket activation, plus a NixOS/home-manager module.

## milestones

1. ~~Agent skeleton: socket handling (`0600`, stale socket, peer uid), process hardening, safe logging, empty `REQUEST_IDENTITIES`. VM test with `ssh-add`.~~ Done.
2. Identity store: sk keys via `ssh-add -K`/stub, lifetime, remove, lock/unlock.
3. `skagent-fido`: libfido2 wrapper, assertion with UV + PIN, retry counter.
4. PIN cache + pinentry.
5. Virtual authenticator + full sign path in VM tests.
6. Eviction triggers via logind, `skagent forget`, `skagent load`.
