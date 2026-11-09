# skagent design

Draft. Findings this is based on: `docs/research/pin-caching.md`.

## goal

- Keys stay `ed25519-sk` with `-O resident -O verify-required` (credProtect `UV_REQUIRED`). Nothing about provisioning changes.
- The authenticator enforces a touch for every signature.
- The PIN is typed once and cached in the agent for a bounded time. It's evicted on lock, suspend, explicit request or errors.
- Drop-in: speaks the ssh-agent protocol on a unix socket. Works with ssh, git, agent forwarding and `ssh-add -K`.

Non-goals: OpenPGP/PIV, non-Linux, and non-sk keys. Those are **refused** (decided). To mix agents, point ssh at skagent per host with `IdentityAgent` (e.g. only for `github.com`) and keep a normal agent for the rest.

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

## multiple keys

skagent replaces ssh-agent for sk keys, so it handles any number of them at once (e.g. a work and a personal YubiKey plugged in together):

- The identity store holds keys from any number of authenticators.
- Per sign request, the device is resolved by probing the key handle against the connected devices (silent assertion, `up=false`, no UV). This is the same trick OpenSSH uses, and it never prompts or blinks the wrong key.
- The PIN cache is per credential. Work and personal key have independent entries, lifetimes and retry guards. Evicting one never touches the other.
- There's one lock per device, so signatures on different keys run in parallel and two requests for the same key queue.
- Unplugging a device evicts the cache entries of the credentials last resolved to it (hidraw remove event), like gpg forgetting the PIN on card removal.
- Later: per-key policy (lifetime, idle timeout) selected by application, comment or fingerprint, e.g. 8h for work and 1h for personal.

## secret memory

Secrets (cached PINs, the `LOCK` passphrase) live in `skagent-secret` buffers:

- Each buffer is its own anonymous mapping, so `mlock` is never shared with unrelated heap data (`munlock` isn't reference counted).
- The data pages are `mlock`ed (never swapped), `MADV_DONTDUMP` (left out of core dumps on top of `RLIMIT_CORE=0`) and `MADV_WIPEONFORK` (a forked child, e.g. pinentry before `exec`, sees zeros).
- `PROT_NONE` guard pages before and after turn an overflow into a crash instead of a silent read or write.
- Contents are zeroized with volatile writes on drop and on clear. `Debug` prints nothing about the content, not even the length. Comparisons are constant time.
- Allocation fails closed: if `mlock` fails (e.g. `RLIMIT_MEMLOCK` exhausted), the operation is refused.
- Considered: `memfd_secret(2)` also removes the pages from the kernel's direct map, but it blocks hibernation while any secret memory exists. That's a bad default on laptops; maybe an opt-in later.
- Not covered: bytes that pass through buffers we don't own (pinentry's pipe, the socket read buffers of `ssh-agent-lib` for `LOCK`). They are short-lived, but not locked.

## protocol surface

| message | behavior |
|---|---|
| `REQUEST_IDENTITIES` | loaded sk keys |
| `SIGN_REQUEST` | `sk-ssh-ed25519@openssh.com` only: find the device that holds the key handle, get the PIN (cache or prompt), assert with `up=true uv=true`, return `sig ‖ flags ‖ counter` |
| `ADD_IDENTITY(_CONSTRAINED)` | sk keys from `ssh-add -K` or `ssh-add <stub>`, any other key type is refused. Lifetime (`-t`) honored. `sk-provider@openssh.com` is accepted for the built-in provider only. Confirm (`-c`), destination constraints (`-h`) and anything unknown **refuse the key**, fail closed |
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
  - `soft-fido2` (pure Rust CTAP 2.1 with a uhid transport, EdDSA, credProtect, PIN, forcePINChange). Decided: used, but only in a separate test-only crate whose binary runs inside the VM. It's **AGPL-3.0**, so it is never a dependency of the agent crates.
  - QEMU USB passthrough of a real key stays an option for manual hardware runs.
- Real-hardware runs stay manual with a documented checklist.

## open questions

- Whether a per-device PIN cache is worth it over per-credential (needs a device identity, FIDO has no portable serial).
- systemd user unit with socket activation, plus a NixOS/home-manager module.

## milestones

1. ~~Agent skeleton: socket handling (`0600`, stale socket, peer uid), process hardening, safe logging, empty `REQUEST_IDENTITIES`. VM test with `ssh-add`.~~ Done.
2. Identity store: sk keys via `ssh-add -K`/stub, lifetime, remove, lock/unlock.
3. `skagent-fido`: libfido2 wrapper, assertion with UV + PIN, retry counter.
4. PIN cache + pinentry.
5. Virtual authenticator + full sign path in VM tests.
6. Eviction triggers via logind, `skagent forget`, `skagent load`.
