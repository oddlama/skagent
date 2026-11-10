# skagent design

Target design; the milestones below distinguish implemented and pending pieces. Findings this is based on: `docs/research/pin-caching.md`.

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
- **Stolen laptop + key while no PIN remains in memory** (evicted, expired, rebooted): PIN needed. An already-running libfido2 call retains its temporary copy until it returns; see concurrency.
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
- `skagent-fido`: safe wrapper over `libfido2-sys`, the same libfido2 OpenSSH uses. Enumerates devices, reads the PIN retry counter and asserts with up/uv/pin. Touch selection and resident credential enumeration are pending. Unsafe code is confined to `raw.rs`.
- `skagent-secret`: guarded, locked, zeroizing memory. Unsafe code is confined to `mapping.rs`.

Why libfido2 and not a pure Rust CTAP stack: OpenSSH signs with exactly the libfido2 assertion semantics (raw client data, `ssh:` rp ids, credProtect), and libfido2 handles hidraw, pcsc and all PIN protocol versions. Matching OpenSSH byte for byte is the point.

## multiple keys

The identity store and PIN cache support multiple credentials. Device selection currently requires exactly one connected authenticator; signing is globally serialized. The target for several connected keys (work + personal):

- The identity store holds keys from any number of authenticators.
- Finding the device that holds a key is the hard part. **A silent probe doesn't work for our keys**: credProtect `UV_REQUIRED` hides the credential from every request without user verification, so a probe with the key handle says "no credentials" on every device, the right one included. That's why OpenSSH falls back to "touch the key you mean" (`sk_probe: selecting sk by touch`). And verifying with a PIN on the wrong device costs that device a retry.
- So skagent remembers where a key lives: after a signature succeeded on a device, the key is bound to that device's identity (its `/dev/hidrawN` node: device number, inode and change time, which change on every replug). With one device connected and no binding yet, that device is used. With several and no binding, the user picks by touch (libfido2's touch-begin/status, the device that gets touched wins), then the PIN is asked for.
- **A cached PIN is only ever sent to the device it was verified on.** The cache entry carries the device identity; if it no longer matches (replug, other device on that node), the entry is dropped and the user is asked again. This also covers "personal key plugged in where the work key was".
- The PIN cache is per credential and device. Work and personal key have independent entries, lifetimes and retry guards. Evicting one never touches the other.
- There's one lock per device, so signatures on different keys run in parallel and two requests for the same key queue.
- Unplugging a device evicts the cache entries bound to it (checked on every use through the device identity, and eagerly on hidraw remove events), like gpg forgetting the PIN on card removal.
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
| `EXTENSION forget-pins@skagent` | evict PINs, keep keys; used by `skagent forget` |
| `EXTENSION session-bind@openssh.com` | currently refused; recording it for destination constraints and prompts is pending |
| anything else | `FAILURE` |

Key loading: `ssh-add -K` with stock tooling works from day one, but it asks for the PIN itself, so the user types it twice. `skagent load` (later) enumerates resident credentials with one PIN entry and primes the cache with it.

## PIN cache rules

1. **Only store PINs the device accepted.** An entry is created after a successful UV assertion, never from raw user input.
2. **An entry** holds the PIN (zeroizing, mlocked), `created_at`, `last_used` and `retries_at_store`, which is the retry counter read right after the successful assertion.
3. **Retry guard.** Before using a cached PIN, read the device's retry counter (free, no attempt consumed). Use the PIN only if the counter equals `retries_at_store`. Anything lower means someone entered a wrong PIN since: evict and prompt. This is stricter than gpg's `>= 3`.
4. **PIN error from the device** (`PIN_INVALID`, `PIN_BLOCKED`, `PIN_AUTH_BLOCKED`): evict immediately and never retry with a cached PIN. Prompt again only through the user, with the remaining retries shown.
5. **Forced PIN change pending** (`PIN_POLICY_VIOLATION`): don't cache. Tell the user to run `ykman fido access change-pin`.
6. **Lifetime:** hard max since creation (default 8h, configurable down), plus an optional idle timeout since last use. There's no "forever".
7. **Evict everything on:** `ssh-add -D`, `ssh-add -x`, logind `Lock`, `LockedHint=true` and `PrepareForSleep(true)` over D-Bus, `skagent forget`, agent shutdown. `ssh-add -d` evicts the removed credential's PIN. Outstanding signing requests are invalidated too; an old request cannot refill the cache.
8. **Scope:** one entry per credential (key handle), bound to the device identity it was verified on (see multiple keys). Never sent anywhere else. The same open device is kept from retry-counter read through prompt and assertion, with node identity checked again before sending the PIN.
9. **Monitoring failure:** caching is disabled until logind subscriptions and a sleep delay inhibitor are established. Losing the bus or logind owner evicts PINs and disables caching until reconnection. Sleep preparation clears the cache before releasing the inhibitor; resuming reacquires it.

Expiry is enforced on lookup; a 15s sweep also wipes unused expired entries from memory. Logind signals are matched to its unique bus owner. Session lock events are filtered by uid; unknown ownership conservatively evicts.

## prompting

- **PIN:** pinentry over Assuan, so it uses whatever the user already has (gnome3/qt/curses/tty). The description names the key (comment, e.g. `alice@example.com yubikey:12345678`) and, once session-bind is handled, the destination host. A small Assuan client reads replies into locked memory and never includes protocol payloads in errors. `--askpass` is an explicit alternative.
- **Touch:** libfido2 blocks until touched. Optionally show a desktop notification (`org.freedesktop.Notifications`) while waiting.

## concurrency

- libfido2 calls block for up to the touch timeout, so they run on `spawn_blocking`.
- Currently one global operation mutex; per-device locks and queue timeouts are pending.
- Signing tickets are captured under the agent state lock. Eviction invalidates queued requests, cancels prompts, and prevents late signatures from being returned or cached. No agent state lock is held over device operations or prompts.
- A blocking libfido2 assertion cannot yet be cancelled: the operation and its temporary PIN copy remain until it returns or times out (~35s). Eviction clears cache entries immediately but not this copy. Active-operation cancellation (`fido_dev_cancel`), including on disconnect and before suspend, is pending.

## testing

- **Rust:** protocol tests against an in-process agent over a real unix socket. The cache policy is a pure state machine over explicit `Instant` values and fabricated device identities, so retry, expiry and eviction rules are deterministic. Signing-ticket revocation and Assuan protocol handling have separate tests.
- **NixOS VM tests:** stock OpenSSH tools (`ssh-add`, `ssh`, `ssh-keygen -Y sign`) against the real binary. For FIDO inside the VM we need a virtual authenticator on `/dev/uhid`:
  - `soft-fido2` (pure Rust CTAP 2.1 with a uhid transport, EdDSA, credProtect, PIN, forcePINChange). Decided: used, but only in a separate test-only crate whose binary runs inside the VM. It's **AGPL-3.0**, so it is never a dependency of the agent crates.
  - QEMU USB passthrough of a real key stays an option for manual hardware runs.
- Real-hardware runs stay manual with a documented checklist.

## open questions

- systemd user unit with socket activation, plus a NixOS/home-manager module.

## milestones

1. ~~Agent skeleton: socket handling (`0600`, stale socket, peer uid), process hardening, safe logging, empty `REQUEST_IDENTITIES`. VM test with `ssh-add`.~~ Done.
2. ~~Identity store: sk keys via `ssh-add -K`/stub, lifetime, remove, lock/unlock.~~ Done.
3. ~~`skagent-fido`: libfido2 wrapper, assertion with UV + PIN, retry counter.~~ Done, exactly one device.
4. ~~PIN cache + pinentry.~~ Done: lifetime/idle limits, retry/device guards, Assuan/askpass, eviction races, Rust and VM tests.
5. ~~Virtual authenticator + full sign path in VM tests.~~ Done early (`skagent-testkey`, `checks.vm-testkey`, `checks.vm-signing`). Open: soft-fido2's credential listing gap (`docs/research/test-key.md`).
6. Logind eviction and `skagent forget` done (VM-tested, including mocked suspend execution through real logind). `skagent load` pending.
7. Multiple devices: device binding, select by touch.
