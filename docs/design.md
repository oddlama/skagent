# skagent design

Target design; the milestones below distinguish implemented and pending pieces. Findings this is based on: `docs/research/pin-caching.md`.

## goal

- Keys stay `ed25519-sk` with `-O resident -O verify-required` (credProtect `UV_REQUIRED`). Nothing about provisioning changes.
- The authenticator enforces a touch for every signature.
- The PIN is typed once and cached in the agent for a bounded time. It's evicted on lock, suspend, explicit request or errors.
- Drop-in: speaks the ssh-agent protocol on a unix socket. Works with ssh, git, agent forwarding and `ssh-add -K`.

Non-goals: OpenPGP/PIV, non-Linux, and non-sk keys. Those are **refused** (decided). To mix agents, point ssh at skagent per host with `IdentityAgent` (e.g. only for `github.com`) and keep a normal agent for the rest.

Beside SSH, skagent decrypts [age](https://age-encryption.org) files with a key derived from a security key. That has a design document of its own, [`age.md`](age.md); what it adds to the points below is noted there and under "age" here.

## threat model

Protected:

- **Lost/stolen YubiKey:** useless without the PIN (`UV_REQUIRED`, discovery needs the PIN too).
- **Leaked key handle (stub file, agent memory dump):** useless without the PIN.
- **Stolen laptop + key while no PIN remains in memory** (evicted, expired, rebooted): PIN needed. An assertion still waiting for a touch when the PINs are evicted is cancelled on the key, which ends its temporary PIN copy; see concurrency.
- **Other local users:** socket is `0600` in `$XDG_RUNTIME_DIR`, and the peer uid is checked on accept (own uid or root, same as OpenSSH).
- **Forwarded agent on a hostile remote host:** every signature still needs a touch on your machine, so no silent use. Keys added with `ssh-add -h` are additionally limited to the listed hops, verified through `session-bind@openssh.com` (see destinations). A key the remote host adds with a leaked key handle can't borrow a loaded key's cached PIN or binding: it's refused, and a signature that doesn't verify with the requesting identity's public key is never returned or cached. A forwarded agent can't make this machine load resident keys or evict its cached PINs: a remote host can only cause a PIN prompt with a signature request while no PIN is cached, and that prompt names what is signed.
- **A fake security key swapped in for a paired one, or plugged in next to it:** it can't sign skagent's pairing challenge, so it gets no PIN, whatever serial it reports (see multiple keys).
- **Core dumps / ptrace by other processes of the same user:** `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`. The PIN sits in a zeroizing, mlocked buffer.

Not protected:

- **Malware running as you in an unlocked session.** It can ask the agent for signatures and gets them whenever you touch. That's true for every ssh-agent. It can also keylog the PIN when you enter it.
- **root.**
- **A rogue USB device used before pairing,** e.g. on a key's first use, with `--no-pairing`, or one that relays to the real key. It receives the PIN through the PIN protocol, the same exposure as OpenSSH today. Pairing trusts the first use.

## architecture

```
ssh / git / ssh-add ── ssh-agent protocol (unix socket, peer-checked) ──> skagent
                                                                          ├─ identity store   sk public keys + key handles, remembered across restarts
                                                                          ├─ PIN cache        bounded, see rules below
                                                                          ├─ PIN prompt       pinentry (Assuan)
                                                                          └─ fido layer       libfido2 via FFI, blocking calls on spawn_blocking
```

Crates:

- `skagent`: CLI, socket and process hardening, protocol handling via `ssh-agent-lib`, identity store, cache policy. `unsafe` is forbidden.
- `skagent-fido`: safe wrapper over `libfido2-sys`, the same libfido2 OpenSSH uses. Enumerates devices, reads the PIN retry counter, selects devices by touch and asserts with up/uv/pin. Enumerates resident SSH credentials through PIN-authenticated credential management. Unsafe code is confined to `raw.rs`.
- `skagent-secret`: guarded, locked, zeroizing memory. Unsafe code is confined to `mapping.rs`.
- `skagent-age`, `skagent-age-plugin`: age's post-quantum recipient for a derived key, and age's plugin protocol in front of the agent; see [`age.md`](age.md). No unsafe code.
- `skagent-fds`: descriptors crossing `exec`. Adopts the sockets systemd passes (`LISTEN_PID` must name the agent, at most two listening unix stream sockets told apart by their names, made close-on-exec, taken before the runtime opens descriptors), and gets a pidfd of a connection's peer (`SO_PEERPIDFD`). Spawned prompts get stdio only: before exec the child marks everything above stderr close-on-exec (`close_range`, `CLOSE_RANGE_CLOEXEC`), because libfido2 opens hidraw without `O_CLOEXEC` and pinentry would otherwise inherit an open security key.

Why libfido2 and not a pure Rust CTAP stack: OpenSSH signs with exactly the libfido2 assertion semantics (raw client data, `ssh:` rp ids, credProtect), and libfido2 handles hidraw, pcsc and all PIN protocol versions. Matching OpenSSH byte for byte is the point.

## multiple keys

The identity store, device bindings and PIN cache support multiple credentials and connected authenticators (work + personal):

- The identity store holds keys from any number of authenticators. Keys added on this machine without a lifetime or destination constraints (`ssh-add`, `skagent load`) are remembered in `$XDG_STATE_HOME/skagent/keys.toml` (0600, atomic) and offered again after a restart or logout: public key, flags, key handle and comment, what a stub file holds; nothing secret. Keys added through a forwarded agent (a connection with a session bind) never change the file, so a remote host can't plant a key that outlives the agent. Adding a remembered key again with a lifetime or destinations forgets it, so it can't come back without them; `ssh-add -d` and `-D` forget too. A file that can't be read is ignored and replaced.
- `REQUEST_IDENTITIES` lists keys on a plugged-in security key first, then keys skagent can't place, then keys whose security key isn't there, each group in the order added. Of two keys a server accepts, ssh signs with the first, so it's the one at hand, without waiting for an absent key. Placing a key uses its binding the way routing would (plug-in, pairing proof, serial); serials and proofs of new plug-ins are read once, and no device is asked when fewer than two keys are listed or none has a binding.
- Finding the device that holds a key is the hard part. **A silent probe doesn't work for our keys**: credProtect `UV_REQUIRED` hides the credential from every request without user verification, so a probe with the key handle says "no credentials" on every device, the right one included. That's why OpenSSH falls back to "touch the key you mean" (`sk_probe: selecting sk by touch`). And verifying with a PIN on the wrong device costs that device a retry.
- So skagent remembers where a key lives: after a signature or authenticated resident enumeration succeeded on a device, the key is bound to that device's identity (its `/dev/hidrawN` node: device number, inode and change time, which change on every replug), for a YubiKey its serial (Yubico's `READ_CONFIG`), and once paired, its pairing (below). With one device connected and no binding yet, that device is used. With several and no binding, the user picks by touch (libfido2's touch-begin/status), then the PIN is asked for. A lost binding requires selection, even with one remaining device; another device is never silently substituted. Two detected touches in one polling round are refused as ambiguous. A device that can't be asked or fails while waiting (unplugged, gave up waiting for its own touch, refused) drops out and the others keep waiting, like OpenSSH's `sk_select_by_touch`; selection fails only when none are left. The exception is the same key: the device that proves the pairing, or for an unpaired YubiKey a plug-in reporting the bound serial, is used without selection (a credential lives on one authenticator only), though its cached PIN stays behind with the old plug-in.
- **Pairing** (`pairing.rs`, trust on first use): right after the first signature with a PIN the user typed, or a load, the key has just shown it holds the SSH key. skagent then looks for its own credential on it (relying party `skagent:pairing`, discoverable, Ed25519, credProtect 2) with that PIN, and creates one if there is none: one more touch, once per key. The popup asks for it (`pair`), Esc declines; a key it fails on or that the user declined isn't asked again until replugged. The binding keeps the credential's id and public key. Before a typed PIN goes to a device that isn't the plug-in that signed last, the device has to sign a random challenge with it, silently (`up=false`, no PIN; the answers are cached per plug-in). The device that can is the key, whatever it reports. One that reports the paired key's serial and can't is refused (`unrecognized`), and so are two that can (`duplicate`); neither gets a PIN. So a fake swapped in for a paired key, or plugged in next to it, gets no PIN, and paired keys without a serial are recognized after a replug too. One credential protects every SSH key on its key, and another machine finds it with its first PIN, without a touch. skagent never creates one when looking failed: creating replaces the key's old one (same user id), which would break the pairing other machines know. `--no-pairing` stops pairing with new keys; pairings made before are still checked.
- Bindings with a serial or a pairing are remembered in `$XDG_STATE_HOME/skagent/bindings.toml` (0600, written to a new file and renamed), under a SHA-256 digest of the credential (application and key handle) rather than the key handle, which for non-resident keys wraps the private key. Nothing in it is secret; an unreadable file is ignored and replaced. Whoever can write it can point a key at another of the user's keys, which costs that key a PIN retry, or at a pairing of their own; they could change `~/.ssh` and the agent's unit just as well. Without a pairing, a device that claims the bound serial is taken for that YubiKey, unless a second device claims it too: then the request fails (`duplicate`) without a PIN going to either. While the plug-in that signed before stays connected, it's used regardless.
- A request whose security key isn't plugged in waits for it (`--plug-in-timeout`, default 15s, `0` fails right away): for the bound key by name when its serial is known, else for any key when none is plugged in. Plugging in another key doesn't end the wait for the bound one. The popup shows it (`no-key`, `wrong-key`), else a desktop notification; a client hangup, the popup's cancel or a revocation end the wait, the timeout fails the request. The connected devices are polled every 250ms; serials and pairing proofs of new plug-ins are read only when a binding needs them, under each device's lock.
- **A cached PIN is only ever sent to the device it was verified on.** The cache entry carries the device identity; if it no longer matches (replug, other device on that node), the entry is dropped and the user is asked again. This also covers "personal key plugged in where the work key was".
- The PIN cache is per credential and device. Work and personal key have independent entries, lifetimes and retry guards. Evicting one never touches the other.
- There's one lock per device and per credential, so bound devices sign in parallel and duplicate requests queue without duplicate prompts. Touch selection takes exclusive access across devices to avoid consuming a touch intended for an assertion. Device locks travel into blocking workers; dropping an async request cannot release the hardware early.
- Bindings survive PIN expiry, lock and `skagent forget`. Removing an identity drops its binding; `ssh-add -D` drops all bindings.
- Device identity changes evict the PIN on its next lookup, and the 15s sweep drops the PINs of unplugged (or replugged) keys without waiting for a request. Permission/ACL changes also change ctime, conservatively requiring selection and a fresh PIN.
- Per-key policy: `--pin-policy application=ssh:personal,lifetime=1h` (or `fingerprint=…`) overrides lifetime and idle timeout for matching keys, e.g. 8h for work and 1h for personal. The first matching rule wins; each cache entry keeps the policy it was stored with.

## secret memory

Secrets (cached PINs, the `LOCK` passphrase) live in `skagent-secret` buffers:

- Each buffer is its own anonymous mapping, so `mlock` is never shared with unrelated heap data (`munlock` isn't reference counted).
- The data pages are `mlock`ed (never swapped; hibernation images still contain locked memory, which is why PINs are dropped before sleep, but a locked agent's passphrase goes into the image), `MADV_DONTDUMP` (left out of core dumps on top of `RLIMIT_CORE=0`) and `MADV_WIPEONFORK` (a forked child, e.g. pinentry before `exec`, sees zeros).
- `PROT_NONE` guard pages before and after turn an overflow into a crash instead of a silent read or write.
- Contents are zeroized with volatile writes on drop and on clear. `Debug` prints nothing about the content, not even the length. Comparisons are constant time.
- Allocation fails closed: if `mlock` fails (e.g. `RLIMIT_MEMLOCK` exhausted), the operation is refused.
- Opt-in `--secret-memory memfd-secret`: buffers live in `memfd_secret(2)` pages instead, mapped over the data pages between the guard pages. They are also removed from the kernel's direct map; never swapped (the kernel keeps secretmem unevictable, so they aren't `mlock`ed, which would fail); not dumped; absent in forked children (`MADV_DONTFORK`, since `MADV_WIPEONFORK` needs private memory). Not the default because the kernel refuses to hibernate while any secretmem exists. skagent drops PINs before sleep, but a locked agent keeps its lock passphrase. The first buffer fixes the backend for the process, and `serve` probes it at startup.
- Not covered: bytes that pass through buffers we don't own (pinentry's pipe, the socket read buffers of `ssh-agent-lib` for `LOCK`, libfido2's heap copies of the PIN hash and the PIN protocol secrets during an operation, which it frees with `freezero`). They are short-lived, but not locked.

## protocol surface

| message | behavior |
|---|---|
| `REQUEST_IDENTITIES` | loaded sk keys the connection may see (destination constraints), those on a plugged-in security key first |
| `SIGN_REQUEST` | `sk-ssh-ed25519@openssh.com` only: find the device that holds the key handle, get the PIN (cache or prompt), assert with `up=true` and the PIN token (the `uv` option stays unset, like OpenSSH), verify the result against the identity's public key like a server would, return `sig ‖ flags ‖ counter` |
| `ADD_IDENTITY(_CONSTRAINED)` | sk keys from `ssh-add -K` or `ssh-add <stub>`, any other key type is refused. Lifetime (`-t`) honored; an identity whose lifetime ended is removed like `ssh-add -d`, PIN and device binding included (on the next request or the 15s sweep). `sk-provider@openssh.com` is accepted for the built-in provider only. Destination constraints (`-h`) are honored (see destinations). Confirm (`-c`) and anything unknown **refuse the key**, fail closed. A key a connection can't see (constraints) can't be replaced through it. A key with another public key but the credential (application and key handle) of a loaded key is refused: PIN cache entries and bindings are per credential, so it would sign with the loaded key's cached PIN and outside its constraints |
| `REMOVE_IDENTITY`, `REMOVE_ALL_IDENTITIES` | drop identities (only ones the connection may see). Remove-all also evicts the whole PIN cache |
| `LOCK` / `UNLOCK` (`ssh-add -x/-X`) | lock evicts the PIN cache and refuses signing until unlock. Passphrase compared in constant time |
| `EXTENSION forget-pins@skagent` | evict PINs, keep keys; used by `skagent forget`. Refused on connections ssh bound (or tried to bind) to a session: evicting first would let a remote host time a PIN prompt |
| `EXTENSION load-resident-keys@skagent` | empty request; agent selects one device, prompts and loads its resident SSH keys; reply is a big-endian u32 count, never a PIN |
| `EXTENSION session-bind@openssh.com` | verify the host key's signature over the session ID and record the hop for this connection; also while locked, like OpenSSH. Failures answer `EXTENSION_FAILURE` |
| `EXTENSION query` | lists the supported extensions |
| anything else | `FAILURE` |

Key loading: `ssh-add -K` with stock tooling asks for the PIN itself, so the user types it again when signing. `skagent load` instead asks inside the running agent, enumerates one selected device's resident credentials and primes their PIN caches and bindings. It skips non-SSH RPs and non-Ed25519 algorithms. credProtect 3 maps to `verify-required`; other policies retain OpenSSH's presence-only behavior. No stub files are written.

Loading stages the whole result before committing. Existing identities retain their lifetimes, comments and flags; conflicting handles or verification policies are refused. Agent lock/removal/forget invalidates a pending load just like signing. A rejected loading PIN evicts only that device's cached PINs, with no automatic retry. Each explicit load prompts afresh; it never tries another device's cached PIN.

## PIN cache rules

1. **Only store PINs the device accepted.** An entry is created after a successful UV assertion or PIN-authenticated credential-management enumeration, never from raw user input.
2. **An entry** holds the PIN (zeroizing, mlocked), `created_at`, `last_used` and `retries_at_store`, which is the retry counter read right after the successful assertion or enumeration.
3. **Retry guard.** Before using a cached PIN, read the device's retry counter (free, no attempt consumed). Use the PIN only if the counter equals `retries_at_store`. Anything lower means someone entered a wrong PIN since: evict and prompt. This is stricter than gpg's `>= 3`.
4. **PIN error from the device** (`PIN_INVALID`, `PIN_BLOCKED`, `PIN_AUTH_BLOCKED`): evict immediately and never retry with a cached PIN. Prompt again only through the user, with the remaining retries shown.
5. **Forced PIN change pending** (`PIN_POLICY_VIOLATION`): don't cache. Tell the user to run `ykman fido access change-pin`.
6. **Lifetime:** hard max since creation (default 8h, configurable, also per key with `--pin-policy`), plus an optional idle timeout since last use. There's no "forever".
7. **Evict everything on:** `ssh-add -D`, `ssh-add -x`, logind `Lock`, `LockedHint=true` and `PrepareForSleep(true)` over D-Bus, `skagent forget`, agent shutdown. `ssh-add -d` and the end of an `ssh-add -t` lifetime evict that credential's PIN and binding. Outstanding requests covered by the eviction are revoked too, so an old request cannot refill the cache: all of them for global evictions, only that credential's for a removal or expiry.
8. **Scope:** one entry per credential (key handle), bound to the device identity it was verified on (see multiple keys). Never sent anywhere else. The same open device is kept from retry-counter read through prompt and assertion, with node identity checked again before sending the PIN.
9. **Monitoring failure:** caching is disabled until logind subscriptions and a sleep delay inhibitor are established. Requests arriving before the first attempt run uncached and aren't revoked when it succeeds or fails: they missed no event, and with socket activation the first request arrives with the agent's start. Every later transition revokes in-flight requests. Losing the bus or logind owner evicts PINs and disables caching until reconnection. Sleep preparation clears the cache before releasing the inhibitor; resuming reacquires it.

Expiry is enforced on lookup; a 15s sweep also wipes unused expired entries from memory. Logind signals are matched to its unique bus owner. Session lock events are filtered by uid; unknown ownership conservatively evicts. The method calls inside the signal loop are bounded to 1s: the ownership lookup (timeout counts as ours) and retaking the sleep inhibitor after resume (timeout restarts the watch, caching stays off meanwhile). zbus blocks its socket reader when any subscription queue is full, so an unbounded call there could deadlock the watcher and let lock and sleep go unnoticed. Proxies don't cache properties.

## prompting

- **PIN:** pinentry over Assuan, so it uses whatever graphical pinentry the user already has (gnome3, qt, ...). Terminal pinentries (curses, tty) don't work: the agent has no terminal to name (`OPTION ttyname` isn't sent), and pinentry's stdin and stdout are the Assuan pipes. The description names the key (comment, e.g. `alice@example.com yubikey:12345678`) and what the signature is for: an SSH login (user, and the host as named by the key's destination constraint or by the fingerprint of the host key the session is bound to), SSHSIG data (its namespace, e.g. `git`), or data of an unknown kind. The same text is logged with every signature. Names come from the signed data, and key comments from whoever added the key, i.e. possibly from another machine on a forwarded agent (`display.rs`): control characters, line separators and invisible formatting characters (zero-width, bidi overrides and isolates) are replaced, quotes are escaped so a name can't end its own quotation, and length is capped. A small Assuan client reads replies into locked memory and never includes protocol payloads in errors. `--askpass` is an explicit alternative, and `--popup` skagent's own popup, which shows every step of a request in one window ([`pinentry.md`](pinentry.md)). A PIN the user typed is first checked without a touch where the key supports credential management (reading its metadata trades the PIN for a token), so the touch is only asked for once the PIN is known to be right; a wrong PIN costs the one retry it would have cost in the assertion. Every prompt is closed (its program killed) after 60s: the request holds its device and shared access to all devices meanwhile, and the lock prefers writers, so an abandoned dialog would otherwise stall selection and through it every other signature. Loading prompts don't mention a touch; credential management needs none.
- **Touch:** libfido2 blocks until touched. Meanwhile a desktop notification (`org.freedesktop.Notifications` on the session bus) says "Touch your security key", with the key and what is signed; during selection "Touch the security key to use". Closed when the operation ends. Best effort: own task, short timeouts, markup-escaped body; `--no-touch-notification` switches it off.

## concurrency

- libfido2 calls block for up to the touch timeout, so they run on `spawn_blocking`.
- Per-device and per-credential locks; bound devices operate independently. Selection takes a global write lock and is polled for at most 30s. PIN prompts are bounded to 60s; waiting for a busy credential or device, or for device access, gives up after 2 minutes ("busy").
- Selection sends no PIN. libfido2 uses a dummy makeCredential with empty pinUvAuthParam, which requires touch before rejection and consumes no PIN retry. A second touch is required for the actual signature. Outstanding probes are cancelled on drop, on the same thread that owns each device.
- Signing tickets are captured under the agent state lock. A ticket is revoked by every global eviction and by the removal or expiry of its own credential (loading tickets: global only, so a key removed while a load is pending can come back with that load). Revocation cancels queued requests and prompts, and prevents late signatures from being returned or cached. No agent state lock is held over device operations or prompts.
- Running device operations end early when their request is revoked or abandoned (`cancel.rs`). An assertion waiting for a touch gets `CTAPHID_CANCEL` through `fido_dev_cancel` from another thread, repeated every 100ms until the worker returns, since a cancel that reaches the key before the request does is ignored. Touch selection checks an abandoned flag every round. Prompts and queue waits are futures and end when dropped. The worker then releases the device and its PIN copy. Calling `fido_dev_cancel` while the owner is inside another call on the same handle is free of data races in libfido2 1.17 (reasoning at `CancelSlot::cancel` in `raw.rs`); the slot is cleared under its lock before the handle is closed. Suspend revokes all tickets, so it cancels too.
- ssh-agent-lib only notices a disconnected client when it writes the reply. So each connection is also watched for hangup, via `EPOLLHUP` on a duplicate of its descriptor that is never read from: a client that disconnects mid-request (Ctrl-C on ssh) cancels the request like a revocation would, but leaves the PIN cache alone. A half close (`EPOLLRDHUP` only: the client shut down its sending side and may still wait for the reply) doesn't count.

## testing

- **Rust:** protocol tests against an in-process agent over a real unix socket. The cache policy is a pure state machine over explicit `Instant` values and fabricated device identities, so retry, expiry and eviction rules are deterministic. Signing-ticket revocation and Assuan protocol handling have separate tests.
- **NixOS VM tests:** stock OpenSSH tools (`ssh-add`, `ssh`, `ssh-keygen -Y sign`) against the real binary. For FIDO inside the VM we need a virtual authenticator on `/dev/uhid`:
  - `soft-fido2` (pure Rust CTAP 2.1 with a uhid transport, EdDSA, credProtect, PIN, forcePINChange). Decided: used, but only in a separate test-only crate whose binary runs inside the VM. It's **AGPL-3.0**, so it is never a dependency of the agent crates.
  - QEMU USB passthrough of a real key stays an option for manual hardware runs.
- Real-hardware runs stay manual with a documented checklist.

## destinations

Following OpenSSH's ssh-agent (`destination.rs`, ported from `identity_permitted` and friends in `ssh-agent.c`):

- ssh sends `session-bind@openssh.com` on every agent connection: host key, session ID, the host's signature over it, and whether the connection authenticates or forwards. skagent verifies the signature and records up to 16 hops per connection. Nothing may follow a hop bound for authentication; a session ID can't change its host key. Any attempt marks the connection as remote, also a failed one.
- `ssh-add -h` constraints (`restrict-destination-v00@openssh.com`) list hops `from > to`, `to` optionally with a user pattern. A constrained key is visible, replaceable and removable on a connection only if every bound hop is allowed by a constraint from the previous hop's host key (the first from this machine); on a connection forwarded to a host, only if a constraint allows it beyond that host. Local, unbound connections see every key.
- A constrained key only signs on a bound connection, and only an SSH user authentication request for the most recently bound session (same session ID; for forwarded connections the request must name the bound host key), as a user the last constraint's pattern allows.
- Websafe: a key whose application isn't `ssh:…` only signs SSH user authentication and SSHSIG data, never data a website could accept as a WebAuthn login.
- Decoding is strict: reserved fields must be empty (ssh-agent-lib's own types silently drop them, so skagent decodes these messages itself), names contain no NUL, nothing may trail.
- Limits: host certificates and host key types newer than the `ssh-key` crate (e.g. OpenSSH 10's `ssh-mldsa44-ed25519`) can't be decoded. Binding a session to such a key fails, which keeps constrained keys off that connection. In constraints, keys of unknown types are skipped (`ssh-add -h` sends every key `known_hosts` has, including ones `UpdateHostKeys` learned), CA entries never match: both only narrow. ssh prefers Ed25519, ECDSA and RSA host keys over `ssh-mldsa44-ed25519`, so normal hosts bind fine.

## age

[`age.md`](age.md) has the design: a credential of its own per identity (relying party `skagent:age`, credProtect 3, hmac-secret), a key pair derived from its secret at decryption time, files in age's native post-quantum format. What that means for the points above:

- **Threat model.** Unlike an SSH key, the private key of an age identity exists in the agent's memory while a file is decrypted: derived, used and wiped within milliseconds. Whoever reads the agent's memory at that moment (root, the kernel) has it for good, and so has whoever gets one derivation out of the security key with a stolen PIN and a hijacked touch. Everything else carries over: without the PIN the security key denies that the credential exists, and it wants a touch for every derivation.
- **Batches.** `skagent batch -- command` trades that for convenience, on request and for a limited time: after one PIN and one touch, whose prompt says so, the identity's key stays in the agent's memory (in `memfd_secret` memory where the kernel has it, whatever `--secret-memory` says) until the command is done, for at most `--batch-lifetime` (10 minutes). Meanwhile the processes the command started get file keys without a touch, and nobody else: the agent proves for every request that its peer descends from the batch's tool (`ancestry.rs`). Malware running as the user can't join such a batch, but it can change what the batch runs, attach to one of its processes where ptrace is allowed, or ask for a batch of its own, which the user would have to touch for. Whatever evicts PINs ends every batch and wipes its key, and so does unplugging the security key. Nothing is kept while PINs can't be cached.
- **Protocol surface.** A second socket (`skagent-age.sock`) answers `age-unwrap@skagent`, `age-new@skagent`, `age-list@skagent` and `age-batch@skagent` and nothing of the ssh-agent protocol; the ssh-agent socket answers none of them. It takes requests from skagent's plugin and command line only, recognized by their executable (`peer.rs`). One request gets at most one file key. A batch lasts as long as the connection it was asked for on, at most.
- **The way to the security key** is the signer's (`Signer::run`): routing by binding, pairing and serial, the PIN cache with its rules, the check of a typed PIN, cancellation, tickets. A PIN that a derivation accepted is cached like one a signature accepted.
- **State.** `$XDG_STATE_HOME/skagent/age.toml` remembers the identities found: credential ids and recipients, nothing secret.
- **Secret memory.** The security key's answer and the seed derived from it are `SecretBuffer`s, and so is the seed a batch keeps. Not covered, and short-lived: libfido2's copy of the answer, what `libcrux-ml-kem` and `x25519-dalek` keep on the stack while they run, and the file key in the reply buffers of ssh-agent-lib.
- **Notifications.** A running batch has a desktop notification with its command, a count of the files and a button that stops it (`notify.rs`). It is the one place where the agent listens to the notification service: for that button, and for the notification being closed.

## open questions

- `skagent load` through a forwarded agent stays refused. An opt-in (e.g. `--allow-forwarded-load`, with prompt and notification naming the forwarded host by its verified host key) is postponed until a workflow needs it: without it, a remote host can only cause a PIN prompt through a signature request while no PIN is cached (it can't evict PINs either), and that prompt says what is signed.

## milestones

1. ~~Agent skeleton: socket handling (`0600`, stale socket, peer uid), process hardening, safe logging, empty `REQUEST_IDENTITIES`. VM test with `ssh-add`.~~ Done.
2. ~~Identity store: sk keys via `ssh-add -K`/stub, lifetime, remove, lock/unlock.~~ Done.
3. ~~`skagent-fido`: libfido2 wrapper, assertion with UV + PIN, retry counter.~~ Done, exactly one device.
4. ~~PIN cache + pinentry.~~ Done: lifetime/idle limits, retry/device guards, Assuan/askpass, eviction races, Rust and VM tests.
5. ~~Virtual authenticator + full sign path in VM tests.~~ Done early (`skagent-testkey`, `checks.vm-testkey`, `checks.vm-signing`). Credential listing is supplemented by the test wrapper; stock `ssh-keygen -K` and `ssh-add -K` now pass (`docs/research/test-key.md`).
6. ~~Eviction triggers, `skagent forget`, `skagent load`.~~ Done, including authenticated enumeration, cache priming, preserved constraints and loading races in `checks.vm-loading`. Logind sleep tests mock the kernel suspend action.
7. ~~Multiple devices: device binding, select by touch.~~ Done, with per-device locking and a two-key VM suite using distinct PINs. Bindings by YubiKey serial, remembered across restarts, and waiting for a key to be plugged in followed with the popup.
8. ~~Cancelling running operations.~~ Done: revocation, suspend and client hangups cancel assertions on the key and stop selections; unplugged keys lose their PINs within 15s. Real-key confirmation pending.
9. ~~Running as a service.~~ Done: systemd socket activation and a home-manager module (socket-activated user service, part of the graphical session, optional load at login), tested in `checks.vm-home-manager`. A NixOS module isn't planned: the agent runs per user, which is home-manager's job.
10. macOS (aarch64-darwin): planned, see [`macos.md`](macos.md).
11. skagent-pinentry, a popup of our own for PIN, touch and errors: planned, see [`pinentry.md`](pinentry.md).
12. Decrypting age files with a key derived from the security key: in progress, see [`age.md`](age.md). Done: identities, decrypting one file per touch, the plugin (`checks.vm-age`), batches (`checks.vm-batch`), the home-manager module's socket. Pending: forwarding, the module's remaining options.
