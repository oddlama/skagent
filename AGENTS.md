# AGENTS.md

Context for anyone (human or agent) changing this repo.

skagent is an ssh-agent for FIDO2 `sk-ssh-ed25519@openssh.com` keys created with `verify-required`. It caches the FIDO2 PIN for a bounded time, while the authenticator still requires a touch for every signature. Read `docs/design.md` before changing behavior. `docs/research/` holds the source-level findings the design is based on.

## layout

- `flake.nix`: flake-parts, numtide devshell, treefmt-nix, nci (nix-cargo-integration). The nci project is called `workspace` so it doesn't collide with the `skagent` crate in `nci.outputs`.
- `rust-toolchain.toml`: the toolchain nci builds with and the devshell provides (incl. rust-analyzer + rust-src from the same release). It's pinned through `flake.lock`.
- `Cargo.toml`: workspace, shared dependency versions and shared lints.
- `crates/skagent`: the agent (lib + `skagent` binary). `#![forbid(unsafe_code)]`. `routing.rs` holds device bindings, per-device/per-credential locks and exclusive touch selection.
- `crates/skagent-secret`: `SecretBuffer`, locked/guarded/zeroizing memory for PINs and passphrases, optionally in `memfd_secret(2)` memory (one backend per process, fixed by the first buffer; choose it before any secret exists). Its `unsafe` is confined to `src/mapping.rs`.
- `crates/skagent-fds`: descriptors crossing `exec`: adopting the socket systemd passes (socket activation) and `inherit_stdio_only` for spawned prompts (libfido2 opens hidraw without `O_CLOEXEC`). Spawn every child of the agent through `prompt::prompt_command`. Its `unsafe` is confined to `src/activation.rs` and `src/children.rs`.
- `crates/skagent-fido`: safe wrapper over libfido2 (via `libfido2-sys`, bindgen against the system headers). Its `unsafe` is confined to `src/raw.rs`. Only `/dev/hidraw*` devices are used; libfido2 also lists YubiKeys over `pcsc://`.
- `crates/skagent-testkey`: **test-only** virtual FIDO2 key on uhid (soft-fido2, AGPL-3.0). Used inside VM tests only. `checks.license-boundary` (`nix/license-boundary.nix`) fails if a shipped crate ever reaches it or soft-fido2 through `Cargo.lock`; add new shipped crates to its `shippedCrates`.
- `nix/tests/`: NixOS VM tests (end to end, real OpenSSH tools against the real binary). `common.nix` has the shared helpers (stub key writer, askpass and pinentry that log prompts, uhid/hidraw setup, a private session bus with a fake notification service that records every call).
- `nix/home-manager.nix`: the home-manager module, exported as `homeModules.default` (with the package defaulting to this flake's). The `home-manager` input is for that output and its VM test.
- `clippy.toml`: proper names allowed without backticks in doc comments.
- `docs/design.md`: architecture, PIN cache rules, threat model. `docs/research/`: findings with source references.

## commands

```sh
nix develop              # or direnv (`.envrc`)
cargo build / cargo test / cargo clippy --all-targets
nix fmt                  # treefmt: nixfmt, deadnix, statix, taplo, rustfmt
nix flake check -L       # treefmt, per-crate tests + clippy, VM tests
nix build                # release binary
```

- nci sets `CARGO_BUILD_TARGET`, so binaries land in `target/<triple>/debug/`. Use `cargo run -- ...`.
- `RUSTFLAGS=-D warnings` is set for the nix builds **and** exported into the devshell. Warnings are errors everywhere, including clippy pedantic warnings in the clippy check.
- No pre-commit hooks. They don't play well with jj, which is also used on this repo. Run `nix fmt` and `nix flake check` yourself before committing.

## rules

- Conventional commits with a scope: `chore(nix): ...`, `docs(research): ...`, `docs(design): ...`, `feat(agent): ...`, `feat(fido): ...`, `feat(cli): ...`, `fix(agent): ...`, `test: ...`, `test(vm): ...`. Commit small and often.
- Write pedantic, deliberate Rust. Correctness and maintainability take priority over speed of implementation.
- Never use `unwrap`, `expect`, `panic!`, `todo!`, `unimplemented!`, `unreachable!`, indexing/slicing that can go out of bounds, unchecked arithmetic, or anything else that can unexpectedly terminate a production execution path. The workspace lints deny all of these (`Cargo.toml`, `[workspace.lints.clippy]`). Don't `#[allow]` them away; restructure the code instead.
- Every Rust crate root must carry `#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]`. That includes `lib.rs`, `main.rs` and every integration test file, since each one is its own crate.
- Propagate errors with `anyhow` and attach actionable context that names the failed operation and the resource involved: `.with_context(|| format!("binding agent socket {}", path.display()))`, not `.context("failed")`.
- Argument parsing: `clap` with derive.
- Tests live in separate files (`crates/<crate>/tests/*.rs`), never in inline `#[cfg(test)]` modules. Logic that needs tests is exposed through the library crate.
- End-to-end behavior is tested in NixOS VMs (`nix/tests/`) in addition to the Rust tests. Anything that touches sockets, permissions, process state or OpenSSH interop needs a VM test.
- `unsafe` is denied workspace-wide (`deny`, so it can be lifted per crate). Only `skagent-secret` (raw mappings), `skagent-fido` (libfido2 FFI) and `skagent-fds` (adopting descriptors, a pre-exec hook) allow it, at their crate root, with every block small, documented (`// SAFETY:`) and behind a safe API. All other crate roots carry `#![forbid(unsafe_code)]`.
- Terminal output must respect the user's terminal colors: use the `colored` crate with the basic ANSI colors only (no truecolor/256-color, no backgrounds), honor `NO_COLOR`, and disable color when the stream isn't a terminal. Don't over-color. Use color to highlight what matters, consistently: red = error, yellow = warning, bold = the value the user has to act on.

## tests

- `crates/skagent/tests/*.rs`: Rust tests, which also run inside every nix package build (a failing test fails `nix build`).
- `nix/tests/agent.nix` (`checks.vm-agent`): the release binary as a transient systemd unit in a NixOS VM, driven by stock `ssh-add`. Build one VM test alone with `nix build -L .#checks.x86_64-linux.vm-agent`.
- `nix/tests/signing.nix` (`checks.vm-signing`): signing with the virtual key, sshd `verify-required`, touch/PIN counting, retry/device guards, expiry, pinentry, eviction during prompts/assertions, logind lock/sleep/outage handling, cancellation on forget and on client hangup, unplug eviction by the sweep. Suspend uses real logind but replaces systemd-suspend's kernel action with a short sleep.
- `nix/tests/destinations.nix` (`checks.vm-destinations`): three VMs (client, jump, target). `ssh-add -K` into skagent, agent forwarding over two hops, prompts naming the verified host, `ssh-add -h` constraints (direct, forwarded, refused beyond the last allowed hop), no remote `skagent load`.
- `nix/tests/loading.nix` (`checks.vm-loading`): resident enumeration and cache priming, no stubs, preserved lifetimes, wrong PIN, load/removal races, empty and multiple devices. The load extension carries no PIN.
- `nix/tests/multiple-keys.nix` (`checks.vm-multiple-keys`): two keys with different PINs; selection before prompting, independent caches, parallel bound signing, removal, cancellation, replacement, a key that gives up waiting during selection, and a client hanging up during selection. Checks retry counters stay at 8.
- `nix/tests/home-manager.nix` (`checks.vm-home-manager`): the module on NixOS through home-manager's NixOS module, with alice's real user manager and session bus. Socket activation, `SSH_AUTH_SOCK`, load at login with the session's display, what pinentry inherits, logout. A `test-session.target` bound to `graphical-session.target` stands in for a compositor. Run commands as alice with `systemd-run --machine=alice@ --user --wait --pipe` and an absolute `bash` path (the user manager's PATH has no bash), and read user unit logs with `journalctl _SYSTEMD_USER_UNIT=...` (`--user-unit` also matches the caller's uid).
- `nix/tests/testkey.nix` (`checks.vm-testkey`): the virtual key against stock OpenSSH, no skagent. If this fails, no FIDO VM test means anything. Its quirks and workarounds: `docs/research/test-key.md`.
- VM test scripts: the driver runs shell commands with `pipefail` and type-checks/lints the Python. Wait with `retry(fn, timeout_seconds=...)` in Python instead of `cmd | grep -q` in shell, and don't shadow driver globals (`log`, `machine`, ...).
- When adding a safety property, check that a test fails without it. Break the code, watch the test fail, restore. The log redaction is covered twice: the rule by `tests/logging.rs`, the wiring by the VM test.

## known ssh-agent-lib behavior

- Unknown message types (e.g. the SSH1 `REMOVE_ALL_RSA_IDENTITIES` = 9 that `ssh-add -D` still sends) fail to decode, and the library drops the connection instead of answering `FAILURE`. `ssh-add` ignores this for the SSH1 message.
- Every refused request (default `Session` methods) is logged at `ERROR` by the library. That's noisy but contains no secrets.
- `listen()` ends on the first `accept` error. `PeerCheckedListener` retries transient errors so that can't happen for resource exhaustion.

## destinations

- `destination.rs` follows OpenSSH's ssh-agent rules for `session-bind@openssh.com` and `restrict-destination-v00@openssh.com`; check changes against `ssh-agent.c` (`identity_permitted`, `process_ext_session_bind`, `process_sign_request2`). Decode those messages with the strict decoders there, not ssh-agent-lib's types: they drop reserved fields and don't check trailing data, which would accept constraints skagent doesn't understand.
- Anything skagent can't decode must only ever narrow where a key may be used: a failed bind hides constrained keys, unknown host key types and CA entries never match.
- Text from signed data (users, namespaces) is shown to the user; pass it through the sanitizer (`Purpose`), it can come from another machine.

## secrets

- The PIN and anything derived from it never get logged, `Debug`-printed or written to disk. Store secrets in `skagent_secret::SecretBuffer` (locked, guarded, zeroized, redacted `Debug`, no `Clone`), never in `String`/`Vec<u8>` longer than unavoidable, and compare them with `constant_time_eq`.
- ssh-agent-lib logs every request at `debug` level (key handles, lock passphrases). Its `debug`/`trace` output must stay filtered no matter what log filter the user passes.
- Fail closed: if a safety check can't be performed (peer credentials, retry counter, socket ownership), refuse the operation. If logind monitoring or the sleep delay inhibitor fails, disable caching until it recovers; uncached signing is still allowed.
- Eviction must revoke signing tickets as well as wipe cache entries. A pending prompt or late assertion must never refill an evicted cache. Global evictions revoke every ticket; removing or expiring one identity (`Signer::forget`) revokes only that credential's tickets, so unrelated signatures keep going.
- Every agent request locks its state through `Shared::state_now`, which removes expired identities with their PINs and bindings, and uses the returned `now` for all lookups under that lock.
- The logind signal loop must keep polling every stream: zbus blocks its socket reader on a full subscription queue. Any method call inside the loop needs a short timeout, and proxies use `CacheProperties::No`.
- Blocking device operations must stay cancellable (`cancel.rs`): assertions run under a `DeviceInterrupt`, selections check an `Abandoned` flag, and long agent requests run under `Hangup::unless_closed`. Cancelling never replaces the ticket check after the worker returns. Only waiting phases (device work, selection, prompts, enumeration) may be cut short by a hangup; authorizing a request and committing its result always run to the end, and functions that change several pieces of state take every lock first and then change everything without another `.await`, so a dropped future can never leave half a change behind. The only libfido2 call allowed concurrently with another on the same handle is `fido_dev_cancel`, through `CancelSlot`; don't call `fido_dev_set_timeout`, `fido_dev_set_pin` or `fido_dev_force_*` after open (see the SAFETY comment there).
- Never send a PIN to a device that isn't known to hold the credential. Wrong-device PIN attempts cost that device a retry, and `verify-required` credentials can't be found by a silent probe (see `docs/design.md`, multiple keys).
- Don't hold the agent state lock across device operations or prompts; they block for up to ~35 s. Per-device locks must travel with the device into blocking workers, never be dropped with an async caller while hardware is still in use.
- Resident loading must preserve existing identity constraints and stage all PIN copies before committing. Only successful PIN-authenticated enumeration may prime caches; never serialize a PIN into an agent extension.
- PIN eviction preserves bindings; identity removal drops them. A stale binding requires touch selection, not automatic substitution of another connected key.
