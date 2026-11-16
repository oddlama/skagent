# macOS (aarch64-darwin): plan

Milestone 10. skagent on macOS with the same guarantees as on Linux: the PIN is
cached for a bounded time, dropped on screen lock, sleep and unplug, and not
cached at all while lock and sleep can't be watched. Started by launchd through
socket activation, set up by the home-manager module.

Nothing here is implemented yet. Today the workspace doesn't even compile on
darwin.

## what the code depends on

Everything Linux-specific, by module, and what replaces it. "Portable" means it
works as is.

| Where | Linux mechanism | macOS replacement |
| --- | --- | --- |
| `skagent-secret/src/mapping.rs` | `mmap`, `mprotect`, `mlock` | portable |
| | `MADV_DONTDUMP` | none; `RLIMIT_CORE=0` and `PT_DENY_ATTACH` cover dumps |
| | `MADV_WIPEONFORK` | `minherit(VM_INHERIT_NONE)`: the child gets no mapping at all |
| | `memfd_secret(2)` | none; `--secret-memory memfd-secret` is Linux-only |
| `skagent-fds/src/children.rs` | `close_range(CLOSE_RANGE_CLOEXEC)` before exec | `fcntl(F_SETFD, FD_CLOEXEC)` on every descriptor above stderr up to `RLIMIT_NOFILE`, in the same pre-exec hook (async-signal-safe) |
| `skagent-fds/src/activation.rs` | systemd `LISTEN_PID`/`LISTEN_FDS`, checked with `SO_DOMAIN` and `SO_ACCEPTCONN` | `launch_activate_socket(name)` (libSystem). rustix has neither socket option on Apple; check the family with `getsockname` instead |
| `skagent/src/hardening.rs` | `PR_SET_DUMPABLE=0` | `ptrace(PT_DENY_ATTACH)`; `RLIMIT_CORE=0` is portable |
| `skagent/src/logind.rs` | logind lock, `LockedHint`, `PrepareForSleep` and sleep delay inhibitor over D-Bus | a native watcher, see below |
| `skagent/src/notify.rs` | `org.freedesktop.Notifications` | none for now: without a session bus it's a no-op already |
| `skagent/src/device.rs` | `/dev/hidrawN`: device number, inode and change time | libfido2's `ioreg://<registry entry ID>` path |
| `skagent-fido/src/lib.rs` | only `/dev/hidraw*` devices | only `ioreg://` devices |
| `skagent-fido/src/raw.rs` | concurrent `fido_dev_cancel`, argued for `hid_linux.c` | the same call, with a new argument for `hid_osx.c` |
| `skagent/src/socket.rs` | default `$XDG_RUNTIME_DIR/skagent.sock` | a per-user directory, see decisions |
| | `renameat2(RENAME_NOREPLACE)` | portable: rustix maps it to `renameatx_np(RENAME_EXCL)` |
| | peer uid check | portable: tokio uses `getpeereid` |
| `skagent/src/cancel.rs` | hangup is `EPOLLHUP` (write-closed) | kqueue's `EV_EOF` on the write filter, same tokio API; needs the existing tests to pass on macOS |
| `nix/home-manager.nix` | systemd user socket and services | `launchd.agents` with `Sockets` (home-manager's `yubikey-agent` module does this already) |
| `flake.nix` | `x86_64-linux`, `aarch64-linux` | add `aarch64-darwin`; VM tests and the test key stay Linux-only |

Portable without changes: the protocol handling, destination constraints, PIN
cache, routing logic, pinentry and askpass clients, message size limit,
display sanitizing, CLI and logging.

## findings

From the libfido2 1.17 sources (`src/hid_osx.c`) and Apple's IOKit sources:

- **Device paths are `ioreg://<id>`**, the IORegistry entry ID of the HID
  service. A replugged key gets a new entry and so a new ID. That makes the
  path itself an identity for one plug-in, which is what `DeviceIdentity`
  models on Linux. "Still the same device" becomes "this path is still
  listed".
- **libfido2 seizes the device** (`kIOHIDOptionsTypeSeizeDevice`). Only one
  handle can exist. So a cancel can't use a second handle and has to go through
  the owner's.
- **Cancelling from another thread looks safe.** `fido_dev_cancel` writes one
  report through `fido_hid_write`, which only reads fields that are fixed
  after open (`ref`, `report_out_len`) and calls `IOHIDDeviceSetReport`. Its
  synchronous path in IOHIDLib (`IOHIDDeviceClass.m`) takes the device's own
  lock to check that it's open, then makes one `IOConnectCallMethod` into the
  kernel. The owner meanwhile reads through a run loop and a pipe. Needs a
  spike on real hardware, since Apple's published sources can lag the shipped
  ones.
- **libfido2 creates its report pipe without `O_CLOEXEC`.** So on macOS, too,
  spawned prompts must not inherit descriptors; the reason is just different
  from Linux, where it's the hidraw device itself.

## lock and sleep watcher

The part that decides whether macOS is worth it: without it, the fail-closed
rule disables caching. It replaces `logind.rs` and feeds the same agent calls
(`caching_pending`, `set_caching_available`, `forget_pins`). The logind loop's
lessons carry over: revoke only on real transitions, bound every call, fail
closed.

- **Screen lock.** The distributed notification `com.apple.screenIsLocked`
  (CoreFoundation's distributed notification center) is the signal most tools
  use. It's undocumented. Back it up by polling `CGSessionCopyCurrentDictionary()`
  every second or so: `CGSSessionScreenIsLocked` set, or `kCGSSessionOnConsoleKey`
  false (fast user switching), counts as locked. Any process of the user can
  post the notification, but faking it only drops PINs.
- **Sleep.** `IORegisterForSystemPower`. On `kIOMessageSystemWillSleep`, drop
  the PINs and revoke requests, then call `IOAllowPowerChange`. That's the
  sleep delay inhibitor of logind: the system waits for the answer (up to
  30 s). `kIOMessageCanSystemSleep` is answered right away.
  `kIOMessageSystemHasPoweredOn` makes caching available again. Laptops write
  a sleep image by default (`hibernatemode 3`), so the PIN must be gone before
  that, like on Linux.
- **Threading.** Both need a CFRunLoop. The watcher runs one on its own thread
  and talks to the async side through channels. The sleep callback waits
  (bounded) until the PINs are dropped before it allows the sleep.
- **Fail closed.** If registering either one fails, caching stays disabled and
  the watcher retries, exactly like a logind outage.

The FFI goes into a new crate, `skagent-darwin`, with `unsafe` confined to its
modules like the other crates. Bindings from the `objc2-core-foundation`,
`objc2-io-kit` and `objc2-core-graphics` crates (MIT/Apache-2.0/Zlib), or
plain `extern "C"` declarations for the few functions needed. `PT_DENY_ATTACH`
and `launch_activate_socket` fit there too.

## open questions

To answer on the Mac before writing code, each with a quick experiment:

1. **Cancel.** Does `fido_dev_cancel` from a second thread stop a YubiKey that
   waits for a touch, reliably and without crashes? A small Rust or C program
   against libfido2 is enough.
2. **Lock signal.** Is `com.apple.screenIsLocked` posted on your macOS version
   for Ctrl-Cmd-Q, the lock screen after the screensaver or display sleep,
   lid close, and fast user switching? And does polling `CGSSessionScreenIsLocked`
   agree?
3. **Sleep.** Does the `kIOMessageSystemWillSleep` callback arrive for lid
   close, the Apple menu and `pmset sleepnow`, early enough to drop the PIN?
   What happens on Power Nap / dark wakes?
4. **OpenSSH.** Does Apple's `/usr/bin/ssh` use sk keys from an agent at all
   (`ssh -Q key`, then a login), and does it send `session-bind`? Apple builds
   without the built-in FIDO middleware. nixpkgs' OpenSSH works either way.
   Also: what does Apple's `ssh-add -K` do (it once meant "keychain")?
5. **pinentry-mac.** Does it work with our Assuan client, and does it stay
   without the "save in keychain" option, since we never send `SETKEYINFO`?
6. **Permissions.** Does listing or opening the key trigger a TCC prompt (Input
   Monitoring)? FIDO's HID usage page should be exempt.
7. **launchd.** Socket activation with `launch_activate_socket`, the agent
   starting on the first connection, stopping at logout. How `SSH_AUTH_SOCK`
   can replace Apple's own agent for GUI apps (`launchctl setenv` at login),
   or whether `IdentityAgent` is the cleaner default.
8. **Hardening.** Does `PT_DENY_ATTACH` keep lldb (as the same user) out? What
   else can read the agent's memory: `task_for_pid` needs entitlements under SIP,
   but check it.

## steps

Each step ends with `nix flake check` green on Linux and the Rust tests green
on the Mac.

1. **It builds.** Add `aarch64-darwin` to the flake. Keep the VM tests and the
   test key Linux-only. Gate the Linux mechanisms above with `cfg`, so the agent
   compiles and runs without caching (no watcher means caching unavailable).
   Gate Linux-only tests (`secretmem`, `/proc` checks, systemd activation).
2. **Platform pieces.** `ioreg://` device listing and identity, the cancel
   argument for `hid_osx.c`, `minherit`, the `fcntl` descriptor loop,
   `PT_DENY_ATTACH` and the default socket path. Signing then works, with a
   PIN prompt every time.
3. **The watcher.** `skagent-darwin` with lock and sleep, wired up like
   `logind::watch_with`. Its decision logic (which transition revokes, when
   caching is available) is a pure state machine with Rust tests, like the
   logind tests with paused time.
4. **launchd and home-manager.** `launch_activate_socket` in `skagent-fds`.
   A darwin branch in `nix/home-manager.nix`: a socket-activated
   `launchd.agents.skagent`, an agent for `loadAtLogin` (`skagent load
   --if-connected`, `RunAtLoad`), and `SSH_AUTH_SOCK` through `sshAuthSock`.
   On macOS the pinentry default is `pinentry_mac`.
5. **Tests and docs.** A macOS part in the hardware checklist, README
   installation notes for macOS, and `AGENTS.md` rules for the darwin crate.

## testing

- The Rust tests run on the Mac, apart from the Linux-only ones.
- There's no VM test on macOS: a virtual FIDO device needs `IOHIDUserDevice`,
  which needs an entitlement Apple only grants on request. So everything that
  needs a security key is tested by hand, with a checklist: signing, caching,
  lock, sleep, unplug, two keys, cancelling, launchd activation, both OpenSSH
  builds.
- CI: a macOS job that builds and runs the Rust tests is possible, but macOS
  minutes cost about ten times the Linux rate on a private repository. I'd add
  it only once the port has settled.

## decisions

Agreed before the port started.

- **Socket path.** launchd needs an absolute path in the plist, without
  variables, and the CLI needs a default. `/tmp` (like `yubikey-agent`) is
  shared by all users, so someone else can create the path first. So it's
  `~/.ssh/skagent.sock`: per user, `0700` by convention, short (sockets are
  limited to 104 bytes on macOS) and known when home-manager builds the plist.
- **Notifications.** None in the first version. Native notifications need an
  app bundle, and `osascript` would be a hack.
- **Apple's OpenSSH.** Supported if question 4 says it works. Otherwise
  nixpkgs' OpenSSH is a requirement.
- **x86_64-darwin.** Probably works, but goes untested, so it stays out of the
  flake's systems.
