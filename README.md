# skagent

ssh-agent for FIDO2 `ed25519-sk` keys. Keeps `verify-required` on the key (PIN + touch per signature), but caches the PIN in the agent for a bounded time. So you touch the key for every signature and type the PIN once per session instead of every time.

Why not just ssh-agent: OpenSSH has no PIN cache for sk keys. With `verify-required`, every signature asks for the PIN via askpass. Dropping `verify-required` gets rid of that, but then the key handle (stub file / agent memory) plus the key is enough to sign. Details in `docs/research/` and `docs/design.md`.

Status: PIN caching, pinentry, multiple connected keys and resident loading work. Tested with a virtual authenticator in NixOS VMs, not yet on real hardware.

```sh
skagent serve                                       # pinentry must be on PATH
# In another terminal:
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/skagent.sock
skagent load                                        # select one device, enter its PIN once
ssh -T git@github.com                                # touch to sign; PIN already cached
skagent forget                                      # drop PINs, keep loaded keys
```

`skagent load` imports Ed25519 resident credentials with an `ssh:` application, establishes device bindings and caches the authenticated PIN for keys that require it. With multiple devices, touch the one to load; repeat for another device. No stub files are written and no PIN crosses the agent socket. Reloading preserves existing identity lifetimes and comments. Newly loaded comments use the application and stored user name—the original SSH comment isn't stored on the device. `ssh-add <stub>` and `ssh-add -K` remain supported.

PINs expire after 8h by default. Use `--pin-lifetime 2h`, optionally `--pin-idle 30m`; `--pin-lifetime 0` disables caching. `--pinentry /path/to/pinentry` selects the dialog, or `--askpass /path/to/ssh-askpass` uses askpass instead (no implicit `$SSH_ASKPASS` fallback).

`ssh-add -d/-D/-x`, the end of an `ssh-add -t` lifetime, logind session locks (`Lock` or `LockedHint`), suspend preparation, and shutdown evict PINs. Lockers that don't notify logind must run `skagent forget` themselves. If logind or its sleep delay inhibitor is unavailable, signing still works but caching stays disabled. Replugging a key or changing its PIN retry counter forces a new prompt.

With several keys connected, the first signature asks you to touch the key holding that credential, then enter its PIN and touch again to sign. Successful signatures establish a device binding: later signatures use that device with one touch, and work/personal PIN caches stay separate. Bound devices can sign concurrently. A lost binding requires selection again—even if only one device remains. `skagent forget` keeps bindings; removing identities clears them.

A PIN prompt left open closes after 60s. Eviction cancels pending prompts, aborts an assertion that waits for a touch on the key itself (`CTAPHID_CANCEL`, the key stops blinking) and discards late signatures. A client that disconnects mid-request (Ctrl-C on `ssh`) cancels its request the same way, without dropping the PIN. An unplugged key loses its cached PIN within 15s. Cancellation is tested against the virtual key only so far.

## dev

```sh
nix develop            # or direnv
cargo test
nix flake check -L     # format, tests, clippy, VM tests
```

Rules for changes are in `AGENTS.md`.
