# skagent

ssh-agent for FIDO2 `ed25519-sk` keys. Keeps `verify-required` on the key (PIN + touch per signature), but caches the PIN in the agent for a bounded time. So you touch the key for every signature and type the PIN once per session instead of every time.

Why not just ssh-agent: OpenSSH has no PIN cache for sk keys. With `verify-required`, every signature asks for the PIN via askpass. Dropping `verify-required` gets rid of that, but then the key handle (stub file / agent memory) plus the key is enough to sign. Details in `docs/research/` and `docs/design.md`.

Status: PIN caching, pinentry and multiple connected security keys work. `skagent load` is still pending. Tested with a virtual authenticator in NixOS VMs, not yet on real hardware.

```sh
skagent serve                                       # pinentry must be on PATH
# In another terminal:
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/skagent.sock
ssh-add ~/.ssh/id_ed25519_sk_rk_example                    # or ssh-add -K with a real key
ssh -T git@github.com                                # PIN once, touch every time
skagent forget                                      # drop PINs, keep loaded keys
```

PINs expire after 8h by default. Use `--pin-lifetime 2h`, optionally `--pin-idle 30m`; `--pin-lifetime 0` disables caching. `--pinentry /path/to/pinentry` selects the dialog, or `--askpass /path/to/ssh-askpass` uses askpass instead (no implicit `$SSH_ASKPASS` fallback).

`ssh-add -d/-D/-x`, logind session locks (`Lock` or `LockedHint`), suspend preparation, and shutdown evict PINs. Lockers that don't notify logind must run `skagent forget` themselves. If logind or its sleep delay inhibitor is unavailable, signing still works but caching stays disabled. Replugging a key or changing its PIN retry counter forces a new prompt.

With several keys connected, the first signature asks you to touch the key holding that credential, then enter its PIN and touch again to sign. Successful signatures establish a device binding: later signatures use that device with one touch, and work/personal PIN caches stay separate. Bound devices can sign concurrently. A lost binding requires selection again—even if only one device remains. `skagent forget` keeps bindings; removing identities clears them.

Eviction cancels pending prompts and discards late signatures. A libfido2 call already in progress cannot yet be interrupted; its temporary PIN copy survives until the call returns or times out (up to about 35s), even after cache eviction.

## dev

```sh
nix develop            # or direnv
cargo test
nix flake check -L     # format, tests, clippy, VM tests
```

Rules for changes are in `AGENTS.md`.
