# skagent

ssh-agent for FIDO2 `ed25519-sk` keys. Keeps `verify-required` on the key (PIN + touch per signature), but caches the PIN in the agent for a bounded time. So you touch the key for every signature and type the PIN once per session instead of every time.

Why not just ssh-agent: OpenSSH has no PIN cache for sk keys. With `verify-required`, every signature asks for the PIN via askpass. Dropping `verify-required` gets rid of that, but then the key handle (stub file / agent memory) plus the key is enough to sign. Details in `docs/research/` and `docs/design.md`.

Status: PIN caching, pinentry, multiple connected keys and resident loading work. Tested with a virtual authenticator in NixOS VMs, not yet on real hardware.

## home-manager

```nix
# A home-manager module; `inputs.skagent` is this flake.
{ inputs, pkgs, ... }:
{
  imports = [ inputs.skagent.homeModules.default ];
  services.skagent = {
    enable = true;
    pinentry.package = pkgs.pinentry-gnome3;  # default: pinentry-qt
    loadAtLogin = true;                       # skagent load when the graphical session starts
    pinPolicies = [ { application = "ssh:personal"; lifetime = "1h"; } ];
  };
}
```

skagent then runs as a socket-activated user service: `$XDG_RUNTIME_DIR/skagent.sock` exists from login on, and the agent starts with the first client, so pinentry and notifications get the display and session bus the user manager has at that moment (your compositor or desktop has to import them, most do). It stops with `graphical-session.target`: logging out drops PINs and loaded keys. `SSH_AUTH_SOCK` is set in shells, systemd and D-Bus activation through home-manager's `sshAuthSock`, unless it comes from agent forwarding; `setSshAuthSock = false` leaves it alone, for `IdentityAgent` in `ssh_config`; setting it conflicts with other agent modules that do the same (`services.ssh-agent`, gpg-agent's SSH support). Needs a home-manager with `sshAuthSock` (26.11 / unstable).

## by hand

```sh
skagent serve                                       # pinentry must be on PATH
# In another terminal:
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/skagent.sock
skagent load                                        # select one device, enter its PIN once
ssh -T git@github.com                                # touch to sign; PIN already cached
skagent forget                                      # drop PINs, keep loaded keys
```

`skagent load` imports Ed25519 resident credentials with an `ssh:` application, establishes device bindings and caches the authenticated PIN for keys that require it. With multiple devices, touch the one to load; repeat for another device. No stub files are written and no PIN crosses the agent socket. Reloading preserves existing identity lifetimes and comments. Newly loaded comments use the application and stored user name—the original SSH comment isn't stored on the device. `ssh-add <stub>` and `ssh-add -K` remain supported.

PINs expire after 8h by default. Use `--pin-lifetime 2h`, optionally `--pin-idle 30m`; `--pin-lifetime 0` disables caching. Per key: `--pin-policy application=ssh:personal,lifetime=1h,idle=15m` (or `fingerprint=SHA256:…`; repeatable, first match wins; `lifetime=0` never caches those keys). `--pinentry /path/to/pinentry` selects the dialog, or `--askpass /path/to/ssh-askpass` uses askpass instead (no implicit `$SSH_ASKPASS` fallback).

`ssh-add -d/-D/-x`, the end of an `ssh-add -t` lifetime, logind session locks (`Lock` or `LockedHint`), suspend preparation, and shutdown evict PINs. Lockers that don't notify logind must run `skagent forget` themselves (on this machine: like `skagent load`, it's refused through a forwarded agent). If logind or its sleep delay inhibitor is unavailable, signing still works but caching stays disabled. Replugging a key or changing its PIN retry counter forces a new prompt.

With several keys connected, the first signature asks you to touch the key holding that credential, then enter its PIN and touch again to sign. Successful signatures establish a device binding: later signatures use that device with one touch, and work/personal PIN caches stay separate. Bound devices can sign concurrently. A lost binding requires selection again—even if only one device remains. `skagent forget` keeps bindings; removing identities clears them.

Agent forwarding works like with ssh-agent, and so does `ssh-add -h` (destination constraints): a key added with `ssh-add -h jump -h 'jump>target'` is usable for logging in to `jump`, and from `jump` to `target` through the forwarded agent, nowhere else; skagent checks every hop against the host key signatures ssh sends (`session-bind@openssh.com`). PIN prompts say what the signature is for, e.g. `log in as "git" to the host with key SHA256:…` or `sign "git" data`, and the agent logs it with every signature. Keys for a web origin (application not `ssh:…`) only sign SSH logins and SSHSIG data.

While a key waits for a touch, a desktop notification says so, with the key and what is signed (`--no-touch-notification` to switch off). A request waiting for a busy key gives up after 2 minutes. `--secret-memory memfd-secret` keeps cached PINs in `memfd_secret(2)` memory, which is also removed from the kernel's direct map; the system can't hibernate while such memory exists, hence opt-in.

A PIN prompt left open closes after 60s. Eviction cancels pending prompts, aborts an assertion that waits for a touch on the key itself (`CTAPHID_CANCEL`, the key stops blinking) and discards late signatures. A client that disconnects mid-request (Ctrl-C on `ssh`) cancels its request the same way, without dropping the PIN. An unplugged key loses its cached PIN within 15s. Cancellation is tested against the virtual key only so far.

Under systemd, `skagent serve` takes the socket from socket activation (`ListenStream=`, one socket) and leaves it in place on exit. PIN prompts get stdio and the agent's environment, no other descriptor of the agent's (needs Linux 5.11).

## dev

```sh
nix develop            # or direnv
cargo test
nix flake check -L     # format, tests, clippy, VM tests
```

Rules for changes are in `AGENTS.md`.
