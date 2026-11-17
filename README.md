[📦 Installation](#-installation) | [🧭 Usage](#-usage) | [🔐 Security](#-security) | [📐 Design](docs/design.md)

## 🔑 skagent

skagent is an ssh-agent for FIDO2 security keys like the YubiKey. It works with
`ed25519-sk` keys created with `verify-required`, where every signature
needs your PIN and a touch. skagent caches the PIN securely and can handle multiple keys.

- 🛡️ **Hardened** with PINs in locked, guarded and zeroized memory, no core dumps and no ptrace
- ⏱️ **Bounded PIN cache** with a hard lifetime, an optional idle timeout and per-key policies
- 🔒 **Forgets your PIN** when the screen locks, the machine sleeps or the key is unplugged
- 🗝️ **Multiple security keys** with separate PIN caches, pick the right one by touch
- 📥 **Loads resident keys** straight from the security key, no stub files needed
- 🌍 **Agent forwarding and `ssh-add -h`** destination constraints, checked like OpenSSH does
- 💬 **Prompts that tell you what you sign**, plus a notification while the key waits for a touch

## 📦 Installation

skagent runs on Linux 5.11 or newer and asks for PINs with a graphical pinentry.

### home-manager

1. Add skagent as an input to your flake
   ```nix
   inputs.skagent.url = "github:oddlama/skagent";
   ```
2. Import the home-manager module and enable it
   ```nix
   { inputs, pkgs, ... }:
   {
     imports = [ inputs.skagent.homeModules.default ];
     services.skagent = {
       enable = true;
       pinentry.package = pkgs.pinentry-gnome3; # default: pinentry-qt
       loadAtLogin = true; # runs `skagent load` when your graphical session starts
       pinPolicies = [ { application = "ssh:personal"; lifetime = "1h"; } ];
     };
   }
   ```

This runs skagent as a socket-activated user service. The socket at
`$XDG_RUNTIME_DIR/skagent.sock` exists from login on, and the agent starts with
its first client. It stops together with your graphical session, so logging out
drops all PINs and loaded keys. Your compositor or desktop has to import the
display variables into the systemd user manager so pinentry and notifications
can show up. Most do that already.

The module also points `SSH_AUTH_SOCK` at skagent, except in sessions that use
a forwarded agent. This needs a home-manager version with `sshAuthSock` (26.11
or unstable) and conflicts with other modules that set it, like
`services.ssh-agent` or gpg-agent's SSH support.

<details>
<summary>Using skagent only for some hosts</summary>

Set `services.skagent.setSshAuthSock = false` and tell ssh which hosts should
use skagent:

```ssh-config
# ~/.ssh/config
Host github.com
  IdentityAgent ${XDG_RUNTIME_DIR}/skagent.sock
```

</details>

### Without home-manager

With nix, `nix shell github:oddlama/skagent` puts you in a shell with skagent.
Otherwise you can build it with `nix build github:oddlama/skagent` or directly with cargo, which needs the libfido2 and OpenSSL
headers, pkg-config and libclang:

```sh
cargo install --locked --git https://github.com/oddlama/skagent skagent
```

Then start the agent and point ssh at it:

```sh
skagent serve # needs a graphical pinentry on your PATH
# In another terminal:
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/skagent.sock
skagent load # loads the resident keys of your security key, asks for the PIN once
ssh -T git@github.com # just touch the key, no PIN prompt
skagent forget # drops all cached PINs and keeps the keys
```

Under systemd, `skagent serve` also accepts its socket through socket
activation (one `ListenStream=`). That's what the home-manager module does.

## 🧭 Usage

### Loading keys

`skagent load` loads the resident `ed25519-sk` keys (those with an `ssh:`
application) from a connected security key. It asks for the PIN once and
caches it for these keys. If several security keys are connected, touch the one
you want to load. No stub files are written, and the PIN never crosses the agent
socket.

The original SSH comment isn't stored on the security key, so loaded keys are
named after their application and user name. Loading again keeps the lifetime
and comment of keys that are already in the agent.

With `--if-connected`, `skagent load` does nothing if no security key is
plugged in. That's what `loadAtLogin` uses, so logging in without your key is
fine.

`ssh-add -K` and `ssh-add <stub>` work too. skagent only accepts `ed25519-sk`
keys and refuses everything else. That includes `ssh-add -c`, since the touch
already confirms every signature.

### PIN caching

skagent caches each PIN for 8 hours by default. Using the PIN doesn't extend
that. You can change this with these options of `skagent serve` or their
home-manager counterparts:

| Option | home-manager | Default | Description |
| --- | --- | --- | --- |
| `--pin-lifetime 2h` | `pinLifetime` | `8h` | How long a PIN stays cached. `0` disables caching. |
| `--pin-idle 30m` | `pinIdle` | off | Also drop a PIN that wasn't used for this long. |
| `--pin-policy RULE` | `pinPolicies` | | Lifetime and idle timeout for some keys, see below. |
| `--pinentry PATH` | `pinentry.package` | `pinentry`, home-manager: `pinentry-qt` | The pinentry program that asks for PINs. |
| `--askpass PATH` | `askpass` | | Ask with an askpass program instead of pinentry. |
| `--popup PATH` | `popup.enable` | | Use skagent's own popup instead of pinentry, see below. |
| `--no-touch-notification` | `touchNotification` | | Don't show a notification while a key waits for a touch. |
| `--secret-memory memfd-secret` | `secretMemory` | `locked` | Keep PINs in `memfd_secret(2)` memory, which is also removed from the kernel's direct map. The system can't hibernate while skagent holds any. |

A policy rule selects keys by `application` or by `fingerprint` (as
`ssh-add -l` shows it) and sets `lifetime` and/or `idle`. The first matching
rule wins:

```sh
skagent serve \
  --pin-policy application=ssh:personal,lifetime=1h,idle=15m \
  --pin-policy fingerprint=SHA256:...,lifetime=0 # never cache the PIN of this key
```

A cached PIN is only ever sent to the security key it was entered for. If you
replug the key, or someone entered a wrong PIN on it in the meantime, skagent
asks you again.

### Naming keys

You can give your SSH keys a label and an emoji, and your YubiKeys a name.
Labels replace the key's comment in prompts and logs, which helps with loaded
keys called `ssh:work openssh`. Emoji and YubiKey names show up in skagent's
popup. With home-manager:

```nix
services.skagent = {
  keys."SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ" = { # as `ssh-add -l` shows it
    emoji = "🦊";
    label = "github-work";
  };
  securityKeys."12345678".name = "Desk 5C NFC"; # serial, as `ykman list --serials` shows it
};
```

Without home-manager, write the same into `~/.config/skagent/config.toml`, or
pass another file with `--config`:

```toml
[keys."SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ"]
emoji = "🦊"
label = "github-work"

[security-keys.12345678]
name = "Desk 5C NFC"
```

skagent refuses to start if the file contains anything it doesn't know, so a
typo can't go unnoticed.

### The popup

Instead of pinentry, skagent can use its own popup: one window that takes you
from the PIN to the touch to the result, and tells you what went wrong if
something does. It replaces the touch notification.

```nix
services.skagent.popup.enable = true;
```

Without home-manager, build it with `nix build .#pinentry` and pass it with
`skagent serve --popup result/bin/skagent-pinentry`. On Wayland compositors
with layer shell (sway, Hyprland, niri, KDE) it appears on top of everything
and takes the keyboard. Elsewhere it's an ordinary window.

### When skagent forgets your PIN

skagent drops cached PINs when:

- your session locks through logind (`loginctl lock-session`, or a locker that sets `LockedHint` like GNOME's)
- the machine is about to suspend or hibernate
- you run `skagent forget`, `ssh-add -D` or `ssh-add -d`, or lock the agent with `ssh-add -x`
- the lifetime of a key added with `ssh-add -t` ends
- a security key is unplugged (within 15 seconds)
- the agent stops

If your screen locker doesn't go through logind, let it run `skagent forget`,
for example `swayidle lock 'skagent forget; swaylock'`. Without logind, skagent
still signs but doesn't cache PINs at all.

Forgetting also cancels whatever is still running. An open PIN prompt closes,
and a key that waits for a touch stops blinking. Pressing Ctrl-C on `ssh`
cancels just that one request and keeps the PIN.

### Multiple keys

You can use work and personal keys at the same time, and their PIN caches stay
separate. The first time a key is used, skagent asks you to touch the security
key that holds it. Then it asks for the PIN, and you touch the key again to
sign. From then on skagent remembers which security key holds which key, so
signatures need just one touch. Keys on different security keys can even sign
at the same time.

If a security key is replugged, you'll pick it by touch again, even if it's the
only one connected. skagent never silently switches to another security key.

### Agent forwarding

Agent forwarding works just like with ssh-agent, and every signature still
needs a touch on your machine. Destination constraints work too. A key added
with `ssh-add -h jump -h 'jump>target'` can log in to `jump` and from there to
`target`, but nowhere else. skagent checks every hop against the host key
signatures ssh sends (`session-bind@openssh.com`).

Through a forwarded agent, remote hosts can't load keys or make skagent forget
PINs. Keys of a web origin (any application other than `ssh:...`) only sign SSH
logins and `ssh-keygen -Y sign` data, nothing a website would accept.

### Prompts and notifications

PIN prompts tell you which key is used and what for, for example
`log in as "git" to the host with key SHA256:...` or `sign "git" data`. The
same text is logged with every signature. Text that comes from another machine
is sanitized before it's shown.

While a key waits for a touch, a desktop notification tells you so. A PIN prompt
nobody answers closes after 60 seconds, and a request that waits for a busy key
gives up after 2 minutes.

## 🔐 Security

skagent keeps your PIN in memory, so here's what that does and doesn't protect
against.

Protected:

- **A lost or stolen security key** is useless without the PIN
- **A leaked key handle** (a stub file or agent memory) is useless without the PIN, too
- **A stolen laptop with the key** still needs the PIN once skagent forgot it (lock, suspend, reboot)
- **Other users** can't use the agent: its socket is private, and skagent checks every client's user id
- **A hostile host with your forwarded agent** still needs a touch for every signature, and `ssh-add -h` limits where keys work
- **Other processes of yours** can't read the agent's memory, since core dumps and ptrace are disabled

Not protected:

- **Malware running as you** in an unlocked session can get signatures whenever you touch the key, like with any agent. It could also log your PIN while you type it.
- **root** can do anything anyway.
- **A malicious USB device** that pretends to hold your key receives the PIN, same as with OpenSSH.

Have a look at [`docs/design.md`](docs/design.md) for the details, and at
[`docs/research`](docs/research) for how OpenSSH and GnuPG handle PINs.

## ❤️ Contributing

Contributions are welcome! Please read [`AGENTS.md`](AGENTS.md)
before changing behavior. It has the rules this code base follows, and
[`docs/design.md`](docs/design.md) explains the reasoning behind them.

```sh
# Enter the devshell with all dependencies (or use direnv)
nix develop
# Format all files
nix fmt
# Run the tests and clippy
cargo test
cargo clippy --all-targets
# Run everything, including the NixOS VM tests against stock OpenSSH
nix flake check -L
```

## 🤖 LLM-ware

As you may have noticed, skagent is LLM-ware. I designed it, but the
implementation was largely written by an LLM. I have manually reviewed the code
and testet it, but at the end of the day most of it is not written by a human.

## 📜 License

Licensed under the MIT license ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>).
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, shall be licensed as above, without any additional terms or conditions.

The virtual security key used by the tests (`crates/skagent-testkey`) links
[soft-fido2](https://crates.io/crates/soft-fido2), which is AGPL-3.0. Builds of
that test-only crate therefore fall under the AGPL. skagent itself never depends
on it.
