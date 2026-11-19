[📦 Installation](#-installation) | [🧭 Usage](#-usage) | [🔐 Security](#-security) | [📐 Design](docs/design.md)

## 🔑 skagent

skagent is an ssh-agent for FIDO2 security keys like the YubiKey. It works with
`ed25519-sk` keys created with `verify-required`, where every signature
needs your PIN and a touch. skagent caches the PIN securely and can handle multiple keys.

- 🛡️ **Hardened** with PINs in locked, guarded and zeroized memory, no core dumps and no ptrace
- ⏱️ **Bounded PIN cache** with a hard lifetime, an optional idle timeout and per-key policies
- 🔒 **Forgets your PIN** when the screen locks, the machine sleeps or the key is unplugged
- 🗝️ **Multiple security keys** with separate PIN caches, recognized by their serial number
- 🤝 **Pairs with your security keys**, so a fake key that pretends to be yours never gets your PIN
- 📥 **Loads resident keys** straight from the security key, no stub files needed
- 🌍 **Agent forwarding and `ssh-add -h`** destination constraints, checked like OpenSSH does
- 🗄️ **Decrypts age files** with a post-quantum key derived from your security key, one touch per file or one for a whole command
- 💬 **Prompts that tell you what you sign**, plus a notification while the key waits for a touch

<p align="center">
  <img alt="skagent's popup, eight times. In its light and dark presets: asking for the PIN of Desk 5C NFC to load its keys, waiting for a touch for github-work, asking to plug in Desk 5C NFC because the plugged-in key doesn't hold github-work, and listing 3 loaded keys. In four styles: Catppuccin Mocha waiting for the touch that starts a batch of decryptions, Solarized Light asking for a PIN with requests waiting, Gruvbox Dark in IBM Plex Sans after signing, and green on black in a monospaced font after a wrong PIN" width="880" src="https://github.com/user-attachments/assets/REPLACE-skagent-popup">
</p>

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
       age.batchLifetime = "5m"; # default: 10m, see age below
     };
   }
   ```

This runs skagent as a socket-activated user service. The socket at
`$XDG_RUNTIME_DIR/skagent.sock` exists from login on, and the agent starts with
its first client. A second socket next to it, `skagent-age.sock`, is for
[age](#age) (`services.skagent.age.enable`, on by default). It stops together with your graphical session, so logging out
drops all PINs. Your keys stay, see below. Your compositor or desktop has to import the
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

Under systemd, `skagent serve` also accepts its sockets through socket
activation: its ssh-agent socket, and for [age](#age) a second socket unit with
`FileDescriptorName=age`. That's what the home-manager module does.

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

skagent remembers the keys you load or add, so they're still there after you log
out or restart it. Nothing secret is stored: it's the public keys and what a
stub file holds, in `~/.local/state/skagent/keys.toml`. Signing still needs the
security key and its PIN. `ssh-add -d` and `ssh-add -D` remove keys for good.
Keys added with a lifetime (`ssh-add -t`) or destinations (`ssh-add -h`), and
keys added through a forwarded agent, aren't remembered.

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
| `--plug-in-timeout 1m` | `plugInTimeout` | `15s` | How long a request waits for its security key to be plugged in. `0` fails right away. |
| `--no-pairing` | `pairing` | on | Don't pair with security keys on first use, see below. |
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

Instead of pinentry, skagent can use its own popup, the one in the picture at
the top: one window that takes you from the PIN to the touch to the result,
and tells you what went wrong if something does. It replaces the touch
notification.

```nix
services.skagent.popup.enable = true;
```

Without home-manager, build it with `nix build .#pinentry` and pass it with
`skagent serve --popup result/bin/skagent-pinentry`. On Wayland compositors
with layer shell (sway, Hyprland, niri, KDE) it appears on top of everything
and takes the keyboard. Elsewhere it's an ordinary window.

### Styling the popup

The popup comes in light and dark, following your desktop (it asks the
desktop portal; without one, set `appearance`). Both are presets you can
adjust: colours, fonts and size.

The second row of the picture at the top shows four styles. Catppuccin Mocha
and Solarized Light are six colours each, Gruvbox Dark adds a font, and the
last one is nobody's palette. Their settings are in
[`nix/screenshots/themes`](nix/screenshots/themes).

```nix
services.skagent.popup = {
  appearance = "dark"; # or "light"; default: the desktop's
  font = "IBM Plex Sans";
  monospaceFont = "Iosevka";
  fontFeatures.ss01 = true;
  scale = 1.25; # the whole popup, text included
  dark = {
    surface = "#2e3440";
    text = "#eceff4";
    accent = "#88c0d0";
  };
};
```

The six base colours are `surface`, `text`, `accent`, `success`, `warning`
and `error`. Borders, fields, tints and icon colours are mixed from them, so
changing `surface` alone still looks right. Each of those can be set too:
`muted-text`, `placeholder`, `border`, `field`, `field-error`, `on-accent`,
`on-success`, `on-warning`, `avatar`, `avatar-warning`, `avatar-error`,
`avatar-missing`, `device`, `ring-track`, `dot` and `dot-hollow`. A font
that isn't installed falls back to the bundled Inter or JetBrains Mono.

Without home-manager, the same goes in `~/.config/skagent/config.toml`:

```toml
[popup]
appearance = "dark"
font = "IBM Plex Sans"
font-features = { ss01 = true }
scale = 1.25

[popup.dark]
surface = "#2e3440"
accent = "#88c0d0"
```

`skagent-pinentry --preview touch` shows a screen with your style, and
`skagent check-config` lists settings skagent would skip. A typo in the
style doesn't stop the agent: it logs a warning and keeps the preset's
value.

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

skagent recognizes a YubiKey by its serial number and any paired security key
by its pairing (see below), so it still knows the key after you replug it or
restart the agent. It writes this down in `~/.local/state/skagent/bindings.toml`.
An unpaired key without a serial you pick by touch again after a replug, even if
only one is plugged in. skagent never silently switches to another security key.

skagent lists keys on a plugged-in security key first. Of two keys a server
accepts, ssh then uses the one you have at hand. If the security key isn't
plugged in, skagent waits for it for 15 seconds and tells you which YubiKey to
plug in, in the popup or in a notification. Pressing Ctrl-C on `ssh` stops the
wait.

### Several accounts on one host

GitHub tells your accounts apart by the key you log in with, and takes the
first one it knows. To use your work account for work repositories, tell git
which key to use there, without host aliases. With home-manager:

```nix
programs.git.includes = [
  {
    # Repositories whose remote is in the work organization
    condition = "hasconfig:remote.*.url:git@github.com:work-org/**";
    contents.core.sshCommand = "ssh -o IdentitiesOnly=yes -i ~/.ssh/work.pub";
  }
];
```

Or in `~/.gitconfig`, for everything under `~/work`, clones included:

```ini
[includeIf "gitdir:~/work/"]
    path = ~/.config/git/work.gitconfig
```

with `~/.config/git/work.gitconfig` holding:

```ini
[core]
    sshCommand = ssh -o IdentitiesOnly=yes -i ~/.ssh/work.pub
```

`-i` only needs the public key; ssh then picks that key from skagent. For a
resident key without a file, write it once with
`ssh-add -L | grep work > ~/.ssh/work.pub`.

### Pairing

The first time you sign with a security key, skagent asks you to touch it once
more. That pairs skagent with the key: it puts a small credential of its own on
the key and remembers it. From then on, before your PIN goes to a key, the key
has to sign a random challenge with that credential, without a touch. A fake key
that pretends to be yours, down to your YubiKey's serial number, can't do that,
so it never gets your PIN.

You pair each key once. On your other machines, skagent finds the credential
with your PIN, no extra touch needed. Press Esc in the popup to skip pairing, or
turn it off with `--no-pairing`.

### Agent forwarding

Agent forwarding works just like with ssh-agent, and every signature still
needs a touch on your machine. Destination constraints work too. A key added
with `ssh-add -h jump -h 'jump>target'` can log in to `jump` and from there to
`target`, but nowhere else. skagent checks every hop against the host key
signatures ssh sends (`session-bind@openssh.com`).

Through a forwarded agent, remote hosts can't load keys or make skagent forget
PINs. Keys of a web origin (any application other than `ssh:...`) only sign SSH
logins and `ssh-keygen -Y sign` data, nothing a website would accept.

### age

skagent can also decrypt [age](https://age-encryption.org) files with a key
that comes from your security key. Create an identity once:

```console
$ skagent age new
age1pq1…
```

skagent asks for the PIN, and the key blinks twice: once to create the
credential, once to read the recipient. That recipient is an ordinary
post-quantum age recipient. Anyone can encrypt to it with age 1.3 or newer, or
with rage and age's `age-plugin-pq`, without skagent and without your key:

```console
$ age -r age1pq1… -o secret.age secret.txt
```

To decrypt, age needs an identity file. It holds no secret, only which key to
ask skagent for, so you can keep it anywhere:

```console
$ skagent age identity > skagent-identity.txt
$ age -d -i skagent-identity.txt secret.age
```

Every file takes one touch, and the PIN if skagent doesn't have it cached.
`age -d -j skagent` works without the file, with the identity on the security
key that's plugged in. The identity file also works for encrypting
(`age -e -i`), and `skagent age list` prints the recipients skagent knows.
On another machine, `skagent load` finds the identity on the key.

- **One recipient type per file:** age refuses to mix post-quantum recipients
  with classic ones, such as SSH host keys or `age1…` keys from
  `age-keygen` without `-pq`. Every other recipient of the file has to be an
  `age1pq1…` key too.
- **Keep a second recipient:** the key exists on that one security key only
  and can't be copied. If you reset the key, block its PIN or lose it, files
  without another recipient are gone. A second security key or an offline
  `age-keygen -pq` key works.
- **How it works:** the security key keeps a secret that never leaves it, and
  skagent derives the age key from the key's answer each time, uses it for
  that one file and wipes it. [`docs/age.md`](docs/age.md) has the details and
  what this can't protect.

#### Many files with one touch

A touch per file gets old when a tool decrypts hundreds of them. Run it in a
batch:

```console
$ skagent batch -- agenix rekey
```

The first file takes your PIN and a touch, and the prompt tells you that it
starts a batch and for which command. After that, the files this command
decrypts need neither. A notification counts them and has a Stop button.

For this, skagent keeps the age key in its memory while the batch runs. That's
more than it does anywhere else, so a batch is bounded:

- **Only the command you ran** uses it: its processes and what they start.
  Other programs still get a touch prompt for every file.
- **It ends with the command,** or after 10 minutes if that comes first.
  `skagent batch --for 2m` asks for less, `skagent serve --batch-lifetime`
  changes the limit, and `--batch-lifetime 0` turns batches off.
- **It ends early** when you lock the screen, the machine goes to sleep, you
  unplug the security key, press Stop or run `skagent forget`. Whatever the
  command decrypts after that takes a touch per file again.

Batches need Linux 6.5 or newer. [`docs/age.md`](docs/age.md) shows the
settings for agenix-rekey.

#### On other machines

With `ssh -A`, age on the remote host can decrypt with the security key in
your machine: the plugin there asks the forwarded agent. skagent only answers
that if you start it with `--age-forwarding`
(`services.skagent.age.forwarding`), because of what it means:

- **Every file takes a touch** on your machine. A batch never covers a remote
  host.
- **The prompt names the host** by its host key, like for a forwarded login.
- **It can't tell you which file** the host wants opened. A hostile host that
  has your forwarded agent can ask for any file it holds a copy of and hope
  that you touch.

The remote host needs age and `age-plugin-skagent`, and the identity file.

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
- **A fake security key** swapped in for yours, or plugged in next to it, gets no PIN once skagent paired with your key
- **age files** need the security key, its PIN and a touch per file, and stay safe against a future quantum computer if all their recipients are post-quantum

Not protected:

- **Malware running as you** in an unlocked session can get signatures whenever you touch the key, like with any agent. It could also log your PIN while you type it.
- **root** can do anything anyway. That includes reading an age key from skagent's memory during the moment it decrypts a file, or while a batch runs, which opens every file for that key, old and new.
- **A program you run in a batch** decrypts what it likes while the batch lasts, and so does anything that can change what the batch runs.
- **A malicious USB device** you use before skagent paired with your real key, or one that sits between your key and the computer and passes its messages on, receives the PIN, same as with OpenSSH.

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
