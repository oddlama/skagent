<p align="center">
  <img alt="skagent's popup, eight times. Four light ones: in its light preset asking for the PIN of Desk 5C NFC to load its keys and waiting for a touch for github-work, in Catppuccin Latte asking for a PIN with requests waiting, and in Solarized Light after signing. Four dark ones: in its dark preset asking to plug in Desk 5C NFC because the plugged-in key doesn't hold github-work and listing 3 loaded keys, in Catppuccin Mocha waiting for the touch that starts a batch of decryptions, and green on black in a monospaced font after a wrong PIN" width="880" src="https://github.com/user-attachments/assets/3574ae98-1579-47c9-b9b2-a51e37da79e5">
</p>

[📦 Installation](#-installation) | [🧭 Usage](#-usage) | [🔐 Security](#-security)

## 🔑 skagent

skagent is a specialized (ssh-)agent for FIDO2 security keys like the YubiKey
with support for multiple hardware keys, multiple ssh keys per hardware key,
forwarding support and encryption via an [`age`](https://github.com/FiloSottile/age) plugin.

It was primarily designed for convenient and secure handling of `ed25519-sk`
keys when created with `verify-required`, where every signature would need both
the PIN and a touch. skagent can securely cache the PIN and provide proper UI
popups when your key needs your attention.

- 🛡️ **Hardened** with PINs in non-dumpable, locked, guarded and zeroized memory (no core dumps and no ptrace)
- 🤝 **Pairs with your security keys**, so a fake key that pretends to be yours can never extract your PIN accidentally
- 📥 **No stub files**, it can load the resident keys from the security key directly
- 🔒 **Forgets your PIN** after a time delay, when the screen locks, the machine sleeps or the key is unplugged (all configurable)
- 🗄️ **Age support** with a custom age plugin and post-quantum keys
- ⏩ **Agent forwarding** with support for destination constraints, including forwarding for aforementioned `age` keys
- 🗝️ **Multiple security keys** with separate PIN caches, recognized by their serial number
- 💬 **Custom pinentry** based on GPUI which is aware of the operation and state of your security key

## 📦 Installation

skagent requires kernel version 5.11 or newer. The recommended way to install is via nix and home-manager which
creates a socket activated systemd user service and does the necessary environment setup. You can also install
it manually of course.

### home-manager

1. Add skagent as an input to your flake
   ```nix
   inputs.skagent.url = "github:oddlama/skagent";
   ```
2. Import the home-manager module and enable it
   ```nix
   { inputs, ... }:
   {
     imports = [ inputs.skagent.homeModules.default ];
     services.skagent = {
       enable = true;
       loadAtLogin = true; # runs `skagent load` when your graphical session starts
       pinPolicies = [ { application = "ssh:personal"; lifetime = "1h"; } ];
       age.batchLifetime = "5m"; # default: 10m, see age below
     };
   }
   ```

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

```sh
nix shell github:oddlama/skagent # a shell with skagent
nix build github:oddlama/skagent#pinentry # the popup, in result/bin/skagent-pinentry
```

Without nix, `cargo install --locked --git https://github.com/oddlama/skagent skagent`
builds the agent. It needs the libfido2 and OpenSSL headers, pkg-config and
libclang, and asks for PINs with a graphical pinentry from your PATH instead of
the popup: leave out `--popup` below.

```sh
skagent serve --popup result/bin/skagent-pinentry
# In another terminal:
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/skagent.sock
skagent load # loads the resident keys of your security key, asks for the PIN once
ssh -T git@github.com # just touch the key, no PIN prompt
skagent forget # drops all cached PINs and keeps the keys
```

Under systemd, `skagent serve` also takes its sockets through socket
activation: the ssh-agent socket, and for [age](#age) a second socket unit with
`FileDescriptorName=age`.

## 🧭 Usage

### Loading keys

`skagent load` loads the resident `ed25519-sk` keys (those with an `ssh:`
application) from a connected security key. It asks for the PIN once and caches
it for these keys. With several security keys connected, touch the one to load.

- **No stub files** are written, and the PIN never crosses the agent socket.
- **Names:** the SSH comment isn't stored on the security key, so loaded keys
  are named after their application and user name. You can
  [give them labels](#naming-keys).
- **`--if-connected`** does nothing when no security key is plugged in.
  `loadAtLogin` uses it, so logging in without your key is fine.
- **`ssh-add -K` and `ssh-add <stub>`** work too. skagent only accepts
  `ed25519-sk` keys, and refuses `ssh-add -c`: the touch already confirms every
  signature.
- **Keys are remembered** across logouts and restarts, until `ssh-add -d` or
  `ssh-add -D`. Nothing secret is stored, only public keys and what a stub file
  holds, in `~/.local/state/skagent/keys.toml`. Keys added with a lifetime
  (`ssh-add -t`), with destinations (`ssh-add -h`) or through a forwarded agent
  aren't remembered.

### PIN caching

skagent caches each PIN for 8 hours, and using it doesn't extend that. A cached
PIN only ever goes to the security key it was entered for: after a replug, or
a wrong PIN on that key in the meantime, skagent asks again.

| `skagent serve` | home-manager | Default | Description |
| --- | --- | --- | --- |
| `--pin-lifetime 2h` | `pinLifetime` | `8h` | How long a PIN stays cached. `0` disables caching. |
| `--pin-idle 30m` | `pinIdle` | off | Also drop a PIN that wasn't used for this long. |
| `--pin-policy RULE` | `pinPolicies` | | Lifetime and idle timeout for some keys, see below. |
| `--popup PATH` | `popup.enable` | home-manager: on | Ask in skagent's own [popup](#the-popup). |
| `--pinentry PATH` | `pinentry.package` | `pinentry`, home-manager: `pinentry-qt` | Ask with this pinentry program instead. |
| `--askpass PATH` | `askpass` | | Ask with an askpass program instead. |
| `--no-touch-notification` | `touchNotification` | | No notification while a key waits for a touch. |
| `--plug-in-timeout 1m` | `plugInTimeout` | `15s` | How long a request waits for its security key to be plugged in. `0` fails right away. |
| `--no-pairing` | `pairing` | on | Don't [pair](#pairing) with security keys on first use. |
| `--secret-memory memfd-secret` | `secretMemory` | `locked` | Keep PINs in `memfd_secret(2)` memory, which is also removed from the kernel's direct map. The system can't hibernate while skagent holds any. |

A policy rule selects keys by `application` or by `fingerprint` (as
`ssh-add -l` shows it) and sets `lifetime` and/or `idle`. The first matching
rule wins:

```sh
skagent serve \
  --pin-policy application=ssh:personal,lifetime=1h,idle=15m \
  --pin-policy fingerprint=SHA256:...,lifetime=0 # never cache the PIN of this key
```

### When skagent forgets your PIN

skagent drops cached PINs when:

- your session locks through logind (`loginctl lock-session`, or a locker that sets `LockedHint` like GNOME's)
- the machine is about to suspend or hibernate
- you run `skagent forget`, `ssh-add -D` or `ssh-add -d`, or lock the agent with `ssh-add -x`
- the lifetime of a key added with `ssh-add -t` ends
- a security key is unplugged (within 15 seconds)
- the agent stops

A screen locker that doesn't go through logind should run `skagent forget`
itself, for example `swayidle lock 'skagent forget; swaylock'`. Without logind,
skagent still signs but doesn't cache PINs at all.

Forgetting also cancels whatever is still running: an open PIN prompt closes,
and a key that waits for a touch stops blinking. Ctrl-C on `ssh` cancels just
that one request and keeps the PIN.

### Naming keys

Give your SSH keys a label and an emoji, and your YubiKeys a name. Labels
replace the key's comment in prompts and logs, which helps with loaded keys
called `ssh:work openssh`. Emoji and YubiKey names show up in the popup.

```nix
services.skagent = {
  keys."SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ" = { # as `ssh-add -l` shows it
    emoji = "🦊";
    label = "github-work";
  };
  securityKeys."12345678".name = "Desk 5C NFC"; # serial, as `ykman list --serials` shows it
};
```

<details>
<summary>Without home-manager</summary>

The same goes in `~/.config/skagent/config.toml`, or in another file passed
with `--config`. skagent refuses to start if the file contains anything it
doesn't know, so a typo can't go unnoticed.

```toml
[keys."SHA256:4NU8jDPeifwDQZBds3tPVzsluIgQ6CTN6zoxKMzxIkQ"]
emoji = "🦊"
label = "github-work"

[security-keys.12345678]
name = "Desk 5C NFC"
```

</details>

### The popup

skagent's own popup, the one in the picture at the top, is one window that
takes you from the PIN to the touch to the result, and tells you what went
wrong if something does. The home-manager module uses it unless you set
`pinentry.package`, `askpass` or `popup.enable = false`. `skagent serve` on its
own takes it with `--popup PATH`.

- **On Wayland** compositors with layer shell (sway, Hyprland, niri, KDE) it
  appears on top of everything and takes the keyboard. Elsewhere it's an
  ordinary window.
- **It draws on the CPU** with Mesa's software Vulkan driver (lavapipe) and
  loads no GPU driver, so it never wakes a sleeping second GPU. NixOS has
  lavapipe with Mesa; elsewhere it may be a package of its own
  (`vulkan-swrast`, `mesa-vulkan-drivers`).
- **Your key only blinks once the prompt is on the screen.** If the popup
  can't show it within 10 seconds, behind a lock screen for example, the
  request fails instead.
- **Without it,** skagent asks for PINs with pinentry or an askpass program,
  and a desktop notification tells you while a key waits for a touch.
- **Every prompt** says which key is used and what for: a login and its host,
  a git signature, a file to decrypt. The same is logged with every signature.
- **Nobody there:** a PIN prompt closes after 60 seconds without an answer, and
  a request that waits for a busy key gives up after 2 minutes.

### Styling the popup

The popup follows your desktop's light or dark setting (it asks the desktop
portal; without one, set `appearance`). Both are presets you can restyle:
colours, fonts and size. The right half of the picture at the top shows four
styles: Catppuccin Latte and Mocha, Solarized Light, and one that is nobody's
palette. Their settings are in
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

Six colours are enough: `surface`, `text`, `accent`, `success`, `warning` and
`error`. Borders, fields, tints and icon colours are mixed from them, so
changing `surface` alone still looks right.
`skagent-pinentry --preview touch` shows a screen with your style.

<details>
<summary>Every colour, and styling without home-manager</summary>

Each mixed colour can be set too: `muted-text`, `placeholder`, `border`,
`field`, `field-error`, `on-accent`, `on-success`, `on-warning`, `avatar`,
`avatar-warning`, `avatar-error`, `avatar-missing`, `device`, `ring-track`,
`dot` and `dot-hollow`. A font that isn't installed falls back to the bundled
Inter or JetBrains Mono.

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

`skagent check-config` lists settings skagent would skip. A typo in the style
doesn't stop the agent: it logs a warning and keeps the preset's value.

</details>

### Multiple keys

Work and personal keys work side by side, each with its own PIN cache.

- **First use:** skagent asks you to touch the security key that holds the
  key, then for the PIN, then for the touch that signs. After that it knows
  which security key holds which key, and a signature is one touch. Keys on
  different security keys can sign at the same time.
- **Replugging:** skagent recognizes a YubiKey by its serial number and any
  paired security key by its [pairing](#pairing), also after a restart (it
  keeps this in `~/.local/state/skagent/bindings.toml`). An unpaired key
  without a serial you pick by touch again. skagent never silently switches to
  another security key.
- **Not plugged in:** keys on a plugged-in security key are listed first, so of
  two keys a server accepts, ssh uses the one you have at hand. For a key that
  isn't plugged in, skagent waits 15 seconds and tells you which YubiKey it
  needs. Ctrl-C on `ssh` stops the wait.

<details>
<summary>Several accounts on one host, like two GitHub accounts</summary>

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

</details>

### Pairing

The first time you sign with a security key, skagent asks for one more touch
to pair with it: it puts a small credential of its own on the key. From then
on, before your PIN goes to a key, the key has to sign a random challenge with
that credential, without a touch. A fake key that pretends to be yours, down
to your YubiKey's serial number, can't do that, so it never gets your PIN.

You pair each key once. On your other machines, skagent finds the credential
with your PIN, no extra touch needed. Press Esc in the popup to skip pairing,
or turn it off with `--no-pairing`.

### Agent forwarding

Agent forwarding works like with ssh-agent, and every signature still needs a
touch on your machine. Destination constraints work too: a key added with
`ssh-add -h jump -h 'jump>target'` can log in to `jump` and from there to
`target`, but nowhere else. skagent checks every hop against the host key
signatures ssh sends (`session-bind@openssh.com`).

Through a forwarded agent, remote hosts can't load keys or make skagent forget
PINs. Keys of a web origin (any application other than `ssh:...`) only sign SSH
logins and `ssh-keygen -Y sign` data, nothing a website would accept.

### age

skagent decrypts [age](https://age-encryption.org) files with a key that comes
from your security key. Create an identity once, with the PIN and two touches:

```console
$ skagent age new
age1pq1…
```

What it prints is an ordinary post-quantum age recipient. Anyone can encrypt to
it with age 1.3 or newer, or with rage and age's `age-plugin-pq`, without
skagent and without your key:

```console
$ age -r age1pq1… -o secret.age secret.txt
```

To decrypt, age needs an identity file. It holds no secret, only which key to
ask skagent for:

```console
$ skagent age identity > skagent-identity.txt
$ age -d -i skagent-identity.txt secret.age
```

Every file takes one touch, and the PIN if it isn't cached.

- **Also:** `age -d -j skagent` decrypts without the identity file, the file
  works for encrypting too (`age -e -i`), `skagent age list` prints the
  recipients skagent knows, and on another machine `skagent load` finds the
  identity on the key.
- **One recipient type per file:** age refuses to mix post-quantum recipients
  with classic ones, such as SSH host keys or `age1…` keys from `age-keygen`
  without `-pq`. Every other recipient of a file has to be an `age1pq1…` key
  too.
- **Keep a second recipient:** the key exists on that one security key and
  can't be copied. If you reset the key, block its PIN or lose it, files
  without another recipient are gone. A second security key or an offline
  `age-keygen -pq` key works.
- **How it works:** the security key keeps a secret that never leaves it.
  skagent derives the age key from the key's answer each time, uses it for
  that one file and wipes it. [`docs/age.md`](docs/age.md) has the details and
  what this can't protect.

#### Many files with one touch

A touch per file gets old when a tool decrypts hundreds of them. Run it in a
batch:

```console
$ skagent batch -- agenix rekey
```

The first file takes your PIN and a touch, and the prompt says that it starts
a batch and for which command. After that, the files this command decrypts
need neither. A notification counts them and has a Stop button.

For this, skagent keeps the age key in memory while the batch runs, which it
does nowhere else. So a batch is bounded:

- **Only the command you ran** uses it: its processes and what they start.
  Other programs still get a touch prompt for every file.
- **It ends with the command,** or after 10 minutes if that comes first.
  `skagent batch --for 2m` asks for less, `skagent serve --batch-lifetime`
  changes the limit, and `--batch-lifetime 0` turns batches off.
- **It ends early** when you lock the screen, the machine goes to sleep, you
  unplug the security key, press Stop or run `skagent forget`. What the
  command decrypts after that takes a touch per file again.

Batches need Linux 6.5 or newer. [`docs/age.md`](docs/age.md) shows the
settings for agenix-rekey.

<details>
<summary>Decrypting on a remote host, through a forwarded agent</summary>

With `ssh -A`, age on a remote host can decrypt with the security key in your
machine: the plugin there asks the forwarded agent. The remote host needs age,
`age-plugin-skagent` and the identity file. skagent only answers if you start
it with `--age-forwarding` (`services.skagent.age.forwarding`), because of what
it means:

- **Every file takes a touch** on your machine. A batch never covers a remote
  host.
- **The prompt names the host** by its host key, like for a forwarded login.
- **It can't tell you which file** the host wants opened. A hostile host that
  has your forwarded agent can ask for any file it holds a copy of and hope
  that you touch.

</details>

## 🔐 Security

skagent keeps your PIN in memory, so here's what that does and doesn't protect
against.

Protected:

- **A lost or stolen security key** is useless without the PIN
- **A leaked key handle** (a stub file or agent memory) is useless without the PIN, too
- **A stolen laptop with the key** still needs the PIN once skagent forgot it (lock, suspend, reboot)
- **Other users** can't use the agent: its socket is private, and skagent checks every client's user id
- **A hostile host with your forwarded agent** still needs a touch for every signature, and `ssh-add -h` limits where keys work
- **Other processes of yours** can't read the memory of the agent or of its popup, since core dumps and ptrace are disabled
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
and tested it, but at the end of the day most of it is not written by a human.

## 📜 License

Licensed under the MIT license ([LICENSE](LICENSE) or <https://opensource.org/licenses/MIT>).
Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this project by you, shall be licensed as above, without any additional terms or conditions.

The virtual security key used by the tests (`crates/skagent-testkey`) links
[soft-fido2](https://crates.io/crates/soft-fido2), which is AGPL-3.0. Builds of
that test-only crate therefore fall under the AGPL. skagent itself never depends
on it.
