# PIN caching: what OpenSSH and GnuPG actually do

Source-level findings that the skagent design builds on. Line numbers refer to the versions in nixpkgs at the time of writing: **OpenSSH 10.6p1** and **GnuPG 2.4.9**. Re-check them when those versions move.

## OpenSSH 10.6p1

### The private key never leaves the authenticator

- The "private key" file of an sk key (`id_ed25519_sk`, or `id_ed25519_sk_rk_<app>` from `ssh-keygen -K`) holds no secret key material. `sshkey_serialize_private_sk` (`sshkey.c:2552`) writes the public key plus `application`, `flags`, `key_handle` and `reserved`. That's all.
- The key handle (FIDO credential ID) tells the authenticator *which* credential to use. Signing happens on the device.

### credProtect decides whether the key handle alone is enough

`sk_enroll` (`sk-usbhid.c`, around line 917) sets the credential protection policy at creation time:

| created with | credProtect | consequence |
|---|---|---|
| `-O verify-required` | `FIDO_CRED_PROT_UV_REQUIRED` | every assertion needs user verification (PIN). Key handle + device + touch is **not** enough. |
| `-O resident` without `verify-required` | `FIDO_CRED_PROT_UV_OPTIONAL_WITH_ID` | usable without PIN if the caller supplies the credential ID (key handle). Discovery without the ID needs the PIN. |

OpenSSH refuses to create resident or verify-required keys on devices without credProtect support.

User presence (touch) is requested per signature unless the key was created with `no-touch-required` (`fido_assert_set_up`, `sk-usbhid.c:1192`).

### ssh-agent does not cache the PIN

`process_sign_request` (`ssh-agent.c`, around lines 945-995):

1. First tries `sshkey_sign` with `pin == NULL`.
2. If that fails with `SSH_ERR_KEY_WRONG_PASSPHRASE` (PIN required), it asks **once** via `read_passphrase(prompt, RP_USE_ASKPASS)`. The agent has no tty, so this needs `SSH_ASKPASS` plus a display, or `SSH_ASKPASS_REQUIRE=force`.
3. After the signature the PIN is wiped with `freezero(pin, strlen(pin))`. Nothing is kept.

So with `verify-required` keys, stock ssh-agent asks for the PIN on every signature, by design.

### `ssh-add -K` writes no files

`load_resident_keys` (`ssh-add.c:598`) calls `sshsk_load_resident` and hands each key straight to the agent with `ssh_add_identity_constrained`, honoring `-t` (lifetime) and `-c` (confirm). No stub file is written. `ssh-keygen -K` is the one that writes files.

## GnuPG 2.4.9 with a YubiKey in OpenPGP mode

### Keys stay on the card

`~/.gnupg/private-keys-v1.d/<keygrip>.key` only holds a "shadowed" key that references the card serial. Sign/decrypt/auth run on the card through scdaemon.

### Layer 1: the card keeps the PIN verified

`scd/app-openpgp.c` tracks verification state in `did_chv1/2/3`. After one successful VERIFY the card stays verified until it loses power or is reset, and scdaemon doesn't ask again (`verify_chv2`, around line 2848; signing around line 5481). The exception is `force_chv1` (the "signature PIN forcing" card flag, `forcesig` in `gpg --card-edit`), which re-verifies for every signature. The authentication key, which gpg-agent uses for ssh, is never re-verified within a card session.

### Layer 2: gpg-agent keeps a copy of the PIN, YubiKey only

- `cache_pin` (around line 2630) only acts for `CARDTYPE_YUBIKEY` and not with `pcsc-shared`. It sends the PIN to gpg-agent (`PINCACHE_PUT`).
- gpg-agent stores it as `CACHE_MODE_PIN` (`agent/cache.c`). It has **no TTL and no max TTL**: `ttl = -1` (line 369) and housekeeping skips it ("Don't let it expire - scdaemon explicitly flushes them", line 207). `default-cache-ttl` and `max-cache-ttl` don't apply.
- Entries are encrypted with AES-128 under a key that lives in the same process (`cache.c:34-48`). That's obfuscation against casual memory scraping, not protection from the process itself.
- It's flushed when scdaemon restarts (`agent/call-daemon.c`: `agent_flush_cache (1)`) and on SIGHUP / `gpgconf --reload gpg-agent` (`agent_sighup_action`, `gpg-agent.c`). There's no idle timeout and no screen-lock integration.
- It's used to re-verify the card silently after a reset (e.g. another program grabbed the card), **but only if the card reports at least 3 retries left**: `remaining >= 3 && pin_from_cache (...)` (`app-openpgp.c:2793`, `:2994`). A wrong cached PIN therefore can't burn through the retry counter.

### Touch

The YubiKey OpenPGP applet has a per-key touch policy on the card (`ykman openpgp keys set-touch sig|dec|aut on|fixed|cached|cached-fixed|off`). gpg doesn't know about it; the operation just blocks until touched. FIDO2 has no equivalent knob: touch is per credential (`no-touch-required` or not) and requested per assertion.

## Takeaways for skagent

- FIDO2 has no equivalent of OpenPGP's layer 1. The authenticator never stays "PIN verified" across assertions in a way OpenSSH could use. A PIN cache for sk keys has to hold the PIN on the host, like gpg's layer 2.
- Keep `verify-required` (`UV_REQUIRED`). Then a leaked key handle is useless without the PIN, and the cache is the only place the PIN lives.
- Copy gpg's retry guard, but tighter (see `docs/design.md`).
- Do better than gpg on lifetime: hard maximum TTL, eviction on lock/suspend, no "forever" mode.
