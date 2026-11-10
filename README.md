# skagent

ssh-agent for FIDO2 `ed25519-sk` keys. Keeps `verify-required` on the key (PIN + touch per signature), but caches the PIN in the agent for a bounded time. So you touch the key for every signature and type the PIN once per session instead of every time.

Why not just ssh-agent: OpenSSH has no PIN cache for sk keys. With `verify-required`, every signature asks for the PIN via askpass. Dropping `verify-required` gets rid of that, but then the key handle (stub file / agent memory) plus the key is enough to sign. Details in `docs/research/` and `docs/design.md`.

Status: milestones 1-3 of `docs/design.md`. skagent holds sk keys, refuses everything else, and signs through libfido2 with one connected key. It still asks for the PIN on every signature (askpass, like ssh-agent); the PIN cache is the next milestone.

```sh
skagent serve --askpass "$(command -v ssh-askpass)"   # socket at $XDG_RUNTIME_DIR/skagent.sock
export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/skagent.sock
ssh-add ~/.ssh/id_ed25519_sk_rk_example                    # or ssh-add -K
ssh -T git@github.com                                  # PIN prompt + touch
```

## dev

```sh
nix develop            # or direnv
cargo test
nix flake check -L     # format, tests, clippy, VM tests
```

Rules for changes are in `AGENTS.md`.
