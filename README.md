# skagent

ssh-agent for FIDO2 `ed25519-sk` keys. Keeps `verify-required` on the key (PIN + touch per signature), but caches the PIN in the agent for a bounded time. So you touch the key for every signature and type the PIN once per session instead of every time.

Why not just ssh-agent: OpenSSH has no PIN cache for sk keys. With `verify-required`, every signature asks for the PIN via askpass. Dropping `verify-required` gets rid of that, but then the key handle (stub file / agent memory) plus the key is enough to sign. Details in `docs/research/` and `docs/design.md`.

Status: scaffolding. Nothing here talks to a FIDO device yet.

## dev

```sh
nix develop            # or direnv
cargo test
nix flake check -L     # format, tests, clippy, VM tests
```

Rules for changes are in `AGENTS.md`.
