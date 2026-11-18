# test data

- `cctv/`: the `hybrid*` vectors of age's test suite, [C2SP/CCTV](https://github.com/C2SP/CCTV/tree/main/age) (`0BSD OR CC0-1.0 OR Unlicense`), unchanged. `hybrid_multiple_recipients` (compressed) and `armor_hybrid` are left out.
- `xwing-draft-10.txt`: the three test vectors of [draft-connolly-cfrg-xwing-kem-10](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/), appendix C, one value per line.
- `spec-example.txt`: the example identity and its recipient from the [age specification](https://c2sp.org/age#the-mlkem768-x25519-ie-x-wing-hybrid-post-quantum-recipient-type).
- `derived-recipient.txt`: the recipient of a security key that answers `00 01 … 1f`. The seed was derived with Python's `hmac` (HKDF-SHA-256, no salt, `info = "skagent/age/v1/mlkem768x25519"`), written as an `AGE-SECRET-KEY-PQ-1…` identity, and turned into the recipient by `age-keygen -y` of age 1.3.2. Nothing of this crate was involved.
- `stock-age-to-derived.age`: `echo hi | age -r "$(cat derived-recipient.txt)"` with age 1.3.2.
