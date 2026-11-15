## What this changes

<!-- One or two sentences. What is different after this merges, and why. -->

## Checklist

- [ ] `cargo test --workspace --locked` passes.
- [ ] `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` are clean.
- [ ] `cargo doc --workspace --no-deps --locked` is clean with `RUSTDOCFLAGS="-D warnings"`.
- [ ] `cargo deny check` passes.
- [ ] `npx --yes prettier@3.9.10 --check .` is clean (a local hook, not a CI gate).
- [ ] No key material, PSK, pairing record or Noise handshake hash appears in code, fixtures, output or commits.
- [ ] A spec deviation has an entry in `docs/spec-deviations.md` and a test.
- [ ] Commits follow Conventional Commits.
