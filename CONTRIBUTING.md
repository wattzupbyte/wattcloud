# Contributing to Wattcloud

Wattcloud is a personal project. Patches are not actively solicited, but
focused contributions — security findings, provider coverage, BYO protocol
improvements — are welcome. This guide tells you what's likely to land
and what isn't.

## Before you start

- **Security vulnerabilities go through private reporting.** Open a
  [GitHub Security Advisory](https://github.com/thewattlabs/wattcloud/security/advisories/new),
  not a public issue. See `SECURITY.md` for the threat model.
- **Read the canonical docs first.** `SPEC.md` (BYO protocol, vault
  format), `SECURITY.md` (threat model, key hierarchy), `DESIGN.md`
  (visual system), `CLAUDE.md` (project layout, hard rules). If your
  change conflicts with any of these, the docs win — open an issue to
  discuss before coding.
- **For non-trivial work, open an issue first.** A PR that surprises the
  maintainer is likely to be closed. Two-paragraph problem statement +
  proposed direction is enough.

## What WILL NOT be merged

These are non-negotiable. They exist because changing them would break
existing users' vaults or invalidate the trust model.

- **Anything that violates a Zero-Knowledge invariant** (`CLAUDE.md` §
  "Zero-Knowledge Invariants"). The relay never sees plaintext, key
  material, or user identity beyond per-device enrollment.
- **Renaming a frozen protocol identifier.** HKDF `info` strings, vault
  root folder name, AES-GCM nonce derivations, manifest field names —
  these are wire-format constants. A change is a protocol version bump
  with a migration plan, not a refactor.
- **Server-side persistence of provider configs, user accounts, or
  session state** beyond per-device enrollment and ephemeral share blobs.
- **Native or mobile targets** for `sdk-core`. Wattcloud is browser-only.
- **Buffer-and-forward "streaming" stubs.** New providers must implement
  real range-based download + resumable/chunked upload (see SPEC.md §
  "Range-Based Download Streaming").

## sdk-core constraints

Code under `sdk/sdk-core/` follows stricter rules than the rest of the
repo:

- No `unwrap`, no `expect`, no `panic!`. Use `Result<T, SdkError>`.
- No direct slice indexing — use `.get()`.
- No `unsafe` without a `# Safety` doc comment **and** fuzz coverage.
- Key types derive `Zeroize` + `ZeroizeOnDrop`; never `Clone`.
- `Debug` impls print `[REDACTED]` for anything sensitive.
- No base64 in `sdk-core` — encode/decode at the WASM boundary.

`#![deny(clippy::unwrap_used, clippy::expect_used)]` is on; CI will fail.

## Build and test

The full local pipeline (mirrors GitHub Actions):

```bash
./scripts/ci.sh
```

Targeted commands are documented in `CLAUDE.md` § "Build & Test". At
minimum, before opening a PR:

- `cargo test --manifest-path sdk/sdk-core/Cargo.toml`
- `cargo test --manifest-path byo-relay/Cargo.toml` (if you touched the
  relay)
- `cd frontend && npm test && npm run build`

For frontend changes that affect rendering, manually verify in a browser
— `tsc` and `vitest` do not catch Svelte template errors.

## Branch and PR process

- Branch off `main`. Use a descriptive prefix: `fix/`, `feat/`, `docs/`,
  `chore/`.
- One logical change per PR. Bundle a fix with its test; don't bundle
  unrelated cleanups.
- Keep diffs small. If a PR grows past ~500 lines of non-generated code,
  split it.
- Rebase, don't merge `main` into your branch.
- CI must be green before review. Doc-only changes (`**/*.md`,
  `LICENSE`, `NOTICE`, `.gitignore`, `.github/dependabot.yml`,
  `.github/ISSUE_TEMPLATE/**`) skip CI by design.

## Commit messages

Conventional Commits style:

```
type(scope): short subject

Optional body explaining the why, not the what.
```

Types in active use: `feat`, `fix`, `docs`, `chore`, `refactor`, `test`,
`ci`. Scope is usually a top-level dir (`sdk-core`, `byo-relay`,
`frontend`, `scripts`, `packaging`) or a domain (`security`, `deps`,
`github`).

## Code style

- Rust: `cargo fmt` and `cargo clippy -- -D warnings` must pass.
- TypeScript / Svelte: `npm run lint` must pass. The frontend uses
  Svelte 5 (runes); see existing components for patterns.
- Don't add comments that just describe what the code does. Comment the
  *why* — non-obvious constraints, frozen protocol values, workarounds
  for specific bugs.

## Licensing

Wattcloud is AGPL-3.0-or-later. By opening a pull request you agree that
your contribution is licensed under the same terms. The Wattcloud name
and wordmark are reserved by the project — forks must be renamed.
