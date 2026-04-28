<!--
Thanks for the PR. Keep this short — fill in what's relevant, delete the rest.
For non-trivial changes, please link an issue you've already discussed.
-->

## Summary

<!-- One paragraph: what changes and why. -->

## Type of change

- [ ] Bug fix
- [ ] Feature
- [ ] Refactor / cleanup
- [ ] Documentation
- [ ] CI / tooling
- [ ] Dependency bump

## Affected area

- [ ] Frontend (Svelte SPA)
- [ ] byo-relay (server)
- [ ] sdk-core / sdk-wasm (crypto)
- [ ] Install / deploy scripts
- [ ] Packaging (systemd, Caddy)
- [ ] Documentation

## Checklist

- [ ] I've read `CONTRIBUTING.md`.
- [ ] `./scripts/ci.sh` passes locally (or I've run the relevant subset).
- [ ] No new code paths send plaintext, key material, or user-identifying data to the relay.
- [ ] No frozen protocol identifier (HKDF info string, vault root path, manifest field name, AES-GCM nonce derivation) was renamed; if one was, this PR is a protocol version bump with a migration plan.
- [ ] Frontend changes were verified in a browser (not just `tsc` / `vitest`).
- [ ] If install scripts, packaging, the BYO protocol, or operator-facing behaviour changed, `docs/` was updated to match.

## Linked issues

<!-- e.g. Closes #123, refs #456. -->
