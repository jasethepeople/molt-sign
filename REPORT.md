## Verdict
Yes — Ed25519 signing and verification work correctly. **12/12 tests pass** on Node.js v22.23.4.

## Files
- `molt-sign.mjs` — standalone sign/verify CLI using Node's built-in crypto.
- `tests/sign.test.mjs` — 12 built-in tests, including the RFC 8032 empty-message vector.
- `package.json` — `npm test` runs `node --test`; no dependencies.
- `README.md` — run instructions, CLI forms, accepted identity files, and pairing instructions for `molt-canonical`.

## Test results
- Command: `npm test`
- Result: 12 tests, 12 passed, 0 failed, 0 skipped.
- The suite covers round-trip, altered message and signature, wrong key, both identity formats, mismatched key rejection with empty stdout, CLI exit codes, empty input, stdin, malformed inputs, and RFC 8032 test vector 1.

## Key formats accepted
- `manifest-signer`: a JSON object with only the `manifest-signer` top-level property; its object must contain exactly `priv` and `pub`, each 64 lowercase hex characters. The private seed is checked against the stated public key.
- `molt.ed25519-identity.v1`: requires the matching schema name, `algorithm: "Ed25519"`, non-empty `purpose`, 64-character lowercase `privateKeyHex` and `publicKeyHex`, and a `keyId` equal to the lowercase SHA-256 digest of the raw public key. The private/public pair is checked before signing.

## Open items
- Node.js 24 was not installed in this environment, so runtime execution was verified on Node.js v22.23.4 only; Node 24 compatibility was not independently exercised.
- No product decision remains. Pairing guidance uses `molt-canonical`'s exported canonicalization function and was not run against a real MOLT artifact.

## What was NOT done
- No repository push, deployment, network access, or changes to existing MOLT files, the ledger, keys, or configuration.
- No real manifest signer key or other deployed private key was accessed or generated. Tests use fresh ephemeral keypairs; the static RFC test fixture is the published RFC 8032 test vector.
