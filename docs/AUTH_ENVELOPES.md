# Gate B1: offline authenticated grant envelopes

**Scope:** This is an **offline HMAC demonstration** only. It is NOT a network transport or a real remote compute authorization service. PorchTalk Gate A remains a separate synthetic offer-routing evaluator.

## What the HMAC envelopes test

A shared secret of at least 32 bytes authenticates an exact canonical JSON claim set: grant ID, owner, grantee, node, model, request ID, PUBLIC/SYNTHETIC classification, maximum estimated cost, issuing time, expiry and a cryptographically randomized 128-bit nonce.

A verifier must already know the expected owner, grantee, node, model, request and data class from trusted local context; message fields are **not** trusted merely because they exist. The verifier also checks a process-local revocation set, a process-local replay guard, and a maximum grant validity window of five minutes.

Tampering, wrong keys, mistaken recipients, wrong models, wrong requests, expiration, revoked grants, excess estimated costs, PRIVATE data, malformed input and replay are all negative controls.

## Deliberate limitations: NOT A LIVE SECURITY SOLUTION

1. **HMAC is symmetric:** anyone possessing the shared key can issue the same MAC. It does *not* independently prove a grant came from the alleged owner. Never share one group secret across the Commons; real identity and owner authorization require a separate design, likely vetted public-key credentials and authenticated device enrollment.
2. **No transport encryption or peer authentication:** no sockets or packet handling are implemented.
3. **No key provisioning, persistence, rotation or recovery:** secrets are only supplied by the caller. The test key is a dummy value that must never be used for a deployment.
4. **Replay protection is only in-memory:** it resets on restart, is not shared across nodes and is not bounded for large-scale operations. Real use needs durable, transactional nonce consumption with expiry and concurrency controls.
5. **Revocation is a caller-supplied in-memory set:** not synchronized, persisted or trustworthy across hosts. A real execution gateway must recheck grant validity and revocation immediately before and during work.
6. **Caller-controlled clock:** tests inject simulated time. Real use requires a sufficiently reliable clock and clock-skew policy.
7. **No route-to-grant integration:** Gate A metadata decisions are not authenticated or attested by Gate B1 and cannot authorize live execution.
8. **No resource reservation or sandbox:** cost caps are assertions; no CPU/GPU/RAM limits are enforced and no jobs execute.

## Local regression

Run:
\`\`\`sh
python -m unittest discover -s tests -v
\`\`\`

New cases live in \`tests/test_auth.py\` and run in the existing two-version GitHub Actions unit-test matrix. There are no additional runtime dependencies.

## Next proposal: Gate B2

- Specify a threat model for a malicious peer and compromised node.
- Establish per-device public identities and human-approved enrollment; use audited cryptography and secure authenticated transport.
- Persist replay prevention and revocation securely, with atomic checks and expiration.
- Wire matching owner/grantee/request/node/model scope into the Gate A routing result.
- Add an operator-approved **synthetic-only** two-PC private LAN handshake, no arbitrary commands or model-weight downloads.
- Validate security negative controls and report performance before considering any execution mode.

**Ledger above ego:** green offline authentication tests do not mean that strangers can safely share GPUs.
