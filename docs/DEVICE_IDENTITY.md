# PorchTalk Gate B2: pinned device identity (offline prototype)

## What exists

- Per-device **ephemeral Ed25519 keys**, generated in process with the widely used `cryptography` library. Private keys are NOT serialized, uploaded or stored by this module.
- Independently approved peer public keys in a caller-selected local SQLite trust store. Enrollment requires `operator_approved=True` and refuses silent replacement or re-enrollment of revoked keys.
- A signed challenge from A to B, verified by B against a pinned public key. The signed response from B binds the **full signed challenge digest**. A verifies B's pinned key and consumes the challenge nonce.
- Exact schema, audience binding, 120-second maximum TTL, 15-second clock-skew allowance, replay protection with SQLite UNIQUE-key atomic inserts and peer revocation.
- Offline tests for forgery, tampering, wrong identity, replay across reopens, expiry, premature messages, bad encoding, enrollment, revocation and transcript swapping.

## Quick evaluation

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/demo_offline_identity.py
```

**This demo creates two temporary SQLite trust databases.** It uses only in-memory keys and never contacts the network.

## Security boundaries

1. **Not live device onboarding.** Public-key fingerprints must be checked out-of-band with the real operator before enrollment. Passing `operator_approved=True` is an assertion by trusted local caller code, not a real human approval UI.
2. **No secure transport.** Even with valid signatures there is NO TLS, end-to-end encryption, authenticated network socket, or session key agreement. Signed transcripts are not secret.
3. **No durable device private keys.** Ephemeral keys vanish on restart. Secure private-key provisioning/storage, backups, hardware-backed protection and revocation/recovery policy remain future work.
4. **Unprotected trust database.** SQLite prevents race duplicates, but neither tampering by local malware nor unauthorized writes by another OS account are prevented by this code. File permissions and OS compartmentalization are essential. There is no database encryption.
5. **No guaranteed trusted time.** Callers can inject a synthetic clock. Production must treat clock drift and changes as possible failure modes.
6. **No complete replay lifecycle.** Consumed nonces persist without pruning; multi-node distributed replay coordination and bounded table growth remain unsolved.
7. **Not execution authorization.** Successful identity proof is neither consent to run a task nor approval to share GPUs. Gate A's routing offers and Gate B1's HMAC research module remain separate. An authenticated network gateway must recheck grants, rights, resources and revocation before and DURING any live job.
8. **Threat model limitations.** Compromised endpoints, stolen private keys, malicious local privileged users, denial-of-service and network active adversaries are not fully mitigated. Authentication != sandboxing or correct computation.

## Controlled next gate: B3

Build a **private LAN transport lab** only after explicit opt-in, no public binds, no port forwarding, authenticated encrypted channels using vetted TLS primitives and pinned device identities, request size/rate limits, durable trust/replay/revocation enforcement, and a SYNTHETIC-only no-execution handshake. Carry receipt provenance into the ledger. Test wrong-host, wrong-key, revoked peer, replay, tampered frame, dropped connection and stale clocks. Keep arbitrary shell commands, weights and model inferencing disconnected until a separately approved gateway passes sandbox and budget checks.

Ledger above ego. A green CI check proves this fixture passes tests, not that public peer networking is safe.
