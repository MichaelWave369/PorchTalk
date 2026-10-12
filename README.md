# PorchTalk

**Ask locally. Collaborate by choice.**

PorchTalk is the proposed consent-first, budget-aware inference routing policy layer for the **Infinite Porch / Infinite Commons** ecosystem. It is independently implemented research code, intended to complement **PhiOS**, **PhiPie**, **Super Φ.Vessel / Crane Fly**, **BudgetGenius**, and **PhiStream**, not duplicate their runtimes.

**Current status: v0.1.0 offline policy prototype.** It evaluates JSON metadata and emits deterministic decisions and SHA-256 checksum receipts. **It does not discover devices, send packets, execute models, move weights, authenticate identities, or permit actual resource sharing.**

## The first six rules

1. **Local-first:** Any eligible local model beats remote alternatives.
2. **Default deny:** Remote routes require requester opt-in AND an active, specific, unexpired grant from the advertised owner.
3. **Private means local:** PRIVATE requests never leave the owner's Porch in v0.1.
4. **Budget limits:** Quality tier and estimated cost, latency, energy, and available memory must satisfy the request.
5. **No silent execution:** The result is a simulation, not authorization to use another machine. A future execution gateway must recheck rights immediately before and during actual execution.
6. **Receipts with caveats:** The SHA-256 checksum detects accidental changes, but is NOT a signature. Offer claims, ownership and cost estimates are unverified.

## Test-drive the neighborhood

Python 3.10+; no runtime dependencies:

```bash
python -m unittest discover -s tests -v
python -m porchtalk.cli examples/two_porches.json --at 2026-10-12T18:00:00Z
```

The example contains two **synthetic** Porches. Alice's laptop doesn't meet the requested quality tier. Bob's desktop is eligible only because Alice opted into remote routing and the fixture contains Bob's bounded, unrevoked grant. To test negative controls, change `allow_remote` to `false`, mark the grant `revoked`, or change `data_class` to `PRIVATE`.

CLI exit codes: `0` route selected, `1` no eligible route, `2` invalid scenario. The `--at` flag simulates time offline. It is not a trusted clock. The JSON fixture is entirely user-authored metadata, not verified node identity or genuine authorization.


## Gate B1: offline authenticated grant research

An opt-in HMAC-based **offline test module** now demonstrates short-lived, one-use claim envelopes scoped to a specific owner, grantee, request, node and model. Its tests reject tampering, replay, expired or revoked grants, exceeded cost budgets and private-data grants.

**Not a LAN security claim:** This is symmetric-key authentication, not public-key identity or proof of independent owner approval. The replay guard and revocation registry are process-local, time is supplied by the caller, and no networking, execution, model weights, or production grants are involved. Gate A does not automatically call Gate B1. Read [Gate B1 threat model](docs/AUTH_ENVELOPES.md) before attempting any transport integration.

## Gate B2: pinned device identity, still offline

`porchtalk.identity` demonstrates in-memory Ed25519 device keys and manually approved peer public-key fingerprints, stored in a caller-selected local SQLite trust database. Its **offline signed challenge/response** verifies both pinned identities, prevents reuse using atomic persisted nonces, and refuses revoked or unknown devices. The key is generated **ephemerally** by the library; it is not backed up, enrolled over the network, or silently written to disk.

**Critical limitation:** This authenticates an offline challenge transcript ONLY. No encrypted transport, network handshake, Gate A/B1 integration, production key management, model loading, resource allocation or compute execution is present. The SQLite trust database itself requires operating-system protection. Operators must verify fingerprints through an independent trusted channel before approving devices.

Run `python -m pip install -e .` and `python -m unittest discover -s tests -v`, or inspect [Gate B2 documentation](docs/DEVICE_IDENTITY.md). `cryptography` provides audited Ed25519 primitives; PorchTalk implements protocol glue only.

## First real-world milestone (NOT implemented)

Two PCs on a private wired LAN, authenticated with explicit grants and a trusted execution gateway. Before enabling this, we need peer authentication, replay resistance, sandboxing, revocation checks during jobs, energy/resource ceilings, human approval, real benchmark receipts and independent security review.

See [Architecture and Gates](docs/ARCHITECTURE.md).

**License:** MIT for PorchTalk source. Third-party model weights, checkpoints and execution runtimes have separate terms.

**Φ369:** Ledger above ego. The toaster is not allowed to borrow your GPU without permission.
