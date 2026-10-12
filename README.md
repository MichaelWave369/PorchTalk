# PorchTalk

**Ask locally. Collaborate by choice.**

PorchTalk is the proposed consent-first, budget-aware inference routing policy layer for the **Infinite Porch / Infinite Commons** ecosystem. It is independently implemented research code, intended to complement **PhiOS**, **PhiPie**, **Super Φ.Vessel / Crane Fly**, **BudgetGenius**, and **PhiStream**, not duplicate their runtimes.

**Current status: v0.6.0 research prototype.** It evaluates offline routing, tests signed consent claims, device fingerprints and loopback TLS 1.3, and can save experimental passphrase-encrypted device identities. **It does not discover LAN devices, connect two physical PCs, execute models, move weights, or permit actual resource sharing.**

## The first six rules

1. **Local-first:** Any eligible local model beats remote alternatives.
2. **Default deny:** Remote routes require requester opt-in AND an active, specific, unexpired grant from the advertised owner.
3. **Private means local:** PRIVATE requests never leave the owner's Porch in v0.1.
4. **Budget limits:** Quality tier and estimated cost, latency, energy, and available memory must satisfy the request.
5. **No silent execution:** The result is a simulation, not authorization to use another machine. A future execution gateway must recheck rights immediately before and during actual execution.
6. **Receipts with caveats:** The SHA-256 checksum detects accidental changes, but is NOT a signature. Offer claims, ownership and cost estimates are unverified.

## Test-drive the neighborhood

Python 3.10+; install the cryptography dependency for identity/TLS/vault experiments with `python -m pip install -e .`. The offline routing command itself uses the Python standard library:

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

## Gate B3: The First Knock, a real loopback TLS test

PorchTalk now has a **single-connection TLS 1.3 mutual-authentication lab** on `127.0.0.1`, with ephemeral test certificates, manual Gate B2 trust pins, signed challenges and 4 KiB message limits. The laboratory listener cannot bind to your LAN, accepts no commands, transfers no model weights, and cannot run a job.

**Critical caveat:** The standard-library TLS setup briefly requires an unencrypted ephemeral PEM key file in a temporary directory (restricted permissions where supported); it is deleted immediately after context initialization. This is **test-only**, not secure production key storage, particularly on Windows. A real two-PC deployment requires separately designed enrollment, key management, authentication and operator approval.

Run `python scripts/demo_loopback_first_knock.py` after installing dependencies, and read [The First Knock: test boundaries](docs/FIRST_KNOCK.md). A green loopback lab is NOT evidence of production readiness or an actual two-PC connection.

## Gate B4a: Preparing two separate PCs, safely

We now have **portable signed PUBLIC-key enrollment cards** with independent full-fingerprint confirmation required before a new device is pinned as trusted. An offline RFC1918 **same-/24 address planning check** rejects accidental public or unapproved endpoints. See [Two-PC readiness](docs/TWO_PC_READINESS.md).

This does **not** open LAN sockets, enroll real PCs automatically, store persistent private signing keys, run models or grant resources. Public cards contain **no private-key material**; the included demo is synthetic and its implicit fixture approval must never be used on real devices.

Run `python scripts/demo_two_pc_readiness.py` for the entirely offline example.

## Gate B4b: restart-stable encrypted device identity

PorchTalk now includes an **optional experimental passphrase-encrypted Ed25519 identity vault**. Local keys can survive program restarts without being stored as plaintext private-key files. The interactive `vault_cli` can create a vault, unlock it, export a signed **public-only** identity card, and inspect a received public card without silently trusting it.

The file uses scrypt + AES-256-GCM with authenticated metadata, refuses overwrite and rejects altered data. **This is not OS-backed Windows DPAPI/TPM protection or production key custody**; no real-device LAN bind or compute grant is enabled. In particular, the B3 loopback harness's temporary PEM-key approach is still unsuitable for persistent real-world keys.

Read [encrypted device vault limitations and CLI](docs/ENCRYPTED_IDENTITY_VAULT.md) before using any identity on a real PC. Try the safe synthetic restart demo with `python scripts/demo_encrypted_identity.py`.

## Gate B4c: manual two-PC public-key pairing

PorchTalk now includes an **interactive offline pairing CLI**. You can inspect a received *untrusted* signed public card, explicitly pin it after entering the **entire independently verified 64-character fingerprint**, inspect locally pinned keys, or revoke a trusted peer with a second exact confirmation.

The pairing command has **no `--yes` option, won't accept piped confirmations**, and creates no trust database before the operator confirms both steps. On POSIX, the trust directory/file must be private; Windows ACL checks still require operator review. Both PCs would need to repeat the process independently.

```sh
python -m porchtalk.pair_cli --help
```

Full Windows-oriented steps and threat limitations: [Human Pairing Ceremony](docs/HUMAN_PAIRING.md).

**This is NOT a live LAN handshake.** The software cannot independently prove that the user obtained the fingerprint from the physical peer, and neither pairing nor a public identity card authorizes compute sharing.

## First real-world milestone (NOT implemented)

Two PCs on a private wired LAN, authenticated with explicit grants and a trusted execution gateway. Before enabling this, we need peer authentication, replay resistance, sandboxing, revocation checks during jobs, energy/resource ceilings, human approval, real benchmark receipts and independent security review.

See [Architecture and Gates](docs/ARCHITECTURE.md).

**License:** MIT for PorchTalk source. Third-party model weights, checkpoints and execution runtimes have separate terms.

**Φ369:** Ledger above ego. The toaster is not allowed to borrow your GPU without permission.
