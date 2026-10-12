# PorchTalk architecture and verification gates

## Scope: v0.1

Offline request + offers + grants + evaluation time -> decision + checksum. There are no sockets, remote execution hooks, model libraries, or network permissions. An offer is self-reported, not a trusted fact. Quality tiers 0-3 and cost units are **fictional estimates**, not calibrated predictions.

The fixed selection order is estimated cost, latency, energy, node ID, model ID *within the preferred local or remote set*. A locally eligible model always precedes remote choices. No peer fallback without requester opt-in. Joining the Commons never implies consent.

## v0.2 candidate: authenticated private LAN

- Separate **discovery** from **approval**; never accept discovery as authentication.
- Bind grants to authenticated owner and requester, node, model, data class, expiry, resource cap and policy. Use trusted clock and check revocation during work.
- Authenticate messages with vetted cryptography; encrypt transport and prevent replay.
- Transmit only explicitly authorized content; private requests stay local.
- Execute predefined sandboxed tasks, never arbitrary shell commands from peers.
- Measure actual latency, memory and energy rather than treating claims as observations.
- Cache compatible verified model weights on hosts under their own redistribution licenses.
- Require an explicit operator approval gate before enabling live peer work.

## Boundaries with related projects

| Existing subsystem | Future integration | Implemented here |
|---|---|---|
| PhiOS / PhiPie | Device UI, identity and grant UX | None |
| Infinite Porch / Commons | Opt-in social presence and node membership | None |
| Crane Fly / Vessie | Model capabilities and orchestration | Synthetic JSON offers |
| BudgetGenius | Budget leases and settlement | Estimated budget hard caps |
| PhiStream | Local per-node memory-tiered inference | None |
| NBG / Ledger | Signed, replayable provenance | SHA-256 checksum only |

## Verification gates

**Gate A:** invalid inputs fail closed; private data local; remote opt-in plus unrevoked matching grant mandatory; estimated budgets enforced; deterministic tie-breaks; CI on two Python versions.

**Gate B (future):** independently authenticated two-node LAN, signed grants, revocation/replay defenses, synthetic negative controls.

**Gate C (future):** isolated authorized synthetic work dispatched to a peer; bounded resources, verified result receipt, operator-controlled session.

**Gate D (future):** compatible PhiStream inference integration with full reference parity and comparative hardware measurements.

No live networking, shared compute, or model inference is claimed.
