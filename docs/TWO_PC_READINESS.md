# Gate B4a: Public Identity Cards + Two-PC LAN Readiness

This milestone is a **preflight and enrollment research kit**. It does not create a real LAN connection. Gate B3 remains **127.0.0.1-only**. Nothing in this PR binds a socket to another machine, stores permanent private keys, opens a firewall, or distributes model weights.

## Portable Public Card

Each in-memory `DeviceIdentity` can export a JSON card containing:
- Device name and protocol version.
- Raw **public** Ed25519 key, base64 encoded.
- SHA-256 fingerprint of that public key.
- Self-signature across a canonical JSON representation of all fields.

The verification routine validates exact fields, key length, fingerprint consistency, and the self-signature. **A valid self-signature only proves someone held the private key when making the card. It does not establish who that someone is.**

The receiving machine must compare the **entire fingerprint** over a separate, independently trusted communication channel and verify the intended device name. The caller must explicitly assert operator approval. Only then can the public key be pinned in Gate B2's `PinnedPeers` SQLite store. Existing and revoked identities cannot be silently replaced. **No private key is ever included in the card.**

The sample demonstration uses disposable, generated identities and treats its automatic synthetic-card approval as **test-only**, not a pattern for enrolling real people's devices.

## Private LAN Static Check

`preflight_two_pc_lab` is a pure function that rejects:
- Public, loopback, link-local, multicast, carrier-grade NAT and noncanonical IPv4 addresses.
- Addresses not in the three RFC 1918 ranges (10/8, 172.16/12, 192.168/16).
- Different /24 networks (conservative restriction for the first experiment).
- Duplicate devices or IPs, network/broadcast-like endpoints, ports below 49152 or above 65535.
- Plans lacking an explicit operator approval parameter.

The output says **PLAN_REVIEW_ONLY**, not READY or AUTHORIZED. A passing check **does NOT** prove the IP belongs to the intended local interface, that the firewall is closed, that the router has no port forwarding, or that network isolation and certificate/key management are adequate.

## Test locally

```sh
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/demo_two_pc_readiness.py
```

There are no sockets in the enrollment and preflight modules.

## Blockers before actually connecting two physical PCs

1. Decide **how to securely persist each device's private signing key**. Gate B2/B3 currently generate *ephemeral* keys; restarting loses the identity. OS-backed secrets/key stores, recovery and key-rotation operations need design and review. The B3 TLS test also briefly writes ephemeral, unencrypted PEM key files; this is not suitable for real keys, particularly on Windows where POSIX permission modes alone are insufficient.
2. An actual user-verifiable fingerprint ceremony and local UI are required. The `operator_approved=True` boolean is not by itself a user consent mechanism.
3. Inspect the actual local interface addresses, firewall configuration, access from guest Wi-Fi, router port mappings, and LAN threat model **on both PCs**.
4. Design an explicitly bounded, opt-in private-IP TLS listener with independent mutual authentication, rate/size/timeout controls, replay and revocation negative tests.
5. Run actual LAN tests on a pair of real machines and preserve operator-reviewed receipts. Keep NO remote command execution or model downloads until later, independent safety gates.

## Existing Phi369 components

PorchTalk will eventually consume read-only PhiOS node descriptions, Crane Fly capability tiers, BudgetGenius lease estimates, and PhiStream inference performance receipts. None are connected yet and **no shared compute** is enabled.

**Ledger above ego. Permission before compute.**
