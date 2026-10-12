# PorchTalk Gate B3: The First Knock (loopback transport laboratory)

This is the **first real TCP/TLS test**, not a LAN or Internet release.

## Implemented

1. A one-shot local listener bound by code to **127.0.0.1** on an ephemeral OS-assigned port; no configurable wildcard bind, no port forwarding, no discovery daemon.
2. Python standard-library **TLS 1.3 mutual certificate verification**, using self-signed, short-lived Ed25519 test certificates. Trust anchors are the exact certificates built from the two known test identities.
3. A second pinned-public-key check against **explicitly enrolled Gate B2 device identities**, plus signed challenge-response inside TLS.
4. Bounded 4 KiB length-prefixed JSON frames, per-connection socket timeouts, deny unknown or revoked device keys, replay protection across runs in Gate B2's SQLite journal, and one-shot server teardown.
5. No inference, commands, file transfers, background service, arbitrary requests, GPU access, or live Gate A/B1 grants.

Run:

\`\`\`bash
python -m pip install -e .
python -m unittest discover -s tests -v
python scripts/demo_loopback_first_knock.py
\`\`\`

The demo generates **two identities on one machine**, enrolls synthetic identities in temporary trust databases and connects them over a local loopback TCP socket. It reports the TLS version and transcript verification status, with resource authorization explicitly set to false. It does **not** establish a network connection between two computers.

## Important limitations

- **Not production key management:** Python's stdlib \`SSLContext.load_cert_chain\` requires file paths. To set up a TLS context, this lab writes **unencrypted ephemeral private-key PEM files** in an OS temporary directory with \`0600\` creation flags, then deletes them once both contexts are loaded. These temporary files can be visible to an OS administrator, snapshots or other privileged programs. On Windows, POSIX permission bits alone do not guarantee restrictive ACLs. Do not use this harness with real private keys or real machine identities.
- **Ephemeral certificates** are generated anew for each local test; no certificate issuance, rotation or identity persistence service exists.
- **Explicit approval is a caller assertion:** B2's \`operator_approved=True\` is *not* a real user confirmation UI. The demonstration auto-enrolls its own generated fixtures; this is inappropriate on a real network.
- **Single-process protocol lab:** both peers run on the same computer, so this doesn't test real cross-host authentication, LAN routing, concurrent availability, energy or node scheduling.
- **Transport != permission:** a valid TLS connection and a B2 signed proof authenticate a pinned test key, not authorization to run a job. No B1 budget lease is attached and no resource request is allowed.
- **Storage and clock trust:** SQLite tampering, private-key theft, host malware, privileged local actors and clock manipulation remain outside the current security guarantees. Nonces are stored indefinitely; cleanup and bounded replay windows are not implemented.
- **No confidentiality outside TLS:** signed challenge contents are visible to the two peers; this test makes no claim about metadata outside the test connection.
- **Never expose these endpoints to public interfaces.** The current hardcoded loopback address is an intentional safety boundary.

## Gate B4 proposal: actual two-PC LAN laboratory

Only after a separate explicit implementation review:
- Design secure persistent per-device key enrollment with properly protected key storage; verify fingerprints on an independent channel.
- Enable an **opt-in bind to a specific private IPv4 address** with confirmed local-interface ownership, Windows Firewall setup instructions, and an operator-controlled one-shot listener.
- Introduce human-reviewed remote enrollment, pin rotation and revocation, detailed bounded logging, persistent replay state limits and port/rate controls.
- Bind a B1-style signed resource grant to authenticated peer identity and a single task, with hard limits and safe synthetic-only execution. Distinguish *identity* from *consent*.
- Test on two actual PCs over wired LAN, including unplugged cable, firewall denial, impostor, wrong key, signed-message replay, expired/revoked access, and failure closure.
- Separate approval for any AI model inference, checkpoint distribution or real shared computation.

**Ledger above ego:** One green loopback proves only the intended local test path.
