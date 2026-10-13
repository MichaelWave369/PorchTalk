# Gate B4d: First two-PC knock (EXPERIMENTAL)

This is a deliberately narrow research experiment. It can make one authenticated, encrypted **proof exchange** between two explicitly approved private-LAN devices. This is a custom protocol, **NOT TLS and NOT independently security-audited**. It is not appropriate for public networks, untrusted peers, or production computing.

## What it can and cannot do

- Must be explicitly run from a local interactive console and approved by typing an exact intent phrase. It never starts automatically.
- One-shot TCP listener binds to a specified RFC1918 private IPv4, never 0.0.0.0. Only one connection is accepted before shutdown.
- Sender and receiver must be configured with exact same-/24 RFC1918 addresses, distinct device IDs, short timeouts and an ephemeral high port.
- Each machine must have already pinned the other's Ed25519 public key via the B4c manual enrollment procedure. Revoked or missing keys are rejected.
- Fresh X25519 key agreement and HKDF-SHA256 produce two AES-256-GCM keys. The protocol exchanges Ed25519-signed HELLO/REPLY records, then **only two fixed-format encrypted proof frames**.
- Fixed 4096-byte frame maximum, short validity windows, durable replay counters through the existing SQLite nonce journal.
- The receipt contains a transcript SHA256 and peer-key fingerprint. The receipt is **not** an independent signature or attestation.

The signed introductory HELLO and REPLY metadata are **plaintext on the wire** (including device IDs, nonces, public session keys and timestamps). The final confirmation frames are encrypted. No arbitrary messages, shell commands, model prompts, file transfers, weights, inference, or CPU/GPU work can be sent.

## Prerequisites for a physical two-PC test

1. Two **operator-owned** computers on one trusted private LAN, with the repo and Python dependencies installed on each. No public port forwarding.
2. Distinct passphrase-encrypted device vaults, generated locally and **never copied between devices**. These are not TPM/DPAPI protected. Check OS account permissions and Windows ACLs independently.
3. Mutual enrollment using the Gate B4c public-card ceremony. Compare the **entire public-key fingerprint directly on the other machine's screen**, independently of any received card.
4. Inspect actual local IP addresses using ipconfig. Manually check Windows Firewall rules, limiting any inbound temporary test port to the designated peer private address. Do **not** disable the firewall wholesale.
5. Type the exact confirmation and the vault password interactively on both devices. No passwords as command-line flags, no unattended daemon and no public internet.
6. Treat any failure as DENIED, and remember **CI has not verified the physical Windows LAN**.

## PowerShell operator illustration

Addresses are **placeholders** and must be changed to actual NIC addresses; never run until the above precautions have been verified. Start the listener on PC B, then the client on PC A. Each command asks for a precise confirmation and then the local password.

On PC B (storage-pc at example 192.168.10.20):

    py -m porchtalk.lan_cli serve --vault "$env:LOCALAPPDATA\PorchTalk\storage-pc.porchkey" --trust-db "$env:LOCALAPPDATA\PorchTalk\known-peers.sqlite3" --local-ip 192.168.10.20 --peer-ip 192.168.10.15 --peer-id main-pc --port 54321 --timeout 5

On PC A (main-pc at example 192.168.10.15):

    py -m porchtalk.lan_cli knock --vault "$env:LOCALAPPDATA\PorchTalk\main-pc.porchkey" --trust-db "$env:LOCALAPPDATA\PorchTalk\known-peers.sqlite3" --local-ip 192.168.10.15 --peer-ip 192.168.10.20 --peer-id storage-pc --port 54321 --timeout 5

No source files or old archives need to be moved or changed.

## Verification levels and exclusions

**Gate B4d CI:** protocol negative controls plus a Linux synthetic integration test on loopback 127.0.0.1/127.0.0.2. Only this test artificially bypasses RFC1918 preflight. The runtime still rejects loopback and public IPs. A green CI run is **not** a validated Windows-to-Windows session.

**Still unresolved:** Windows protected key storage, independent code/security review, mature TLS/mTLS or Noise implementation, revocation lifecycle, replay journal pruning, recoverability, firewall inspection automation, resource-consent authorization and compute sandboxing. The current password-encrypted vault may reveal a key to privileged local malware; the protocol is not audited and cannot defend against all active network threats.

**Future Gate B5:** independently review any synthetic bounded workload runner, verified node capability claims and audited resource budget enforcement. The current Gate B4d transport **cannot execute any job**.

**Ledger above ego. First prove the knock.**
