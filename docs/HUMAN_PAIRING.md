# Gate B4c: The human pairing ceremony (offline, public keys only)

This adds the operator-facing trust decision that was missing from B4a and B4b. It does **not** enable a LAN listener, send a packet, authenticate a session, distribute AI weights, or grant compute.

## What the operator actually approves

The received file is an **untrusted public identity card**. Its signature verifies that its creator held the private key for the included public key. It **does not** prove that the card came from the machine/person you intended.

Before pairing:
1. **On the OTHER physical machine**, create or unlock that machine's own encrypted device vault and read its full 64-character public key fingerprint **directly on that machine's trusted screen**. The passphrase remains on that device.
2. Transfer **only the public signed JSON card**. A USB drive, local manual copy, or other transfer method is fine; the card is public, but the delivery channel itself is NOT trusted.
3. On the receiving machine, run the pairing command and check the **claimed** device ID. Type the **entire** fingerprint you independently observed on the other machine. Do not paste/copy the fingerprint from the transferred card, email, or an attacker-controlled chat.
4. Type the final explicit confirmation, e.g. \`ENROLL storage-pc\`. Only after both input steps will PorchTalk create/open the local trusted-peers SQLite database and pin that public key.
5. Repeat in reverse on the other physical machine to establish *mutual* local trust. Pairing does not start a network connection.

A matching typed fingerprint and confirmation are **caller assertions**, not an independently authenticated identity attestation. Compromised endpoints, malicious terminals and deceptive human interactions remain outside our guarantees.

## Windows PowerShell illustration

Run from your existing **local repository checkout** with Python and dependencies installed:

\`\`\`powershell
py -m pip install -e .

# On EACH machine, choose its own distinct device ID and separate directories.
$root = Join-Path $env:LOCALAPPDATA 'PorchTalk'
New-Item -ItemType Directory -Path $root -Force | Out-Null

# PC A shown; substitute storage-pc on PC B.
py -m porchtalk.vault_cli init --device-id main-pc --vault (Join-Path $root 'main-pc.porchkey')
py -m porchtalk.vault_cli export-card --vault (Join-Path $root 'main-pc.porchkey') --out (Join-Path $root 'main-pc-public.json')

# Move ONLY the other computer's public JSON card to an accessible path.
# Inspect B's public card on PC A. This by itself DOES NOT enroll or trust B.
py -m porchtalk.pair_cli inspect-card --card 'C:\PATH\TO\storage-pc-public.json'

# Independently confirm storage-pc's full fingerprint on its own screen.
py -m porchtalk.pair_cli enroll --card 'C:\PATH\TO\storage-pc-public.json' --trust-db (Join-Path $root 'known-peers.sqlite3') --expected-id storage-pc
py -m porchtalk.pair_cli list --trust-db (Join-Path $root 'known-peers.sqlite3')

# If necessary, require interactive confirmation before rejecting this peer.
py -m porchtalk.pair_cli revoke --trust-db (Join-Path $root 'known-peers.sqlite3') --device-id storage-pc
\`\`\`

**Security warnings:** The B4b vault uses password-derived encryption, **not Windows DPAPI, Windows Hello, TPM or a hardware keystore**. Neither the vault nor the pairing CLI audits Windows ACL permissions. Store the keys and peer database in a protected user-only location; inspect ACLs independently. Don't reuse the demo passphrase and don't copy any \`.porchkey\` files between machines. Secure key backup/recovery and rotation remain unimplemented.

## Negative controls

- A card with duplicate JSON keys, extra fields, tampered signature, mismatched claim or oversized input is refused.
- Non-interactive shell input, absent or incorrect typed fingerprint, wrong device ID and wrong confirmation refuse enrollment **without creating a trust DB**.
- Re-enrollment with a different key cannot silently replace an approved identity. Revoked keys cannot be silently re-enrolled.
- Revocation requires a specific typed command and never creates an empty trust store.
- On POSIX, a dedicated owner-only (0700) trust directory and owner-only (0600) database file are required. Symlinked trust DB/directory and public card paths are rejected where detectable.
- On Windows, file access controls are **not verified** by this code, and symlink/TOCTOU races and compromised privileged users are not eliminated.

## Tests

\`\`\`bash
python -m pip install -e .
python -m unittest discover -s tests -v
\`\`\`

No pairing test talks to other computers or starts a listener. CI runs on Linux Python 3.10/3.12; operator Windows-specific testing is still needed.

## Blocking issues before connecting two PCs

1. Inspect Windows key and trust DB ACLs, plus choose proper OS-backed identity custody rather than treating passphrase encryption as a complete production solution.
2. Design a remote one-shot TLS handshake that never loads persistent signing keys through B3's unencrypted temporary PEM files. Decide transport session key binding and handle mutual certificate verification safely.
3. Make the actual interface, firewall and address explicit. Restrict to a chosen RFC1918 LAN address; never 0.0.0.0 or public binds.
4. Apply peer enrollment and revocation checks at connection time, include persistent replay defenses, rate limits and clear user-visible refusal receipts.
5. Test on two physical machines with adversarial inputs. Still no remote commands, weight downloads or compute allocations.
6. Only then investigate an independently approved synthetic resource grant and guarded executor.

**Ledger above ego: a signed card is a claim; verified human consent is an additional event.**
