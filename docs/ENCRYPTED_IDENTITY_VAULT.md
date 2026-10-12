# Gate B4b: Encrypted, restart-stable Porch identity vault

**Scope:** experimental, local-only at-rest identity storage. This is NOT production-grade device provisioning, protected hardware key storage, TLS deployment, or an actual two-PC session.

Until B4b, PorchTalk only generated *ephemeral* signing keys. Their fingerprint changed whenever the application restarted. This milestone adds a way to persist one Ed25519 identity in a **passphrase-encrypted** local file and to regenerate a PUBLIC-only signed identity card after restart.

## Cryptographic format

- Ed25519 raw private seed remains in process memory, not a plaintext key file.
- Random 128-bit salt and scrypt key derivation: N=32768, r=8, p=1, 32-byte key.
- AES-256-GCM authenticated encryption with independent 96-bit random nonce.
- Device name, public key, KDF/format/cipher parameters and nonce are included as **authenticated associated data**. The encrypted seed must match the public key after decrypting.
- Exact JSON structure; reject duplicates, unsupported algorithms, weak/reduced KDF settings, malformed or oversized input and tampered ciphertext.
- Exclusive-write creation refuses an existing identity, avoiding silent key replacement. On POSIX, the file is mode 0600 and the parent must not be group/world writable. Symlink paths are rejected where detectable.
- No key migration, recovery, passphrase rotation, peer connection or grants happen automatically.

## Windows and threat-model warnings

- This is **password-based file encryption**, not Windows DPAPI, TPM, Windows Credential Manager or a hardware-backed key store. The application and unlocked private key are still vulnerable to malware, keyloggers, privileged processes and memory theft.
- **Windows ACLs are not independently checked or hardened here.** Keep the vault in a user-owned protected folder and use full-disk encryption where available. This implementation alone cannot guarantee Windows file-system isolation.
- An attacker with the encrypted vault can attempt **offline password guessing**. Use a long, unique passphrase; 14 characters is only a minimum length, not a strength guarantee.
- Do not put passphrases in CLI arguments, scripts, environment variables, terminal history, Git commits or bug reports. The CLI prompts via \`getpass\`. Python cannot guarantee memory zeroization of copies.
- The file is written without plaintext, but an interrupted write could leave a partially written encrypted file; it will fail to open. There is no automatic backup or atomic passphrase rotation. Losing the passphrase or the only copy of the vault permanently loses the identity.
- The GitHub test fixture's example passphrase is **public** and for disposable, locally generated test identities only. It MUST NOT be used for real devices.
- **Existing Gate B3 TLS still writes a temporary, unencrypted, *ephemeral* PEM for its loopback-only test. Never feed it a real persisted identity.** Secure OS-backed TLS identity loading requires separate work before real LAN tests.

## CLI: local interactive vault

Install source on your own computer (Python 3.10+):

\`\`\`powershell
python -m pip install -e .
python -m porchtalk.vault_cli init --device-id main-pc --vault "$HOME\porchtalk-identity.porchkey"
python -m porchtalk.vault_cli export-card --vault "$HOME\porchtalk-identity.porchkey" --out "$HOME\main-pc-public-card.json"
python -m porchtalk.vault_cli verify-card --card "$HOME\main-pc-public-card.json"
\`\`\`

The first two commands prompt for the secret without accepting a \`--password\` argument. The signed public card can be safely exchanged for enrollment **only after** the operator verifies the full fingerprint through an independent trusted channel. \`verify-card\` does *not* establish who issued the card.

**Do not run these commands expecting a LAN server or an AI worker. There are no sockets in B4b.**

## CI and reproducibility

\`\`\`bash
python -m unittest discover -s tests -v
python scripts/demo_encrypted_identity.py
\`\`\`

Tests cover passphrase round trips, owner-only POSIX modes, overwrite rejection, malformed formats, symlinks, wrong passwords, changes to authenticated metadata, ciphertext tampering, private-material absence in public cards, simulated restart identity continuity and a subsequent fully **offline** Gate B2 challenge-response.

## Next gate: B4c

- Evaluate OS-backed keys and a secure interface that avoids transient plaintext TLS key files, including **Windows ACL/DPAPI/TPM** behavior and loss/recovery.
- Implement operator-verifiable pairing with an actual separate device, secret transport only through authenticated channels, and manually inspected private-LAN interface/firewall settings.
- Allow exactly one opt-in TLS handshake on a verified private address with **no remote commands and no compute allocation**; assert peer certificate/key pins and signed challenge transcript.
- Red-team replay, substitution, downgrade, denial, clock skew, unauthenticated peers and key-recovery paths.
- Integrate scoped compute grants only in a later, independently reviewed step.

**Ledger above ego. Identity continuity is a prerequisite, not permission to use someone else's hardware.**
