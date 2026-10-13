# Gate B4e: Windows observation and two-peer evidence

Gate B4e makes no new background listeners or remote execution engines. It only observes local Windows configuration and compares saved, user-supplied handshake receipts. The experimental B4d protocol is unchanged.

## 1. Inspect local Windows configuration (read only)

In PowerShell, on each PC with its own real address, run the following. The values below are placeholders, not your actual network settings:

    .\scripts\inspect_windows_readiness.ps1 -LocalIPv4 192.168.10.15 -PeerIPv4 192.168.10.20 -Port 54321

The script reads Windows local IPv4/interface records, observed connection profile, active firewall-profile enabled flag when available, and whether the proposed high port appears to have a current listener. It checks whether the supplied addresses are canonical RFC1918 and within the same /24 for the first lab.

It NEVER creates sockets, modifies the firewall, alters files, reads vault secrets, or grants compute. Its output is OBSERVATION_ONLY_NOT_AN_AUTHORIZATION. It always records unresolved manual checks: fingerprints, Windows ACLs, router port forwarding, firewall inbound peer restrictions, network segment trust and unaudited transport review. An enabled Windows Firewall does not certify a safe port rule.

Do not share the JSON report publicly without reviewing its device IP details. GitHub's Windows runner is not your physical PC and cannot validate your router or local LAN.

## 2. Save a one-shot proof receipt

After separate B4d operator approval and proper firewall/key safeguards, its manual command supports an optional argument:

    --receipt-out "$env:LOCALAPPDATA\PorchTalk\my-one-shot-receipt.json"

This creates a public-information JSON receipt only after handshake success. The output file will NEVER be overwritten. If receipt file writing fails after a successful proof, the CLI exits with code 3 and prints a clear message that the handshake succeeded but its evidence wasn't saved. Exit code 2 still means the session was denied or failed.

Receipts contain public device identities, public-key fingerprints, and transcript digests, not vault passwords, signing keys, model prompts or code. They are NOT digitally signed independent attestations; a malicious endpoint or editor could forge them.

## 3. Compare both receipts offline

After collecting each PC's JSON receipt without copying private vaults, run:

    python -m porchtalk.evidence_cli path\to\main-pc.json path\to\storage-pc.json

The strict comparator confirms:
- Both files claim a B4d one-shot success, and both preserve mandatory danger warnings.
- The device names and local/remote public-key fingerprints are mirrored.
- Signed handshake transcript SHA-256 values match exactly.
- Neither file claims routing, job execution or compute authorization.

The response SELF_REPORTED_RECEIPTS_CONSISTENT includes independently_attested=false and real_hardware_verified=false. Passing shows metadata consistency only; it cannot prove that the supplied files genuinely came from two physical machines or that the unaudited protocol is secure.

## 4. Windows-specific corrections

GitHub CI now runs Python unit tests on Windows as well as Linux, plus a Windows PowerShell report smoke test. This surfaced and fixed two issues concealed on Linux:
- Reopened SQLite handles in the replay test were not closed by the registered cleanup callback.
- Corrupt SQLite trust database initialization could leak an OS file handle.

The Windows CI job validates behavior on a disposable GitHub runner; no actual two-PC Windows LAN test is claimed.

## Still prohibited or unresolved

No remote shell commands, arbitrary data frames, AI inference, weight transfers, peer discovery daemons or GPU leasing. The Windows identity vault is passphrase-encrypted but NOT TPM/DPAPI-backed, Windows ACLs are not automatically audited, and B4d uses an experimental custom encrypted-proof protocol rather than independently audited TLS/mTLS. Never open a public port or disable the firewall for this experiment.

Only after a manually reviewed real hardware proof should the project consider a separately governed synthetic-job sandbox, budget limits, revocation, performance measurement and then later PhiStream integration.

Ledger above ego. Two consistent receipts do not mean two GPUs are working together.
