# PorchTalk Field Capture C3: First Real Windows Observations

**Scope:** read-only examination of the two operator-owned Windows machines. No network knock, key exchange, private-key read, firewall change or remote compute.

Gate #12 compares two Windows JSON observations. This step makes it safer and easier to *collect* them from the physical machines, producing one new, non-overwriting JSON per run. Copies of public observation JSON are all that should be transferred.

## On each computer

1. Use `ipconfig` and inspect the intended adapter's IPv4 address. Confirm both PCs are actually on the same trusted private LAN, and do not rely on the fictional addresses below.
2. Clone or use a local read-only checkout of `MichaelWave369/PorchTalk` on the computer. The capture command does not need to be Administrator and must not require disabling Windows Firewall.
3. Create an output directory that you control. The script refuses a nonexistent directory or a symlink/reparse-point destination.

```powershell
$dest = Join-Path $env:USERPROFILE 'Documents\PorchTalkFieldEvidence'
New-Item -ItemType Directory -Path $dest -Force | Out-Null
```

4. On PC A, substitute **your real** IPv4 values for the fictional examples:

```powershell
.\scripts\capture_windows_field_evidence.ps1 `
  -LocalIPv4 '192.168.10.15' `
  -PeerIPv4 '192.168.10.20' `
  -Port 54321 `
  -OutputDirectory $dest
```

5. On PC B, reverse the intended addresses (again use real observed IPv4 values):

```powershell
.\scripts\capture_windows_field_evidence.ps1 `
  -LocalIPv4 '192.168.10.20' `
  -PeerIPv4 '192.168.10.15' `
  -Port 54321 `
  -OutputDirectory $dest
```

The command prints JSON containing the **new** output path and its SHA-256. The report itself is compatible with the browser Evidence Desk. The new report filename includes a UTC timestamp and a short random suffix; the script uses an exclusive create-new file mode and never moves or overwrites existing files. Leave source files untouched and back up copies to your USB if desired.

## Review, transfer and compare

Open each JSON report in an ordinary text editor first. It may reveal private IPv4 and firewall-profile information. Do not publish these files without checking for sensitive topology metadata.

Copy only the two generated **observation JSON** files to the computer on which you're viewing <https://michaelwave369.github.io/PorchTalk/>. In **Evidence Desk**, select Porch A's Windows report and Porch B's Windows report, then compare. The site runs fully client-side and does not upload selected files.

To check integrity when copying, recompute the SHA-256 on the destination:

```powershell
Get-FileHash -LiteralPath 'C:\PATH\TO\COPY.json' -Algorithm SHA256
```

Compare it to the original report hash printed by the capture command. This detects changes to file bytes after capture, but **is not a signature, trusted attestation, or evidence that another physical computer actually generated the report**.

## Non-negotiable caveats

- The capture's success means a **local observation file was written**, not that both machines are ready for connection. An IP may have been supplied incorrectly or might not be assigned to the machine. The report's `local_ipv4_observed_on_interface` indicates only what the Windows API claims.
- A reported firewall-enabled flag does **not** establish an appropriately scoped inbound rule. A zero-warning comparison does **not** certify port-forwarding, VPN isolation, device ownership, Windows vault ACLs, or cryptographic transport security.
- Existing PorchTalk B4d connection code remains experimental and not independently audited. These read-only observations **do not authorize starting** that protocol.
- The script cannot prove that the host or output directory is free from privileged tampering. SHA-256 here is checksum-only.
- Do not copy `.porchkey` files, passwords, signing seeds, private credential databases or files from the original C:/D: archive. This workflow only reads local Windows system information and creates new observations in the chosen folder.
- The script requires an **existing local directory** and refuses redirect/reparse-point output destinations. It may leave a partial *new* file if a disk error occurs during writing. It will not overwrite an existing file.

## Verification

GitHub Windows CI runs `scripts/test_capture_windows_field_evidence.ps1` to check: creation of two distinct files, byte preservation of the first, hash integrity, denial of public IP plans, and refusal to create missing output directories. CI's simulated inputs do **not** establish real-device readiness.

**Ledger above ego. Capture first. Compare second. Approve networking only after separate security review.**