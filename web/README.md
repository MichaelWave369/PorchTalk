# PorchTalk Control Room

A standalone **React + Vite** GitHub Pages interface for PorchTalk's Infinite Porch neighborhood compute research.

**This is an interactive offline browser demonstration, not a live distributed AI interface.** No private keys, device identities, signed grants, model weights, inference prompts, or real network peers are loaded into this static app. Its demo nodes, timing, energy, cost, and quality tiers are invented *simulation inputs*, not benchmark or inventory facts.

## Views and interactions

- **Overview:** local/peer network topology illustration and live *in-tab* routing preview.
- **Route Lab:** change data class, quality requirement, cost/latency/energy budgets, simulated opt-in and demo grants, then generate an unsigned local JSON receipt.
- **Porch Nodes:** toggle four hypothetical nodes on and off, with explicit fictional labels and memory/cost estimates.
- **Trust & Consent:** understand why identity, sharing permission and budget are separate policies. Browser toggles are not authorization.
- **Evidence Ledger:** Gate A through B4 research status, with unverified real-hardware/security gates clearly marked.

All simulations are local JavaScript. There is no backend, tracking, analytics, externally loaded font, storage permission, websocket, model download or hardware access. A receipt can be downloaded by deliberate user action using a browser Blob, or copied to the clipboard. Its SHA-256 checksum is **not a cryptographic signature or attestation**.

## Evidence Desk: local read-only JSON inspection

The **Evidence Desk** menu lets an operator deliberately select:
- A local JSON report from `scripts/inspect_windows_readiness.ps1` to view the reported private address plan, Windows interface claims, firewall-profile state and unresolved manual checks.
- Two separate B4d JSON handshake receipts, saved using `--receipt-out`, to compare mirrored IDs/public-key fingerprints and the claimed matching transcript hash.

Files are **read inside the browser tab, not uploaded**. Import accepts only `.json` files of at most 8 KiB and an exact known schema; no arbitrary JSON fields are displayed or executed. The desk does not save imported data to localStorage, network services, or the repository. Refreshing or clearing the page drops the imported state.

Click **Load synthetic example** to see deliberately fabricated, clearly labeled sample evidence without owning two PCs. Loading a real file resets synthetic evidence so fake and imported receipts cannot be accidentally mixed.

**Limits:** The browser can only check consistency of untrusted JSON. It does not cryptographically verify signed handshake records, prove that either physical PC was contacted, or authorize remote computation. It cannot detect duplicate JSON object keys; the canonical Python `python -m porchtalk.evidence_cli` tool performs stricter offline parsing and remains the reference checker. Don't select `.porchkey` vault files, private keys, passwords or confidential logs.

## Two-Porch Windows comparison

The Evidence Desk now accepts **two separately captured read-only Windows reports**. It cross-checks mirrored local/peer IPv4 addresses, equal high TCP ports and the conservative same-/24 RFC1918 input rule. It separately flags absent interface observations, unknown or disabled firewall profiles, already-listening ports, non-Private network profiles and inspection errors.

The resulting status is **SELF_REPORTED_WINDOWS_PLANS_MATCH_WITH_MANUAL_BLOCKERS**, always with `lan_connection_authorized=false`, `real_hardware_verified=false` and `compute_authorized=false`. Even apparently clean files require independent fingerprint confirmation, exact firewall rules, protected Windows vaults and a fresh operator security review.

### Capture two reports without opening a port

Use `ipconfig` on each physical PC to learn its *actual* local IPv4. The values here are fictional examples and must be replaced. In a local PowerShell session inside the PorchTalk repository:

PC A:

```powershell
.\scripts\inspect_windows_readiness.ps1 -LocalIPv4 192.168.10.15 -PeerIPv4 192.168.10.20 -Port 54321 | Set-Content -Path .\porch-a-readiness.json -Encoding UTF8
```

PC B, reversing the example addresses:

```powershell
.\scripts\inspect_windows_readiness.ps1 -LocalIPv4 192.168.10.20 -PeerIPv4 192.168.10.15 -Port 54321 | Set-Content -Path .\porch-b-readiness.json -Encoding UTF8
```

Copy **only** these read-only JSON files to the browser machine and select them in **Evidence Desk → Local observation inspector**, then click **Compare both Windows reports**. The browser can read UTF-8 with or without the Windows PowerShell BOM. It keeps file contents in this tab only. Do not transfer `.porchkey` vaults, private keys or passphrases.

These files can reveal private IP addresses and network profile observations, so review before posting publicly. Comparing them **does not connect PCs, audit security, modify firewall settings, or authorize a LAN handshake**.
## Capture real Windows observations, without connecting PCs

PorchTalk now includes an optional [copy-only Windows field capture script](../docs/FIELD_CAPTURE.md). It runs the existing read-only inspector, validates a conservative private-address plan, and saves an **exclusive-create** JSON report in an existing, operator-selected local folder. It prints a SHA-256 checksum; that is only an integrity checksum, **not identity attestation**.

Run the capture on each owned PC using its *actual* IPv4 addresses, leave original project files untouched, and transfer only copies of the new observation JSON into the Control Room Evidence Desk. The site compares the two reports entirely in the tab. **No socket is opened, no firewall is changed, and the reports do not authorize the experimental LAN handshake or resource use.**
## Development

Requires Node.js 22 or later. From the repository root:

```sh
cd web
npm install
npm run check
npm run dev
npm run build
npm run preview
```

The app uses the GitHub project subpath base **/PorchTalk/**, so the intended site is:

https://michaelwave369.github.io/PorchTalk/

This URL only works once GitHub Pages is configured for GitHub Actions and the deployment has successfully completed.

## GitHub Actions deployment

- `.github/workflows/web-check.yml` runs the local router simulation test suite and Vite build for PRs.
- `.github/workflows/pages.yml` runs a static Pages build/deploy after a change to the web app is merged into `main`, or by manual workflow dispatch.

Repository owner: select **Settings → Pages → Build and deployment → Source: GitHub Actions**, if not already set. After a successful Pages workflow, the URL should serve the React app.

We intentionally **do not publish a test app from unreviewed feature branches**. The dashboard keeps the Python protocol implementation and security-critical runtime separate.

## Security boundaries

Do NOT paste identity vault passphrases, private identity files, API keys, unredacted evidence, or confidential data into this UI. The app does not request them. No fake grant is ever sent to the Python network implementation. Production device pairing and real hardware evidence remain manual processes documented under `../docs`.

**Ledger above ego. Consent before compute.**
