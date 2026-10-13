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
