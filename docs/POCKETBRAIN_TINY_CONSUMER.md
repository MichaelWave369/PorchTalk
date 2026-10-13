# PorchTalk × PocketBrain Tiny: isolated opt-in SDK consumer

**Evidence level:** Experimental. This is a separate static page under PorchTalk; it is not wired into the Python router, B1 grants, B2 identity, B3/B4 transport, web route simulator or any remote peer.

## Operator-reported precursor

A PocketBrain-hosted SDK consumer was observed on 2026-10-12 generating a 204-character answer to a 69-character prompt on WebGPU q4f16 using ONNX SmolLM2-135M. The supplied local, self-reported receipt stated:

- 416.5 ms total wall time, including model prefill and JavaScript overhead.
- 42.8 ms first token callback and 58.4 ms first visible text.
- 39 token callback events and 93.64 callback events/s over the **whole generation**.
- No parity reference, cache claim or independent throughput benchmark.

This proved SDK-mediated inference on PocketBrain's site **only**, not independent-origin use. The earlier PocketBrain v0.2 main lab run was also real, but a different prompt/length, so these numbers do not establish a speedup.

## Test the independent PorchTalk application

After merge and deployment, open:

`https://michaelwave369.github.io/PorchTalk/tiny-ai-lab.html`

Click **Explicitly load PocketBrain AI**. That is the only event that imports the PocketBrain SDK and triggers third-party runtime/model downloads. Generate, then inspect the nested `POCKETBRAIN_TINY_RUN_V2` receipt and copy the combined `PORCHTALK_POCKETBRAIN_SDK_CONSUMER_V1` receipt if you wish.

**Crucial:** PorchTalk and PocketBrain GitHub Pages paths are under the **same** `https://michaelwave369.github.io` origin. This tests a different *application* but **not** browser CORS across two origins.

## Test a genuinely independent browser origin

On your own PC, run PorchTalk's normal local Vite server:

```sh
cd web
npm install
npm run dev
```

Then open:

`http://127.0.0.1:5173/PorchTalk/tiny-ai-lab.html`

The consumer runs at `http://127.0.0.1:5173`, while the imported SDK runs from `https://michaelwave369.github.io`. The lab reports `is_cross_origin=true` and the **actual** remote dynamic ESM import must succeed before a model can load. A successful model response with a nested receipt is an operator-observed end-to-end cross-origin test. If your dev server maps static files differently, use the served `/tiny-ai-lab.html` path and inspect the browser URL's origin; the script's origin check is what matters.

This is still **not** broad production CORS compatibility or a security certification. It tests one origin, one browser, one model.

## Boundaries and privacy

- Merely opening the new page does not import PocketBrain. The SDK is imported inside the Load click handler.
- That click downloads PocketBrain JS from GitHub Pages, executable Transformers.js from jsDelivr, and model artifacts from Hugging Face. Network hosts see standard request metadata.
- Inference is local to the consumer's browser. No prompt is uploaded to an inference API by this integration.
- No credentials, stored memory, PorchTalk devices, route grants or private keys are read. No peers contacted.
- The receipt is in memory and copies to clipboard only when the operator clicks Copy.
- The SDK entrypoint is **not** fully immutable: it transitively imports PocketBrain files not pinned to a commit. Do not promote for production until pinned, hashed and independently verified.
- The root PorchTalk Control Room remains a simulation with no inference workers. This is a separate, explicitly opened experiment.

## Validation

`cd web && npm run check && npm run build` tests origin classification, consent wiring, and receipt contract. CI tests only stubs and source; **it never downloads or executes a real model**. Real inference and CORS are hardware/browser tests.

## Next gates

- [ ] Host and verify cross-application generation on the separate PorchTalk page.
- [ ] Run locally at a different browser origin and record the import result + actual model receipt.
- [ ] Pin SDK and model assets to immutable revisions, verify licensing, CORS and supply chain.
- [ ] Confirm CPU and mobile behavior and failure modes.
- [ ] Obtain separate explicit authorization for any real PorchTalk routing integration.

Ledger above ego.
