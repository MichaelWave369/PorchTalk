import { classifySdkOrigin, makeConsumerReceipt, POCKETBRAIN_TINY_SDK_URL } from './tiny-ai-origin.mjs';

const byId = (id) => document.getElementById(id);
const loadBtn = byId('tiny-load');
const generateBtn = byId('tiny-generate');
const copyBtn = byId('tiny-copy');
const prompt = byId('tiny-prompt');
const output = byId('tiny-output');
const status = byId('tiny-status');
const lastReceipt = byId('tiny-receipt');
const originStatus = byId('tiny-origin');
const backend = byId('tiny-backend');
const mode = byId('tiny-mode');

let client = null;
let completedReceipt = null;
let classification = classifySdkOrigin(location.href);
originStatus.textContent = classification.different_origin
  ? 'Distinct origins: YES · Browser must permit a cross-origin ESM import.'
  : 'Distinct origins: NO · Both URLs share ' + classification.consumer_origin + '.';

function errorText(error) {
  return error instanceof Error ? error.message : String(error);
}

loadBtn.addEventListener('click', async () => {
  loadBtn.disabled = true;
  backend.disabled = true;
  status.textContent = 'Importing PocketBrain SDK (opt-in)…';
  try {
    // Import itself is delayed until a direct Load click.
    // The SDK's own load() then fetches remote inference runtime/model artifacts.
    const { createPocketBrainTinyClient } = await import(POCKETBRAIN_TINY_SDK_URL);
    client = createPocketBrainTinyClient();
    status.textContent = 'PocketBrain SDK module imported; loading real model…';
    await client.load({
      preferredDevice: backend.value,
      onProgress(event) {
        if (typeof event?.status === 'string') {
          status.textContent = 'Loading model · ' + event.status;
        }
      },
    });
    const state = client.getStatus();
    if (!state.ready) throw new Error('SDK did not report a ready model.');
    status.textContent = 'READY · ' + state.model + ' · ' + state.device + ' · ' + state.dtype;
    generateBtn.disabled = false;
  } catch (error) {
    status.textContent = 'Load failed: ' + errorText(error);
    loadBtn.disabled = false;
    backend.disabled = false;
    client = null;
  }
});

generateBtn.addEventListener('click', async () => {
  if (!client?.getStatus().ready || !prompt.value.trim()) {
    output.textContent = 'Load a model and enter a prompt.';
    return;
  }
  generateBtn.disabled = true;
  copyBtn.disabled = true;
  completedReceipt = null;
  output.textContent = 'Generating…';
  lastReceipt.textContent = 'No completed inference receipt.';
  try {
    const result = await client.generate(prompt.value, {
      mode: mode.value,
      maxNewTokens: 64,
      onText(value) { output.textContent = value; },
    });
    output.textContent = result.text;
    completedReceipt = makeConsumerReceipt(result.receipt, classification, client.getStatus());
    lastReceipt.textContent = JSON.stringify(completedReceipt, null, 2);
    copyBtn.disabled = false;
  } catch (error) {
    output.textContent = 'Generation failed: ' + errorText(error);
  } finally {
    generateBtn.disabled = false;
  }
});

copyBtn.addEventListener('click', async () => {
  if (!completedReceipt) return;
  try {
    await navigator.clipboard.writeText(JSON.stringify(completedReceipt, null, 2));
    copyBtn.textContent = 'Receipt copied';
  } catch {
    copyBtn.textContent = 'Copy blocked · manually select JSON';
  }
});
