import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import {
  POCKETBRAIN_TINY_SDK_URL, classifySdkOrigin, makeConsumerReceipt,
} from '../public/tiny-ai-origin.mjs';

test('PocketBrain and PorchTalk Pages are different applications but same browser origin', () => {
  const finding = classifySdkOrigin('https://michaelwave369.github.io/PorchTalk/tiny-ai-lab.html');
  assert.equal(finding.different_origin, false);
  assert.equal(finding.sdk_origin, 'https://michaelwave369.github.io');
});

test('PorchTalk localhost and remote PocketBrain are distinct browser origins', () => {
  const finding = classifySdkOrigin('http://127.0.0.1:5173/PorchTalk/tiny-ai-lab.html');
  assert.equal(finding.different_origin, true);
  assert.equal(finding.consumer_origin, 'http://127.0.0.1:5173');
  assert.throws(() => classifySdkOrigin('https://some.example/', 'http://some.example/sdk.mjs'), /HTTPS/);
});

test('external URL fixed, no secret text in integration receipt', () => {
  assert.equal(POCKETBRAIN_TINY_SDK_URL, 'https://michaelwave369.github.io/PocketBrain/sdk/v0.1/index.mjs');
  const finding = classifySdkOrigin('http://127.0.0.1:5173/');
  const actual = makeConsumerReceipt(
    {
      schema: 'POCKETBRAIN_TINY_RUN_V2',
      generation_wall_ms: 416.5, mode: 'baseline',
      prompt_or_output_text_in_receipt: false,
    },
    finding,
    { ready: true, model: 'onnx-community/SmolLM2-135M-Instruct-ONNX-GQA', device: 'webgpu', version: '0.1.0-experimental' },
  );
  assert.equal(actual.inference_completed, true);
  assert.equal(actual.is_cross_origin, true);
  assert.equal(actual.porch_remote_compute_authorized, false);
  assert.equal(actual.peers_contacted, false);
  assert.equal(actual.prompt_or_response_in_receipt, false);
  assert.equal(actual.model_receipt.generation_wall_ms, 416.5);
  assert.throws(() => makeConsumerReceipt({ schema: 'FAKE' }, finding, { ready: true, model: 'x' }), /Expected a real Tiny/);
});

test('default PorchTalk app does not eagerly import external SDK', () => {
  const html = readFileSync(new URL('../public/tiny-ai-lab.html', import.meta.url), 'utf8');
  const lab = readFileSync(new URL('../public/tiny-ai-lab.mjs', import.meta.url), 'utf8');
  assert.match(html, /id="tiny-load"/);
  assert.match(html, /NOT distinct browser origins/);
  assert.match(lab, /loadBtn\.addEventListener\('click'/);
  assert.match(lab, /await import\(POCKETBRAIN_TINY_SDK_URL\)/);
  assert.doesNotMatch(lab, /^import\s*\{[^}]*createPocketBrainTinyClient/m);
  assert.match(lab, /makeConsumerReceipt\(/);
});
