/** Pure, no-network origin classification for PorchTalk's optional Tiny SDK experiment. */
export const POCKETBRAIN_TINY_SDK_URL = 'https://michaelwave369.github.io/PocketBrain/sdk/v0.1/index.mjs';

export function classifySdkOrigin(consumerUrl, sdkUrl = POCKETBRAIN_TINY_SDK_URL) {
  const consumer = new URL(consumerUrl);
  const sdk = new URL(sdkUrl);
  if (sdk.protocol !== 'https:') {
    throw new Error('SDK import must use HTTPS.');
  }
  return Object.freeze({
    consumer_origin: consumer.origin,
    sdk_origin: sdk.origin,
    different_origin: consumer.origin !== sdk.origin,
    evidence: 'ORIGIN_CLASSIFICATION_ONLY_NOT_CORS_OR_MODEL_PROOF',
  });
}

export function makeConsumerReceipt(generationReceipt, classification, sdkStatus) {
  if (!generationReceipt || generationReceipt.schema !== 'POCKETBRAIN_TINY_RUN_V2') {
    throw new Error('Expected a real Tiny v0.2 receipt from an SDK generation.');
  }
  if (!sdkStatus?.model || !sdkStatus?.ready) {
    throw new Error('SDK must report a ready model.');
  }
  return {
    schema: 'PORCHTALK_POCKETBRAIN_SDK_CONSUMER_V1',
    evidence: 'OPERATOR_BROWSER_SELF_REPORTED',
    consumer_app: 'PorchTalk optional local inference lab',
    consumer_origin: classification.consumer_origin,
    sdk_origin: classification.sdk_origin,
    is_cross_origin: classification.different_origin,
    sdk_model: sdkStatus.model,
    sdk_backend: sdkStatus.device,
    sdk_version: sdkStatus.version,
    imported_sdk_executed: true,
    inference_completed: true,
    porch_remote_compute_authorized: false,
    porch_routing_used: false,
    peers_contacted: false,
    prompt_or_response_in_receipt: false,
    caveat: 'This does not independently validate CORS on other origins, production supply-chain integrity, model parity, or performance.',
    model_receipt: generationReceipt,
  };
}
