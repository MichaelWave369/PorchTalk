/** Offline, untrusted, bounded JSON inspection. No networking, storage or keys.
 * Browser JSON.parse cannot detect duplicate JSON keys; Python remains authoritative.
 */
export const MAX_LOCAL_JSON_BYTES = 8192
const HEX64 = /^[0-9a-f]{64}$/
const DEVICE_ID = /^[A-Za-z0-9._-]{1,80}$/
const RECEIPT_KEYS = ['status','protocol','local_device_id','local_fingerprint_sha256','peer_device_id','peer_fingerprint_sha256','transcript_sha256','proof_messages_encrypted','handshake_identity_metadata_visible','transport_type','route_authorized','compute_authorized','warnings']
const WARNINGS = ['NOT_SECURITY_AUDITED','ONE_SHOT_ONLY','NO_COMMAND_OR_MODEL_PAYLOAD']
const WINDOWS_KEYS = ['schema','status','generated_at_utc','local_ipv4_entered','peer_ipv4_entered','proposed_port','static_rfc1918_pair_valid','local_ipv4_observed_on_interface','observed_interface_index','observed_prefix_length','observed_network_category','firewall_active_profile_enabled','proposed_port_already_listening','inspection_errors','unresolved_manual_checks','sockets_opened_by_this_script','firewall_modified_by_this_script','private_keys_read_by_this_script','compute_authorized']

export class EvidenceInputError extends Error {}

function exactObject(value, keys, kind) {
  if (!value || Array.isArray(value) || typeof value !== 'object') throw new EvidenceInputError(kind + ' must be a JSON object')
  const present = Object.keys(value)
  if (present.length !== keys.length || present.some(k => !keys.includes(k))) throw new EvidenceInputError(kind + ' has unknown or missing fields')
}
function literalIPv4(value) {
  if (typeof value !== 'string' || !/^[0-9]{1,3}(?:\.[0-9]{1,3}){3}$/.test(value)) return false
  return value.split('.').every(part => (part.length === 1 || part[0] !== '0') && Number(part) <= 255)
}
function privateIPv4(value) {
  if (!literalIPv4(value)) return false
  const [a,b] = value.split('.').map(Number)
  return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)
}
function same24(a,b) {
  if (!privateIPv4(a) || !privateIPv4(b) || a === b) return false
  const left = a.split('.').map(Number), right = b.split('.').map(Number)
  return left.slice(0,3).every((part,i) => part === right[i]) &&
    ![0,255].includes(left[3]) && ![0,255].includes(right[3])
}
const integer = v => Number.isInteger(v)
const boolean = v => typeof v === 'boolean'
const nullable = (v, fn) => v === null || fn(v)
const safeNotes = v => Array.isArray(v) && v.length <= 32 && v.every(note => typeof note === 'string' && note.length <= 120)

export function inspectWindowsReport(value) {
  exactObject(value, WINDOWS_KEYS, 'Windows observation')
  if (value.schema !== 'PORCHTALK_WINDOWS_READINESS_V1' || value.status !== 'OBSERVATION_ONLY_NOT_AN_AUTHORIZATION') {
    throw new EvidenceInputError('Unknown or unauthorized Windows observation format')
  }
  if (typeof value.generated_at_utc !== 'string' || value.generated_at_utc.length > 80 ||
      !literalIPv4(value.local_ipv4_entered) || !literalIPv4(value.peer_ipv4_entered) ||
      !integer(value.proposed_port) || value.proposed_port < 49152 || value.proposed_port > 65535 ||
      !boolean(value.static_rfc1918_pair_valid) || !boolean(value.local_ipv4_observed_on_interface) ||
      !nullable(value.observed_interface_index, v => integer(v) && v >= 0) ||
      !nullable(value.observed_prefix_length, v => integer(v) && v >= 0 && v <= 32) ||
      !nullable(value.observed_network_category, v => typeof v === 'string' && v.length <= 80) ||
      !nullable(value.firewall_active_profile_enabled, boolean) ||
      !nullable(value.proposed_port_already_listening, boolean) ||
      !safeNotes(value.inspection_errors) || !safeNotes(value.unresolved_manual_checks) ||
      value.unresolved_manual_checks.length < 5 ||
      value.sockets_opened_by_this_script !== false ||
      value.firewall_modified_by_this_script !== false ||
      value.private_keys_read_by_this_script !== false || value.compute_authorized !== false) {
    throw new EvidenceInputError('Malformed or misleading Windows observation')
  }
  if (value.static_rfc1918_pair_valid !== same24(value.local_ipv4_entered, value.peer_ipv4_entered)) {
    throw new EvidenceInputError('Address validity contradicts supplied addresses')
  }
  return {
    status: 'UNTRUSTED_WINDOWS_OBSERVATION_INSPECTED',
    observed_local_ipv4: value.local_ipv4_entered, proposed_peer_ipv4: value.peer_ipv4_entered,
    proposed_port: value.proposed_port, private_address_plan: value.static_rfc1918_pair_valid,
    local_interface_claimed: value.local_ipv4_observed_on_interface,
    network_category_claimed: value.observed_network_category,
    firewall_enabled_claimed: value.firewall_active_profile_enabled,
    port_listening_claimed: value.proposed_port_already_listening,
    inspection_error_count: value.inspection_errors.length,
    pending_manual_checks: value.unresolved_manual_checks.slice(),
    network_connected: false, compute_authorized: false, independently_verified: false,
  }
}

export function inspectKnockReceipt(value) {
  exactObject(value, RECEIPT_KEYS, 'Handshake receipt')
  if (value.status !== 'LAN_ONE_SHOT_ENCRYPTED_KNOCK_PASS' ||
      value.protocol !== 'PORCHTALK_LAN_KNOCK_V1' ||
      value.transport_type !== 'EXPERIMENTAL_ED25519_X25519_AESGCM_NOT_TLS') {
    throw new EvidenceInputError('Unrecognized experimental receipt')
  }
  if (typeof value.local_device_id !== 'string' || !DEVICE_ID.test(value.local_device_id) ||
      typeof value.peer_device_id !== 'string' || !DEVICE_ID.test(value.peer_device_id) ||
      value.local_device_id === value.peer_device_id ||
      typeof value.local_fingerprint_sha256 !== 'string' || !HEX64.test(value.local_fingerprint_sha256) ||
      typeof value.peer_fingerprint_sha256 !== 'string' || !HEX64.test(value.peer_fingerprint_sha256) ||
      typeof value.transcript_sha256 !== 'string' || !HEX64.test(value.transcript_sha256) ||
      value.proof_messages_encrypted !== true ||
      value.handshake_identity_metadata_visible !== true ||
      value.route_authorized !== false || value.compute_authorized !== false ||
      !Array.isArray(value.warnings) || value.warnings.length !== WARNINGS.length ||
      !value.warnings.every(w => typeof w === 'string') ||
      !WARNINGS.every(w => value.warnings.includes(w))) {
    throw new EvidenceInputError('Malformed receipt or false security claim')
  }
  return {
    local_device_id: value.local_device_id,
    local_fingerprint_sha256: value.local_fingerprint_sha256,
    peer_device_id: value.peer_device_id,
    peer_fingerprint_sha256: value.peer_fingerprint_sha256,
    transcript_sha256: value.transcript_sha256,
  }
}

export function compareKnockReceipts(left,right) {
  const a = inspectKnockReceipt(left), b = inspectKnockReceipt(right)
  if (a.local_device_id !== b.peer_device_id || a.peer_device_id !== b.local_device_id) {
    throw new EvidenceInputError('Device names do not mirror')
  }
  if (a.local_fingerprint_sha256 !== b.peer_fingerprint_sha256 ||
      a.peer_fingerprint_sha256 !== b.local_fingerprint_sha256) {
    throw new EvidenceInputError('Pinned public-key fingerprints do not cross-match')
  }
  if (a.transcript_sha256 !== b.transcript_sha256) {
    throw new EvidenceInputError('Handshake transcripts differ')
  }
  return {status:'SELF_REPORTED_RECEIPTS_CONSISTENT',devices:[a.local_device_id,b.local_device_id].sort(),
    transcript_sha256:a.transcript_sha256,independently_attested:false,real_hardware_verified:false,session_authorized_for_compute:false}
}

export async function readLocalJSON(file) {
  if (!file || typeof file.name !== 'string' || !/\.json$/i.test(file.name) ||
      !Number.isInteger(file.size) || file.size < 1 || file.size > MAX_LOCAL_JSON_BYTES) {
    throw new EvidenceInputError('Choose a .json file of at most 8 KiB, never a private .porchkey')
  }
  const data = await file.text()
  if (new TextEncoder().encode(data).byteLength > MAX_LOCAL_JSON_BYTES) {
    throw new EvidenceInputError('Evidence exceeds the 8 KiB limit')
  }
  try {
    const parsed = JSON.parse(data)
    if (parsed === null || Array.isArray(parsed) || typeof parsed !== 'object') {
      throw new EvidenceInputError('Top-level JSON must be an object')
    }
    return parsed
  } catch (error) {
    if (error instanceof EvidenceInputError) throw error
    throw new EvidenceInputError('Invalid JSON file')
  }
}
