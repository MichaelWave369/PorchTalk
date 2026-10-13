/** Synthetic fixtures for UI education ONLY, never actual real-device receipts. */
export const syntheticWindowsObservation = {
  schema:'PORCHTALK_WINDOWS_READINESS_V1',
  status:'OBSERVATION_ONLY_NOT_AN_AUTHORIZATION',
  generated_at_utc:'2026-10-12T00:00:00.000Z',
  local_ipv4_entered:'192.168.10.15',
  peer_ipv4_entered:'192.168.10.20',
  proposed_port:54321,
  static_rfc1918_pair_valid:true,
  local_ipv4_observed_on_interface:false,
  observed_interface_index:null,
  observed_prefix_length:null,
  observed_network_category:null,
  firewall_active_profile_enabled:null,
  proposed_port_already_listening:null,
  inspection_errors:['EXAMPLE_ONLY_NO_WINDOWS_PC_INSPECTED'],
  unresolved_manual_checks:[
    'VERIFY_PEER_PUBLIC_KEY_FINGERPRINT_OUT_OF_BAND',
    'INSPECT_VAULT_AND_TRUST_DATABASE_WINDOWS_ACLS',
    'VERIFY_ROUTER_HAS_NO_PORT_FORWARDING_OR_EXPOSURE',
    'LIMIT_TEMPORARY_INBOUND_FIREWALL_RULE_TO_INTENDED_PEER',
    'VERIFY_PEER_NETWORK_SEGMENT_AND_GUEST_WIFI_ISOLATION',
    'REVIEW_CUSTOM_PROTOCOL_SECURITY_BEFORE_ANY_REAL_USE',
  ],
  sockets_opened_by_this_script:false,
  firewall_modified_by_this_script:false,
  private_keys_read_by_this_script:false,
  compute_authorized:false,
}
const shared = {
  status:'LAN_ONE_SHOT_ENCRYPTED_KNOCK_PASS',
  protocol:'PORCHTALK_LAN_KNOCK_V1',
  transcript_sha256:'a'.repeat(64),
  proof_messages_encrypted:true,
  handshake_identity_metadata_visible:true,
  transport_type:'EXPERIMENTAL_ED25519_X25519_AESGCM_NOT_TLS',
  route_authorized:false,
  compute_authorized:false,
  warnings:['NOT_SECURITY_AUDITED','ONE_SHOT_ONLY','NO_COMMAND_OR_MODEL_PAYLOAD'],
}
export const syntheticLeftReceipt = {
  ...shared, local_device_id:'sample-main-pc', local_fingerprint_sha256:'b'.repeat(64),
  peer_device_id:'sample-neighbor', peer_fingerprint_sha256:'c'.repeat(64),
}
export const syntheticRightReceipt = {
  ...shared, local_device_id:'sample-neighbor', local_fingerprint_sha256:'c'.repeat(64),
  peer_device_id:'sample-main-pc', peer_fingerprint_sha256:'b'.repeat(64),
}


export const syntheticNeighborWindowsObservation = {
  ...syntheticWindowsObservation,
  local_ipv4_entered:'192.168.10.20',
  peer_ipv4_entered:'192.168.10.15',
  // This is a FAKE record for UI demonstration, not independent hardware proof.
  inspection_errors:['EXAMPLE_ONLY_NO_WINDOWS_PC_INSPECTED'],
}
