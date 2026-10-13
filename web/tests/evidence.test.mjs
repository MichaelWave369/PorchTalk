import assert from 'node:assert/strict'
import test from 'node:test'
import { MAX_LOCAL_JSON_BYTES, EvidenceInputError, inspectWindowsReport, inspectKnockReceipt, compareKnockReceipts, compareWindowsReports, compareWindowsSummaries, readLocalJSON } from '../src/evidence.js'
import { syntheticWindowsObservation as sample, syntheticNeighborWindowsObservation as neighbor, syntheticLeftReceipt as a, syntheticRightReceipt as b } from '../src/evidence-fixtures.js'

const copy = value => structuredClone(value)

test('Windows synthetic report is inspected without granting authority', () => {
  const r = inspectWindowsReport(sample)
  assert.equal(r.status, 'UNTRUSTED_WINDOWS_OBSERVATION_INSPECTED')
  assert.equal(r.compute_authorized, false)
  assert.equal(r.independently_verified, false)
  assert.equal(r.local_interface_claimed, false)
  assert.equal(r.firewall_enabled_claimed, null)
})
test('reject false private-address validity claim', () => {
  const forged = copy(sample)
  forged.local_ipv4_entered = '8.8.8.8'
  assert.throws(() => inspectWindowsReport(forged), EvidenceInputError)
})
test('reject misleading grant from Windows report', () => {
  const bad = copy(sample)
  bad.compute_authorized = true
  assert.throws(() => inspectWindowsReport(bad), EvidenceInputError)
})
test('refuse unknown keys in readiness input', () => {
  assert.throws(() => inspectWindowsReport({...sample, execute:'shell'}), EvidenceInputError)
})
test('refuse malformed observations and removed human checks', () => {
  const bad = copy(sample)
  bad.unresolved_manual_checks = []
  assert.throws(() => inspectWindowsReport(bad), EvidenceInputError)
  const bad2 = copy(sample)
  bad2.firewall_modified_by_this_script = true
  assert.throws(() => inspectWindowsReport(bad2), EvidenceInputError)
})
test('firewall enabled is a claimed observation only', () => {
  const observed = {...sample, firewall_active_profile_enabled:true}
  assert.equal(inspectWindowsReport(observed).firewall_enabled_claimed,true)
  assert.equal(inspectWindowsReport(observed).independently_verified,false)
})
test('proper mirrored receipts are only self-reported consistency', () => {
  const matched = compareKnockReceipts(a,b)
  assert.equal(matched.status,'SELF_REPORTED_RECEIPTS_CONSISTENT')
  assert.equal(matched.independently_attested,false)
  assert.equal(matched.real_hardware_verified,false)
  assert.equal(matched.session_authorized_for_compute,false)
})
test('reject forged compute authorization on either receipt', () => {
  assert.throws(() => compareKnockReceipts({...a,compute_authorized:true},b),EvidenceInputError)
  assert.throws(() => compareKnockReceipts(a,{...b,route_authorized:true}),EvidenceInputError)
})
test('reject missing warning or fabricated protocol/transport status', () => {
  assert.throws(() => compareKnockReceipts({...a,warnings:['ONE_SHOT_ONLY']},b),EvidenceInputError)
  assert.throws(() => inspectKnockReceipt({...a,protocol:'TLSv1.3'}),EvidenceInputError)
})
test('reject mismatched transcripts and public key pins', () => {
  assert.throws(() => compareKnockReceipts(a,{...b,transcript_sha256:'f'.repeat(64)}),EvidenceInputError)
  assert.throws(() => compareKnockReceipts(a,{...b,peer_fingerprint_sha256:'f'.repeat(64)}),EvidenceInputError)
})
test('reject mismatched device names and same-device claims', () => {
  assert.throws(() => compareKnockReceipts(a,{...b,local_device_id:'impostor'}),EvidenceInputError)
  assert.throws(() => inspectKnockReceipt({...a,peer_device_id:'sample-main-pc'}),EvidenceInputError)
})
test('reject missing, extra, and unexpected fields', () => {
  const bad = copy(a)
  delete bad.transcript_sha256
  assert.throws(() => inspectKnockReceipt(bad),EvidenceInputError)
  assert.throws(() => inspectKnockReceipt({...a,run_shell:true}),EvidenceInputError)
})
test('bounded JSON reader accepts synthetic JSON within limit', async () => {
  const text = JSON.stringify(a)
  const file = {name:'test.json',size:Buffer.byteLength(text),text:async()=>text}
  assert.deepEqual(await readLocalJSON(file),a)
})
test('JSON reader refuses a private vault, oversized file and wrong type', async () => {
  const huge = {name:'sample.json',size:MAX_LOCAL_JSON_BYTES+1,text:async()=>'{}'}
  await assert.rejects(readLocalJSON(huge),EvidenceInputError)
  await assert.rejects(readLocalJSON({name:'key.porchkey',size:2,text:async()=>'{}'}),EvidenceInputError)
  await assert.rejects(readLocalJSON({name:'array.json',size:2,text:async()=>'[]'}),EvidenceInputError)
  await assert.rejects(readLocalJSON({name:'bad.json',size:4,text:async()=>'{bad'}),EvidenceInputError)
})
test('filename extension cannot bypass byte-size verification', async () => {
  const fake = {name:'safe.json',size:3,text:async()=> 'X'.repeat(MAX_LOCAL_JSON_BYTES+1)}
  await assert.rejects(readLocalJSON(fake),EvidenceInputError)
})


test('two mirrored private address plans are consistent but never authorized', () => {
  const result = compareWindowsReports(sample, neighbor)
  assert.equal(result.status, 'SELF_REPORTED_WINDOWS_PLANS_MATCH_WITH_MANUAL_BLOCKERS')
  assert.equal(result.porch_a_ipv4, '192.168.10.15')
  assert.equal(result.porch_b_ipv4, '192.168.10.20')
  assert.equal(result.proposed_port, 54321)
  assert.equal(result.matching_static_private_ipv4_plan, true)
  assert.equal(result.real_hardware_verified, false)
  assert.equal(result.independently_attested, false)
  assert.equal(result.lan_connection_authorized, false)
  assert.equal(result.compute_authorized, false)
  assert.ok(result.manual_checks_remain.length >= 6)
})
test('refuse when both Windows reports claim the same local address', () => {
  assert.throws(() => compareWindowsReports(sample, sample), /same local device/)
})
test('refuse reports not addressing each other in reverse', () => {
  const falsePeer = copy(neighbor)
  falsePeer.peer_ipv4_entered = '192.168.10.25'
  assert.throws(() => compareWindowsReports(sample, falsePeer), EvidenceInputError)
})
test('refuse mismatched proposed TCP ports', () => {
  assert.throws(() => compareWindowsReports(sample, {...neighbor, proposed_port:54322}), /ports differ/)
})
test('refuse public or incomplete private address plans', () => {
  const invalid = copy(neighbor)
  invalid.local_ipv4_entered = '8.8.8.8'
  invalid.static_rfc1918_pair_valid = false
  assert.throws(() => compareWindowsReports(sample, invalid), EvidenceInputError)
  assert.throws(() => compareWindowsReports(sample, {...neighbor, static_rfc1918_pair_valid:false}), EvidenceInputError)
})
test('missing reported interfaces and unknown firewall/ports are findings, not approvals', () => {
  const result = compareWindowsReports(sample, neighbor)
  assert.ok(result.observation_warnings.includes('PORCH_A_LOCAL_INTERFACE_NOT_OBSERVED'))
  assert.ok(result.observation_warnings.includes('PORCH_B_LOCAL_INTERFACE_NOT_OBSERVED'))
  assert.ok(result.observation_warnings.includes('PORCH_A_FIREWALL_NOT_CONFIRMED_ENABLED'))
  assert.ok(result.observation_warnings.includes('PORCH_B_PORT_STATUS_UNKNOWN'))
  assert.ok(result.observation_warnings.includes('PORCH_A_INSPECTION_ERRORS'))
})
test('apparently clean self-reported observations still cannot authorize networking', () => {
  const clean = src => ({
    ...src, local_ipv4_observed_on_interface:true,
    observed_interface_index:5, observed_prefix_length:24,
    observed_network_category:'Private', firewall_active_profile_enabled:true,
    proposed_port_already_listening:false, inspection_errors:[],
  })
  const result = compareWindowsReports(clean(sample), clean(neighbor))
  assert.deepEqual(result.observation_warnings, [])
  assert.equal(result.lan_connection_authorized, false)
  assert.equal(result.real_hardware_verified, false)
  assert.ok(result.manual_checks_remain.includes('OBTAIN_INDEPENDENT_SECURITY_REVIEW_OF_EXPERIMENTAL_PROTOCOL'))
})
test('existing listener or Public network profile is flagged', () => {
  const aBad = {...sample, proposed_port_already_listening:true, observed_network_category:'Public'}
  const result = compareWindowsReports(aBad, neighbor)
  assert.ok(result.observation_warnings.includes('PORCH_A_PROPOSED_PORT_ALREADY_LISTENING'))
  assert.ok(result.observation_warnings.includes('PORCH_A_NETWORK_PROFILE_NOT_PRIVATE'))
})
test('cannot compare missing, unchecked or non-inspected observations', () => {
  assert.throws(() => compareWindowsSummaries(null, inspectWindowsReport(neighbor)), EvidenceInputError)
  assert.throws(() => compareWindowsSummaries({status:'READY'}, inspectWindowsReport(neighbor)), EvidenceInputError)
})
test('comparison is symmetric for reversed machine order without changing trust verdict', () => {
  const forward = compareWindowsReports(sample, neighbor)
  const reverse = compareWindowsReports(neighbor, sample)
  assert.equal(forward.porch_a_ipv4, reverse.porch_b_ipv4)
  assert.equal(forward.porch_b_ipv4, reverse.porch_a_ipv4)
  assert.equal(forward.lan_connection_authorized, reverse.lan_connection_authorized)
  assert.equal(forward.real_hardware_verified, false)
})
test('validated bounded summaries may be compared without keeping original JSON', () => {
  const result = compareWindowsSummaries(inspectWindowsReport(sample), inspectWindowsReport(neighbor))
  assert.equal(result.status, 'SELF_REPORTED_WINDOWS_PLANS_MATCH_WITH_MANUAL_BLOCKERS')
  assert.equal(result.lan_connection_authorized, false)
})
