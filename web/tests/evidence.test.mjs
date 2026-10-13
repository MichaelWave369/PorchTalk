import assert from 'node:assert/strict'
import test from 'node:test'
import { MAX_LOCAL_JSON_BYTES, EvidenceInputError, inspectWindowsReport, inspectKnockReceipt, compareKnockReceipts, readLocalJSON } from '../src/evidence.js'
import { syntheticWindowsObservation as sample, syntheticLeftReceipt as a, syntheticRightReceipt as b } from '../src/evidence-fixtures.js'

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
