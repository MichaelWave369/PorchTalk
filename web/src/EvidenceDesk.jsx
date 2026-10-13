import React, { useState } from 'react'
import { AlertTriangle, CheckCircle2, FileJson, FolderOpen, Info, LockKeyhole, RotateCcw, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react'
import { EvidenceInputError, compareKnockReceipts, inspectWindowsReport, inspectKnockReceipt, readLocalJSON } from './evidence.js'
import { syntheticWindowsObservation, syntheticLeftReceipt, syntheticRightReceipt } from './evidence-fixtures.js'

function EvidenceFile({ title, subtitle, onLoad, status }) {
  const [filename, setFilename] = useState('')
  async function change(e) {
    const file = e.target.files?.[0]
    if (!file) return
    try {
      await onLoad(file)
      setFilename(file.name)
    } catch (_) {
      setFilename('')
    }
    e.target.value = ''
  }
  return <div className="desk-file">
    <div className="desk-file-icon"><FileJson size={24} /></div>
    <div className="desk-file-copy"><strong>{title}</strong><p>{subtitle}</p>{filename && <small className="desk-file-name">{filename}</small>}</div>
    <label className="desk-file-button"><FolderOpen size={15}/> Choose JSON
      <input type="file" accept=".json,application/json" onChange={change} aria-label={'Choose ' + title + ' JSON file'} />
    </label>
    {status && <div className="desk-file-status"><CheckCircle2 size={15} /> Locally inspected</div>}
  </div>
}

export default function EvidenceDesk() {
  const [readiness, setReadiness] = useState(null)
  const [left, setLeft] = useState(null)
  const [right, setRight] = useState(null)
  const [feedback, setFeedback] = useState('')
  const [source, setSource] = useState('NONE')
  const [pairResult, setPairResult] = useState(null)

  async function loadReport(file) {
    setFeedback('')
    setReadiness(null)
    setSource('NONE')
    try {
      const report = inspectWindowsReport(await readLocalJSON(file))
      setReadiness(report)
      setSource('LOCAL_FILE_UNTRUSTED')
    } catch (error) {
      setFeedback('Windows report refused: ' + (error instanceof EvidenceInputError ? error.message : 'file could not be inspected'))
      throw error
    }
  }

  async function loadReceipt(file, which) {
    setFeedback('')
    setPairResult(null)
    if (which === 'left') setLeft(null)
    else setRight(null)
    setSource('LOCAL_FILE_UNTRUSTED')
    try {
      const raw = await readLocalJSON(file)
      inspectKnockReceipt(raw)
      if (which === 'left') setLeft(raw)
      else setRight(raw)
    } catch (error) {
      setFeedback('Handshake receipt refused: ' + (error instanceof EvidenceInputError ? error.message : 'file could not be inspected'))
      throw error
    }
  }

  function compare() {
    setFeedback('')
    setPairResult(null)
    try {
      setPairResult(compareKnockReceipts(left, right))
    } catch (error) {
      setFeedback('Receipts do not match: ' + (error instanceof EvidenceInputError ? error.message : 'invalid evidence'))
    }
  }

  function example() {
    setFeedback('')
    setReadiness(inspectWindowsReport(syntheticWindowsObservation))
    setLeft(syntheticLeftReceipt)
    setRight(syntheticRightReceipt)
    setPairResult(compareKnockReceipts(syntheticLeftReceipt, syntheticRightReceipt))
    setSource('SYNTHETIC_EXAMPLE_ONLY')
  }

  function clearAll() {
    setFeedback('')
    setReadiness(null)
    setLeft(null)
    setRight(null)
    setPairResult(null)
    setSource('NONE')
  }

  return <div className="evidence-desk">
    <div className="desk-banner">
      <span><LockKeyhole size={17} /> BROWSER-LOCAL / NO UPLOADS</span>
      <p>Inspect locally saved PorchTalk evidence. Files are read inside this tab only. Never select passwords, identity vaults, private keys, or confidential logs.</p>
      <div className="desk-actions">
        <button className="outlined-btn" type="button" onClick={example}><FileJson size={16} /> Load synthetic example</button>
        <button className="outlined-btn" type="button" onClick={clearAll}><RotateCcw size={16} /> Clear imported evidence</button>
      </div>
      {source === 'SYNTHETIC_EXAMPLE_ONLY' && <div className="desk-example-warning"><AlertTriangle size={16}/> SYNTHETIC DEMO: fabricated device identities, fingerprints, and transcript. This does not represent a hardware test.</div>}
    </div>

    <section className="panel desk-panel">
      <div className="panel-head"><div><span className="kicker">READINESS / WINDOWS</span><h3>Local observation inspector</h3></div><span className="desk-status">NO AUTOMATIC APPROVAL</span></div>
      <EvidenceFile title="Windows readiness report" subtitle="JSON output from the read-only PowerShell inspector" onLoad={loadReport} status={!!readiness} />
      {readiness ? <>
        <div className="desk-results">
          <div><small>Entered local address</small><strong>{readiness.observed_local_ipv4}</strong></div>
          <div><small>Proposed peer address</small><strong>{readiness.proposed_peer_ipv4}</strong></div>
          <div><small>Port</small><strong>{readiness.proposed_port}</strong></div>
          <div><small>Address plan</small><strong>{readiness.private_address_plan ? 'RFC1918 /24 format' : 'INVALID PLAN'}</strong></div>
          <div><small>Windows interface claim</small><strong>{readiness.local_interface_claimed ? 'Observed by report' : 'Not observed'}</strong></div>
          <div><small>Firewall enabled claim</small><strong>{readiness.firewall_enabled_claimed === null ? 'UNKNOWN' : readiness.firewall_enabled_claimed ? 'Enabled (not clearance)' : 'DISABLED'}</strong></div>
        </div>
        <div className="desk-advisory"><ShieldAlert size={18}/><div><strong>Still requires operator review</strong><p>{readiness.pending_manual_checks.length} manual checks unresolved. Report errors: {readiness.inspection_error_count}. An enabled firewall or a valid address is not proof of safe connectivity.</p></div></div>
      </> : <p className="desk-placeholder">Nothing imported. Use the read-only Windows script in the repository to produce a report, or try the synthetic example.</p>}
    </section>

    <section className="panel desk-panel">
      <div className="panel-head"><div><span className="kicker">HANDSHAKE / EVIDENCE</span><h3>Compare two Porch receipts</h3></div><span className="desk-status">SELF-REPORTED ONLY</span></div>
      <div className="desk-twins">
        <EvidenceFile title="Porch A receipt" subtitle="JSON from one participant's one-shot handshake" onLoad={file => loadReceipt(file, 'left')} status={!!left} />
        <EvidenceFile title="Porch B receipt" subtitle="JSON from the other participant's handshake" onLoad={file => loadReceipt(file, 'right')} status={!!right} />
      </div>
      <button className="primary-btn desk-compare" type="button" disabled={!left || !right} onClick={compare}><ShieldCheck size={17}/> Compare two local receipts</button>
      {pairResult && <div className="desk-pass">
        <CheckCircle2 size={21}/><div><strong>Self-reported receipts are consistent</strong>
          <p>{pairResult.devices.join(' ↔ ')} · matching identity fingerprints and transcript hash.</p>
          <small>NOT independently attested · NOT verified physical hardware · NO compute authorization.</small>
        </div>
      </div>}
      {!pairResult && <p className="desk-placeholder">Receipts must contain mirrored device names, matching public-key fingerprints, and an identical transcript digest. The browser cannot authenticate the files' origin.</p>}
    </section>

    {feedback && <div role="alert" className="desk-error"><XCircle size={18}/>{feedback}</div>}
    <div className="desk-footer-note"><Info size={18}/><p>These are browser-side checks, not the Python protocol verifier. JavaScript JSON parsing does not detect duplicate object keys. For stricter offline validation, use <code>python -m porchtalk.evidence_cli a.json b.json</code> from a trusted local checkout. No import authorizes a route, a compute grant, or an actual LAN connection.</p></div>
  </div>
}
