import React, { useState } from 'react'
import { AlertTriangle, CheckCircle2, FileJson, FolderOpen, Info, LockKeyhole, RotateCcw, ShieldAlert, ShieldCheck, XCircle } from 'lucide-react'
import { EvidenceInputError, compareKnockReceipts, compareWindowsReports, compareWindowsSummaries, inspectWindowsReport, inspectKnockReceipt, readLocalJSON } from './evidence.js'
import { syntheticWindowsObservation, syntheticNeighborWindowsObservation, syntheticLeftReceipt, syntheticRightReceipt } from './evidence-fixtures.js'

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
  const [neighborReadiness, setNeighborReadiness] = useState(null)
  const [windowsMatch, setWindowsMatch] = useState(null)
  const [fileVersion, setFileVersion] = useState(0)
  const [left, setLeft] = useState(null)
  const [right, setRight] = useState(null)
  const [feedback, setFeedback] = useState('')
  const [source, setSource] = useState('NONE')
  const [pairResult, setPairResult] = useState(null)

  async function loadReport(file, which) {
    setFeedback('')
    setWindowsMatch(null)
    if (source === 'SYNTHETIC_EXAMPLE_ONLY') {
      setReadiness(null)
      setNeighborReadiness(null)
      setLeft(null)
      setRight(null)
      setPairResult(null)
      setFileVersion(n => n + 1)
    }
    if (which === 'main') setReadiness(null)
    else setNeighborReadiness(null)
    setSource('NONE')
    try {
      const report = inspectWindowsReport(await readLocalJSON(file))
      if (which === 'main') setReadiness(report)
      else setNeighborReadiness(report)
      setSource('LOCAL_FILE_UNTRUSTED')
    } catch (error) {
      setFeedback('Windows report refused: ' + (error instanceof EvidenceInputError ? error.message : 'file could not be inspected'))
      throw error
    }
  }

  function compareWindows() {
    setFeedback('')
    setWindowsMatch(null)
    try {
      setWindowsMatch(compareWindowsSummaries(readiness, neighborReadiness))
    } catch (error) {
      setFeedback('Windows reports disagree: ' + (error instanceof EvidenceInputError ? error.message : 'invalid local observation'))
    }
  }

  async function loadReceipt(file, which) {
    setFeedback('')
    setPairResult(null)
    if (source === 'SYNTHETIC_EXAMPLE_ONLY') {
      setReadiness(null)
      setNeighborReadiness(null)
      setWindowsMatch(null)
      setLeft(null)
      setRight(null)
      setFileVersion(n => n + 1)
    }
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
    setNeighborReadiness(inspectWindowsReport(syntheticNeighborWindowsObservation))
    setWindowsMatch(compareWindowsReports(syntheticWindowsObservation, syntheticNeighborWindowsObservation))
    setFileVersion(n => n + 1)
    setLeft(syntheticLeftReceipt)
    setRight(syntheticRightReceipt)
    setPairResult(compareKnockReceipts(syntheticLeftReceipt, syntheticRightReceipt))
    setSource('SYNTHETIC_EXAMPLE_ONLY')
  }

  function clearAll() {
    setFeedback('')
    setReadiness(null)
    setNeighborReadiness(null)
    setWindowsMatch(null)
    setLeft(null)
    setRight(null)
    setPairResult(null)
    setFileVersion(n => n + 1)
    setSource('NONE')
  }

  return <div className="evidence-desk">
    <div className="desk-banner">
      <span><LockKeyhole size={17} /> BROWSER-LOCAL / NO UPLOADS</span>
      <p>Inspect locally saved PorchTalk evidence. Files are read inside this tab only. Never select passwords, identity vaults, private keys, or confidential logs.</p>
      <div className="desk-actions">
        <a className="outlined-btn" href="https://github.com/MichaelWave369/PorchTalk/blob/main/docs/FIELD_CAPTURE.md"
          target="_blank" rel="noopener noreferrer"><Info size={16} /> Field capture guide</a>
        <button className="outlined-btn" type="button" onClick={example}><FileJson size={16} /> Load synthetic example</button>
        <button className="outlined-btn" type="button" onClick={clearAll}><RotateCcw size={16} /> Clear imported evidence</button>
      </div>
      {source === 'SYNTHETIC_EXAMPLE_ONLY' && <div className="desk-example-warning"><AlertTriangle size={16}/> SYNTHETIC DEMO: fabricated device identities, fingerprints, and transcript. This does not represent a hardware test.</div>}
    </div>

    <section className="panel desk-panel">
      <div className="panel-head"><div><span className="kicker">READINESS / WINDOWS</span><h3>Local observation inspector</h3></div><span className="desk-status">NO AUTOMATIC APPROVAL</span></div>
      <div className="desk-twins">
        <EvidenceFile key={'windows-a-' + fileVersion} title="Porch A Windows report"
          subtitle="Read-only PowerShell JSON collected on the first PC"
          onLoad={file => loadReport(file, 'main')} status={!!readiness} />
        <EvidenceFile key={'windows-b-' + fileVersion} title="Porch B Windows report"
          subtitle="Read-only PowerShell JSON collected on the other PC"
          onLoad={file => loadReport(file, 'neighbor')} status={!!neighborReadiness} />
      </div>
      <button className="primary-btn desk-compare" type="button"
        disabled={!readiness || !neighborReadiness}
        onClick={compareWindows}><ShieldCheck size={17}/> Compare both Windows reports</button>
      {(readiness || neighborReadiness) ? <div className="desk-results">
        {[
          {label: 'Porch A', value: readiness},
          {label: 'Porch B', value: neighborReadiness},
        ].map(item => <div key={item.label} className="desk-observation">
          <small>{item.label}</small>
          <strong>{item.value?.observed_local_ipv4 || 'NOT IMPORTED'}</strong>
          <p>Expected peer: {item.value?.proposed_peer_ipv4 || 'Unknown'}</p>
          <p>Port: {item.value?.proposed_port ?? 'Unknown'}</p>
          <p>Interface: {item.value ? (item.value.local_interface_claimed ? 'Claimed present' : 'Not observed') : 'Unknown'}</p>
          <p>Firewall: {item.value?.firewall_enabled_claimed === null || !item.value ? 'Unknown' : item.value.firewall_enabled_claimed ? 'Reported on' : 'Reported off'}</p>
        </div>)}
      </div> : <p className="desk-placeholder">Import two separate read-only Windows reports, one collected on each physical PC, or load the synthetic example. Nothing is uploaded.</p>}
      {windowsMatch && <div className="desk-pass">
        <CheckCircle2 size={21}/><div>
          <strong>Supplied private-address plans cross-match</strong>
          <p>{windowsMatch.porch_a_ipv4} ↔ {windowsMatch.porch_b_ipv4} · proposed port {windowsMatch.proposed_port}</p>
          <small>{windowsMatch.observation_warnings.length} observations require attention · {windowsMatch.manual_checks_remain.length} mandatory manual reviews still open.</small>
          {windowsMatch.observation_warnings.length > 0 && <ul className="desk-findings">
            {windowsMatch.observation_warnings.map(w => <li key={w}>{w.replaceAll('_', ' ').toLowerCase()}</li>)}
          </ul>}
          <p className="desk-no-approval">NOT independently attested · NOT real-hardware verified · NO permission to open a port or share compute.</p>
        </div>
      </div>}
      <div className="desk-advisory"><ShieldAlert size={18}/><div><strong>Address consistency is not network readiness</strong>
        <p>Neither JSON file proves interface ownership, trusted fingerprint enrollment, protected Windows keys, correct firewall rules or router isolation. Actual network tests still require separate operator authorization and security review.</p>
      </div></div>
    </section>

    <section className="panel desk-panel">
      <div className="panel-head"><div><span className="kicker">HANDSHAKE / EVIDENCE</span><h3>Compare two Porch receipts</h3></div><span className="desk-status">SELF-REPORTED ONLY</span></div>
      <div className="desk-twins">
        <EvidenceFile key={'receipt-a-' + fileVersion} title="Porch A receipt" subtitle="JSON from one participant's one-shot handshake" onLoad={file => loadReceipt(file, 'left')} status={!!left} />
        <EvidenceFile key={'receipt-b-' + fileVersion} title="Porch B receipt" subtitle="JSON from the other participant's handshake" onLoad={file => loadReceipt(file, 'right')} status={!!right} />
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
