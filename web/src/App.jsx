import React, { useMemo, useState } from 'react'
import { decide } from './routing.js'
import EvidenceDesk from './EvidenceDesk.jsx'
import {
  Activity, ArrowDownRight, ArrowRight, ArrowUpRight, Ban, BookOpen, Cable,
  Check, CheckCircle2, ChevronDown, ChevronRight, CircleDot, Clock3,
  Code2, Copy, Cpu, Database, Download, ExternalLink, FileCheck2,
  Fingerprint, Github, Globe2, HardDrive, HeartHandshake, Home,
  Info, LayoutDashboard, LockKeyhole, Menu, Network, Play, Power,
  Radio, RotateCcw, Server, Settings2, Shield, ShieldAlert, ShieldCheck,
  SlidersHorizontal, Sparkles, Terminal, WifiOff, X, Zap,
} from 'lucide-react'

const REPO = 'https://github.com/MichaelWave369/PorchTalk'
const DOCUMENTATION = REPO + '/tree/main/docs'
const INITIAL_NODES = [
  {
    id: 'main', name: 'Main Porch', subtitle: 'Primary workstation', place: 'YOUR PORCH',
    model: 'RTX 5070 · inference slot', type: 'local', tier: 3, cost: 4,
    latency: 680, energy: 112, memory: 12288, required: 8192, available: true,
    description: 'A capable local route for more demanding requests.',
  },
  {
    id: 'seed', name: 'Porch Seed', subtitle: 'Lightweight offline companion', place: 'YOUR PORCH',
    model: '~135M-class model · conceptual', type: 'local', tier: 1, cost: 1,
    latency: 280, energy: 18, memory: 512, required: 300, available: true,
    description: 'Small local intelligence for simple, private tasks.',
  },
  {
    id: 'neighbor', name: 'Neighbor Porch', subtitle: 'Consented community peer', place: 'PEER PORCH',
    model: 'RTX 3060 · illustrative offer', type: 'remote', tier: 2, cost: 2,
    latency: 890, energy: 170, memory: 12288, required: 6200, available: true,
    description: 'Can be considered only with both sides explicitly consenting.',
  },
  {
    id: 'salvage', name: 'Salvage Porch', subtitle: 'Older CPU workstation', place: 'PEER PORCH',
    model: 'CPU-only · illustrative offer', type: 'remote', tier: 1, cost: 1,
    latency: 3400, energy: 310, memory: 8192, required: 1800, available: true,
    description: 'A hypothetical low-capability device with strict power limits.',
  },
]

const INITIAL_REQUEST = {
  dataClass: 'SYNTHETIC', minTier: 2, maxCost: 6, maxLatency: 3000,
  maxEnergy: 300, allowRemote: false,
}

const NAV = [
  { id: 'overview', label: 'Overview', Icon: LayoutDashboard },
  { id: 'lab', label: 'Route Lab', Icon: SlidersHorizontal },
  { id: 'nodes', label: 'Porch Nodes', Icon: Network },
  { id: 'trust', label: 'Trust & Consent', Icon: ShieldCheck },
  { id: 'evidence', label: 'Evidence Ledger', Icon: FileCheck2 },
  { id: 'desk', label: 'Evidence Desk', Icon: Database },
]

const GATES = [
  { label: 'A', title: 'Local-first policy', detail: 'Bounded selection, deny-by-default, simulation receipts', state: 'TESTED' },
  { label: 'B1', title: 'Grant envelope tests', detail: 'Single-use claim signing, scope, expiry and revocation controls', state: 'TESTED' },
  { label: 'B2', title: 'Pinned device identities', detail: 'Ed25519 proof, human enrollment and encrypted vaults', state: 'TESTED' },
  { label: 'B3', title: 'Loopback first knock', detail: 'Mutually pinned TLS 1.3 on one test machine', state: 'TESTED' },
  { label: 'B4', title: 'Private-LAN research', detail: 'Manual pairing, unaudited handshake, Windows readiness checks', state: 'LAB ONLY' },
  { label: 'NEXT', title: 'Verified physical hardware', detail: 'Actual two-PC observations, security review and reproducible evidence', state: 'NOT VERIFIED' },
]

function Pill({ children, variant = 'muted', Icon }) {
  return <span className={'pill pill-' + variant}>{Icon && <Icon size={13} />}{children}</span>
}

function SectionHeading({ eyebrow, title, text, action }) {
  return <div className="section-heading">
    <div>
      <div className="eyebrow"><span className="eyebrow-line" />{eyebrow}</div>
      <h2>{title}</h2>
      {text && <p>{text}</p>}
    </div>
    {action}
  </div>
}

function Toggle({ checked, onChange, label, detail, disabled = false }) {
  return <label className={'toggle-line' + (disabled ? ' disabled' : '')}>
    <span className="toggle-copy"><strong>{label}</strong>{detail && <small>{detail}</small>}</span>
    <input aria-label={label} type="checkbox" checked={checked} disabled={disabled}
      onChange={e => onChange(e.target.checked)} />
    <span className="switch" aria-hidden="true"><span /></span>
  </label>
}

function NetworkDiagram({ nodes, setPage }) {
  return <div className="network-diagram" role="img"
    aria-label="Diagram showing the main Porch linked to a local seed, a neighbor Porch and an older compute node">
    <svg className="network-lines" viewBox="0 0 700 365" preserveAspectRatio="none" aria-hidden="true">
      <defs>
        <linearGradient id="networkBeam" x1="0%" y1="0%" x2="100%" y2="0%">
          <stop stopColor="#78e9be" stopOpacity=".6" />
          <stop offset="1" stopColor="#78e9be" stopOpacity=".08" />
        </linearGradient>
      </defs>
      <path d="M352 178 L150 76 M352 178 L548 81 M352 178 L552 290 M352 178 L155 288"
        stroke="url(#networkBeam)" strokeDasharray="5 9" strokeWidth="2" fill="none" />
      <circle cx="352" cy="178" r="98" fill="none" stroke="#89f5c8" strokeOpacity=".09" strokeDasharray="3 7" />
      <circle cx="352" cy="178" r="145" fill="none" stroke="#89f5c8" strokeOpacity=".05" />
    </svg>
    <div className="network-core">
      <div className="core-glow" />
      <div className="core-icon"><Home size={30} strokeWidth={1.7} /></div>
      <strong>PORCHTALK</strong>
      <span>Routing intelligence</span>
    </div>
    {nodes.map((node, index) =>
      <button key={node.id} type="button"
        className={'orbit-node orbit-' + index + (node.available ? '' : ' orbit-offline')}
        onClick={() => setPage('nodes')} title={'Inspect ' + node.name}>
        <span className="orbit-marker">{node.type === 'local' ? <Cpu size={21} /> : <Server size={21} />}</span>
        <strong>{node.name}</strong>
        <small>{node.type === 'local' ? 'LOCAL' : 'OPT-IN PEER'}</small>
      </button>
    )}
    <div className="network-caption"><CircleDot size={13} /><span>Illustrative topology · not live discovery</span></div>
  </div>
}

function NodeCard({ node, onToggle, showDetails = false }) {
  return <div className={'node-card' + (node.available ? '' : ' node-disabled')}>
    <div className="node-top">
      <div className={'node-icon ' + (node.type === 'local' ? 'local-icon' : 'peer-icon')}>
        {node.type === 'local' ? <Cpu size={22} /> : <Server size={22} />}
      </div>
      <span className={'status-text ' + (node.available ? 'online' : 'offline')}>
        <i />{node.available ? 'SIMULATED ONLINE' : 'SIMULATED OFFLINE'}
      </span>
    </div>
    <div className="node-name">{node.name}</div>
    <div className="node-sub">{node.subtitle}</div>
    <p className="node-model">{node.model}</p>
    <div className="node-metrics">
      <div><span>Tier</span><strong>{node.tier}/3</strong></div>
      <div><span>Est. cost</span><strong>{node.cost} u</strong></div>
      <div><span>Latency</span><strong>{node.latency} ms</strong></div>
    </div>
    {showDetails && <div className="node-expanded"><p>{node.description}</p><p>Memory: {node.required.toLocaleString()} MiB required / {node.memory.toLocaleString()} MiB offered. Energy: {node.energy} mWh estimate.</p></div>}
    <Toggle checked={node.available} onChange={onToggle}
      label="Include in simulation" detail="Does not control physical hardware" />
  </div>
}

function GateGrid({ compact = false }) {
  return <div className={'gate-grid' + (compact ? ' compact' : '')}>
    {GATES.map((gate, idx) => <div className="gate-item" key={gate.label}>
      <div className={'gate-symbol ' + (idx >= 4 ? 'pending' : 'complete')}>
        {idx < 4 ? <Check size={16} strokeWidth={2.5} /> : <span>{idx === 4 ? '◐' : '—'}</span>}
      </div>
      <div className="gate-copy">
        <div className="gate-head"><strong>{gate.label} · {gate.title}</strong></div>
        {!compact && <p>{gate.detail}</p>}
        <small>{gate.state}</small>
      </div>
    </div>)}
  </div>
}

function App() {
  const [page, setPage] = useState('overview')
  const [mobileMenu, setMobileMenu] = useState(false)
  const [nodes, setNodes] = useState(INITIAL_NODES)
  const [request, setRequest] = useState(INITIAL_REQUEST)
  const [grants, setGrants] = useState({ neighbor: false, salvage: false })
  const [receipt, setReceipt] = useState(null)
  const [notice, setNotice] = useState('')
  const decision = useMemo(() => decide(request, nodes, grants), [request, nodes, grants])
  const usableCount = nodes.filter(node => node.available).length

  function changeRequest(name, value) {
    setRequest(old => ({ ...old, [name]: value }))
    setReceipt(null)
  }

  function changeNode(id, available) {
    setNodes(old => old.map(node => node.id === id ? { ...node, available } : node))
    setReceipt(null)
  }

  function changeGrant(id, value) {
    setGrants(old => ({ ...old, [id]: value }))
    setReceipt(null)
  }

  function resetLab() {
    setNodes(INITIAL_NODES)
    setRequest(INITIAL_REQUEST)
    setGrants({ neighbor: false, salvage: false })
    setReceipt(null)
    setNotice('Lab reset to its local-first starting state.')
  }

  async function runSimulation() {
    const result = decide(request, nodes, grants)
    const payload = {
      schema: 'PORCHTALK_BROWSER_SIMULATION_V1',
      evaluated_at: new Date().toISOString(),
      source: 'BROWSER_ONLY',
      scenario: { request, nodes: nodes.map(({ id, type, tier, cost, latency, energy, memory, required, available }) =>
        ({ id, type, tier, cost, latency, energy, memory, required, available })), grants },
      decision: {
        status: result.status, mode: result.mode, reason: result.reason,
        node_id: result.selected ? result.selected.id : null,
        estimated_cost_units: result.selected ? result.selected.cost : null,
      },
      rejected_offers: result.decisions.filter(item => !item.eligible).map(({ id, reason }) => ({ id, reason })),
      warnings: [
        'SIMULATION_ONLY_NO_REAL_ROUTING',
        'FAKE_ESTIMATES_NOT_HARDWARE_BENCHMARKS',
        'DEMO_GRANTS_ARE_NOT_CRYPTOGRAPHIC_AUTHORIZATION',
        'CHECKSUM_NOT_A_SIGNATURE',
      ],
    }
    let checksum = 'UNAVAILABLE'
    try {
      const data = new TextEncoder().encode(JSON.stringify(payload))
      const digest = await crypto.subtle.digest('SHA-256', data)
      checksum = Array.from(new Uint8Array(digest)).map(x => x.toString(16).padStart(2, '0')).join('')
    } catch (_) {
      // Browser still displays the exact underlying simulation without a hash.
    }
    setReceipt({ ...payload, sha256_demo_checksum: checksum })
    setNotice(result.status === 'ROUTED' ? 'Synthetic route selected. No network request was sent.' : 'Route denied. No eligible node met the constraints.')
  }

  async function copyReceipt() {
    if (!receipt) return
    try {
      await navigator.clipboard.writeText(JSON.stringify(receipt, null, 2))
      setNotice('Synthetic JSON receipt copied.')
    } catch (_) {
      setNotice('Clipboard was unavailable. Use Download JSON instead.')
    }
  }

  function downloadReceipt() {
    if (!receipt) return
    const blob = new Blob([JSON.stringify(receipt, null, 2) + '\n'], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const element = document.createElement('a')
    element.href = url
    element.download = 'porchtalk-simulation-receipt.json'
    document.body.appendChild(element)
    element.click()
    element.remove()
    URL.revokeObjectURL(url)
    setNotice('Synthetic receipt downloaded to this device.')
  }

  function navigate(target) {
    setPage(target)
    setMobileMenu(false)
    setNotice('')
    window.scrollTo({ top: 0, behavior: 'smooth' })
  }

  return <div className="app-frame">
    <aside className={'sidebar' + (mobileMenu ? ' sidebar-open' : '')}>
      <a href="#overview" className="brand" onClick={e => { e.preventDefault(); navigate('overview') }}>
        <span className="brand-mark"><Home size={25} strokeWidth={1.8} /><span className="brand-dot" /></span>
        <span className="brand-words"><strong>PorchTalk<span className="brand-period">.</span></strong><small>THE NEIGHBORHOOD NETWORK</small></span>
      </a>
      <div className="sidebar-body">
        <div className="nav-heading">WORKSPACE</div>
        <nav aria-label="PorchTalk dashboard sections">
          {NAV.map(({ id, label, Icon }) =>
            <button key={id} className={'nav-item' + (page === id ? ' active' : '')}
              onClick={() => navigate(id)} aria-current={page === id ? 'page' : undefined}>
              <Icon size={19} /><span>{label}</span>{page === id && <span className="nav-selected" />}
            </button>
          )}
        </nav>
        <div className="nav-heading lower">PROJECT</div>
        <a className="nav-item" href={REPO} target="_blank" rel="noopener noreferrer">
          <Github size={19} /><span>GitHub Repository</span><ExternalLink size={14} className="nav-external" />
        </a>
        <a className="nav-item" href={DOCUMENTATION} target="_blank" rel="noopener noreferrer">
          <BookOpen size={19} /><span>Documentation</span><ExternalLink size={14} className="nav-external" />
        </a>
      </div>
      <div className="sidebar-bottom">
        <div className="sidebar-status"><span className="pulse-dot" /> BROWSER RESEARCH LAB</div>
        <p>All scenario data stays in this tab. No telemetry, API calls, or AI workers.</p>
        <div className="sidebar-version">Φ369 ECOSYSTEM <span>WEB v0.1</span></div>
      </div>
    </aside>

    {mobileMenu && <button className="mobile-backdrop" onClick={() => setMobileMenu(false)} aria-label="Close navigation" />}

    <main className="main">
      <header className="topbar">
        <div className="topbar-left">
          <button className="mobile-toggle" onClick={() => setMobileMenu(x => !x)} aria-label="Toggle navigation"><Menu size={22} /></button>
          <span className="topbar-crumb">PORCHTALK</span><ChevronRight size={14} />
          <span className="topbar-current">{NAV.find(x => x.id === page)?.label}</span>
        </div>
        <div className="topbar-right">
          <span className="topbar-local"><LockKeyhole size={14} /> LOCAL UI ONLY</span>
          <span className="topbar-avatar">Φ</span>
        </div>
      </header>

      <div className="content">
        {page === 'overview' && <>
          <div className="hero">
            <div className="hero-left">
              <div className="hero-kicker"><span className="green-tick" /> INFINITE PORCH / RESEARCH ENVIRONMENT</div>
              <h1>Intelligence is<br /><em>better together.</em></h1>
              <p>Your AI doesn't need to know everything. It just needs to know which door it's allowed to knock on.</p>
              <div className="hero-actions">
                <button className="primary-btn" onClick={() => navigate('lab')}><Play size={16} fill="currentColor" /> Open Route Lab <ArrowRight size={17} /></button>
                <button className="ghost-btn" onClick={() => navigate('trust')}><Shield size={17} /> Explore consent model</button>
              </div>
              <div className="hero-note"><Info size={15} /> Interactive offline visualization. Not a live compute network.</div>
            </div>
            <div className="hero-right"><NetworkDiagram nodes={nodes} setPage={navigate} /></div>
          </div>

          <div className="stat-grid">
            <div className="stat-card"><div className="stat-icon"><Network size={21} /></div><span>Demo nodes available</span><strong>{usableCount} <small>/ 4</small></strong><p>Editable simulation roster</p></div>
            <div className="stat-card"><div className="stat-icon"><ShieldCheck size={21} /></div><span>Default sharing policy</span><strong className="status-word">DENY</strong><p>Remote access requires two approvals</p></div>
            <div className="stat-card"><div className="stat-icon"><Activity size={21} /></div><span>Research milestones</span><strong>5 <small>/ 6</small></strong><p>Offline/CI work vs. real hardware</p></div>
            <div className="stat-card"><div className="stat-icon"><WifiOff size={21} /></div><span>Browser connections</span><strong>0 <small>peers</small></strong><p>No live endpoints configured</p></div>
          </div>

          <div className="overview-grid">
            <section className="panel">
              <div className="panel-head"><div><span className="kicker">ROUTING PREVIEW</span><h3>The next best door</h3></div><button className="text-button" onClick={() => navigate('lab')}>Open lab <ArrowUpRight size={16} /></button></div>
              <div className="decision-preview">
                <span className="mini-orb"><Zap size={22} /></span>
                <div><small>CURRENT SIMULATED DECISION</small><strong>{decision.selected ? decision.selected.name : 'No eligible route'}</strong><span>{decision.selected ? decision.reason.replaceAll('_', ' ') : 'Adjust scenario constraints'}</span></div>
                <Pill variant={decision.selected ? 'good' : 'warning'}>{decision.status}</Pill>
              </div>
              <div className="decision-note"><ShieldCheck size={17} /><span>Local eligible nodes always take precedence over shared community nodes.</span></div>
            </section>
            <section className="panel">
              <div className="panel-head"><div><span className="kicker">PROTOCOL STATUS</span><h3>Built for trust, not hype</h3></div><Pill variant="warning">LAB</Pill></div>
              <div className="mini-gates"><GateGrid compact /></div>
              <button className="panel-link" onClick={() => navigate('evidence')}>View all verification gates <ArrowRight size={16} /></button>
            </section>
          </div>

          <section className="bottom-banner">
            <div className="bottom-banner-icon"><HeartHandshake size={26} /></div>
            <div><strong>Your Porch. Your keys. Your choice.</strong><p>Portability, consent and evidence before compute. Built for the Infinite Commons, designed to work without it.</p></div>
            <button className="ghost-btn" onClick={() => navigate('trust')}>The trust model <ArrowRight size={16} /></button>
          </section>
        </>}

        {page === 'lab' && <>
          <SectionHeading eyebrow="SIMULATION / ROUTE ENGINE" title="Crane Fly Routing Lab"
            text="Explore how a local-first budget policy selects a model. Every number below is illustrative, not a benchmark or a verified model capability."
            action={<button className="outlined-btn" onClick={resetLab}><RotateCcw size={16} /> Reset scenario</button>} />
          <div className="lab-layout">
            <div className="lab-controls">
              <section className="panel control-panel">
                <div className="panel-head"><div><span className="kicker">01 / REQUEST</span><h3>Task requirements</h3></div><SlidersHorizontal size={20} className="muted-icon" /></div>
                <div className="field-group"><label htmlFor="task-class">Data classification</label>
                  <div className="select-wrap"><select id="task-class" value={request.dataClass} onChange={e => changeRequest('dataClass', e.target.value)}>
                    <option value="PRIVATE">PRIVATE · never off Porch</option><option value="SYNTHETIC">SYNTHETIC · safe demo data</option><option value="PUBLIC">PUBLIC · shareable data</option>
                  </select><ChevronDown size={17} /></div>
                </div>
                <div className="slider-field"><div className="slider-title"><label htmlFor="quality">Minimum quality tier</label><strong>{request.minTier} <small>/ 3</small></strong></div><input type="range" id="quality" min="0" max="3" step="1" value={request.minTier} onChange={e => changeRequest('minTier', Number(e.target.value))} /><div className="range-labels"><span>Basic</span><span>Advanced</span></div></div>
                <div className="slider-field"><div className="slider-title"><label htmlFor="cost">Max fictional cost</label><strong>{request.maxCost} <small>units</small></strong></div><input type="range" id="cost" min="0" max="8" step="1" value={request.maxCost} onChange={e => changeRequest('maxCost', Number(e.target.value))} /><div className="range-labels"><span>0</span><span>8</span></div></div>
                <div className="slider-field"><div className="slider-title"><label htmlFor="latency">Max estimated latency</label><strong>{request.maxLatency.toLocaleString()} <small>ms</small></strong></div><input type="range" id="latency" min="300" max="5000" step="100" value={request.maxLatency} onChange={e => changeRequest('maxLatency', Number(e.target.value))} /><div className="range-labels"><span>300 ms</span><span>5,000 ms</span></div></div>
                <div className="slider-field"><div className="slider-title"><label htmlFor="energy">Max estimated energy</label><strong>{request.maxEnergy} <small>mWh</small></strong></div><input type="range" id="energy" min="20" max="450" step="10" value={request.maxEnergy} onChange={e => changeRequest('maxEnergy', Number(e.target.value))} /><div className="range-labels"><span>20 mWh</span><span>450 mWh</span></div></div>
              </section>
              <section className="panel control-panel">
                <div className="panel-head"><div><span className="kicker">02 / SHARING</span><h3>Permission boundaries</h3></div><LockKeyhole size={20} className="muted-icon" /></div>
                <Toggle checked={request.allowRemote} onChange={value => changeRequest('allowRemote', value)}
                  label="Allow remote fallback" detail="Requester opt-in, simulation only" />
                <div className="divider-line" />
                <Toggle checked={grants.neighbor} onChange={value => changeGrant('neighbor', value)}
                  label="Neighbor grant" detail="Synthetic grant toggle, not a signed credential" />
                <Toggle checked={grants.salvage} onChange={value => changeGrant('salvage', value)}
                  label="Salvage grant" detail="Synthetic grant toggle, not a signed credential" />
                <div className="policy-hint"><Info size={16} /><span>PRIVATE requests can never route remotely, even when every simulated permission is enabled.</span></div>
              </section>
            </div>
            <div className="lab-output">
              <section className="panel output-panel">
                <div className="panel-head"><div><span className="kicker">03 / POLICY PREVIEW</span><h3>Decision engine</h3></div><Pill variant="muted">BROWSER ONLY</Pill></div>
                <div className={'decision-result ' + (decision.selected ? 'accept' : 'deny')}>
                  <div className="result-mini">{decision.selected ? <CheckCircle2 size={23} /> : <Ban size={23} />}</div>
                  <div><span>SELECTED ROUTE</span><strong>{decision.selected?.name || 'No eligible route'}</strong><small>{decision.reason.replaceAll('_', ' ')}</small></div>
                  <div className="result-mode">{decision.mode || 'DENIED'}</div>
                </div>
                <div className="candidate-list">
                  {decision.decisions.map(candidate => <div className="candidate" key={candidate.id}>
                    <div className={'candidate-dot' + (candidate.eligible ? ' ok' : '')}>{candidate.eligible ? <Check size={13} /> : <X size={13} />}</div>
                    <div><strong>{candidate.name}</strong><small>{candidate.model}</small></div>
                    <span className={candidate.eligible ? 'candidate-yes' : 'candidate-no'}>{candidate.reason.replaceAll('_', ' ')}</span>
                  </div>)}
                </div>
                <button className="primary-btn full" onClick={runSimulation}><Play size={16} fill="currentColor" /> Evaluate & create local receipt <ArrowRight size={17} /></button>
              </section>
              <section className="panel receipt-panel">
                <div className="panel-head"><div><span className="kicker">04 / AUDIT</span><h3>Simulation receipt</h3></div>
                  <div className="receipt-actions"><button onClick={copyReceipt} disabled={!receipt} title="Copy JSON"><Copy size={16} /></button><button onClick={downloadReceipt} disabled={!receipt} title="Download JSON"><Download size={16} /></button></div>
                </div>
                {receipt ? <pre className="receipt-code">{JSON.stringify(receipt, null, 2)}</pre> :
                  <div className="receipt-empty"><FileCheck2 size={28} /><strong>No receipt generated yet</strong><span>Evaluate a scenario to create a local, unsigned JSON research receipt.</span></div>}
                <div className="receipt-disclaimer"><ShieldAlert size={15} /> SHA-256 is not a signature. Demo grants are not actual authorizations.</div>
              </section>
            </div>
          </div>
        </>}

        {page === 'nodes' && <>
          <SectionHeading eyebrow="NEIGHBORHOOD / DEMO ROSTER" title="Porch Nodes"
            text="Switch fictional node availability to explore resilience and routing decisions. This panel is not connected to hardware, your LAN, or model runtimes."
            action={<button className="outlined-btn" onClick={resetLab}><RotateCcw size={16} /> Restore roster</button>} />
          <div className="node-intro panel"><div><Radio size={19} /><strong>{usableCount} of 4 demo nodes marked available</strong></div><Pill variant="muted">NO LIVE DISCOVERY</Pill></div>
          <div className="nodes-grid">{nodes.map(node =>
            <NodeCard key={node.id} node={node} showDetails onToggle={value => changeNode(node.id, value)} />)}
          </div>
          <div className="inline-note"><HardDrive size={20} /><div><strong>Weights stay where they belong.</strong><p>PorchTalk's future interface would route bounded requests to authorized compatible models. This browser does not stage PhiStream weights or merge VRAM across machines.</p></div></div>
        </>}

        {page === 'trust' && <>
          <SectionHeading eyebrow="GOVERNANCE / HUMAN FIRST" title="Trust & Consent"
            text="An approved identity is not the same thing as permission to use compute. Peer discovery, public-key enrollment, request consent, and resource grants are distinct boundaries." />
          <div className="trust-hero">
            <div className="trust-hero-icon"><Fingerprint size={36} /></div>
            <div><span className="kicker">THE PORCH PRINCIPLE</span><h3>Visitors can knock.<br />Nobody has to answer.</h3><p>Every Porch remains locally owned and functional, even when the Commons is disconnected.</p></div>
            <Pill variant="good" Icon={LockKeyhole}>DEFAULT DENY</Pill>
          </div>
          <div className="trust-cards">
            <div className="trust-card"><div className="trust-number">01</div><ShieldCheck size={25} /><h3>Identity</h3><p>Know which public device key was manually pinned. Fingerprints still need human verification.</p><small>PUBLIC KEY ≠ COMPUTE ACCESS</small></div>
            <div className="trust-card"><div className="trust-number">02</div><HeartHandshake size={25} /><h3>Consent</h3><p>The requester and device owner must both agree, with clear task scope and revocation.</p><small>NO IMPLIED COMMUNITY GRANTS</small></div>
            <div className="trust-card"><div className="trust-number">03</div><SlidersHorizontal size={25} /><h3>Budget</h3><p>Enforce capability, resource and privacy limits before work, not after the hardware overheats.</p><small>NO REAL EXECUTOR YET</small></div>
          </div>
          <section className="panel trust-sim">
            <div className="panel-head"><div><span className="kicker">DEMO POLICY CONTROLS</span><h3>See consent in action</h3></div><Pill variant="muted">SIMULATED</Pill></div>
            <div className="trust-controls">
              <Toggle checked={request.allowRemote} onChange={value => changeRequest('allowRemote', value)} label="Requester permits remote fallback" detail="Request-side opt-in" />
              <Toggle checked={grants.neighbor} onChange={value => changeGrant('neighbor', value)} label="Neighbor grants demo use" detail="Owner-side simulated permission" />
              <Toggle checked={grants.salvage} onChange={value => changeGrant('salvage', value)} label="Salvage node grants demo use" detail="Owner-side simulated permission" />
            </div>
            <div className="trust-status"><div className="trust-status-icon"><Shield size={21} /></div><span>{request.allowRemote && (grants.neighbor || grants.salvage) ? 'Synthetic peer consideration permitted for PUBLIC/SYNTHETIC requests only.' : 'Remote fallback remains denied unless both sides opt in.'}</span><button className="text-button" onClick={() => navigate('lab')}>Try a route <ArrowRight size={16} /></button></div>
          </section>
          <div className="inline-note"><ShieldAlert size={20} /><div><strong>Browser toggles are not real resource grants.</strong><p>No cryptographic keys or identities are created in this website. For the implemented Python research code, review the audited limitations and the manual pairing runbooks in the repository.</p></div></div>
        </>}

        {page === 'desk' && <>
          <SectionHeading eyebrow="FIELD DESK / OFFLINE EVIDENCE" title="The Evidence Desk"
            text="Read Windows observation reports and compare two signed-handshake claim receipts, entirely in this browser tab. No private files or actual network connections." />
          <EvidenceDesk />
        </>}

        {page === 'evidence' && <>
          <SectionHeading eyebrow="LEDGER / VERIFIED BOUNDARIES" title="Evidence & Gates"
            text="A research milestone counts only for what it actually demonstrated. Green CI is good evidence for tests, not proof of a secure distributed compute network."
            action={<a className="outlined-btn" href={DOCUMENTATION} target="_blank" rel="noopener noreferrer">Read protocol docs <ArrowUpRight size={17} /></a>} />
          <div className="evidence-summary">
            <div><CircleDot size={18} /><strong>RESEARCH PROTOTYPE</strong><span>Not a public network</span></div>
            <div><ShieldCheck size={18} /><strong>PERMISSION FIRST</strong><span>No browser compute sharing</span></div>
            <div><Activity size={18} /><strong>CI TESTED</strong><span>Linux and Windows runners</span></div>
          </div>
          <section className="panel ledger-panel">
            <div className="panel-head"><div><span className="kicker">MILESTONE REGISTER</span><h3>What we've tested</h3></div><Pill variant="warning">HARDWARE PENDING</Pill></div>
            <GateGrid />
          </section>
          <div className="evidence-split">
            <section className="panel">
              <div className="panel-head"><div><span className="kicker">WHAT IS REAL</span><h3>Implemented research</h3></div><CheckCircle2 size={19} className="accent-icon" /></div>
              <div className="statement"><Check size={17} /><span>Deterministic local-first routing policy in Python</span></div>
              <div className="statement"><Check size={17} /><span>Cryptographic identity and grant research modules</span></div>
              <div className="statement"><Check size={17} /><span>Single-use LAN proof protocol with explicit manual operation</span></div>
              <div className="statement"><Check size={17} /><span>Read-only Windows network checks and receipt comparisons</span></div>
            </section>
            <section className="panel">
              <div className="panel-head"><div><span className="kicker">WHAT IS NOT CLAIMED</span><h3>Still behind the gate</h3></div><ShieldAlert size={19} className="warn-icon" /></div>
              <div className="statement pending-statement"><X size={17} /><span>Production-secure, independently audited LAN transport</span></div>
              <div className="statement pending-statement"><X size={17} /><span>Verified proof from two physical Windows machines</span></div>
              <div className="statement pending-statement"><X size={17} /><span>Sandboxed remote work and enforceable resource leases</span></div>
              <div className="statement pending-statement"><X size={17} /><span>PhiStream model inference or model-weight distribution</span></div>
            </section>
          </div>
          <section className="bottom-banner ledger-banner">
            <div className="bottom-banner-icon"><Database size={24} /></div>
            <div><strong>Ledger above ego.</strong><p>The source and tests are public. Explore the code, inspect the receipts, and hold every claim to its actual evidence.</p></div>
            <a className="ghost-btn" href={REPO} target="_blank" rel="noopener noreferrer">View source <ExternalLink size={16} /></a>
          </section>
        </>}
      </div>
      <footer className="footer"><span>© 2026 PORCHTALK · Φ369 RESEARCH</span><span>NO TRACKERS · NO BACKEND · NO LIVE PEERS</span><span>LEDGER ABOVE EGO</span></footer>
    </main>
    {notice && <div className="toast" role="status"><CheckCircle2 size={16} /><span>{notice}</span><button onClick={() => setNotice('')} aria-label="Dismiss notification"><X size={15} /></button></div>}
  </div>
}

export default App
