import assert from 'node:assert/strict'
import test from 'node:test'
import { decide } from '../src/routing.js'

const local = {
  id: 'main', type: 'local', tier: 3, cost: 4, latency: 500,
  energy: 100, memory: 8192, required: 6000, available: true,
}
const seed = {
  id: 'seed', type: 'local', tier: 1, cost: 1, latency: 100,
  energy: 15, memory: 600, required: 400, available: true,
}
const peer = {
  id: 'bob', type: 'remote', tier: 2, cost: 2, latency: 700,
  energy: 110, memory: 8192, required: 6000, available: true,
}
const base = {
  dataClass: 'SYNTHETIC', minTier: 2, maxCost: 8,
  maxLatency: 3000, maxEnergy: 300, allowRemote: false,
}
const evalRoute = (r = {}, nodes = [local, seed, peer], grants = {}) =>
  decide({ ...base, ...r }, nodes.map(n => ({ ...n })), grants)

test('default routes locally without sending data to peers', () => {
  const d = evalRoute()
  assert.equal(d.selected.id, 'main')
  assert.equal(d.mode, 'LOCAL')
  assert.equal(d.decisions.find(n => n.id === 'bob').reason, 'REMOTE_DISABLED')
})

test('local-first overrides a cheaper eligible peer', () => {
  const d = evalRoute({ allowRemote: true }, [local, peer], { bob: true })
  assert.equal(d.selected.id, 'main')
  assert.equal(d.reason, 'LOCAL_FIRST')
})

test('remote fallback needs both requester opt-in and matching simulated grant', () => {
  const nodes = [{ ...local, available: false }, peer]
  assert.equal(evalRoute({ allowRemote: true }, nodes).status, 'DENIED')
  assert.equal(evalRoute({}, nodes, { bob: true }).status, 'DENIED')
  const permitted = evalRoute({ allowRemote: true }, nodes, { bob: true })
  assert.equal(permitted.mode, 'REMOTE')
  assert.equal(permitted.selected.id, 'bob')
})

test('PRIVATE data never leaves the Porch, even with every demo permission', () => {
  const decision = evalRoute(
    { allowRemote: true, dataClass: 'PRIVATE' },
    [peer], { bob: true }
  )
  assert.equal(decision.status, 'DENIED')
  assert.equal(decision.decisions[0].reason, 'PRIVATE_STAYS_LOCAL')
})

test('insufficient memory denies a claimed offer', () => {
  const decision = evalRoute({}, [{ ...local, memory: 10 }])
  assert.equal(decision.status, 'DENIED')
  assert.equal(decision.decisions[0].reason, 'INSUFFICIENT_MEMORY')
})

test('quality ceiling and fictional estimated limits fail closed', () => {
  assert.equal(evalRoute({ minTier: 3 }, [peer], { bob: true }).status, 'DENIED')
  assert.equal(evalRoute({ maxCost: 1 }, [local]).status, 'DENIED')
  assert.equal(evalRoute({ maxEnergy: 20 }, [local]).status, 'DENIED')
  assert.equal(evalRoute({ maxLatency: 100 }, [local]).status, 'DENIED')
})

test('offline peers are never selected', () => {
  const decision = evalRoute({ allowRemote: true }, [{ ...peer, available: false }], { bob: true })
  assert.equal(decision.status, 'DENIED')
  assert.equal(decision.decisions[0].reason, 'NODE_OFFLINE')
})

test('peer cost grant simulation caps at five units', () => {
  const d = evalRoute({ allowRemote: true }, [{ ...peer, cost: 6 }], { bob: true })
  assert.equal(d.status, 'DENIED')
  assert.equal(d.decisions[0].reason, 'PEER_GRANT_COST_LIMIT')
})

test('deterministic tie order and input order independence', () => {
  const nodes = [{ ...local, id: 'b' }, { ...local, id: 'a' }]
  assert.equal(evalRoute({}, nodes).selected.id, 'a')
  assert.equal(evalRoute({}, nodes.reverse()).selected.id, 'a')
})

test('empty roster is denied', () => {
  assert.equal(evalRoute({}, []).status, 'DENIED')
  assert.equal(evalRoute({}, []).reason, 'NO_ELIGIBLE_ROUTE')
})
