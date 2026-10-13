/** Deterministic *browser simulation* of Gate A constraints.
 * Demo offers are hypothetical. The Python router remains the protocol reference.
 * No API requests or network I/O. No credentials are created or verified.
 */
export function decide(request, nodes, grants) {
  const eligibleLocal = []
  const eligibleRemote = []
  const decisions = []
  for (const node of nodes) {
    let reason = ''
    if (!node.available) reason = 'NODE_OFFLINE'
    else if (node.required > node.memory) reason = 'INSUFFICIENT_MEMORY'
    else if (node.tier < request.minTier) reason = 'QUALITY_BELOW_TARGET'
    else if (node.cost > request.maxCost || node.latency > request.maxLatency || node.energy > request.maxEnergy) reason = 'BUDGET_EXCEEDED'
    else if (node.type === 'remote' && !request.allowRemote) reason = 'REMOTE_DISABLED'
    else if (node.type === 'remote' && request.dataClass === 'PRIVATE') reason = 'PRIVATE_STAYS_LOCAL'
    else if (node.type === 'remote' && !grants[node.id]) reason = 'NO_SIMULATED_GRANT'
    else if (node.type === 'remote' && node.cost > 5) reason = 'PEER_GRANT_COST_LIMIT'
    decisions.push({ ...node, eligible: !reason, reason: reason || 'ELIGIBLE' })
    if (!reason) (node.type === 'local' ? eligibleLocal : eligibleRemote).push(node)
  }
  const sorted = group => [...group].sort((a, b) =>
    (a.cost - b.cost) || (a.latency - b.latency) || (a.energy - b.energy) ||
    a.id.localeCompare(b.id)
  )
  const chosen = sorted(eligibleLocal)[0] || sorted(eligibleRemote)[0] || null
  return {
    status: chosen ? 'ROUTED' : 'DENIED',
    mode: chosen ? (chosen.type === 'local' ? 'LOCAL' : 'REMOTE') : null,
    reason: chosen ? (chosen.type === 'local' ? 'LOCAL_FIRST' : 'SIMULATED_GRANT_FALLBACK') : 'NO_ELIGIBLE_ROUTE',
    selected: chosen,
    decisions,
  }
}
