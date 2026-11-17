import { BLOCK_STEP, fetchBlocklistRows, KEYSET_CHUNK, type Rpc } from './blocklist-fetch.ts'

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
  }
}

async function assertRejects(fn: () => Promise<unknown>, includes: string): Promise<void> {
  try {
    await fn()
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    if (!msg.includes(includes)) throw new Error(`Expected an error with "${includes}", got "${msg}"`)
    return
  }
  throw new Error(`Expected an error with "${includes}"`)
}

// DOS/DOS.AI#7620: the blocklist rows are read in heap-block ranges, once each.

Deno.test('walks every block once, reads blocks gained during the run, and sorts the rows', async () => {
  const calls: string[] = []
  const counts = [2 * BLOCK_STEP + 10, 3 * BLOCK_STEP + 5, 3 * BLOCK_STEP + 5]
  const rpc: Rpc = (fn, body) => {
    if (fn === 'threat_intel_block_count') {
      calls.push('count')
      return Promise.resolve(counts.shift() ?? 0)
    }
    calls.push(`range ${body.p_first_block}+${body.p_block_count}`)
    const b = Math.ceil(Number(body.p_first_block) / BLOCK_STEP)
    return Promise.resolve([
      { entity_type: 'domain', entity_value: `d${3 - b}.example`, category: 'scam', source: 'z' },
      { entity_type: 'domain', entity_value: `d${3 - b}.example`, category: 'phishing', source: 'a' },
      { entity_type: 'phone', entity_value: `09000000${b}`, category: 'spam', name: null, risk_score: 50 },
      { entity_type: 'url', entity_value: 'https://never.example/', category: 'scam', source: 'x' },
    ])
  }
  const rows = await fetchBlocklistRows(rpc)
  assertEquals(calls, [
    'count',
    `range 0+${BLOCK_STEP}`,
    `range ${BLOCK_STEP}+${BLOCK_STEP}`,
    `range ${2 * BLOCK_STEP}+10`,
    'count',
    // Blocks gained after the last range was read start where that range ended.
    `range ${2 * BLOCK_STEP + 10}+${BLOCK_STEP - 5}`,
    'count',
  ])
  assertEquals(rows.method, 'block_range')
  assertEquals(rows.calls, 7)
  assertEquals(rows.domains.map((r) => `${r.entity_value} ${r.source}`), [
    'd0.example a', 'd0.example z', 'd1.example a', 'd1.example z',
    'd2.example a', 'd2.example z', 'd3.example a', 'd3.example z',
  ])
  assertEquals(rows.phones.map((r) => r.entity_value), ['090000000', '090000001', '090000002', '090000003'])
})

Deno.test('an empty table makes no range call', async () => {
  const calls: string[] = []
  const rows = await fetchBlocklistRows((fn) => {
    calls.push(fn)
    return Promise.resolve(fn === 'threat_intel_block_count' ? 0 : [])
  })
  assertEquals(calls, ['threat_intel_block_count', 'threat_intel_block_count'])
  assertEquals([rows.phones.length, rows.domains.length], [0, 0])
})

Deno.test('falls back to keyset pages when the database has no block-range function', async () => {
  const calls: string[] = []
  const rpc: Rpc = (fn, body) => {
    calls.push(`${fn} ${body.p_cursor ?? 'start'}`)
    if (fn === 'threat_intel_block_count') return Promise.resolve(null)
    if (fn === 'get_phone_blacklist') return Promise.resolve([{ entity_value: '0900000001', category: 'spam' }])
    if (!body.p_cursor) {
      return Promise.resolve(Array.from({ length: KEYSET_CHUNK }, (_, i) => ({
        entity_value: `d${String(i).padStart(6, '0')}.example`, category: 'scam', source: 's',
      })))
    }
    return Promise.resolve([{ entity_value: 'zz.example', category: 'scam', source: 's' }])
  }
  const rows = await fetchBlocklistRows(rpc)
  assertEquals(rows.method, 'keyset')
  assertEquals(calls, [
    'threat_intel_block_count start',
    'get_phone_blacklist start',
    'get_domain_blacklist start',
    `get_domain_blacklist d${String(KEYSET_CHUNK - 1).padStart(6, '0')}.example`,
  ])
  assertEquals([rows.phones.length, rows.domains.length], [1, KEYSET_CHUNK + 1])
})

Deno.test('a table that keeps growing is read for a bounded number of extra rounds', async () => {
  let n = 10
  let ranges = 0
  await fetchBlocklistRows((fn) => {
    if (fn === 'threat_intel_block_count') return Promise.resolve(n++)
    ranges++
    return Promise.resolve([])
  })
  assertEquals(ranges, 6)
})

Deno.test('a range call that returns no rows array fails the run', async () => {
  await assertRejects(
    () => fetchBlocklistRows((fn) => Promise.resolve(fn === 'threat_intel_block_count' ? 10 : null)),
    'get_blocklist_block_range did not return rows',
  )
})

Deno.test('a bad block count fails the run', async () => {
  await assertRejects(() => fetchBlocklistRows(() => Promise.resolve([])), 'threat_intel_block_count returned')
})
