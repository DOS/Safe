import {
  type DeltaState,
  FULL_SEND_EVERY_MS,
  fingerprintOf,
  parseState,
  planDelta,
  stableJson,
  storageDeltaStore,
} from './feed-delta.ts'

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(`Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`)
  }
}

// DOS/DOS.AI#7620: between full sends only new or changed feed entries are sent.

const NOW = Date.parse('2026-11-17T06:00:00Z')
const a = { entity_type: 'domain', entity_value: 'a.example', source: 'feed', category: 'phishing', risk_score: 80, raw_data: { list: 'x' } }
const b = { entity_type: 'domain', entity_value: 'b.example', source: 'feed', category: 'phishing', risk_score: 80, raw_data: {} }
const c = { entity_type: 'domain', entity_value: 'c.example', source: 'feed', category: 'scam', risk_score: 70, raw_data: {} }

async function stateOf(entries: unknown[], lastFullAt: string): Promise<DeltaState> {
  return { v: 1, lastFullAt, fingerprints: await Promise.all(entries.map(fingerprintOf)) }
}

Deno.test('stableJson ignores key order and undefined values', async () => {
  assertEquals(stableJson({ b: 1, a: { d: [1, { z: 1, y: 2 }], c: undefined } }), '{"a":{"d":[1,{"y":2,"z":1}]},"b":1}')
  assertEquals(stableJson({ at: new Date('2026-11-17T00:00:00Z') }), '{"at":"2026-11-17T00:00:00.000Z"}')
  assertEquals(await fingerprintOf({ x: 1, y: 'v' }), await fingerprintOf({ y: 'v', x: 1 }))
  // The first 64 bits of SHA-256("{\"x\":1}").
  assertEquals(await fingerprintOf({ x: 1 }), '5041bf1f713df204')
})

Deno.test('no saved state: everything is sent and the full send time is now', async () => {
  const plan = await planDelta([a, b], null, NOW)
  assertEquals([plan.full, plan.reason, plan.entries.length], [true, 'no_state', 2])
  assertEquals(plan.next.lastFullAt, new Date(NOW).toISOString())
  assertEquals(plan.next.fingerprints, [await fingerprintOf(a), await fingerprintOf(b)])
})

Deno.test('between full sends only new and changed entries are sent', async () => {
  const lastFull = new Date(NOW - 2 * 86_400_000).toISOString()
  const changedA = { ...a, risk_score: 95 }
  const plan = await planDelta([changedA, b, c], await stateOf([a, b], lastFull), NOW)
  assertEquals([plan.full, plan.reason], [false, 'delta'])
  assertEquals(plan.entries, [changedA, c])
  // The full send time does not move; the fingerprints are the whole current feed.
  assertEquals(plan.next.lastFullAt, lastFull)
  assertEquals(plan.next.fingerprints, await Promise.all([changedA, b, c].map(fingerprintOf)))
})

Deno.test('an unchanged feed sends nothing between full sends', async () => {
  const plan = await planDelta([a, b], await stateOf([b, a], new Date(NOW - 86_400_000).toISOString()), NOW)
  assertEquals(plan.entries.length, 0)
})

Deno.test('a full send is due once the interval has passed', async () => {
  const justBefore = await planDelta([a], await stateOf([a], new Date(NOW - FULL_SEND_EVERY_MS + 1000).toISOString()), NOW)
  assertEquals([justBefore.full, justBefore.entries.length], [false, 0])
  const due = await planDelta([a], await stateOf([a], new Date(NOW - FULL_SEND_EVERY_MS).toISOString()), NOW)
  assertEquals([due.full, due.reason, due.entries.length], [true, 'refresh_due', 1])
  assertEquals(due.next.lastFullAt, new Date(NOW).toISOString())
})

Deno.test('the full send interval stays under the 7-day last_seen refresh', () => {
  // bulk_upsert_threats refreshes last_seen_at after 7 days and expiry cuts at 14: a full send
  // must come within 7 days of the previous one (see feed-delta.ts).
  if (!(FULL_SEND_EVERY_MS < 7 * 86_400_000)) throw new Error('FULL_SEND_EVERY_MS must stay below 7 days')
})

Deno.test('a state with a bad or future time means a full send', async () => {
  assertEquals((await planDelta([a], { v: 1, lastFullAt: 'nope', fingerprints: [] }, NOW)).reason, 'no_state')
  assertEquals((await planDelta([a], await stateOf([a], new Date(NOW + 60_000).toISOString()), NOW)).reason, 'no_state')
})

Deno.test('parseState accepts only the current shape', () => {
  assertEquals(parseState({ v: 1, lastFullAt: 't', fingerprints: ['ab'] }), { v: 1, lastFullAt: 't', fingerprints: ['ab'] })
  assertEquals(parseState({ v: 2, lastFullAt: 't', fingerprints: [] }), null)
  assertEquals(parseState({ v: 1, lastFullAt: 't', fingerprints: [1] }), null)
  assertEquals(parseState(null), null)
})

Deno.test('storageDeltaStore saves gzip JSON and loads it back; a missing object is no state', async () => {
  const objects = new Map<string, Uint8Array>()
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input)
    if (init?.method === 'POST') {
      objects.set(url, new Uint8Array(await new Response(init.body).arrayBuffer()))
      return new Response('{}', { status: 200 })
    }
    const body = objects.get(url)?.slice().buffer as ArrayBuffer | undefined
    return body ? new Response(body, { status: 200 }) : new Response('{"error":"not_found"}', { status: 400 })
  }) as typeof fetch
  const store = storageDeltaStore({ url: 'https://db.example', key: 'k', fetch: fakeFetch })
  assertEquals(await store.load('watchlist_internet'), null)
  const state = await stateOf([a, b], new Date(NOW).toISOString())
  assertEquals(await store.save('watchlist_internet', state), true)
  assertEquals([...objects.keys()], ['https://db.example/storage/v1/object/dosafe-feed-state/watchlist_internet.json.gz'])
  assertEquals(await store.load('watchlist_internet'), state)
})

Deno.test('storageDeltaStore treats an unreadable object or a failed call as no state', async () => {
  const garbage = storageDeltaStore({
    url: 'https://db.example',
    key: 'k',
    fetch: (() => Promise.resolve(new Response('not gzip', { status: 200 }))) as typeof fetch,
  })
  assertEquals(await garbage.load('f'), null)
  const down = storageDeltaStore({
    url: 'https://db.example',
    key: 'k',
    fetch: (() => Promise.reject(new Error('down'))) as typeof fetch,
  })
  assertEquals(await down.load('f'), null)
  assertEquals(await down.save('f', await stateOf([a], new Date(NOW).toISOString())), false)
})
