import {
  entityHashOrder,
  type DeltaState,
  type FeedLease,
  finishRun,
  FULL_SEND_EVERY_MS,
  fingerprintOf,
  isStorageNotFound,
  parseState,
  planDelta,
  rpcFeedLeases,
  SCRIPT_LEASE_RENEW_EVERY_MS,
  savedRunStatus,
  scriptFeedLease,
  startRun,
  stableJson,
  storageDeltaStore,
  TOMBSTONE_STATE,
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

// Storage's answer for a missing object (HTTP 400, the real status in the body).
const NOT_FOUND = '{"statusCode":"404","code":"NoSuchKey","error":"not_found","message":"Object not found"}'

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
  assertEquals(plan.entries, await entityHashOrder([changedA, c]))
  assertEquals(plan.entries.length, 2)
  // The full send time does not move; the fingerprints are the whole current feed.
  assertEquals(plan.next.lastFullAt, lastFull)
  assertEquals(plan.next.fingerprints, await Promise.all([changedA, b, c].map(fingerprintOf)))
})

// DOS/DOS.AI#7925: entries go out in the order of the conflict index, entity_hash.
async function dbEntityHash(value: string): Promise<string> {
  // dosafe.bulk_upsert_threats: '0x' || encode(digest(lower(entity_value), 'sha256'), 'hex')
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value.toLowerCase())))
  return '0x' + Array.from(digest, (x) => x.toString(16).padStart(2, '0')).join('')
}

Deno.test('entries are sent in entity_hash order, every one of them, whatever the plan', async () => {
  const feed = Array.from({ length: 300 }, (_, i) => ({ ...b, entity_value: `Host-${i}.Example` }))
  const expected = [...feed]
  const hashes = new Map(await Promise.all(feed.map(async (e) => [e, await dbEntityHash(e.entity_value)] as const)))
  expected.sort((x, y) => (hashes.get(x)! < hashes.get(y)! ? -1 : 1))

  const full = await planDelta(feed, null, NOW)
  assertEquals(full.entries, expected)
  // The saved fingerprints keep the feed order; only the send order changes.
  assertEquals(full.next.fingerprints, await Promise.all(feed.map(fingerprintOf)))

  const delta = await planDelta(feed, await stateOf(feed.slice(0, 100), new Date(NOW - 86_400_000).toISOString()), NOW)
  assertEquals(delta.entries, expected.filter((e) => feed.indexOf(e) >= 100))
})

Deno.test('entityHashOrder keeps equal keys in order and puts entries without a value first', async () => {
  const x1 = { entity_value: 'same.example', source: 's1' }
  const x2 = { entity_value: 'SAME.example', source: 's2' }
  const none = { source: 's3' }
  assertEquals(await entityHashOrder([x1, x2, none]), [none, x1, x2])
  assertEquals(await entityHashOrder([]), [])
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
    if (init?.method === 'DELETE') {
      // What Storage answers for an object that does not exist.
      return objects.delete(url) ? new Response('{}', { status: 200 }) : new Response(NOT_FOUND, { status: 400 })
    }
    if (init?.method === 'POST') {
      objects.set(url, new Uint8Array(await new Response(init.body).arrayBuffer()))
      return new Response('{}', { status: 200 })
    }
    const body = objects.get(url)?.slice().buffer as ArrayBuffer | undefined
    return body ? new Response(body, { status: 200 }) : new Response(NOT_FOUND, { status: 400 })
  }) as typeof fetch
  const store = storageDeltaStore({ url: 'https://db.example', key: 'k', fetch: fakeFetch })
  assertEquals(await store.load('watchlist_internet'), null)
  const state = await stateOf([a, b], new Date(NOW).toISOString())
  assertEquals(await store.save('watchlist_internet', state), true)
  assertEquals([...objects.keys()], ['https://db.example/storage/v1/object/dosafe-feed-state/watchlist_internet.json.gz'])
  assertEquals(await store.load('watchlist_internet'), state)
  assertEquals(await store.clear('watchlist_internet'), true)
  assertEquals(await store.load('watchlist_internet'), null)
  // Clearing a state that is not there is fine.
  assertEquals(await store.clear('watchlist_internet'), true)
})

Deno.test('startRun removes the state before writing; when it cannot, it writes a tombstone; else nothing is sent', async () => {
  const lastFull = new Date(NOW - 86_400_000).toISOString()
  const plan = await planDelta([a, b, c], await stateOf([a, b], lastFull), NOW)
  assertEquals(plan.entries, [c])
  const cleared: string[] = []
  const saved: DeltaState[] = []
  const ok = {
    load: () => Promise.resolve(null),
    save: (_f: string, st: DeltaState) => { saved.push(st); return Promise.resolve(true) },
    clear: (f: string) => { cleared.push(f); return Promise.resolve(true) },
  }
  assertEquals(await startRun(ok, 'feed', plan), [c])
  assertEquals([cleared, saved.length], [['feed'], 0])
  // DOS/DOS.AI#7625: the state could not be removed, so it is overwritten with a tombstone.
  const stuck = { ...ok, clear: () => Promise.resolve(false) }
  assertEquals(await startRun(stuck, 'feed', plan), [c])
  assertEquals(saved, [TOMBSTONE_STATE])
  // Neither works: the old fingerprints would stay, so the run must not write.
  const broken = { ...stuck, save: () => Promise.resolve(false) }
  let threw = false
  try {
    await startRun(broken, 'feed', plan)
  } catch {
    threw = true
  }
  assertEquals(threw, true)
})

Deno.test('a tombstone state asks for a full send', async () => {
  const plan = await planDelta([a, b], parseState(JSON.parse(JSON.stringify(TOMBSTONE_STATE))), NOW)
  assertEquals([plan.full, plan.reason, plan.entries.length], [true, 'refresh_due', 2])
})

Deno.test('isStorageNotFound: only a missing object or bucket', () => {
  assertEquals(isStorageNotFound(404, ''), true)
  assertEquals(isStorageNotFound(400, NOT_FOUND), true)
  assertEquals(isStorageNotFound(400, '{"statusCode":"404","code":"NoSuchBucket","error":"Bucket not found","message":"Bucket not found"}'), true)
  assertEquals(isStorageNotFound(400, '{"statusCode":"403","code":"InvalidJWT","error":"InvalidJWT","message":"jwt expired"}'), false)
  assertEquals(isStorageNotFound(400, 'not json'), false)
  assertEquals(isStorageNotFound(400, '{}'), false)
  assertEquals(isStorageNotFound(500, NOT_FOUND), false)
})

Deno.test('storageDeltaStore.clear fails on any error other than not found', async () => {
  const answering = (status: number, body: string) =>
    storageDeltaStore({ url: 'https://db.example', key: 'k', fetch: (() => Promise.resolve(new Response(body, { status }))) as typeof fetch })
  assertEquals(await answering(500, '{"statusCode":"500","error":"internal"}').clear('f'), false)
  assertEquals(await answering(400, '{"statusCode":"403","code":"InvalidJWT","error":"InvalidJWT"}').clear('f'), false)
  assertEquals(await answering(400, NOT_FOUND).clear('f'), true)
  assertEquals(await answering(404, '').clear('f'), true)
})

// DOS/DOS.AI#7625: one run of a feed at a time.

function leaseServer(answers: Record<string, (args: Record<string, unknown>) => Response>) {
  const calls: { fn: string; args: Record<string, unknown> }[] = []
  const fakeFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const fn = String(input).split('/rpc/')[1]
    const args = JSON.parse(String(init?.body))
    calls.push({ fn, args })
    const answer = answers[fn]
    if (!answer) throw new Error(`unexpected call ${fn}`)
    return answer(args)
  }) as typeof fetch
  return {
    calls,
    leases: rpcFeedLeases({ url: 'https://db.example', key: 'k', fetch: fakeFetch, newHolder: () => 'h-1' }),
    defaultLeases: rpcFeedLeases({ url: 'https://db.example', key: 'k', fetch: fakeFetch }),
  }
}

const json = (v: unknown, status = 200) => new Response(JSON.stringify(v), { status })

Deno.test('rpcFeedLeases: a free feed is leased, renewed and released by this holder', async () => {
  const { calls, leases } = leaseServer({
    acquire_feed_lease: () => json({ acquired: true, expires_at: '2026-11-18T00:15:00Z' }),
    renew_feed_lease: () => json(true),
    release_feed_lease: () => json(true),
  })
  const r = await leases.acquire('urlhaus', 900)
  if (!r.held) throw new Error('expected the lease')
  assertEquals(r.lease.supported, true)
  assertEquals(await r.lease.renew(), 'held')
  await r.lease.release()
  assertEquals(calls, [
    { fn: 'acquire_feed_lease', args: { p_feed: 'urlhaus', p_holder: 'h-1', p_ttl_seconds: 900 } },
    { fn: 'renew_feed_lease', args: { p_feed: 'urlhaus', p_holder: 'h-1', p_ttl_seconds: 900 } },
    { fn: 'release_feed_lease', args: { p_feed: 'urlhaus', p_holder: 'h-1' } },
  ])
})

Deno.test('rpcFeedLeases: every acquire has its own holder, so two runs in one isolate exclude each other', async () => {
  const { calls, defaultLeases } = leaseServer({ acquire_feed_lease: () => json({ acquired: true }) })
  await defaultLeases.acquire('urlhaus', 900)
  await defaultLeases.acquire('urlhaus', 900)
  const holders = calls.map((c) => c.args.p_holder)
  assertEquals([typeof holders[0], holders[0] === holders[1]], ['string', false])
})

Deno.test('rpcFeedLeases: a held feed is reported with its expiry', async () => {
  const { leases } = leaseServer({ acquire_feed_lease: () => json({ acquired: false, expires_at: '2026-11-18T00:15:00Z' }) })
  assertEquals(await leases.acquire('urlhaus', 900), { held: false, until: '2026-11-18T00:15:00Z' })
})

Deno.test('rpcFeedLeases: without the lease functions the run goes on unprotected; other errors throw', async () => {
  const missing = leaseServer({ acquire_feed_lease: () => json({ code: 'PGRST202', message: 'Could not find the function' }, 404) })
  const r = await missing.leases.acquire('urlhaus', 900)
  if (!r.held) throw new Error('expected a lease stand-in')
  assertEquals([r.lease.supported, await r.lease.renew()], [false, 'held'])
  await r.lease.release()
  assertEquals(missing.calls.length, 1)

  const down = leaseServer({ acquire_feed_lease: () => json({ message: 'boom' }, 503) })
  let threw = false
  try {
    await down.leases.acquire('urlhaus', 900)
  } catch {
    threw = true
  }
  assertEquals(threw, true)
})

Deno.test('rpcFeedLeases: a lost lease and a failed renewal are told apart', async () => {
  const lost = leaseServer({ acquire_feed_lease: () => json({ acquired: true }), renew_feed_lease: () => json(false) })
  const r = await lost.leases.acquire('urlhaus', 900)
  if (!r.held) throw new Error('expected the lease')
  assertEquals(await r.lease.renew(), 'lost')
  const failing = leaseServer({ acquire_feed_lease: () => json({ acquired: true }), renew_feed_lease: () => json({}, 500) })
  const f = await failing.leases.acquire('urlhaus', 900)
  if (!f.held) throw new Error('expected the lease')
  assertEquals(await f.lease.renew(), 'error')
})

Deno.test('finishRun saves only while the lease is held', async () => {
  const saved: string[] = []
  const store = {
    load: () => Promise.resolve(null),
    save: (f: string) => { saved.push(f); return Promise.resolve(true) },
    clear: () => Promise.resolve(true),
  }
  const lease = (r: 'held' | 'lost' | 'error'): FeedLease => ({ supported: true, renew: () => Promise.resolve(r), release: () => Promise.resolve() })
  const next = await stateOf([a], new Date(NOW).toISOString())
  assertEquals(await finishRun(store, lease('lost'), 'feed', next), 'lease_lost')
  // A failed renewal: not known to be held, so no save, and reported like a failed save (it alerts).
  assertEquals(await finishRun(store, lease('error'), 'feed', next), 'not_saved')
  assertEquals(saved, [])
  assertEquals(await finishRun(store, lease('held'), 'feed', next), 'saved')
  assertEquals(saved, ['feed'])
  assertEquals(await finishRun({ ...store, save: () => Promise.resolve(false) }, lease('held'), 'feed', next), 'not_saved')
})

Deno.test('savedRunStatus: a failed save makes the run partial, which alerts', () => {
  assertEquals(savedRunStatus('saved'), { status: 'success', error: null })
  assertEquals(savedRunStatus('lease_lost'), { status: 'success', error: null })
  assertEquals(savedRunStatus('not_saved').status, 'partial')
})

Deno.test('scriptFeedLease: none when held elsewhere; released when the scope ends', async () => {
  const busy = leaseServer({ acquire_feed_lease: () => json({ acquired: false, expires_at: 't' }) })
  assertEquals(await scriptFeedLease(busy.leases, 'hagezi_tif', 5400), null)

  const free = leaseServer({ acquire_feed_lease: () => json({ acquired: true }), release_feed_lease: () => json(true) })
  {
    await using lease = await scriptFeedLease(free.leases, 'hagezi_tif', 5400)
    assertEquals(lease?.supported, true)
  }
  assertEquals(free.calls.map((c) => c.fn), ['acquire_feed_lease', 'release_feed_lease'])
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
  assertEquals(await down.clear('f'), false)
})

Deno.test('scriptFeedLease.ensure renews every few minutes and stops a run that lost the feed', async () => {
  let clock = 0
  let answer: () => Response = () => json(true)
  const server = leaseServer({ acquire_feed_lease: () => json({ acquired: true }), renew_feed_lease: () => answer() })
  const lease = await scriptFeedLease(server.leases, 'hagezi_tif', 5400, { now: () => clock })
  if (!lease) throw new Error('expected the lease')
  const renewals = () => server.calls.filter((c) => c.fn === 'renew_feed_lease').length
  const throws = async () => {
    try {
      await lease.ensure()
      return false
    } catch {
      return true
    }
  }
  await lease.ensure()
  assertEquals(renewals(), 0)
  clock = SCRIPT_LEASE_RENEW_EVERY_MS
  await lease.ensure()
  assertEquals(renewals(), 1)
  // A failed call while the lease is still clearly valid: the run goes on.
  answer = () => json({}, 503)
  clock += SCRIPT_LEASE_RENEW_EVERY_MS
  assertEquals(await throws(), false)
  // Too close to the expiry without a confirmed renewal: the run stops.
  clock = SCRIPT_LEASE_RENEW_EVERY_MS + 5400 * 1000 - 60_000
  assertEquals(await throws(), true)
  // Another run took the feed: the run stops at once.
  answer = () => json(false)
  clock = 0
  const fresh = await scriptFeedLease(server.leases, 'hagezi_tif', 5400, { now: () => clock })
  clock = SCRIPT_LEASE_RENEW_EVERY_MS
  let stopped = false
  try {
    await fresh!.ensure()
  } catch {
    stopped = true
  }
  assertEquals(stopped, true)
})
