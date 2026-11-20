// Send only what changed in a full-list feed since its last complete run (DOS/DOS.AI#7620).
//
// Copy of the DOSafe feed-delta module that DOSafe's own importers use; keep the two equal.
//
// Why: every entry sent to dosafe.bulk_upsert_threats costs random disk reads on the database (an
// index probe plus the stored row), even when nothing changes; the churn guard skips the write but
// not the reads. Full-list feeds re-send the same entries every run, so most of that IO buys nothing.
//
// How: a run fingerprints every entry of the feed. Between full sends it sends only the entries
// whose fingerprint the last complete run did not have (new, changed, or listed again); once
// FULL_SEND_EVERY_MS has passed since the last full send, or when no state is stored, it sends the
// whole feed. The state (the fingerprints and the time of the last full send) is saved only after a
// run that stored every row. Before a run writes anything, the saved state is removed, or overwritten
// with a tombstone when it cannot be removed (startRun), so a run that stops half-way, or whose state
// upload fails, is followed by a full send: the fingerprints never describe rows the database no
// longer has. One run of a feed at a time holds the feed's lease (rpcFeedLeases, finishRun).
// Entries that leave the feed are not touched, as before; they age out on the existing schedule.
// The entries to send come out in entity_hash order (entityHashOrder), which cuts the index reads.
//
// Why a full send at least every 6 days: bulk_upsert_threats refreshes a row's last_seen_at only
// when it is older than 7 days, and dosafe.expire_unseen_threats expires rows unseen for 14 days
// before the latest complete run. After a full send at time T every listed row has
// last_seen_at > T - 7 days, so as long as the next full send comes within 7 days, no listed row
// can fall behind the 14-day cutoff. 6 days leaves a day for a late or failed run.
//
// What can lag by up to 6 days (until the next full send), compared with sending every run:
// an entry the database dropped on a run and would accept now (its trusted entity was revoked, or
// its source was paused in dosafe.threat_source_pauses and then resumed). A delta run never loses
// a new or changed entry.

export const FULL_SEND_EVERY_MS = 6 * 24 * 60 * 60 * 1000
const STATE_VERSION = 1

export interface DeltaState {
  v: number
  /** ISO time the last full send started. */
  lastFullAt: string
  /** Fingerprints of every entry of the last complete run. */
  fingerprints: string[]
}

export interface DeltaPlan<T> {
  /** The entries to send this run, in entity_hash order (entityHashOrder). */
  entries: T[]
  full: boolean
  reason: 'no_state' | 'refresh_due' | 'delta'
  /** The state to save once the run stored every row. */
  next: DeltaState
}

/** JSON with object keys sorted, so two equal entries always give the same text. */
export function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  // As JSON.stringify does: a Date (or any object with toJSON) is written as what toJSON returns.
  const withToJson = value as { toJSON?: () => unknown }
  if (typeof withToJson.toJSON === 'function') return stableJson(withToJson.toJSON())
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`
  const obj = value as Record<string, unknown>
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort()
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableJson(obj[k])}`).join(',')}}`
}

const encoder = new TextEncoder()
const HEX = Array.from({ length: 256 }, (_, i) => i.toString(16).padStart(2, '0'))

/** 64 bits of SHA-256 over the entry's stable JSON (Web Crypto, so no Node types are needed). */
export async function fingerprintOf(entry: unknown): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(stableJson(entry))))
  let hex = ''
  for (let i = 0; i < 8; i++) hex += HEX[digest[i]]
  return hex
}

// ─── Send order (DOS/DOS.AI#7925) ───
//
// bulk_upsert_threats finds the stored row of each entry through the unique index on
// dosafe.threat_intel (entity_hash, source), where entity_hash is '0x' || sha256(lower(entity_value)).
// Sent in feed order, the entries of one chunk sit on as many different leaves of that index (1 GB on
// Production, against 512 MB of shared_buffers), so nearly every entry costs a disk read for its leaf
// on top of the read for its row. Sent in entity_hash order, a chunk of a large feed covers one narrow
// key range and its entries share a few hundred leaves. Measured on Beta (read-only, same probe as the
// conflict check): 1.56 blocks read per entry in feed order, 0.91 in hash order. Only the order
// changes: every entry is still sent, and the database sorts each call by entity_hash itself.

/** The first 64 bits of sha256(lower(entity_value)), as hex: the order of the conflict index. */
async function entityHashKey(entry: unknown): Promise<string> {
  const value = (entry as { entity_value?: unknown } | null)?.entity_value
  if (typeof value !== 'string') return ''
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value.toLowerCase())))
  let hex = ''
  for (let i = 0; i < 8; i++) hex += HEX[digest[i]]
  return hex
}

/**
 * The entries in entity_hash order (stable: equal keys keep their order). An entry without a
 * string entity_value sorts first; the order only affects how many index pages a chunk reads.
 */
export async function entityHashOrder<T>(entries: T[]): Promise<T[]> {
  const keys = new Array<string>(entries.length)
  const BATCH = 4096
  for (let i = 0; i < entries.length; i += BATCH) {
    const part = await Promise.all(entries.slice(i, i + BATCH).map(entityHashKey))
    for (let j = 0; j < part.length; j++) keys[i + j] = part[j]
  }
  const order = Array.from({ length: entries.length }, (_, i) => i)
  order.sort((x, y) => (keys[x] < keys[y] ? -1 : keys[x] > keys[y] ? 1 : x - y))
  return order.map((i) => entries[i])
}

async function fingerprintAll(entries: unknown[]): Promise<string[]> {
  const out = new Array<string>(entries.length)
  const BATCH = 4096
  for (let i = 0; i < entries.length; i += BATCH) {
    const part = await Promise.all(entries.slice(i, i + BATCH).map(fingerprintOf))
    for (let j = 0; j < part.length; j++) out[i + j] = part[j]
  }
  return out
}

export async function planDelta<T>(entries: T[], previous: DeltaState | null, nowMs: number): Promise<DeltaPlan<T>> {
  const fingerprints = await fingerprintAll(entries)
  const startedAt = new Date(nowMs).toISOString()
  const lastFullMs = previous ? Date.parse(previous.lastFullAt) : NaN

  if (!previous || !Number.isFinite(lastFullMs) || lastFullMs > nowMs) {
    return { entries: await entityHashOrder(entries), full: true, reason: 'no_state', next: { v: STATE_VERSION, lastFullAt: startedAt, fingerprints } }
  }
  if (nowMs - lastFullMs >= FULL_SEND_EVERY_MS) {
    return { entries: await entityHashOrder(entries), full: true, reason: 'refresh_due', next: { v: STATE_VERSION, lastFullAt: startedAt, fingerprints } }
  }
  const seen = new Set(previous.fingerprints)
  const send = entries.filter((_, i) => !seen.has(fingerprints[i]))
  return {
    entries: await entityHashOrder(send),
    full: false,
    reason: 'delta',
    next: { v: STATE_VERSION, lastFullAt: previous.lastFullAt, fingerprints },
  }
}

export function parseState(value: unknown): DeltaState | null {
  if (!value || typeof value !== 'object') return null
  const v = value as Record<string, unknown>
  if (v.v !== STATE_VERSION || typeof v.lastFullAt !== 'string' || !Array.isArray(v.fingerprints)) return null
  if (!v.fingerprints.every((f) => typeof f === 'string')) return null
  return { v: STATE_VERSION, lastFullAt: v.lastFullAt, fingerprints: v.fingerprints as string[] }
}

export interface DeltaStore {
  /** The saved state, or null when there is none or it cannot be read (the run then sends everything). */
  load(feed: string): Promise<DeltaState | null>
  /** Saves the state; false when it could not (the next run is then a full send). */
  save(feed: string, state: DeltaState): Promise<boolean>
  /** Removes the state (true also when there was none); false when that failed. */
  clear(feed: string): Promise<boolean>
}

/**
 * A state that describes nothing and asks for a full send (its last full send is long past). It
 * stands in for a removed state when the removal fails (DOS/DOS.AI#7625).
 */
export const TOMBSTONE_STATE: DeltaState = { v: STATE_VERSION, lastFullAt: new Date(0).toISOString(), fingerprints: [] }

/**
 * The entries to send, once the saved state is gone: a run that stops half-way must not leave
 * fingerprints of rows it changed only in part. When the state cannot be removed it is overwritten
 * with TOMBSTONE_STATE; when neither works the run must not write at all (it throws), because a
 * later delta run would trust the old fingerprints for rows this run changed.
 */
export async function startRun<T>(store: DeltaStore, feed: string, plan: DeltaPlan<T>): Promise<T[]> {
  if (await store.clear(feed)) return plan.entries
  console.warn(`feed-delta: state for ${feed} could not be removed, overwriting it with a tombstone`)
  if (await store.save(feed, TOMBSTONE_STATE)) return plan.entries
  throw new Error(`feed-delta: state for ${feed} can be neither removed nor overwritten; nothing sent`)
}

// ─── One run of a feed at a time (DOS/DOS.AI#7625) ───
//
// Two runs of one feed can overlap (pg_cron starts sync-threats-6h and retry-failed-syncs at the
// same minute; a manual `?sources=` call or workflow dispatch can start during a scheduled run).
// Each removes the state, sends, and saves its own fingerprints; the later save may describe values
// the other run overwrote. A run therefore takes the feed's lease (the database function
// dosafe.acquire_feed_lease) before it touches the state, saves the state only while it still holds
// the lease (finishRun), and releases it at the end. A run that finds the lease held skips the feed.
// Until the lease functions exist in the database, runs go on without a lease, as before.

export interface FeedLease {
  /** False when the database has no lease functions yet: the run goes on without a lease. */
  readonly supported: boolean
  /**
   * Extends the lease: 'held' when it did, 'lost' when this run no longer holds it, 'error' when
   * the call failed (whether the run still holds it is then unknown).
   */
  renew(): Promise<'held' | 'lost' | 'error'>
  /** Gives the lease back; a failure only logs (the lease then expires on its own). */
  release(): Promise<void>
}

export type LeaseResult = { held: true; lease: FeedLease } | { held: false; until: string | null }

export interface FeedLeases {
  /** Throws when the database cannot answer: the run must not go on unprotected. */
  acquire(feed: string, ttlSeconds: number): Promise<LeaseResult>
}

/** Saves the state only while the run still holds the feed's lease. */
export async function finishRun(
  store: DeltaStore,
  lease: FeedLease,
  feed: string,
  next: DeltaState,
): Promise<'saved' | 'not_saved' | 'lease_lost'> {
  const renewed = await lease.renew()
  if (renewed === 'lost') {
    // Another run took the feed and saves its own state: not an error of this run.
    console.warn(`feed-delta: the lease on ${feed} was lost before the save; the state is not saved`)
    return 'lease_lost'
  }
  if (renewed === 'error') {
    // Not known to be held: do not save, and report it like a failed save (it alerts).
    console.warn(`feed-delta: the lease on ${feed} could not be renewed; the state is not saved`)
    return 'not_saved'
  }
  return (await store.save(feed, next)) ? 'saved' : 'not_saved'
}

const NO_LEASE: FeedLease = { supported: false, renew: async () => 'held', release: async () => {} }

/** How often a script renews its lease while it sends, and how long before expiry it gives up. */
export const SCRIPT_LEASE_RENEW_EVERY_MS = 5 * 60 * 1000
// Covers one chunk with all its retries (three 120 s requests and two 5 s pauses, 370 s in the
// importers), so a chunk ensure() lets through finishes before the lease can expire.
const SCRIPT_LEASE_MARGIN_MS = 10 * 60 * 1000

export interface ScriptFeedLease extends FeedLease, AsyncDisposable {
  /**
   * Call before each chunk it sends: renews the lease every few minutes, and throws when the run
   * no longer holds it, or cannot show it does before it expires. A run that outlived its lease
   * must stop writing: another run may have taken the feed and saved newer fingerprints.
   */
  ensure(): Promise<void>
}

/**
 * For an import script: the feed's lease, released when the `await using` scope ends (also when
 * the script throws), or null after a notice when another run holds it. ttlSeconds should be the
 * job's timeout, so the lease of a run that is killed does not outlive it.
 */
export async function scriptFeedLease(
  leases: FeedLeases,
  feed: string,
  ttlSeconds: number,
  opts: { now?: () => number } = {},
): Promise<ScriptFeedLease | null> {
  const now = opts.now ?? Date.now
  const leased = await leases.acquire(feed, ttlSeconds)
  if (!leased.held) {
    console.log(`::notice::${feed}: another run holds its lease (until ${leased.until ?? 'unknown'}); nothing to do`)
    return null
  }
  const lease = leased.lease
  let heldAt = now()
  return {
    supported: lease.supported,
    renew: () => lease.renew(),
    release: () => lease.release(),
    [Symbol.asyncDispose]: () => lease.release(),
    async ensure() {
      if (now() - heldAt < SCRIPT_LEASE_RENEW_EVERY_MS) return
      const renewed = await lease.renew()
      if (renewed === 'held') {
        heldAt = now()
        return
      }
      if (renewed === 'lost') throw new Error(`feed lease for ${feed} lost: another run took the feed`)
      // A failed call: go on while the lease last confirmed is still clearly valid.
      if (now() - heldAt > ttlSeconds * 1000 - SCRIPT_LEASE_MARGIN_MS) {
        throw new Error(`feed lease for ${feed} could not be renewed before it expires`)
      }
    },
  }
}

/** sync_log status and error of an import that stored every row it sent, by the result of its save. */
export function savedRunStatus(save: 'saved' | 'not_saved' | 'lease_lost'): { status: 'success' | 'partial'; error: string | null } {
  return save === 'not_saved'
    ? { status: 'partial', error: 'all rows stored, but the delta state was not saved: the next runs send the whole feed' }
    : { status: 'success', error: null }
}

/** Leases kept by the dosafe lease functions, called through PostgREST. */
export function rpcFeedLeases(opts: {
  url: string
  key: string
  timeoutMs?: number
  fetch?: typeof fetch
  /** A new holder id for each acquire (a random UUID by default; tests pass a fixed one). */
  newHolder?: () => string
}): FeedLeases {
  const doFetch = opts.fetch ?? fetch
  const timeoutMs = opts.timeoutMs ?? 30_000
  const newHolder = opts.newHolder ?? (() => crypto.randomUUID())
  const call = (fn: string, args: Record<string, unknown>) =>
    doFetch(`${opts.url}/rest/v1/rpc/${fn}`, {
      method: 'POST',
      headers: {
        apikey: opts.key,
        Authorization: `Bearer ${opts.key}`,
        'Content-Type': 'application/json',
        'Content-Profile': 'dosafe',
        'Accept-Profile': 'dosafe',
      },
      body: JSON.stringify(args),
      signal: AbortSignal.timeout(timeoutMs),
    })

  return {
    async acquire(feed, ttlSeconds) {
      // One holder per acquire, never per module: an Edge isolate can serve two overlapping runs,
      // and a shared holder would let the second take the first one's lease.
      const holder = newHolder()
      const res = await call('acquire_feed_lease', { p_feed: feed, p_holder: holder, p_ttl_seconds: ttlSeconds })
      const text = await res.text()
      if (!res.ok) {
        // PGRST202: no such function in the schema cache, i.e. the migration is not applied yet.
        if (res.status === 404 && /PGRST202/.test(text)) {
          console.warn(`feed-delta: no lease functions in the database; ${feed} runs without a lease`)
          return { held: true, lease: NO_LEASE }
        }
        throw new Error(`feed lease for ${feed}: HTTP ${res.status}`)
      }
      const body = JSON.parse(text) as { acquired?: unknown; expires_at?: unknown }
      if (body.acquired !== true) {
        return { held: false, until: typeof body.expires_at === 'string' ? body.expires_at : null }
      }
      return {
        held: true,
        lease: {
          supported: true,
          async renew() {
            try {
              const r = await call('renew_feed_lease', { p_feed: feed, p_holder: holder, p_ttl_seconds: ttlSeconds })
              const t = await r.text()
              if (!r.ok) {
                console.warn(`feed-delta: lease on ${feed} not renewed (HTTP ${r.status})`)
                return 'error'
              }
              const v = JSON.parse(t)
              if (v === true) return 'held'
              if (v === false) return 'lost'
              return 'error'
            } catch (e) {
              console.warn(`feed-delta: lease on ${feed} not renewed: ${e instanceof Error ? e.message : e}`)
              return 'error'
            }
          },
          async release() {
            try {
              const r = await call('release_feed_lease', { p_feed: feed, p_holder: holder })
              await r.body?.cancel()
              if (!r.ok) console.warn(`feed-delta: lease on ${feed} not released (HTTP ${r.status}); it expires on its own`)
            } catch (e) {
              console.warn(`feed-delta: lease on ${feed} not released: ${e instanceof Error ? e.message : e}`)
            }
          },
        },
      }
    },
  }
}

async function gzip(text: string): Promise<Blob> {
  return await new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'))).blob()
}

async function gunzip(data: ArrayBuffer): Promise<string> {
  return await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'))).text()
}

export const DELTA_BUCKET = 'dosafe-feed-state'
/** file_size_limit of the bucket, as its migration sets it. */
export const DELTA_BUCKET_LIMIT_BYTES = 50 * 1024 * 1024

/**
 * Whether a Storage error answer means "no such object" or "no such bucket". Storage answers those
 * with HTTP 400 and the real status in the body ({"statusCode":"404","error":"not_found"} or
 * "Bucket not found"); a later version may answer 404 itself. Any other 400 is a real failure.
 */
export function isStorageNotFound(status: number, body: string): boolean {
  if (status === 404) return true
  if (status !== 400) return false
  try {
    const b = JSON.parse(body) as { statusCode?: unknown; code?: unknown; error?: unknown }
    return String(b.statusCode) === '404' || b.code === 'NoSuchKey' || b.code === 'NoSuchBucket' ||
      b.error === 'not_found' || b.error === 'Bucket not found'
  } catch {
    return false
  }
}

/** State kept as one gzip JSON object per feed in a private Supabase Storage bucket. */
export function storageDeltaStore(opts: {
  url: string
  key: string
  bucket?: string
  timeoutMs?: number
  fetch?: typeof fetch
}): DeltaStore {
  const bucket = opts.bucket ?? DELTA_BUCKET
  const doFetch = opts.fetch ?? fetch
  const timeoutMs = opts.timeoutMs ?? 30_000
  const objectUrl = (feed: string) =>
    `${opts.url}/storage/v1/object/${bucket}/${encodeURIComponent(feed)}.json.gz`
  const headers = { apikey: opts.key, Authorization: `Bearer ${opts.key}` }

  return {
    async load(feed) {
      try {
        const res = await doFetch(objectUrl(feed), { headers, signal: AbortSignal.timeout(timeoutMs) })
        if (!res.ok) {
          const body = await res.text().catch(() => '')
          if (!isStorageNotFound(res.status, body)) console.warn(`feed-delta: no state for ${feed} (HTTP ${res.status})`)
          return null
        }
        return parseState(JSON.parse(await gunzip(await res.arrayBuffer())))
      } catch (e) {
        console.warn(`feed-delta: state for ${feed} unreadable: ${e instanceof Error ? e.message : e}`)
        return null
      }
    },
    async clear(feed) {
      try {
        const res = await doFetch(objectUrl(feed), { method: 'DELETE', headers, signal: AbortSignal.timeout(timeoutMs) })
        if (res.ok) {
          await res.body?.cancel()
          return true
        }
        // Nothing to remove (no such object, or no bucket yet) is a success; any other error is not.
        if (isStorageNotFound(res.status, await res.text().catch(() => ''))) return true
        console.warn(`feed-delta: state for ${feed} not cleared (HTTP ${res.status})`)
        return false
      } catch (e) {
        console.warn(`feed-delta: state for ${feed} not cleared: ${e instanceof Error ? e.message : e}`)
        return false
      }
    },
    async save(feed, state) {
      try {
        const body = await gzip(JSON.stringify(state))
        // HaGeZi's state is ~22 MB (DOS/DOS.AI#7625): say so well before it reaches the limit.
        if (body.size > DELTA_BUCKET_LIMIT_BYTES * 0.6) {
          console.warn(`feed-delta: state for ${feed} is ${body.size} bytes, over 60% of the bucket's ${DELTA_BUCKET_LIMIT_BYTES}-byte limit`)
        }
        const res = await doFetch(objectUrl(feed), {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/gzip', 'x-upsert': 'true' },
          body,
          signal: AbortSignal.timeout(timeoutMs),
        })
        await res.body?.cancel()
        if (!res.ok) console.warn(`feed-delta: state for ${feed} not saved (HTTP ${res.status}, ${body.size} bytes)`)
        return res.ok
      } catch (e) {
        console.warn(`feed-delta: state for ${feed} not saved: ${e instanceof Error ? e.message : e}`)
        return false
      }
    },
  }
}
