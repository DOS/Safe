// Send only what changed in a full-list feed since its last complete run (DOS/DOS.AI#7620).
//
// Copy of DOS/DOSafe supabase/functions/_shared/feed-delta.ts; keep the two equal.
//
// Why: every entry sent to dosafe.bulk_upsert_threats costs random disk reads on the database (an
// index probe plus the stored row), even when nothing changes; the churn guard skips the write but
// not the reads. Full-list feeds re-send the same entries every run, so most of that IO buys nothing.
//
// How: a run fingerprints every entry of the feed. Between full sends it sends only the entries
// whose fingerprint the last complete run did not have (new, changed, or listed again); once
// FULL_SEND_EVERY_MS has passed since the last full send, or when no state is stored, it sends the
// whole feed. The state (the fingerprints and the time of the last full send) is saved only after a
// run that stored every row, so a failed or partial run is simply repeated against the older state.
// Entries that leave the feed are not touched, as before; they age out on the existing schedule.
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
  /** The entries to send this run. */
  entries: T[]
  full: boolean
  reason: 'no_state' | 'refresh_due' | 'delta'
  /** The state to save once the run stored every row. */
  next: DeltaState
}

/** JSON with object keys sorted, so two equal entries always give the same text. */
export function stableJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value) ?? 'null'
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
    return { entries, full: true, reason: 'no_state', next: { v: STATE_VERSION, lastFullAt: startedAt, fingerprints } }
  }
  if (nowMs - lastFullMs >= FULL_SEND_EVERY_MS) {
    return { entries, full: true, reason: 'refresh_due', next: { v: STATE_VERSION, lastFullAt: startedAt, fingerprints } }
  }
  const seen = new Set(previous.fingerprints)
  const send = entries.filter((_, i) => !seen.has(fingerprints[i]))
  return {
    entries: send,
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
  /** Saves the state; false when it could not (the next run then repeats against the older state). */
  save(feed: string, state: DeltaState): Promise<boolean>
}

async function gzip(text: string): Promise<Blob> {
  return await new Response(new Blob([text]).stream().pipeThrough(new CompressionStream('gzip'))).blob()
}

async function gunzip(data: ArrayBuffer): Promise<string> {
  return await new Response(new Blob([data]).stream().pipeThrough(new DecompressionStream('gzip'))).text()
}

export const DELTA_BUCKET = 'dosafe-feed-state'

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
          await res.body?.cancel()
          if (res.status !== 400 && res.status !== 404) console.warn(`feed-delta: no state for ${feed} (HTTP ${res.status})`)
          return null
        }
        return parseState(JSON.parse(await gunzip(await res.arrayBuffer())))
      } catch (e) {
        console.warn(`feed-delta: state for ${feed} unreadable: ${e instanceof Error ? e.message : e}`)
        return null
      }
    },
    async save(feed, state) {
      try {
        const res = await doFetch(objectUrl(feed), {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/gzip', 'x-upsert': 'true' },
          body: await gzip(JSON.stringify(state)),
          signal: AbortSignal.timeout(timeoutMs),
        })
        await res.body?.cancel()
        if (!res.ok) console.warn(`feed-delta: state for ${feed} not saved (HTTP ${res.status})`)
        return res.ok
      } catch (e) {
        console.warn(`feed-delta: state for ${feed} not saved: ${e instanceof Error ? e.message : e}`)
        return false
      }
    },
  }
}
