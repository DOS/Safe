/**
 * Reads the rows of the mobile blocklist files from the database
 * (scripts/generate-blocklist.ts).
 *
 * DOS/DOS.AI#7620: the export reads dosafe.threat_intel once, in heap order,
 * through dosafe.get_blocklist_block_range. The old way, keyset pages of
 * get_domain_blacklist / get_phone_blacklist in entity_value order, read about
 * one table page per row; the block walk reads each table page once.
 *
 * The block-range function returns rows unsorted, so the rows are sorted here
 * (by value, then source) before the entries are built: the files keep a stable
 * order and buildDomainEntries / buildPhoneEntries see duplicates in a fixed
 * order. When the database does not have the function yet, the old keyset
 * paging is used.
 */

import type { DomainRow, PhoneRow } from './blocklist-entries.ts'

/** Heap blocks per call: 2,048 x 8 KB = 16 MB of table, ~55k rows (one jsonb value, so PostgREST max_rows cannot cut it). */
export const BLOCK_STEP = 2048
/** Extra rounds for blocks the table gains during the run. */
const MAX_TAIL_ROUNDS = 5
/** Rows per keyset page on the fallback path. */
export const KEYSET_CHUNK = 50000

export interface BlockRangeRow extends PhoneRow, DomainRow {
  entity_type?: string | null
  report_count?: number | null
}

/** Calls a database function; resolves to null when the function does not exist (PostgREST 404 / PGRST202). */
export type Rpc = (fn: string, body: Record<string, unknown>) => Promise<unknown[] | number | null>

export interface BlocklistRows {
  phones: PhoneRow[]
  domains: DomainRow[]
  /** 'block_range' or 'keyset' (the fallback). */
  method: string
  calls: number
}

function compareRows(a: DomainRow, b: DomainRow): number {
  const av = String(a.entity_value ?? '')
  const bv = String(b.entity_value ?? '')
  if (av !== bv) return av < bv ? -1 : 1
  const as = String(a.source ?? '')
  const bs = String(b.source ?? '')
  return as < bs ? -1 : as > bs ? 1 : 0
}

export async function fetchBlocklistRows(rpc: Rpc, log: (line: string) => void = () => {}): Promise<BlocklistRows> {
  const first = await rpc('threat_intel_block_count', {})
  if (first === null) {
    log('dosafe.threat_intel_block_count is missing: falling back to keyset pages')
    return await fetchByKeyset(rpc, log)
  }
  if (typeof first !== 'number' || !Number.isSafeInteger(first) || first < 0) {
    throw new Error(`threat_intel_block_count returned ${JSON.stringify(first)}`)
  }

  const phones: PhoneRow[] = []
  const domains: DomainRow[] = []
  let total = first
  let from = 0
  let calls = 1
  // Each request stops at the block count known when it is made, so blocks the table gains later
  // are read by the next round, started from where the last one ended.
  for (let round = 0; ; round++) {
    while (from < total) {
      const count = Math.min(BLOCK_STEP, total - from)
      const rows = await rpc('get_blocklist_block_range', { p_first_block: from, p_block_count: count })
      calls++
      if (!Array.isArray(rows)) throw new Error('get_blocklist_block_range did not return rows')
      for (const row of rows as BlockRangeRow[]) {
        if (row.entity_type === 'phone') phones.push(row)
        else if (row.entity_type === 'domain') domains.push(row)
      }
      log(`  blocks ${from}-${from + count - 1} of ${total}: ${rows.length} rows`)
      from += count
    }
    const now = await rpc('threat_intel_block_count', {})
    calls++
    if (typeof now !== 'number' || !Number.isSafeInteger(now)) {
      throw new Error(`threat_intel_block_count returned ${JSON.stringify(now)}`)
    }
    // A table that keeps growing is read for a few more rounds, not forever.
    if (now <= total || round >= MAX_TAIL_ROUNDS) break
    total = now
  }

  phones.sort(compareRows)
  domains.sort(compareRows)
  return { phones, domains, method: 'block_range', calls }
}

async function fetchByKeyset(rpc: Rpc, log: (line: string) => void): Promise<BlocklistRows> {
  let calls = 1
  const all = async (fn: string): Promise<DomainRow[]> => {
    const out: DomainRow[] = []
    let cursor: string | null = null
    while (true) {
      const body: Record<string, unknown> = { p_limit: KEYSET_CHUNK, p_since: null }
      if (cursor) body.p_cursor = cursor
      else body.p_offset = 0
      const chunk = await rpc(fn, body)
      calls++
      // An empty or failed page ends nothing silently: a missing function here is an error.
      if (!Array.isArray(chunk)) throw new Error(`${fn} did not return rows`)
      out.push(...(chunk as DomainRow[]))
      log(`  ${fn}: got ${chunk.length} rows (total ${out.length})`)
      if (chunk.length < KEYSET_CHUNK) break
      cursor = String((chunk[chunk.length - 1] as DomainRow).entity_value ?? '')
    }
    return out
  }
  const phones = await all('get_phone_blacklist')
  const domains = await all('get_domain_blacklist')
  return { phones, domains, method: 'keyset', calls }
}
