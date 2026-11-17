/**
 * Generates compressed blocklist files for mobile download.
 *
 * Output: uploads to Supabase Storage `blocklist` bucket:
 *   - blocklist.json.gz — combined phones + domains
 *   - phones.json.gz — phone numbers only (legacy)
 *   - domains.json.gz — domains only
 *
 * Only blocking threats are written: see scripts/blocklist-entries.ts
 * (DOS/DOS.AI#7444). The rows are read in one pass over the table: see
 * scripts/blocklist-fetch.ts (DOS/DOS.AI#7620).
 *
 * Usage: deno run --allow-net --allow-env scripts/generate-blocklist.ts
 *
 * Requires: SUPABASE_SERVICE_ROLE_KEY env var.
 * Note: service_role has 120s statement_timeout (vs 8s for anon/authenticated).
 */

import { buildDomainEntries, buildPhoneEntries } from './blocklist-entries.ts'
import { fetchBlocklistRows, type Rpc } from './blocklist-fetch.ts'

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ||
  Deno.env.get('NEXT_PUBLIC_SUPABASE_URL') ||
  'https://gulptwduchsjcsbndmua.supabase.co'
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

if (!SUPABASE_KEY) {
  console.error('ERROR: SUPABASE_SERVICE_ROLE_KEY is required.')
  Deno.exit(1)
}

/** One database call. Null when the function does not exist (PostgREST 404 PGRST202), so the caller can fall back. */
const rpc: Rpc = async (fnName, body) => {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/${fnName}`, {
    method: 'POST',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Content-Profile': 'dosafe',
    },
    body: JSON.stringify(body),
  })
  if (res.status === 404) {
    const text = await res.text()
    if (text.includes('PGRST202')) return null
    throw new Error(`RPC ${fnName} error: 404 ${text}`)
  }
  // Throw rather than return []: an empty page ends pagination, so a failed
  // call would publish a truncated or empty blocklist.
  if (!res.ok) {
    throw new Error(`RPC ${fnName} error: ${res.status} ${await res.text()}`)
  }
  return await res.json()
}

async function gzipCompress(data: Uint8Array): Promise<Uint8Array> {
  const cs = new CompressionStream('gzip')
  const writer = cs.writable.getWriter()
  writer.write(data)
  writer.close()
  const chunks: Uint8Array[] = []
  const reader = cs.readable.getReader()
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    chunks.push(value)
  }
  let len = 0
  for (const c of chunks) len += c.length
  const result = new Uint8Array(len)
  let pos = 0
  for (const c of chunks) { result.set(c, pos); pos += c.length }
  return result
}

async function uploadToStorage(bucket: string, path: string, data: Uint8Array) {
  const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${path}`
  let res = await fetch(url, {
    method: 'PUT',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/gzip',
    },
    body: data,
  })
  if (!res.ok) {
    res = await fetch(`${SUPABASE_URL}/storage/v1/object/${bucket}/${path}`, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/gzip',
      },
      body: data,
    })
  }
  if (!res.ok) {
    console.error(`Upload ${path} failed: ${res.status} ${await res.text()}`)
    return false
  }
  return true
}

async function sha256hex(data: Uint8Array): Promise<string> {
  const hash = await crypto.subtle.digest('SHA-256', data)
  return Array.from(new Uint8Array(hash)).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function uploadJson(bucket: string, path: string, obj: unknown) {
  const data = new TextEncoder().encode(JSON.stringify(obj))
  const url = `${SUPABASE_URL}/storage/v1/object/${bucket}/${path}`
  let res = await fetch(url, {
    method: 'PUT',
    headers: {
      'apikey': SUPABASE_KEY,
      'Authorization': `Bearer ${SUPABASE_KEY}`,
      'Content-Type': 'application/json',
      'Cache-Control': 'public, max-age=0, must-revalidate',
    },
    body: data,
  })
  if (!res.ok) {
    res = await fetch(url, {
      method: 'POST',
      headers: {
        'apikey': SUPABASE_KEY,
        'Authorization': `Bearer ${SUPABASE_KEY}`,
        'Content-Type': 'application/json',
        'Cache-Control': 'public, max-age=0, must-revalidate',
      },
      body: data,
    })
  }
  return res.ok
}

async function main() {
  console.log('Fetching blocklist rows...')
  const t0 = Date.now()
  const rows = await fetchBlocklistRows(rpc, (line) => console.log(line))
  console.log(`  ${rows.method}: ${rows.phones.length} phone rows, ${rows.domains.length} domain rows, ${rows.calls} calls, ${((Date.now() - t0) / 1000).toFixed(1)}s`)

  const phones = buildPhoneEntries(rows.phones)
  console.log(`  Kept ${phones.length} blocking phones`)

  const domains = buildDomainEntries(rows.domains)
  console.log(`  Kept ${domains.length} blocking domains`)

  // Never replace the published files with an empty list.
  if (phones.length === 0 || domains.length === 0) {
    throw new Error(`Refusing to upload: ${phones.length} phones, ${domains.length} domains`)
  }

  const now = new Date().toISOString()

  // Generate combined file
  console.log('Generating blocklist.json.gz...')
  const combined = {
    v: 2,
    generated: now,
    phones: { total: phones.length, entries: phones },
    domains: { total: domains.length, entries: domains },
  }
  const combinedJson = new TextEncoder().encode(JSON.stringify(combined))
  const combinedGz = await gzipCompress(combinedJson)
  console.log(`  JSON: ${(combinedJson.length / 1024 / 1024).toFixed(1)}MB → GZ: ${(combinedGz.length / 1024 / 1024).toFixed(1)}MB`)

  // Generate phones-only (legacy)
  console.log('Generating phones.json.gz...')
  const phonesOnly = { v: 1, generated: now, total: phones.length, phones }
  const phonesJson = new TextEncoder().encode(JSON.stringify(phonesOnly))
  const phonesGz = await gzipCompress(phonesJson)
  console.log(`  JSON: ${(phonesJson.length / 1024 / 1024).toFixed(1)}MB → GZ: ${(phonesGz.length / 1024 / 1024).toFixed(1)}MB`)

  // Generate domains-only
  console.log('Generating domains.json.gz...')
  const domainsOnly = { v: 1, generated: now, total: domains.length, domains }
  const domainsJson = new TextEncoder().encode(JSON.stringify(domainsOnly))
  const domainsGz = await gzipCompress(domainsJson)
  console.log(`  JSON: ${(domainsJson.length / 1024 / 1024).toFixed(1)}MB → GZ: ${(domainsGz.length / 1024 / 1024).toFixed(1)}MB`)

  // Generate meta.json — lightweight manifest for mobile to check before downloading
  const checksum = await sha256hex(combinedGz)
  const meta = {
    version: checksum.slice(0, 12),
    generated: now,
    phones: phones.length,
    domains: domains.length,
    total: phones.length + domains.length,
    sizeBytes: combinedGz.length,
    checksum,
  }
  console.log(`Generating meta.json (version: ${meta.version})...`)

  // Upload the data files first; meta.json goes last so mobile never sees a
  // version whose files did not upload.
  console.log('Uploading to Supabase Storage...')
  const results = await Promise.all([
    uploadToStorage('blocklist', 'blocklist.json.gz', combinedGz),
    uploadToStorage('blocklist', 'phones.json.gz', phonesGz),
    uploadToStorage('blocklist', 'domains.json.gz', domainsGz),
  ])
  if (!results.every(Boolean)) {
    throw new Error('Some uploads failed; meta.json not updated')
  }
  if (!await uploadJson('blocklist', 'meta.json', meta)) {
    throw new Error('Upload meta.json failed')
  }
  console.log('✅ All files uploaded successfully!')

  console.log(`\nSummary:`)
  console.log(`  Phones: ${phones.length}`)
  console.log(`  Domains: ${domains.length}`)
  console.log(`  Combined GZ: ${(combinedGz.length / 1024 / 1024).toFixed(1)}MB`)
  console.log(`  Version: ${meta.version}`)
}

main().catch((err) => {
  console.error(`❌ ${err instanceof Error ? err.message : err}`)
  Deno.exit(1)
})

