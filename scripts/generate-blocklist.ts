/**
 * Generates compressed blocklist files for mobile download.
 *
 * Output: uploads to Supabase Storage `blocklist` bucket:
 *   - blocklist.json.gz — combined phones + domains
 *   - phones.json.gz — phone numbers only (legacy)
 *   - domains.json.gz — domains only
 *
 * Usage: deno run --allow-net --allow-env scripts/generate-blocklist.ts
 *
 * Requires: SUPABASE_SERVICE_ROLE_KEY env var.
 * Note: service_role has 120s statement_timeout (vs 8s for anon/authenticated).
 */

const SUPABASE_URL = Deno.env.get('SUPABASE_URL') ||
  Deno.env.get('NEXT_PUBLIC_SUPABASE_URL') ||
  'https://gulptwduchsjcsbndmua.supabase.co'
const SUPABASE_KEY = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!

if (!SUPABASE_KEY) {
  console.error('ERROR: SUPABASE_SERVICE_ROLE_KEY is required.')
  Deno.exit(1)
}

const CHUNK_SIZE = 50000

interface PhoneEntry { p: string; n: string | null; c: string; r: number }
interface DomainEntry { d: string; c: string; s: string | null }

async function fetchRpc(fnName: string, limit: number, cursor: string | null): Promise<any[]> {
  const body: Record<string, unknown> = { p_limit: limit, p_since: null }
  if (cursor) {
    body.p_cursor = cursor
  } else {
    body.p_offset = 0
  }
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
  if (!res.ok) {
    console.error(`RPC ${fnName} error: ${res.status} ${await res.text()}`)
    return []
  }
  return await res.json()
}

async function fetchAll(fnName: string): Promise<any[]> {
  const all: any[] = []
  let cursor: string | null = null
  let hasMore = true
  while (hasMore) {
    const t0 = Date.now()
    const chunk = await fetchRpc(fnName, CHUNK_SIZE, cursor)
    const elapsed = ((Date.now() - t0) / 1000).toFixed(1)
    const total = all.length + chunk.length
    console.log(`  ${fnName}: got ${chunk.length} rows (total ${total}, ${elapsed}s)`)
    all.push(...chunk)
    hasMore = chunk.length === CHUNK_SIZE
    if (chunk.length > 0) {
      cursor = chunk[chunk.length - 1].entity_value
    }
  }
  return all
}

function normalizePhone(phone: string): string | null {
  let d = phone.replace(/[^\d+]/g, '')
  if (d.startsWith('+84')) d = '0' + d.slice(3)
  else if (d.startsWith('84') && d.length === 11) d = '0' + d.slice(2)
  if (/^0\d{9}$/.test(d)) return d
  if (/^\+\d{7,15}$/.test(d)) return d
  if (/^\d{7,15}$/.test(d)) return d
  return null
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
  console.log('Fetching phones...')
  const rawPhones = await fetchAll('get_phone_blacklist')
  console.log(`  Got ${rawPhones.length} phone rows`)

  // Dedup phones
  const phoneMap = new Map<string, PhoneEntry>()
  for (const row of rawPhones) {
    const num = normalizePhone(row.entity_value)
    if (!num) continue
    const existing = phoneMap.get(num)
    if (!existing || (row.risk_score ?? 0) > existing.r) {
      phoneMap.set(num, {
        p: num,
        n: row.name || null,
        c: row.category || 'scam',
        r: row.risk_score ?? 50,
      })
    }
  }
  const phones = Array.from(phoneMap.values())
  console.log(`  Deduped to ${phones.length} phones`)

  console.log('Fetching domains...')
  const rawDomains = await fetchAll('get_domain_blacklist')
  console.log(`  Got ${rawDomains.length} domain rows`)

  // Dedup domains
  const domainMap = new Map<string, DomainEntry>()
  for (const row of rawDomains) {
    const domain = (row.entity_value || '').trim().toLowerCase()
    if (!domain || !domain.includes('.') || domain.length < 4) continue
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) continue // skip IPs
    if (!domainMap.has(domain)) {
      domainMap.set(domain, {
        d: domain,
        c: row.category || 'phishing',
        s: row.source || null,
      })
    }
  }
  const domains = Array.from(domainMap.values())
  console.log(`  Deduped to ${domains.length} domains`)

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

  // Upload
  console.log('Uploading to Supabase Storage...')
  const results = await Promise.all([
    uploadToStorage('blocklist', 'blocklist.json.gz', combinedGz),
    uploadToStorage('blocklist', 'phones.json.gz', phonesGz),
    uploadToStorage('blocklist', 'domains.json.gz', domainsGz),
    uploadJson('blocklist', 'meta.json', meta),
  ])

  if (results.every(Boolean)) {
    console.log('✅ All files uploaded successfully!')
  } else {
    console.error('❌ Some uploads failed')
  }

  console.log(`\nSummary:`)
  console.log(`  Phones: ${phones.length}`)
  console.log(`  Domains: ${domains.length}`)
  console.log(`  Combined GZ: ${(combinedGz.length / 1024 / 1024).toFixed(1)}MB`)
  console.log(`  Version: ${meta.version}`)
}

main()

