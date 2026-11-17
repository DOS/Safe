/**
 * Turns rows of dosafe.get_phone_blacklist / get_domain_blacklist into the
 * entries of the mobile blocklist files (scripts/generate-blocklist.ts).
 *
 * Only blocking categories are written (DOS/DOS.AI#7444). The database
 * functions already return only active, unexpired rows of these categories
 * whose value is not an active trusted entity (DOS/DOS.Me migration
 * 20261117130000_dosafe_blacklist_export_blocking_only.sql); the check here
 * keeps a row such as `legitimate` out of the files even if a database has not
 * received that migration. Keep the lists equal to the migration's and to
 * DOS/DOS.AI apps/dosafe-web/src/lib/blocklist-categories.ts.
 *
 * Allow-lists: a category a feed adds later stays out until it is reviewed.
 */

export const DOMAIN_BLOCKING_CATEGORIES: ReadonlySet<string> = new Set([
  'scam',
  'phishing',
  'malware',
  'spam',
  'fraud',
])

export const PHONE_BLOCKING_CATEGORIES: ReadonlySet<string> = new Set([
  ...DOMAIN_BLOCKING_CATEGORIES,
  'immigration_fraud',
  'robocall',
  'unwanted_call',
])

export interface PhoneEntry { p: string; n: string | null; c: string; r: number }
export interface DomainEntry { d: string; c: string; s: string | null }

export interface PhoneRow {
  entity_value?: string | null
  category?: string | null
  name?: string | null
  risk_score?: number | null
}

export interface DomainRow {
  entity_value?: string | null
  category?: string | null
  source?: string | null
}

export function normalizePhone(phone: string): string | null {
  let d = phone.replace(/[^\d+]/g, '')
  if (d.startsWith('+84')) d = '0' + d.slice(3)
  else if (d.startsWith('84') && d.length === 11) d = '0' + d.slice(2)
  if (/^0\d{9}$/.test(d)) return d
  if (/^\+\d{7,15}$/.test(d)) return d
  if (/^\d{7,15}$/.test(d)) return d
  return null
}

/** One entry per normalized number, keeping the highest risk score. */
export function buildPhoneEntries(rows: PhoneRow[]): PhoneEntry[] {
  const phoneMap = new Map<string, PhoneEntry>()
  for (const row of rows) {
    const category = String(row.category ?? '')
    if (!PHONE_BLOCKING_CATEGORIES.has(category)) continue
    const num = normalizePhone(String(row.entity_value ?? ''))
    if (!num) continue
    const existing = phoneMap.get(num)
    if (!existing || (row.risk_score ?? 0) > existing.r) {
      phoneMap.set(num, {
        p: num,
        n: row.name || null,
        c: category,
        r: row.risk_score ?? 50,
      })
    }
  }
  return Array.from(phoneMap.values())
}

/** One entry per lowercased domain, first row wins; IPs and short values are skipped. */
export function buildDomainEntries(rows: DomainRow[]): DomainEntry[] {
  const domainMap = new Map<string, DomainEntry>()
  for (const row of rows) {
    const category = String(row.category ?? '')
    if (!DOMAIN_BLOCKING_CATEGORIES.has(category)) continue
    const domain = String(row.entity_value ?? '').trim().toLowerCase()
    if (!domain || !domain.includes('.') || domain.length < 4) continue
    if (/^\d+\.\d+\.\d+\.\d+$/.test(domain)) continue // skip IPs
    if (!domainMap.has(domain)) {
      domainMap.set(domain, {
        d: domain,
        c: category,
        s: row.source || null,
      })
    }
  }
  return Array.from(domainMap.values())
}
