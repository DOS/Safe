import { buildDomainEntries, buildPhoneEntries } from './blocklist-entries.ts'

function assertEquals(actual: unknown, expected: unknown): void {
  if (JSON.stringify(actual) !== JSON.stringify(expected)) {
    throw new Error(
      `Expected ${JSON.stringify(expected)}, got ${JSON.stringify(actual)}`,
    )
  }
}

// DOS/DOS.AI#7444: a legitimate or other non-blocking row never reaches the
// mobile blocklist files.

Deno.test('buildDomainEntries keeps only blocking categories', () => {
  assertEquals(
    buildDomainEntries([
      { entity_value: 'Evil.example', category: 'phishing', source: 'feed-a' },
      { entity_value: 'bank.example.vn', category: 'legitimate', source: 'tinnhiemmang' },
      { entity_value: 'odd.example', category: 'unknown', source: 'feed-b' },
      { entity_value: 'nocat.example', category: null, source: 'feed-c' },
      { entity_value: 'fraud.example', category: 'fraud', source: null },
    ]),
    [
      { d: 'evil.example', c: 'phishing', s: 'feed-a' },
      { d: 'fraud.example', c: 'fraud', s: null },
    ],
  )
})

Deno.test('buildDomainEntries does not let a legitimate row hide a threat row of the same domain', () => {
  assertEquals(
    buildDomainEntries([
      { entity_value: 'shop.example', category: 'legitimate', source: 'tinnhiemmang' },
      { entity_value: 'shop.example', category: 'scam', source: 'feed-a' },
    ]),
    [{ d: 'shop.example', c: 'scam', s: 'feed-a' }],
  )
})

Deno.test('buildDomainEntries still skips IPs, short values and duplicates', () => {
  assertEquals(
    buildDomainEntries([
      { entity_value: '1.2.3.4', category: 'phishing', source: 'feed-a' },
      { entity_value: 'a.b', category: 'phishing', source: 'feed-a' },
      { entity_value: 'dup.example', category: 'phishing', source: 'feed-a' },
      { entity_value: 'DUP.example', category: 'scam', source: 'feed-b' },
    ]),
    [{ d: 'dup.example', c: 'phishing', s: 'feed-a' }],
  )
})

Deno.test('buildPhoneEntries keeps only blocking categories', () => {
  assertEquals(
    buildPhoneEntries([
      { entity_value: '+84901234561', category: 'scam', risk_score: 80 },
      { entity_value: '+84901234562', category: 'legitimate', risk_score: 10 },
      { entity_value: '+84901234563', category: 'political', risk_score: 50 },
      { entity_value: '+84901234564', category: 'fraud', risk_score: 70 },
      { entity_value: '+84901234565', category: 'robocall', risk_score: 60 },
      { entity_value: '+84901234566', category: 'unknown', risk_score: 60 },
    ]).map((e) => `${e.p}:${e.c}`),
    ['0901234561:scam', '0901234564:fraud', '0901234565:robocall'],
  )
})

Deno.test('buildPhoneEntries does not let a legitimate row replace a threat row of the same number', () => {
  assertEquals(
    buildPhoneEntries([
      { entity_value: '0901234567', category: 'spam', risk_score: 40, name: null },
      { entity_value: '+84901234567', category: 'legitimate', risk_score: 95, name: 'Bank' },
    ]),
    [{ p: '0901234567', n: null, c: 'spam', r: 40 }],
  )
})
