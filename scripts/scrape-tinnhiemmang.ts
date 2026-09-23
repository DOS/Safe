/**
 * Scraper for tinnhiemmang.vn — Vietnam's National Cybersecurity Center (NCA)
 *
 * Scrapes three datasets:
 *   1. /website-lua-dao  — 125K+ scam/phishing websites (blacklist)
 *   2. /website-tin-nhiem — verified trusted websites (whitelist)
 *   3. /to-chuc-tin-nhiem — verified trusted organizations (whitelist)
 *
 * Imports directly into threat_intel via bulk_upsert_threats RPC.
 *
 * Usage:
 *   deno run --allow-net --allow-env scripts/scrape-tinnhiemmang.ts
 *
 * Env vars:
 *   SUPABASE_URL              - e.g. https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  - service role key for RPC calls
 *
 * Options (via env):
 *   DATASET=blacklist|whitelist_web|whitelist_org|all  (default: all)
 *   START_PAGE=N              - resume from page N (default: 1)
 *   MAX_PAGES=N               - stop after N pages (default: unlimited)
 *   CONCURRENCY=N             - parallel page fetches (default: 3)
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error(
    "Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY",
  );
  Deno.exit(1);
}

const DATASET = Deno.env.get("DATASET") ?? "all";
const START_PAGE = parseInt(Deno.env.get("START_PAGE") ?? "1", 10);
const MAX_PAGES = parseInt(Deno.env.get("MAX_PAGES") ?? "0", 10); // 0 = unlimited
const CONCURRENCY = parseInt(Deno.env.get("CONCURRENCY") ?? "3", 10);
const BATCH_SIZE = 500;
const SOURCE = "tinnhiemmang";
const DELAY_MS = 300;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface ScamEntry {
  domain: string;
  detected_date: string | null;
  impersonated_org: string | null;
  status: string; // handling, done, unknown
}

interface TrustedWebEntry {
  domain: string;
  org_name: string | null;
  org_url: string | null;
}

interface TrustedOrgEntry {
  name: string;
  phone: string | null;
  website: string | null;
  address: string | null;
  org_url: string; // tinnhiemmang profile URL
}

interface ThreatEntry {
  entity_type: string;
  entity_value: string;
  source: string;
  category: string;
  risk_score: number;
  raw_data: Record<string, unknown>;
}

// ---------------------------------------------------------------------------
// HTML parsing helpers
// ---------------------------------------------------------------------------

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, "").trim();
}

function extractDomain(raw: string): string {
  // Strip SVG icons and HTML tags
  let cleaned = stripHtml(raw);
  // Remove protocol
  cleaned = cleaned.replace(/^https?:\/\//, "");
  // Remove trailing path/query
  cleaned = cleaned.split("/")[0].split("?")[0];
  return cleaned.trim().toLowerCase();
}

// ---------------------------------------------------------------------------
// Fetch with retry
// ---------------------------------------------------------------------------

async function fetchPage(url: string, retries = 3): Promise<string> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, {
        headers: {
          "User-Agent":
            "Mozilla/5.0 (compatible; DOSafe-Scraper/1.0; +https://dosafe.io)",
          Accept: "text/html",
        },
        signal: AbortSignal.timeout(30000),
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return await res.text();
    } catch (err) {
      if (attempt === retries) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(`  Fetch attempt ${attempt}/${retries} failed: ${msg}`);
      await sleep(2000 * attempt);
    }
  }
  throw new Error("unreachable");
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// ---------------------------------------------------------------------------
// Parse scam website page (/website-lua-dao)
// ---------------------------------------------------------------------------

function parseScamPage(html: string): { entries: ScamEntry[]; totalPages: number } {
  const entries: ScamEntry[] = [];

  const items = html.match(/<li class="item\d+">(.*?)<\/li>/gs) ?? [];
  for (const item of items) {
    // Domain — in <span class="webkit-box-2">
    const domainMatch = item.match(/webkit-box-2">\s*(.*?)\s*<\/span>/s);
    if (!domainMatch) continue;
    const domain = extractDomain(domainMatch[1]);
    if (!domain) continue;

    // Date
    const dateMatch = item.match(
      /(?:phát hiện|phát\s+hiện)\s+ngày\s+([\d/]+)/,
    );
    const detected_date = dateMatch ? dateMatch[1] : null;

    // Impersonated org
    const orgMatch = item.match(
      /danh-ba-tin-nhiem\/[^"]+">\s*(?:<label>[^<]*<\/label>)?\s*(.*?)\s*<\/a>/s,
    );
    const impersonated_org = orgMatch ? stripHtml(orgMatch[1]) : null;

    // Status
    const status = item.includes('class="handling"')
      ? "handling"
      : item.includes('class="done"')
        ? "done"
        : "unknown";

    entries.push({ domain, detected_date, impersonated_org, status });
  }

  // Total pages from pagination
  let totalPages = 1;
  const pageMatches = html.match(/page=(\d+)/g) ?? [];
  for (const pm of pageMatches) {
    const num = parseInt(pm.replace("page=", ""), 10);
    if (num > totalPages) totalPages = num;
  }

  return { entries, totalPages };
}

// ---------------------------------------------------------------------------
// Parse trusted website page (/website-tin-nhiem)
// ---------------------------------------------------------------------------

function parseTrustedWebPage(html: string): { entries: TrustedWebEntry[]; totalPages: number } {
  const entries: TrustedWebEntry[] = [];

  const items = html.match(/<li class="item\d+">(.*?)<\/li>/gs) ?? [];
  for (const item of items) {
    // Domain in <span> inside webkit-box-1 link
    const domainMatch = item.match(/webkit-box-1">\s*<span>\s*(.*?)\s*<\/span>/s)
      ?? item.match(/webkit-box-2">\s*(.*?)\s*<\/span>/s);
    if (!domainMatch) continue;
    const domain = extractDomain(domainMatch[1]);
    if (!domain) continue;

    // Org name — "Sở hữu bởi" label or generic danh-ba link
    const orgMatch = item.match(
      /(?:Sở hữu bởi|Mạo danh tổ chức)[^<]*<\/label>\s*(.*?)\s*<\/a>/s,
    );
    const org_name = orgMatch ? stripHtml(orgMatch[1]) : null;

    const orgUrlMatch = item.match(
      /href="(https:\/\/tinnhiemmang\.vn\/danh-ba-tin-nhiem\/[^"]+)"/,
    );
    const org_url = orgUrlMatch ? orgUrlMatch[1] : null;

    entries.push({ domain, org_name, org_url });
  }

  let totalPages = 1;
  const pageMatches = html.match(/page=(\d+)/g) ?? [];
  for (const pm of pageMatches) {
    const num = parseInt(pm.replace("page=", ""), 10);
    if (num > totalPages) totalPages = num;
  }

  return { entries, totalPages };
}

// ---------------------------------------------------------------------------
// Parse trusted org page (/to-chuc-tin-nhiem)
// ---------------------------------------------------------------------------

function parseTrustedOrgPage(html: string): { entries: TrustedOrgEntry[]; totalPages: number } {
  const entries: TrustedOrgEntry[] = [];

  const items = html.match(/<li class="item\d+">(.*?)<\/li>/gs) ?? [];
  for (const item of items) {
    // Org name — in <a class="sf-semibold"><span> or webkit-box variants
    const nameMatch = item.match(/class="sf-semibold[^"]*">\s*<span[^>]*>\s*(.*?)\s*<\/span>/s)
      ?? item.match(/webkit-box-1">\s*<span>\s*(.*?)\s*<\/span>/s)
      ?? item.match(/webkit-box-2">\s*(.*?)\s*<\/span>/s);
    if (!nameMatch) continue;
    const name = stripHtml(nameMatch[1]);
    if (!name) continue;

    // Profile URL
    const urlMatch = item.match(
      /href="(https:\/\/tinnhiemmang\.vn\/danh-ba-tin-nhiem\/[^"]+)"/,
    );
    const org_url = urlMatch ? urlMatch[1] : "";

    // Phone (if visible in listing)
    const phoneMatch = item.match(/(0\d{8,10})/);
    const phone = phoneMatch ? phoneMatch[1] : null;

    // Website
    const webMatch = item.match(
      /(?:Website|website)[:\s]*([\w.-]+\.\w{2,})/i,
    );
    const website = webMatch ? webMatch[1] : null;

    entries.push({ name, phone, website, address: null, org_url });
  }

  let totalPages = 1;
  const pageMatches = html.match(/page=(\d+)/g) ?? [];
  for (const pm of pageMatches) {
    const num = parseInt(pm.replace("page=", ""), 10);
    if (num > totalPages) totalPages = num;
  }

  return { entries, totalPages };
}

// ---------------------------------------------------------------------------
// Supabase bulk_upsert_threats
// ---------------------------------------------------------------------------

async function bulkUpsertThreats(
  entries: ThreatEntry[],
  retries = 3,
): Promise<number> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(
        `${SUPABASE_URL}/rest/v1/rpc/bulk_upsert_threats`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            apikey: SUPABASE_KEY!,
            Authorization: `Bearer ${SUPABASE_KEY}`,
            "Content-Profile": "dosafe",
          },
          body: JSON.stringify({ p_entries: entries }),
        },
      );

      if (!res.ok) {
        const body = await res.text();
        throw new Error(`bulk_upsert_threats failed (${res.status}): ${body}`);
      }

      const result = await res.json();
      return typeof result === "number" ? result : entries.length;
    } catch (err) {
      if (attempt === retries) throw err;
      const msg = err instanceof Error ? err.message : String(err);
      console.warn(
        `  Upsert attempt ${attempt}/${retries} failed: ${msg}`,
      );
      await sleep(3000);
    }
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Scrape + import pipeline
// ---------------------------------------------------------------------------

async function scrapeAndImport(
  label: string,
  baseUrl: string,
  parseFn: (html: string) => { entries: any[]; totalPages: number },
  toThreatEntry: (entry: any) => ThreatEntry | null,
): Promise<number> {
  console.log(`\n=== ${label} ===`);
  console.log(`URL: ${baseUrl}`);

  // First page to get total
  const firstHtml = await fetchPage(`${baseUrl}?page=${START_PAGE}`);
  const firstResult = parseFn(firstHtml);
  const totalPages = MAX_PAGES > 0
    ? Math.min(firstResult.totalPages, START_PAGE + MAX_PAGES - 1)
    : firstResult.totalPages;

  console.log(
    `Found ${firstResult.entries.length} entries on page ${START_PAGE}, total pages: ${totalPages}`,
  );

  let allEntries: ThreatEntry[] = [];
  let totalUpserted = 0;
  const startTime = Date.now();
  const globalSeen = new Set<string>(); // Global dedup across all pages

  // Convert first page entries
  for (const e of firstResult.entries) {
    const te = toThreatEntry(e);
    if (!te) continue;
    const key = `${te.entity_type}:${te.entity_value}`;
    if (globalSeen.has(key)) continue;
    globalSeen.add(key);
    allEntries.push(te);
  }

  // Scrape remaining pages with concurrency
  let currentPage = START_PAGE + 1;

  while (currentPage <= totalPages) {
    // Batch fetch with concurrency
    const pagesToFetch: number[] = [];
    for (let j = 0; j < CONCURRENCY && currentPage <= totalPages; j++) {
      pagesToFetch.push(currentPage++);
    }

    const results = await Promise.allSettled(
      pagesToFetch.map(async (page) => {
        const html = await fetchPage(`${baseUrl}?page=${page}`);
        return parseFn(html);
      }),
    );

    for (const result of results) {
      if (result.status === "fulfilled") {
        for (const e of result.value.entries) {
          const te = toThreatEntry(e);
          if (!te) continue;
          const key = `${te.entity_type}:${te.entity_value}`;
          if (globalSeen.has(key)) continue;
          globalSeen.add(key);
          allEntries.push(te);
        }
      } else {
        console.warn(`  Page fetch failed: ${result.reason}`);
      }
    }

    // Flush batch when large enough (already deduped by globalSeen)
    if (allEntries.length >= BATCH_SIZE) {
      const batch = allEntries.splice(0, BATCH_SIZE);
      const count = await bulkUpsertThreats(batch);
      totalUpserted += count;
      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      const pagesProcessed = currentPage - START_PAGE;
      const totalPagesToProcess = totalPages - START_PAGE + 1;
      const pct = ((pagesProcessed / totalPagesToProcess) * 100).toFixed(1);
      console.log(
        `  Page ${currentPage - 1}/${totalPages} (${pct}%) | Upserted: ${totalUpserted} | ${elapsed}s`,
      );
    }

    await sleep(DELAY_MS);
  }

  // Flush remaining (already deduped by globalSeen)
  if (allEntries.length > 0) {
    const count = await bulkUpsertThreats(allEntries);
    totalUpserted += count;
  }

  const totalTime = ((Date.now() - startTime) / 1000).toFixed(1);
  console.log(`  Done: ${totalUpserted} entries in ${totalTime}s`);

  return totalUpserted;
}

// ---------------------------------------------------------------------------
// Converters
// ---------------------------------------------------------------------------

function scamToThreat(entry: ScamEntry): ThreatEntry | null {
  if (!entry.domain) return null;
  return {
    entity_type: "domain",
    entity_value: entry.domain,
    source: SOURCE,
    category: "scam",
    risk_score: entry.status === "done" ? 85 : 70,
    raw_data: {
      detected_date: entry.detected_date,
      impersonated_org: entry.impersonated_org,
      status: entry.status,
      origin: "website_lua_dao",
    },
  };
}

function trustedWebToThreat(entry: TrustedWebEntry): ThreatEntry | null {
  if (!entry.domain) return null;
  return {
    entity_type: "domain",
    entity_value: entry.domain,
    source: SOURCE,
    category: "legitimate",
    risk_score: 5,
    raw_data: {
      org_name: entry.org_name,
      org_url: entry.org_url,
      origin: "website_tin_nhiem",
    },
  };
}

function trustedOrgToThreat(entry: TrustedOrgEntry): ThreatEntry | null {
  if (!entry.name) return null;
  // Use org_url slug as unique identifier to avoid name collisions
  const slug = entry.org_url?.split("/").pop() ?? "";
  const entityValue = entry.website ?? slug ?? entry.name;
  if (!entityValue) return null;
  return {
    entity_type: entry.website ? "domain" : "organization",
    entity_value: entityValue,
    source: SOURCE,
    category: "legitimate",
    risk_score: 5,
    raw_data: {
      name: entry.name,
      phone: entry.phone,
      org_url: entry.org_url,
      origin: "to_chuc_tin_nhiem",
    },
  };
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  console.log("=== Tín Nhiệm Mạng Scraper ===");
  console.log(`Dataset: ${DATASET} | Start page: ${START_PAGE} | Max pages: ${MAX_PAGES || "unlimited"} | Concurrency: ${CONCURRENCY}\n`);

  let totalImported = 0;

  if (DATASET === "all" || DATASET === "blacklist") {
    totalImported += await scrapeAndImport(
      "Scam Websites (Blacklist)",
      "https://tinnhiemmang.vn/website-lua-dao",
      parseScamPage,
      scamToThreat,
    );
  }

  if (DATASET === "all" || DATASET === "whitelist_web") {
    totalImported += await scrapeAndImport(
      "Trusted Websites (Whitelist)",
      "https://tinnhiemmang.vn/website-tin-nhiem",
      parseTrustedWebPage,
      trustedWebToThreat,
    );
  }

  if (DATASET === "all" || DATASET === "whitelist_org") {
    totalImported += await scrapeAndImport(
      "Trusted Organizations (Whitelist)",
      "https://tinnhiemmang.vn/to-chuc-tin-nhiem",
      parseTrustedOrgPage,
      trustedOrgToThreat,
    );
  }

  console.log(`\n=== All done! Total imported: ${totalImported} ===`);
}

main().catch((err) => {
  console.error("Fatal error:", err);
  Deno.exit(1);
});

