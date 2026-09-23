/**
 * Scraper for scam.vn
 *
 * Paginates the list page (/danh-sach?trang=N&xep=2) and extracts
 * domain/name/phone entities from titles. Uses FlareSolverr to bypass
 * Cloudflare JS challenge protection.
 *
 * All data is upserted into dosafe.raw_imports via Supabase REST API,
 * then process_pending_imports() extracts entities into threat_intel.
 *
 * Usage:
 *   deno run --allow-net --allow-env scripts/scrape-scam-vn.ts
 *
 * Env vars:
 *   SUPABASE_URL              - e.g. https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  - service role key
 *   FLARESOLVERR_URL           - FlareSolverr endpoint (default: https://fs.dos.ai)
 *
 * Options (via env):
 *   START_PAGE=N    - start from page N (default 1)
 *   END_PAGE=N      - stop after page N (default: all)
 *   BATCH_SIZE=N    - upsert batch size (default 100)
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY");
  Deno.exit(1);
}

const SOURCE = "scam_vn";
const BASE_URL = "https://scam.vn";
const FLARESOLVERR_URL = Deno.env.get("FLARESOLVERR_URL") ?? "https://fs.dos.ai";
const PROXY_URL = Deno.env.get("PROXY_URL") ?? "";
const START_PAGE = parseInt(Deno.env.get("START_PAGE") ?? "1", 10);
const END_PAGE = parseInt(Deno.env.get("END_PAGE") ?? "9999", 10);
const BATCH_SIZE = parseInt(Deno.env.get("BATCH_SIZE") ?? "100", 10);

// ─── Helpers ───

async function fetchHtml(url: string, retries = 3): Promise<string | null> {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const res = await fetch(`${FLARESOLVERR_URL}/v1`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: (() => {
          const b: Record<string, unknown> = { cmd: "request.get", url, maxTimeout: 30000 };
          if (PROXY_URL) b.proxy = { url: PROXY_URL };
          return JSON.stringify(b);
        })(),
        signal: AbortSignal.timeout(45000),
      });
      if (!res.ok) {
        console.warn(`  FlareSolverr [${res.status}] for ${url} (attempt ${attempt})`);
        if (attempt < retries) await sleep(3000 * attempt);
        continue;
      }
      const data = await res.json();
      if (data.solution?.status !== 200) {
        console.warn(`  FlareSolverr solution status ${data.solution?.status} for ${url} (attempt ${attempt})`);
        if (attempt < retries) await sleep(3000 * attempt);
        continue;
      }
      return data.solution.response;
    } catch (err) {
      console.warn(`  Fetch error: ${(err as Error).message} (attempt ${attempt})`);
      if (attempt < retries) await sleep(3000 * attempt);
    }
  }
  return null;
}

function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ─── Entity Type Detection ───

// Common TLDs for domain detection
const TLD_PATTERN = /\.(com|net|org|vn|io|co|xyz|top|info|biz|me|app|dev|site|online|store|shop|club|vip|pro|life|world|cc|tv|win|live|fun|tech|space|link|work|click|press|party|bid|trade|stream|review|loan|date|racing|download|cricket|science|accountant|faith|men|sexy|gdn|pw|cf|ga|gq|ml|tk|buzz|in|us|uk|au|de|fr|cn|tw|jp|kr|ru|id|ph|my|sg|th)$/i;

function classifyTitle(title: string): { entityType: string; entityValue: string; domain: string | null } {
  const trimmed = title.trim();

  // Check if title looks like a domain name
  if (TLD_PATTERN.test(trimmed) && !trimmed.includes(" ")) {
    const domain = trimmed.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, "");
    return { entityType: "domain", entityValue: domain, domain };
  }

  // Check if title is a phone number
  const phoneClean = trimmed.replace(/[\s.\-()]/g, "");
  if (/^\+?\d{9,15}$/.test(phoneClean)) {
    return { entityType: "phone", entityValue: phoneClean, domain: null };
  }

  // Check if title contains a URL pattern
  const urlMatch = trimmed.match(/([a-zA-Z0-9\-]+\.(?:com|net|org|vn|io|xyz|top|vip|club|me|app|site|online|store|shop|pro|world|cc|life))/i);
  if (urlMatch) {
    const domain = urlMatch[1].toLowerCase();
    return { entityType: "domain", entityValue: domain, domain };
  }

  // Otherwise treat as a person/organization name
  return { entityType: "name", entityValue: trimmed, domain: null };
}

// ─── List Page Parser ───

interface ListEntry {
  slug: string;
  title: string;
  amount: string;
  views: number;
  date: string;
}

function parseListPage(html: string): ListEntry[] {
  const entries: ListEntry[] = [];
  // Match table rows: <td>N</td><td><a href="/canh-bao/SLUG">TITLE</a></td><td>AMOUNT</td><td>VIEWS</td><td>DATE</td>
  // Support both single and double quotes around href value
  const regex = /href=["']\/canh-bao\/([^"']+)["'][^>]*>([^<]+)<\/a>(?:<\/td>)?<td>([^<]*)<\/td><td>([^<]*)<\/td><td>([^<]*)<\/td>/g;
  let match;
  while ((match = regex.exec(html)) !== null) {
    entries.push({
      slug: match[1],
      title: match[2].trim(),
      amount: match[3].trim(),
      views: parseInt(match[4].replace(/\D/g, "") || "0", 10),
      date: match[5].trim(),
    });
  }
  return entries;
}

// ─── Supabase Upsert ───

interface RawImportRow {
  source: string;
  source_id: string;
  raw_data: Record<string, unknown>;
}

// Match the `bulk_upsert_raw_imports` RPC pattern that scrape-checkscam-vn.ts
// already uses. The RPC owns the conflict target server-side (DO UPDATE on
// (source, source_id)) so the client never needs to know the unique-index
// name, and a duplicate inside a batch no longer rolls the whole batch back
// the way a plain PostgREST insert did pre-#101. `status` is omitted; the
// table default ('pending') matches what scam.vn always set explicitly.
async function upsertBatch(rows: RawImportRow[]): Promise<number> {
  if (rows.length === 0) return 0;

  const res = await fetch(
    `${SUPABASE_URL}/rest/v1/rpc/bulk_upsert_raw_imports`,
    {
      method: "POST",
      headers: {
        "apikey": SUPABASE_KEY!,
        "Authorization": `Bearer ${SUPABASE_KEY}`,
        "Content-Profile": "dosafe",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_entries: rows }),
    },
  );

  if (!res.ok) {
    const err = await res.text();
    console.error(`  Upsert error: ${res.status} ${err.slice(0, 200)}`);
    return 0;
  }

  return rows.length;
}

function buildRow(entry: ListEntry): RawImportRow {
  const { entityType, entityValue, domain } = classifyTitle(entry.title);

  const rawData: Record<string, unknown> = {
    title: entry.title,
    slug: entry.slug,
    date: entry.date,
    amount: entry.amount,
    views: entry.views,
    link: `${BASE_URL}/canh-bao/${entry.slug}`,
    category: "scam",
    detected_entity_type: entityType,
  };

  // Populate standard fields based on detected entity type
  if (entityType === "domain") {
    rawData.domain = domain;
    rawData.websites = [domain!];
  } else if (entityType === "phone") {
    rawData.phone = entityValue;
    rawData.all_phones = [entityValue];
  } else {
    // name or other
    rawData.name = entityValue;
  }

  return {
    source: SOURCE,
    source_id: entry.slug,
    raw_data: rawData,
  };
}

// ─── Process Pending Imports ───

async function processPendingImports(): Promise<void> {
  console.log("\n🔄 Running process_pending_imports() in batches...");
  let totalProcessed = 0;
  const IMPORT_BATCH = 50;

  while (true) {
    const res = await fetch(`${SUPABASE_URL}/rest/v1/rpc/process_pending_imports`, {
      method: "POST",
      headers: {
        "apikey": SUPABASE_KEY!,
        "Authorization": `Bearer ${SUPABASE_KEY}`,
        "Content-Profile": "dosafe",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ p_limit: IMPORT_BATCH }),
    });

    if (!res.ok) {
      const err = await res.text();
      console.error(`  process_pending_imports error: ${res.status} ${err.slice(0, 200)}`);
      break;
    }

    const count = await res.json();
    totalProcessed += count;

    if (count === 0) break;
    console.log(`  Processed batch: ${count} (total: ${totalProcessed})`);
  }

  console.log(`  ✅ Total processed: ${totalProcessed}`);
}

// ─── Main ───

async function main() {
  console.log("🕷️  Scam.vn scraper starting...");
  console.log(`   Pages: ${START_PAGE} to ${END_PAGE === 9999 ? "all" : END_PAGE}`);
  console.log(`   Batch size: ${BATCH_SIZE}`);
  console.log(`   FlareSolverr: ${FLARESOLVERR_URL}`);
  console.log(`   Note: Using FlareSolverr to bypass Cloudflare — extracting from list titles`);
  console.log();

  let totalEntries = 0;
  let totalUpserted = 0;
  let page = START_PAGE;
  let pendingRows: RawImportRow[] = [];
  let fetchFailedOnFirstPage = false;

  const stats = { domains: 0, phones: 0, names: 0 };

  while (page <= END_PAGE) {
    const listUrl = `${BASE_URL}/danh-sach?trang=${page}&xep=2`;
    console.log(`📄 Page ${page}: ${listUrl}`);

    const listHtml = await fetchHtml(listUrl);
    if (!listHtml) {
      console.log("  ❌ Failed to fetch list page, stopping.");
      if (page === START_PAGE) fetchFailedOnFirstPage = true;
      break;
    }

    const entries = parseListPage(listHtml);
    if (entries.length === 0) {
      console.log("  ✅ No more entries, done.");
      break;
    }

    console.log(`  Found ${entries.length} entries`);
    totalEntries += entries.length;

    for (const entry of entries) {
      const row = buildRow(entry);
      pendingRows.push(row);

      const detectedType = row.raw_data.detected_entity_type as string;
      if (detectedType === "domain") stats.domains++;
      else if (detectedType === "phone") stats.phones++;
      else stats.names++;
    }

    // Flush batch when accumulated enough
    if (pendingRows.length >= BATCH_SIZE) {
      const upserted = await upsertBatch(pendingRows);
      totalUpserted += upserted;
      console.log(`  💾 Batch upserted: ${upserted}/${pendingRows.length}`);
      pendingRows = [];
    }

    page++;
    await sleep(2000);
  }

  // Flush remaining
  if (pendingRows.length > 0) {
    const upserted = await upsertBatch(pendingRows);
    totalUpserted += upserted;
    console.log(`  💾 Final batch upserted: ${upserted}/${pendingRows.length}`);
  }

  console.log("\n📊 Summary:");
  console.log(`   Total entries: ${totalEntries}`);
  console.log(`   Total upserted: ${totalUpserted}`);
  console.log(`   Domains: ${stats.domains} | Phones: ${stats.phones} | Names: ${stats.names}`);

  if (totalUpserted > 0) {
    await processPendingImports();
  }

  if (fetchFailedOnFirstPage) {
    console.error("\n❌ Scrape failed: list page fetch returned no HTML on the very first page.");
    console.error("   Likely cause: FlareSolverr (fs.dos.ai) is down or scam.vn changed its Cloudflare challenge.");
    Deno.exit(1);
  }

  console.log("\n✅ Done!");
}

main().catch(err => {
  console.error("Fatal error:", err);
  Deno.exit(1);
});

