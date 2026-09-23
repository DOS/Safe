/**
 * Import Phishing.Database active phishing links into DOSafe threat_intel.
 *
 * The phishing-links-ACTIVE.txt file is 65MB / 789k URLs — too large for
 * Supabase Edge Function wall-time. Run this locally instead.
 *
 * Usage:
 *   deno run --allow-net --allow-env scripts/import-phishing-links.ts
 *
 * Env vars:
 *   SUPABASE_URL              - e.g. https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  - service role key for RPC calls
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY");
  Deno.exit(1);
}

const LINKS_URL = "https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/phishing-links-ACTIVE.txt";
const CHUNK_SIZE = 5000;

console.log("Fetching phishing-links-ACTIVE.txt (65MB)...");
const res = await fetch(LINKS_URL, { signal: AbortSignal.timeout(300000) });
if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);

const text = await res.text();
const lines = text.split("\n").filter((l) => {
  const t = l.trim();
  return t && !t.startsWith("#") && !t.startsWith("//");
});
// Deduplicate URLs (file has duplicates that cause ON CONFLICT errors within same chunk)
const uniqueUrls = [...new Set(lines.map((l) => l.trim().toLowerCase()))];
console.log(`Parsed ${lines.length} phishing links → ${uniqueUrls.length} unique`);

// Build entries
const entries = uniqueUrls.map((url) => ({
  entity_type: "url",
  entity_value: url,
  source: "phishing_database",
  category: "phishing",
  risk_score: 85,
  raw_data: {},
}));

let totalAdded = 0;

for (let i = 0; i < entries.length; i += CHUNK_SIZE) {
  const chunk = entries.slice(i, i + CHUNK_SIZE);
  const chunkNum = Math.floor(i / CHUNK_SIZE) + 1;

  let retries = 3;
  while (retries > 0) {
    try {
      const resp = await fetch(`${SUPABASE_URL}/rest/v1/rpc/bulk_upsert_threats`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Profile": "dosafe",
          Authorization: `Bearer ${SUPABASE_KEY}`,
          apikey: SUPABASE_KEY,
        },
        body: JSON.stringify({ p_entries: chunk }),
        signal: AbortSignal.timeout(120000),
      });

      if (!resp.ok) {
        const err = await resp.text();
        if (retries > 1 && resp.status >= 500) {
          retries--;
          console.log(`Chunk ${chunkNum} failed (${resp.status}), retrying... (${retries} left)`);
          await new Promise((r) => setTimeout(r, 5000));
          continue;
        }
        console.error(`Chunk ${chunkNum} failed: ${resp.status} ${err}`);
        break;
      }

      totalAdded += chunk.length;
      console.log(`Uploaded ${totalAdded}/${entries.length} (chunk ${chunkNum})`);
      break;
    } catch (e) {
      if (retries > 1) {
        retries--;
        console.log(`Chunk ${chunkNum} error: ${e}, retrying... (${retries} left)`);
        await new Promise((r) => setTimeout(r, 5000));
        continue;
      }
      console.error(`Chunk ${chunkNum} error: ${e}`);
      break;
    }
  }
}

console.log(`\nDone! Total uploaded: ${totalAdded}/${entries.length}`);

