/**
 * Import MetaMask eth-phishing-detect blacklist into DOSafe threat_intel.
 *
 * config.json is ~8MB with 200k+ domains — too large for Supabase Edge Function
 * 150s timeout. Runs via GitHub Actions (sync-large-sources.yml) every 6h.
 *
 * Usage:
 *   deno run --allow-net --allow-env scripts/import-metamask.ts
 *
 * Env vars:
 *   SUPABASE_URL              - e.g. https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  - service role key for RPC calls
 */

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const SOURCE = "metamask";

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error("Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY");
  Deno.exit(1);
}

// ─── Sync log helpers (match Edge Function format for DOSiren) ───

async function logStart(): Promise<string> {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/sync_log`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      apikey: SUPABASE_KEY!,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      "Content-Profile": "dosafe",
      "Accept-Profile": "dosafe",
      Prefer: "return=representation",
    },
    body: JSON.stringify({ source: SOURCE, status: "running" }),
  });
  if (!res.ok) {
    console.error("logStart error:", await res.text());
    return "";
  }
  const rows = await res.json();
  return rows?.[0]?.id ?? "";
}

async function logFinish(id: string, status: string, processed: number, added: number, error?: string) {
  if (!id) return;
  await fetch(`${SUPABASE_URL}/rest/v1/sync_log?id=eq.${id}`, {
    method: "PATCH",
    headers: {
      "Content-Type": "application/json",
      apikey: SUPABASE_KEY!,
      Authorization: `Bearer ${SUPABASE_KEY}`,
      "Content-Profile": "dosafe",
    },
    body: JSON.stringify({
      status,
      entries_processed: processed,
      entries_added: added,
      error: error ?? null,
      finished_at: new Date().toISOString(),
    }),
  });
}

// ─── Main ───

const logId = await logStart();
const CONFIG_URL =
  "https://raw.githubusercontent.com/MetaMask/eth-phishing-detect/main/src/config.json";
const CHUNK_SIZE = 5000;

try {
  console.log("Fetching MetaMask eth-phishing-detect config...");
  const res = await fetch(CONFIG_URL, { signal: AbortSignal.timeout(120000) });
  if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);

  const config = await res.json();
  const blacklist: string[] = config.blacklist ?? [];
  const uniqueDomains = [...new Set(blacklist.map((d: string) => d.toLowerCase()))];
  console.log(`MetaMask: ${blacklist.length} blacklist domains → ${uniqueDomains.length} unique`);

  const entries = uniqueDomains.map((domain) => ({
    entity_type: "domain",
    entity_value: domain,
    source: SOURCE,
    category: "phishing",
    risk_score: 90,
    raw_data: { list: "blacklist" },
  }));

  let totalAdded = 0;

  for (let i = 0; i < entries.length; i += CHUNK_SIZE) {
    const chunk = entries.slice(i, i + CHUNK_SIZE);
    const chunkNum = Math.floor(i / CHUNK_SIZE) + 1;
    const totalChunks = Math.ceil(entries.length / CHUNK_SIZE);

    let retries = 3;
    while (retries > 0) {
      try {
        const resp = await fetch(`${SUPABASE_URL}/rest/v1/rpc/bulk_upsert_threats`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Profile": "dosafe",
            Authorization: `Bearer ${SUPABASE_KEY}`,
            apikey: SUPABASE_KEY!,
          },
          body: JSON.stringify({ p_entries: chunk }),
          signal: AbortSignal.timeout(120000),
        });

        if (!resp.ok) {
          const err = await resp.text();
          if (retries > 1 && resp.status >= 500) {
            retries--;
            console.log(`Chunk ${chunkNum}/${totalChunks} failed (${resp.status}), retrying... (${retries} left)`);
            await new Promise((r) => setTimeout(r, 5000));
            continue;
          }
          console.error(`Chunk ${chunkNum}/${totalChunks} failed: ${resp.status} ${err}`);
          break;
        }

        totalAdded += chunk.length;
        console.log(`Uploaded ${totalAdded}/${entries.length} (chunk ${chunkNum}/${totalChunks})`);
        break;
      } catch (e) {
        if (retries > 1) {
          retries--;
          console.log(`Chunk ${chunkNum}/${totalChunks} error: ${e}, retrying... (${retries} left)`);
          await new Promise((r) => setTimeout(r, 5000));
          continue;
        }
        console.error(`Chunk ${chunkNum}/${totalChunks} error: ${e}`);
        break;
      }
    }
  }

  console.log(`\nDone! Total uploaded: ${totalAdded}/${entries.length}`);
  await logFinish(logId, "success", entries.length, totalAdded);
} catch (e) {
  const msg = e instanceof Error ? e.message : String(e);
  console.error(`Fatal error: ${msg}`);
  await logFinish(logId, "failed", 0, 0, msg);
  Deno.exit(1);
}

