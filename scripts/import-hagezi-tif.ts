/**
 * Import HaGeZi Threat Intelligence Feeds (TIF) domains into DOSafe threat_intel.
 *
 * The TIF list aggregates ~300 threat intel sources (PhishTank, Cert.pl, ThreatFox,
 * Cisco Talos, etc.) into ~2.1M domains - too large for Supabase Edge Function
 * wall-time. Run this locally instead.
 *
 * Usage:
 *   deno run --allow-net --allow-env scripts/import-hagezi-tif.ts
 *
 * Env vars:
 *   SUPABASE_URL              - e.g. https://xxx.supabase.co
 *   SUPABASE_SERVICE_ROLE_KEY  - service role key for RPC calls
 */

import { isCompleteUpload, parseTifDomains, TIF_URL } from "./hagezi-tif.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");

if (!SUPABASE_URL || !SUPABASE_KEY) {
  console.error(
    "Missing required env vars: SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY",
  );
  Deno.exit(1);
}

const CHUNK_SIZE = 5000;

console.log("Fetching HaGeZi TIF domains list...");
const res = await fetch(TIF_URL, { signal: AbortSignal.timeout(120000) });
if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);

const uniqueDomains = parseTifDomains(await res.text());
console.log(`Parsed ${uniqueDomains.length} unique domains`);

// Build entries
const entries = uniqueDomains.map((domain) => ({
  entity_type: "domain",
  entity_value: domain,
  source: "hagezi_tif",
  category: "phishing",
  risk_score: 80,
  raw_data: {},
}));

let totalAdded = 0;

for (let i = 0; i < entries.length; i += CHUNK_SIZE) {
  const chunk = entries.slice(i, i + CHUNK_SIZE);
  const chunkNum = Math.floor(i / CHUNK_SIZE) + 1;
  const totalChunks = Math.ceil(entries.length / CHUNK_SIZE);

  let retries = 3;
  while (retries > 0) {
    try {
      const resp = await fetch(
        `${SUPABASE_URL}/rest/v1/rpc/bulk_upsert_threats`,
        {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Profile": "dosafe",
            Authorization: `Bearer ${SUPABASE_KEY}`,
            apikey: SUPABASE_KEY,
          },
          body: JSON.stringify({ p_entries: chunk }),
          signal: AbortSignal.timeout(120000),
        },
      );

      if (!resp.ok) {
        const err = await resp.text();
        if (retries > 1 && resp.status >= 500) {
          retries--;
          console.log(
            `Chunk ${chunkNum}/${totalChunks} failed (${resp.status}), retrying... (${retries} left)`,
          );
          await new Promise((r) => setTimeout(r, 5000));
          continue;
        }
        console.error(
          `Chunk ${chunkNum}/${totalChunks} failed: ${resp.status} ${err}`,
        );
        break;
      }

      totalAdded += chunk.length;
      console.log(
        `Uploaded ${totalAdded}/${entries.length} (chunk ${chunkNum}/${totalChunks})`,
      );
      break;
    } catch (e) {
      if (retries > 1) {
        retries--;
        console.log(
          `Chunk ${chunkNum}/${totalChunks} error: ${e}, retrying... (${retries} left)`,
        );
        await new Promise((r) => setTimeout(r, 5000));
        continue;
      }
      console.error(`Chunk ${chunkNum}/${totalChunks} error: ${e}`);
      break;
    }
  }
}

console.log(`\nDone! Total uploaded: ${totalAdded}/${entries.length}`);
const uploadComplete = isCompleteUpload(totalAdded, entries.length);

// Write to sync_log for health monitoring
// After source consolidation, HaGeZi TIF is the sole domain source — monitoring is critical.
try {
  const logResp = await fetch(`${SUPABASE_URL}/rest/v1/sync_log`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Content-Profile": "dosafe",
      Authorization: `Bearer ${SUPABASE_KEY}`,
      apikey: SUPABASE_KEY,
      Prefer: "return=minimal",
    },
    body: JSON.stringify({
      source: "hagezi_tif",
      started_at: new Date(Date.now() - 60000).toISOString(), // approximate
      finished_at: new Date().toISOString(),
      entries_processed: entries.length,
      entries_added: totalAdded,
      status: uploadComplete ? "success" : "failed",
      error: uploadComplete
        ? null
        : `Incomplete upload: ${totalAdded}/${entries.length}`,
    }),
  });
  if (logResp.ok) {
    console.log("Sync log entry written ✓");
  } else {
    console.warn(
      `Failed to write sync_log: ${logResp.status} ${await logResp.text()}`,
    );
  }
} catch (e) {
  console.warn(`Failed to write sync_log: ${e}`);
}

if (!uploadComplete) {
  throw new Error(`Incomplete HaGeZi upload: ${totalAdded}/${entries.length}`);
}

