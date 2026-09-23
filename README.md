# Safe

Safe intel jobs - scheduled ingestion for the DOSafe threat-intel pipeline.

Runs on GitHub-hosted runners (public repo = free Actions minutes). Scripts
scrape/import public threat sources and write straight into the internal
Supabase DB via repository secrets. **No scraped data is ever committed
here** - only the job definitions and scripts.

| Workflow | Schedule | Jobs |
|---|---|---|
| Sync Large Sources | every 2 days 01:30 UTC | MetaMask, ScamSniffer, Phishing links, HaGeZi TIF |
| Daily Scrape (scam.vn + tinnhiemmang) | every 2 days 04:00 UTC | scam.vn (via FlareSolverr), tinnhiemmang |
| Generate Blocklist Files | after the above + 2-day safety net | regenerate downloadable blocklist files |

Manual run: Actions tab -> pick workflow -> Run workflow.
