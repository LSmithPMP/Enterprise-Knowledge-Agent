# TODO — Enterprise Knowledge Research Agent

Tracked work items. Status as of Monday May 11, 2026 evening session.

---

## DONE — Live n8n Deployment (Monday May 11, 2026)

Both workflows deployed to n8n cloud, end-to-end tested with real LLM calls,
real external tool calls (NIST NVD, CISA ICS-CERT), real FastAPI integration,
and full cybersecurity controls active.

**Execution evidence:**
- W1 (Enterprise Research Pipeline) — 16 nodes, ID#168, version `b5bd99bd`,
  May 11 21:13:14, succeeded in 16.791s. All 16 nodes active including
  HMAC Verify (real raw-body signing), API Key Auth, Rate Limiter,
  Prompt-Injection Filter.
- W2 (Threat Surveillance + Eval Drift) — 15 nodes, end-to-end green,
  May 11 ~20:00, succeeded. All four LLM calls succeeded (severity classifier,
  ATT&CK for ICS mapper, gap detector, compliance impact assessor). CISA
  ICS-CERT feed returned real advisory data (MAXHUB Pivot Client CVE-2026-6411).

**Engineering deltas captured in committed workflow JSONs:**
- CISA URL corrected to `/cybersecurity-advisories/ics-advisories.xml`
- Webhook node configured with `rawBody: true` to enable byte-exact HMAC
- HMAC Verify reads raw body via `webhookNode.binary.data.data` (n8n v2.x path)
- API Key Auth reads from webhook payload via `$('1. Webhook — Inbound Query').first().json.body`
  pattern, robust against upstream transforms
- HTTP request nodes use `Authorization: Bearer {{ $env.API_KEY }}` header
- HTTP request bodies use `$('Node Name').first().json.xxx` expression scoping
  to pull from original webhook payload rather than current-node `$json`

---

## MEDIUM — Rotate API_KEY

During Monday evening debugging, the API_KEY was visible in plaintext base64
within an n8n Code-node diagnostic output. While the exposure was scoped to
the user's own n8n cloud workspace, defense-in-depth requires rotation.

**Fix.** Generate a fresh 64-character hex API_KEY. Update `.env`. Update
the n8n Code-node `validKey` constant in W1 node 3. No external service
calls used the leaked value.

---

## MEDIUM — Corpus / NVD Description Mismatch

**Issue.** Some corpus CVE identifiers (e.g. `CVE-2024-3891`) happen to be
real NVD entries but with synthetic AV/OT descriptions in the corpus that
don't match the real NVD record.

**Fix.** Rewrite `data/corpus.json` with real NVD-sourced AV/OT CVEs and
their real descriptions, OR explicitly prefix synthetic identifiers with
`[MOCK]` and short-circuit `_lookup_nvd` on that prefix.

---

## MEDIUM — Golden-Dataset Baseline

Workflow 2's drift-detection node calls `/eval/golden-rescore`. The endpoint
returns a stub today.

**Fix.** Build 20-scenario golden dataset spanning AV, AI/ML, OT, 5G/V2X,
cybersecurity, and finance domains. Persist as `data/eval_baseline.jsonl`.
Update endpoint to score each scenario via the orchestrator and persist.

---

## LOW — NVD Lookup Cache + Retry

`ThreatIntelAgent._lookup_nvd` is rate-limited by NVD on repeat lookups
within a 30-second window. Successive orchestrator runs alternate between
"all verified" and "0 verified."

**Fix.** Add local cache keyed by CVE ID with 24-hour TTL. Implement retry
with exponential backoff on NVD timeouts. Honor NVD rate limit guidance
(5 req/30s without API key; 50 req/30s with).

---

## LOW — Streamlit Sidebar Numbering

The 14-agent sidebar list renders "1." fourteen times due to a Streamlit
markdown quirk where ordered-list items reset per `st.caption()` call.

**Fix.** Replace the loop with a single `st.markdown()` containing a
hard-coded numbered list, or embed the number directly in non-numbered
captions.

---

*Maintained by Lamonte Smith — Milford, MI*
