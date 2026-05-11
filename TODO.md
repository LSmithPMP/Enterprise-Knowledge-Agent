# TODO — Enterprise Knowledge Research Agent

Outstanding work items, ordered by priority. Each item describes the issue,
why it matters, and the proposed fix.

---

## HIGH — Corpus / Real-NVD Description Mismatch

**Discovered:** May 10, 2026 (Week 8 build session)
**Status:** Open — to address next session

**Issue.** The corpus (`data/corpus.json`) embeds CVE identifiers such as
`CVE-2024-3891`, `CVE-2024-4521`, and `CVE-2024-5893` along with synthetic
descriptions tailored to the AV/OT cybersecurity domain (e.g. "UDS diagnostic
protocol memory exposure in ECU variants"). Some of these CVE identifiers
happen to be real entries in the NIST NVD — but their **real NVD descriptions
do not match the synthetic corpus descriptions** (for example, `CVE-2024-3891`
is a real Mattermost server CVE, not an automotive ECU issue).

**Why it matters.** The orchestrator's deterministic provenance footer
(`PATCH 10`) honestly reports that these CVEs are verified against live NVD.
That report is technically true. However, the synthesizer's body text
then attributes corpus-authored descriptions to those CVEs, which creates
a subtle factual misalignment between the verified label and the surrounding
narrative. The evaluator does not currently catch this because it does not
cross-check the CVE description against the upstream NVD `description` field.

**Two acceptable fixes (pick one):**

1. **Mock all corpus CVE identifiers explicitly.** Rewrite `data/corpus.json`
   to use prefix `[MOCK]CVE-XXXX-XXXX` for every fictional CVE. Update
   `_lookup_nvd` to skip lookups on `[MOCK]`-prefixed identifiers and return
   `verified: False` immediately with a clear "synthetic demonstration"
   source field. Update `ThreatIntelAgent` and `SynthesizerAgent` system
   prompts to enforce the `[MOCK]` convention.

2. **Use real CVEs with their real descriptions.** Rewrite `data/corpus.json`
   to reference real AV/OT-relevant CVEs sourced from CISA ICS-CERT
   advisories and NVD, with descriptions copied or summarized from the
   authoritative source. Cite the source URL on each entry.

**Definition of done.**
- Corpus rewritten using one of the two approaches above.
- `python3 orchestrator.py` produces an executive summary where the
  provenance footer and the body content are consistent (either both
  honestly labeled `[UNVERIFIED]` or both grounded in real NVD content).
- Evaluation passes with hallucination_risk ≤ 0.15 and citation
  coverage ≥ 80%.
- Commit and push.

---

## MEDIUM — `n8n notified: 404` on every run

**Issue.** The orchestrator's post-pipeline n8n webhook notification returns
404 because the workflows have not been deployed and activated against a
publicly reachable n8n endpoint.

**Fix.** Deploy `n8n/workflow_1_research_pipeline.json` and
`n8n/workflow_2_threat_surveillance.json` to the n8n cloud instance.
Configure credentials. Activate workflows. Expose the local FastAPI via
ngrok or Cloudflare Tunnel so n8n can reach it. Update the orchestrator
notification URL.

---

## MEDIUM — Eval-drift baseline not yet established

**Issue.** Workflow 2 references golden-dataset re-scoring for drift
detection, but no baseline run has been persisted as the comparison anchor.

**Fix.** Build a 20-scenario golden dataset (see design doc §5.2), run the
orchestrator across all 20, persist scores as `data/eval_baseline.jsonl`,
and update Workflow 2 to load this file as the comparison anchor.

---

## LOW — Replace `dashboard/` placeholder with Streamlit UI

**Issue.** The `dashboard/` directory exists but is empty.

**Fix.** Build the Streamlit analyst dashboard described in design doc §2.1.

---

*Maintained by Lamonte Smith — Milford, MI*
