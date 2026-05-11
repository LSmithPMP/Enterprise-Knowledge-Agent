"""
Enterprise Knowledge Research Agent — Streamlit Analyst Dashboard.

Provides the interactive UI described in the system design document, layer 1
(Client / Edge). Calls the FastAPI gateway at http://127.0.0.1:8000 and renders
the 14-agent pipeline result: executive summary, key insights, action items,
citations, evaluation scores, observability metrics, and the deterministic
provenance footer.

Run:
    streamlit run dashboard/app.py
"""

import os
import json
import time
from datetime import datetime
import requests
import streamlit as st
from dotenv import load_dotenv

load_dotenv()

API_BASE = os.getenv("EKA_API_BASE", "http://127.0.0.1:8000")
API_KEY = os.getenv("API_KEY", "")

st.set_page_config(
    page_title="EKA — Enterprise Knowledge Research Agent",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────────────────────────────────────
# Sidebar — system status + role selection
# ─────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("# 🛡️ EKA")
    st.caption("Enterprise Knowledge Research Agent")
    st.caption("14-Agent System · AV/OT Cybersecurity")

    st.divider()
    st.markdown("### Role")
    role = st.selectbox(
        "Role-Based Access Control",
        ["ANALYST", "ENGINEER", "EXECUTIVE"],
        index=0,
        help="ANALYST/ENGINEER see PUBLIC + INTERNAL. EXECUTIVE adds RESTRICTED.",
    )

    st.divider()
    st.markdown("### System Status")
    try:
        h = requests.get(f"{API_BASE}/health", timeout=2).json()
        st.success(f"API ✓  v{h.get('version', '?')}")
    except Exception:
        st.error("API unreachable")
        st.caption(f"Configured: `{API_BASE}`")

    st.divider()
    st.markdown("### 14 Agents")
    for i, agent in enumerate([
        "QueryClassifier", "Planner", "Retriever", "WebSearch",
        "ThreatIntel", "GapDetection", "CybersecFramework",
        "Compliance", "Citation", "Synthesizer",
        "Evaluation", "ConfidenceTracker", "Observability", "QueryAudit",
    ], 1):
        st.caption(f"{i:2d}. {agent}")

# ─────────────────────────────────────────────────────────────────────────────
# Main panel
# ─────────────────────────────────────────────────────────────────────────────

st.markdown("## Enterprise Knowledge Research Agent")
st.caption(
    "Autonomous research over AV/OT cybersecurity corpus with external tool "
    "calling (NIST NVD, CISA ICS-CERT), framework mapping (NIST CSF, MITRE "
    "ATT&CK for ICS, ISO 21434, UNECE WP.29), LLM-as-judge evaluation, and "
    "human-in-the-loop escalation."
)

example_queries = [
    "What CVEs affect our V2X infrastructure and what is the MITRE ATT&CK mapping?",
    "Summarize our ISO 21434 compliance status across vehicle programs.",
    "What is our secure OTA update architecture and what are the gaps?",
    "Identify the most critical OT/ICS vulnerabilities in our ECU baseline.",
    "Compare C-V2X and DSRC security posture for connected vehicle deployments.",
]
selected_example = st.selectbox(
    "Example queries",
    [""] + example_queries,
    format_func=lambda x: x if x else "— select an example or type your own below —",
)

default_query = selected_example if selected_example else ""
query = st.text_area(
    "Research query",
    value=default_query,
    height=100,
    max_chars=2000,
    placeholder="e.g. What CVEs affect our V2X infrastructure?",
)

submit = st.button("Run 14-agent research pipeline", type="primary", disabled=not query.strip())

# ─────────────────────────────────────────────────────────────────────────────
# Execution + result rendering
# ─────────────────────────────────────────────────────────────────────────────

if submit and query.strip():
    if not API_KEY:
        st.error("API_KEY not set in environment. Add to .env and restart Streamlit.")
        st.stop()

    progress = st.progress(0, "Submitting query...")
    start = time.time()

    try:
        progress.progress(20, "Authenticating and validating input...")
        resp = requests.post(
            f"{API_BASE}/query",
            headers={"Authorization": f"Bearer {API_KEY}"},
            json={"query": query, "role": role},
            timeout=180,
        )
        progress.progress(80, "Running pipeline (14 agents)...")
        resp.raise_for_status()
        data = resp.json()
        progress.progress(100, "Complete")
        time.sleep(0.3)
        progress.empty()
    except requests.HTTPError as e:
        progress.empty()
        try:
            detail = resp.json().get("detail", str(e))
        except Exception:
            detail = str(e)
        st.error(f"Pipeline error: {detail}")
        st.stop()
    except Exception as e:
        progress.empty()
        st.error(f"Connection error: {e}")
        st.stop()

    elapsed = time.time() - start
    result = data.get("result", {}) or {}
    trace_id = data.get("trace_id", "")

    # Extract from the actual orchestrator schema (nested dicts)
    synthesis = result.get("synthesis", {}) or {}
    evaluation = result.get("evaluation", {}) or {}
    confidence = result.get("confidence", {}) or {}
    threat_intel = result.get("threat_intel", {}) or {}
    framework = result.get("framework_mapping", {}) or {}
    compliance = result.get("compliance", {}) or {}
    citations = result.get("citations", {}) or {}
    gap_analysis = result.get("gap_analysis", {}) or {}
    observability = result.get("observability", {}) or {}

    eval_score = float(evaluation.get("overall_score", 0.0) or 0.0)
    hallucination = float(evaluation.get("hallucination_risk", 0.0) or 0.0)
    eval_pass = eval_score >= 0.65 and hallucination <= 0.30
    flags = evaluation.get("flags", []) or []

    citation_coverage = float(citations.get("coverage_score", 0.0) or 0.0)
    corpus_coverage = float(gap_analysis.get("corpus_coverage", 0.0) or 0.0)
    total_cost = float(result.get("total_cost_usd", 0.0) or 0.0)
    total_latency = float(result.get("total_latency_s", elapsed) or elapsed)
    agents_invoked_list = result.get("agents_invoked", []) or []
    agents_invoked_n = len(agents_invoked_list)

    # Top-line metrics row
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        if eval_pass:
            st.success(f"PASS  {eval_score:.2f}")
        else:
            st.warning(f"REVIEW  {eval_score:.2f}")
        st.caption("Evaluation")
    with c2:
        st.metric("Hallucination", f"{hallucination:.2f}", help="Lower is better; block threshold 0.30")
    with c3:
        st.metric("Citations", f"{int(citation_coverage * 100)}%")
    with c4:
        st.metric("Corpus coverage", f"{int(corpus_coverage * 100)}%")
    with c5:
        st.metric("Latency", f"{total_latency:.1f}s")

    c6, c7, c8 = st.columns(3)
    with c6:
        st.metric("Agents invoked", f"{agents_invoked_n}/14")
    with c7:
        st.metric("Pipeline cost", f"${total_cost:.4f}")
    with c8:
        st.caption("Trace ID")
        st.code(trace_id[:8] if trace_id else "—", language=None)

    # Confidence status badge
    conf_status = confidence.get("status", "UNKNOWN")
    if conf_status == "PASS":
        st.info(f"Pipeline confidence: {confidence.get('pipeline_confidence', 0):.2f} — status {conf_status}")
    elif conf_status == "ESCALATION":
        st.warning(f"Pipeline confidence: {confidence.get('pipeline_confidence', 0):.2f} — status {conf_status} (human review recommended)")
    else:
        st.error(f"Pipeline confidence: {confidence.get('pipeline_confidence', 0):.2f} — status {conf_status}")

    st.divider()

    # Executive summary (includes the deterministic provenance footer)
    st.markdown("### Executive Summary")
    summary = synthesis.get("executive_summary", "—")
    st.markdown(summary)

    # Insights and action items side-by-side
    col_left, col_right = st.columns(2)
    with col_left:
        st.markdown("### Key Insights")
        for insight in synthesis.get("key_insights", []) or []:
            st.markdown(f"- {insight}")
    with col_right:
        st.markdown("### Action Items")
        for item in synthesis.get("action_items", []) or []:
            st.markdown(f"- {item}")

    st.divider()

    # Expandable transparency sections
    with st.expander("🔍 Citations & retrieved documents"):
        cite_list = citations.get("citations", []) or []
        if cite_list:
            for c in cite_list:
                if isinstance(c, dict):
                    st.markdown(f"**{c.get('doc_id', '?')}** — {c.get('claim', c.get('title', ''))}")
                    if c.get("source"):
                        st.caption(f"Source: {c['source']}")
                else:
                    st.markdown(f"- {str(c)[:300]}")
            st.caption(f"Total: {citations.get('citation_count', 0)}  |  Coverage: {int(citation_coverage * 100)}%  |  Uncited: {len(citations.get('uncited_claims', []) or [])}")
        else:
            st.info("No citations returned for this query.")

    with st.expander("🧪 Threat intelligence (NVD + MITRE ATT&CK)"):
        if threat_intel:
            cves = threat_intel.get("cves_identified", []) or []
            techniques = threat_intel.get("mitre_techniques", []) or []
            st.markdown(f"**CVEs identified:** {', '.join(cves) if cves else '—'}")
            st.markdown(f"**MITRE ATT&CK techniques:** {', '.join(techniques) if techniques else '—'}")
            st.markdown(f"**Severity:** {threat_intel.get('severity', '—')}")
            st.markdown(f"**Affected systems:** {', '.join(threat_intel.get('affected_systems', []) or []) or '—'}")
            nvd = threat_intel.get("nvd_data", []) or []
            if nvd:
                st.markdown("**NVD data (live API):**")
                for entry in nvd:
                    if isinstance(entry, dict):
                        verified = entry.get("verified", False)
                        badge = "✓ VERIFIED" if verified else "⚠ UNVERIFIED"
                        st.markdown(f"- `{entry.get('cve_id', '?')}` — {badge} — CVSS {entry.get('cvss', 'n/a')} — {str(entry.get('description', ''))[:140]}")

    with st.expander("🛡️ Framework mapping (NIST CSF + MITRE ATT&CK for ICS + ISO 21434 + UNECE WP.29)"):
        if framework:
            st.markdown(f"**NIST CSF functions:** {', '.join(framework.get('nist_csf_functions', []) or []) or '—'}")
            st.markdown(f"**NIST controls:** {', '.join(framework.get('nist_controls', []) or []) or '—'}")
            st.markdown(f"**MITRE techniques:** {', '.join(framework.get('mitre_techniques', []) or []) or '—'}")
            st.markdown(f"**ISO 21434 clauses:** {', '.join(framework.get('iso_21434_clauses', []) or []) or '—'}")
            st.markdown(f"**UNECE WP.29 refs:** {', '.join(framework.get('unece_wp29_refs', []) or []) or '—'}")
            st.markdown(f"**Risk level:** {framework.get('risk_level', '—')}")

    with st.expander("📋 Compliance assessment"):
        if compliance:
            st.markdown(f"**Compliance score:** {compliance.get('compliance_score', 0)}%")
            st.markdown(f"**Priority:** {compliance.get('priority', '—')}")
            for label, key in [
                ("ISO 21434 gaps", "iso_21434_gaps"),
                ("UNECE R155 gaps", "unece_r155_gaps"),
                ("UNECE R156 gaps", "unece_r156_gaps"),
                ("NIST SP 800-82 gaps", "nist_sp800_82_gaps"),
            ]:
                items = compliance.get(key, []) or []
                if items:
                    st.markdown(f"**{label}:**")
                    for it in items:
                        st.markdown(f"- {it}")

    with st.expander("⚠️ Gap analysis"):
        gaps = gap_analysis.get("gaps_identified", []) or []
        missing = gap_analysis.get("missing_topics", []) or []
        recommended = gap_analysis.get("recommended_sources", []) or []
        if gaps or missing or recommended:
            if gaps:
                st.markdown("**Gaps identified:**")
                for g in gaps:
                    st.markdown(f"- {g}")
            if missing:
                st.markdown("**Missing topics:**")
                for m in missing:
                    st.markdown(f"- {m}")
            if recommended:
                st.markdown("**Recommended sources:**")
                for r in recommended:
                    st.markdown(f"- {r}")
        else:
            st.info("No gaps identified.")

    with st.expander("📊 Evaluation detail (LLM-as-judge)"):
        if evaluation:
            ec1, ec2 = st.columns(2)
            with ec1:
                st.markdown(f"**Relevance:** {evaluation.get('relevance_score', 0):.2f}")
                st.markdown(f"**Grounding:** {evaluation.get('grounding_score', 0):.2f}")
                st.markdown(f"**Completeness:** {evaluation.get('completeness_score', 0):.2f}")
            with ec2:
                st.markdown(f"**Security/Compliance:** {evaluation.get('security_compliance_score', 0):.2f}")
                st.markdown(f"**Hallucination risk:** {evaluation.get('hallucination_risk', 0):.2f}")
                st.markdown(f"**Overall:** {evaluation.get('overall_score', 0):.2f}")
            if flags:
                st.warning("Evaluation flags:")
                for fl in flags:
                    st.markdown(f"- {fl}")
            if evaluation.get("judgment"):
                st.caption(evaluation["judgment"])

    with st.expander("🔭 Observability"):
        if observability:
            st.markdown(f"**Overall health:** {observability.get('overall_health', '—')}")
            st.markdown(f"**Alert level:** {observability.get('alert_level', '—')}")
            for label, key in [
                ("Anomalies", "anomalies_detected"),
                ("Cost alerts", "cost_alerts"),
                ("Latency alerts", "latency_alerts"),
                ("Quality alerts", "quality_alerts"),
                ("Recommendations", "recommendations"),
            ]:
                items = observability.get(key, []) or []
                if items:
                    st.markdown(f"**{label}:**")
                    for it in items:
                        st.markdown(f"- {it}")

    with st.expander("🛰️ Full pipeline trace (raw)"):
        st.json(result)

else:
    st.info("Enter a research query above and click **Run** to execute the 14-agent pipeline.")

st.divider()
st.caption(
    "Lamonte Smith · Interview Kickstart Applied Agentic AI · Week 8 · Milford, MI · 2026 · "
    f"API: `{API_BASE}`"
)
