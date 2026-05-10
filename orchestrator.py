"""
================================================================================
ORCHESTRATOR
Enterprise Knowledge Research Agent
================================================================================
Coordinates all 13 agents + 1 evaluator in a full research pipeline:

1.  QueryClassifierAgent  — classify query, set retrieval strategy
2.  PlannerAgent          — decompose into research steps
3.  RetrieverAgent        — RAG search with role-based access control
4.  WebSearchAgent        — external threat intelligence
5.  ThreatIntelAgent      — CVE lookup + MITRE ATT&CK for ICS mapping
6.  GapDetectionAgent     — identify corpus gaps
7.  CybersecurityFrameworkAgent — NIST CSF + MITRE ATT&CK mapping
8.  ComplianceAgent       — ISO 21434, UNECE WP.29, NIST SP 800-82
9.  CitationAgent         — trace claims to source documents
10. SynthesizerAgent      — structured research response
11. EvaluationAgent       — LLM-as-judge quality scoring
12. ConfidenceTrackerAgent — aggregate confidence, block low-quality runs
13. ObservabilityAgent    — cost/latency/quality monitoring
14. QueryAuditAgent       — immutable audit log + policy violation detection
================================================================================
"""

import os
import json
import uuid
import time
import requests
from datetime import datetime, timezone
from dotenv import load_dotenv

from agents.query_classifier_agent import QueryClassifierAgent
from agents.planner_agent import PlannerAgent
from agents.retriever_web_threat_agents import RetrieverAgent, WebSearchAgent, ThreatIntelAgent
from agents.gap_framework_compliance_citation_agents import (
    GapDetectionAgent, CybersecurityFrameworkAgent, ComplianceAgent, CitationAgent
)
from agents.synthesizer_evaluation_agents import SynthesizerAgent, EvaluationAgent
from agents.confidence_observability_audit_agents import (
    ConfidenceTrackerAgent, ObservabilityAgent, QueryAuditAgent
)

load_dotenv()

RESULTS_PATH = os.path.join(os.path.dirname(__file__), "data/last_run_results.json")
N8N_WEBHOOK_URL = "https://lamontesmith.app.n8n.cloud/webhook/enterprise-research"


def run_pipeline(query: str, user_role: str = "ANALYST") -> dict:
    """
    Execute the full 13-agent research pipeline.

    Flow:
    Classify → Plan → Retrieve → Web Search → Threat Intel →
    Gap Detection → Framework Mapping → Compliance → Citation →
    Confidence Check → Synthesize → Evaluate → Observe → Audit → Notify n8n
    """
    print(f"\n{'='*60}")
    print(f"ENTERPRISE KNOWLEDGE RESEARCH AGENT")
    print(f"{'='*60}")
    print(f"Query: {query[:80]}...")
    print(f"User Role: {user_role}")
    print(f"{'='*60}\n")

    run_id = str(uuid.uuid4())[:8]
    pipeline_start = time.time()
    all_costs = []
    agent_scores = {}
    hallucination_risks = {}
    sensitivity_accessed = []
    agents_invoked = []

    # ── STEP 1: QUERY CLASSIFICATION ──────────────────────────────────────────
    print("Step 1: Classifying query...")
    classifier = QueryClassifierAgent()
    classification = classifier.run(query, user_role)
    all_costs.append(classification.cost)
    agents_invoked.append("QueryClassifierAgent")
    print(f"  Category: {classification.query_category} | "
          f"Confidence: {classification.confidence:.2f}")

    # ── STEP 2: RESEARCH PLANNING ─────────────────────────────────────────────
    print("Step 2: Planning research steps...")
    planner = PlannerAgent()
    plan = planner.run(query, {"category": classification.query_category,
                                "required_agents": classification.required_agents})
    all_costs.append(plan.cost)
    agents_invoked.append("PlannerAgent")
    print(f"  {len(plan.steps)} research steps planned")
    for step in plan.steps:
        print(f"    Step {step.step_id}: [{step.agent}] {step.action[:60]}")

    # ── STEP 3: RAG RETRIEVAL ─────────────────────────────────────────────────
    print("Step 3: Retrieving internal documents (RAG)...")
    retriever = RetrieverAgent()
    retrieval = retriever.run(query, user_role)
    all_costs.append(retrieval.cost)
    agents_invoked.append("RetrieverAgent")
    sensitivity_accessed = list(set([d.sensitivity for d in retrieval.documents]))
    agent_scores["RetrieverAgent"] = len(retrieval.documents) / 5.0  # Normalize
    print(f"  Found: {retrieval.total_found} documents | "
          f"Filtered by role: {retrieval.filtered_by_role}")
    for doc in retrieval.documents:
        print(f"    {doc.doc_id} [{doc.sensitivity}] relevance={doc.relevance:.2f}: "
              f"{doc.title[:50]}")

    # ── STEP 4: EXTERNAL WEB SEARCH ───────────────────────────────────────────
    search_type = "threat_intelligence" if classification.query_category == "security" else "technical_research"
    print(f"Step 4: External web search ({search_type})...")
    web_searcher = WebSearchAgent()
    web_results = web_searcher.run(query, search_type)
    all_costs.append(web_results.cost)
    agents_invoked.append("WebSearchAgent")
    agent_scores["WebSearchAgent"] = 0.75 if web_results.results else 0.3
    print(f"  External results: {len(web_results.results)} | "
          f"Filtered: {web_results.filtered}")

    # ── STEP 5: THREAT INTEL (security queries only) ─────────────────────────
    threat_output = None
    if classification.query_category in ["security", "compliance"]:
        print("Step 5: Threat intelligence analysis (CVE + MITRE ATT&CK)...")
        combined_context = (
            "\n".join([d.excerpt for d in retrieval.documents]) + "\n" +
            "\n".join([r.get("finding", "") for r in web_results.results])
        )
        threat_agent = ThreatIntelAgent()
        threat_output = threat_agent.run(combined_context)
        all_costs.append(threat_output.cost)
        agents_invoked.append("ThreatIntelAgent")
        agent_scores["ThreatIntelAgent"] = 0.85
        print(f"  CVEs: {threat_output.cves_identified} | "
              f"MITRE techniques: {threat_output.mitre_techniques} | "
              f"Severity: {threat_output.severity}")
    else:
        print("Step 5: Skipping threat intel (non-security query)")

    # ── STEP 6: GAP DETECTION ────────────────────────────────────────────────
    print("Step 6: Detecting knowledge gaps...")
    doc_dicts = [d.model_dump() for d in retrieval.documents]
    gap_agent = GapDetectionAgent()
    gap_output = gap_agent.run(query, doc_dicts)
    all_costs.append(gap_output.cost)
    agents_invoked.append("GapDetectionAgent")
    agent_scores["GapDetectionAgent"] = gap_output.confidence
    print(f"  Corpus coverage: {gap_output.corpus_coverage:.0%} | "
          f"Gaps found: {len(gap_output.gaps_identified)}")
    for gap in gap_output.gaps_identified[:3]:
        print(f"    GAP: {gap[:70]}")

    # ── STEP 7: CYBERSECURITY FRAMEWORK MAPPING ───────────────────────────────
    framework_output = None
    if classification.query_category in ["security", "compliance"]:
        print("Step 7: Mapping to cybersecurity frameworks...")
        findings_text = (
            "\n".join([d.excerpt for d in retrieval.documents[:5]]) + "\n" +
            (f"CVEs: {threat_output.cves_identified}\n"
             f"MITRE: {threat_output.mitre_techniques}" if threat_output else "")
        )
        framework_agent = CybersecurityFrameworkAgent()
        framework_output = framework_agent.run(findings_text)
        all_costs.append(framework_output.cost)
        agents_invoked.append("CybersecurityFrameworkAgent")
        agent_scores["CybersecurityFrameworkAgent"] = 0.82
        print(f"  NIST CSF: {framework_output.nist_csf_functions} | "
              f"Risk: {framework_output.risk_level}")
    else:
        print("Step 7: Skipping framework mapping (non-security query)")

    # ── STEP 8: COMPLIANCE ASSESSMENT ────────────────────────────────────────
    compliance_output = None
    if classification.query_category in ["compliance", "security", "strategic"]:
        print("Step 8: Assessing regulatory compliance...")
        compliance_context = "\n".join([d.excerpt for d in retrieval.documents[:5]])
        compliance_agent = ComplianceAgent()
        compliance_output = compliance_agent.run(
            compliance_context,
            "\n".join([d.excerpt for d in retrieval.documents[:3]])
        )
        all_costs.append(compliance_output.cost)
        agents_invoked.append("ComplianceAgent")
        agent_scores["ComplianceAgent"] = compliance_output.compliance_score
        print(f"  Compliance score: {compliance_output.compliance_score:.0%} | "
              f"Priority: {compliance_output.priority}")
    else:
        print("Step 8: Skipping compliance (non-compliance query)")

    # ── STEP 9: CITATION TRACING ──────────────────────────────────────────────
    print("Step 9: Tracing citations to source documents...")
    combined_findings = (
        "\n".join([d.excerpt for d in retrieval.documents]) + "\n" +
        "\n".join([r.get("finding", "") for r in web_results.results[:3]])
    )
    citation_agent = CitationAgent()
    citation_source_docs = [
        {
            "doc_id": d.doc_id,
            "title": d.title,
            "category": d.category,
            "sensitivity": d.sensitivity,
            "date": d.date,
            "excerpt": d.excerpt
        }
        for d in retrieval.documents
    ]
    citation_output = citation_agent.run(combined_findings, citation_source_docs)
    all_costs.append(citation_output.cost)
    agents_invoked.append("CitationAgent")
    agent_scores["CitationAgent"] = citation_output.coverage_score
    print(f"  Citations: {citation_output.citation_count} | "
          f"Coverage: {citation_output.coverage_score:.0%} | "
          f"Uncited: {len(citation_output.uncited_claims)}")

    # ── STEP 10: CONFIDENCE TRACKING ──────────────────────────────────────────
    print("Step 10: Aggregating confidence scores...")
    confidence_tracker = ConfidenceTrackerAgent()
    confidence_result = confidence_tracker.run(
        agent_scores=agent_scores,
        hallucination_risks=hallucination_risks,
        corpus_coverage=gap_output.corpus_coverage,
        citation_coverage=citation_output.coverage_score
    )
    all_costs.append(confidence_tracker.cost_log[-1] if confidence_tracker.cost_log else None)
    agents_invoked.append("ConfidenceTrackerAgent")
    print(f"  Pipeline confidence: {confidence_result.get('pipeline_confidence', 0):.2f} | "
          f"Status: {confidence_result.get('status', 'UNKNOWN')}")

    # Block synthesis if confidence tracker says so
    if confidence_result.get("block_synthesis", False) and confidence_result.get("pipeline_confidence", 0) < 0.60:
        print(f"\n  [BLOCKED] {confidence_result.get('confidence_summary','')}")
        return _build_blocked_result(run_id, query, user_role, confidence_result, all_costs)

    # ── STEP 11: SYNTHESIS ────────────────────────────────────────────────────
    print("Step 11: Synthesizing research response (gpt-4o)...")
    all_findings = {
        "query": query,
        "classification": classification.model_dump() if hasattr(classification, 'model_dump') else {},
        "retrieved_documents": [d.model_dump() for d in retrieval.documents],
        "web_search_results": web_results.results[:5],
        "threat_intel": threat_output.model_dump() if threat_output else {},
        "gap_analysis": gap_output.model_dump() if hasattr(gap_output, 'model_dump') else {},
        "framework_mapping": framework_output.model_dump() if framework_output else {},
        "compliance_assessment": compliance_output.model_dump() if compliance_output else {},
        "citations": citation_output.model_dump() if hasattr(citation_output, 'model_dump') else {},
        "confidence": confidence_result,
    }
    synthesizer = SynthesizerAgent()
    synthesis = synthesizer.run(query, all_findings, user_role)
    all_costs.append(synthesis.cost)
    agents_invoked.append("SynthesizerAgent")
    print(f"  Synthesis complete | Confidence: {synthesis.confidence:.2f}")

    # ── STEP 12: EVALUATION ───────────────────────────────────────────────────
    print("Step 12: Evaluating response quality (LLM-as-judge)...")
    evaluator = EvaluationAgent()
    evaluation = evaluator.evaluate(
        query=query,
        synthesis=synthesis,
        source_docs=doc_dicts,
        gap_analysis=gap_output.model_dump() if hasattr(gap_output, 'model_dump') else {}
    )
    all_costs.append(evaluation.cost)
    agents_invoked.append("EvaluationAgent")
    hallucination_risks["SynthesizerAgent"] = evaluation.hallucination_risk
    status = "PASS" if evaluation.passed else "FAIL"
    print(f"  [{status}] Overall: {evaluation.overall_score:.2f} | "
          f"Hallucination risk: {evaluation.hallucination_risk:.2f}")
    if evaluation.flags:
        for flag in evaluation.flags:
            print(f"    FLAG: {flag[:80]}")

    # ── STEP 13: OBSERVABILITY ────────────────────────────────────────────────
    print("Step 13: Running observability analysis...")
    total_latency = round(time.time() - pipeline_start, 2)
    valid_costs = [c for c in all_costs if c is not None]
    total_usd = round(sum(c.estimated_usd for c in valid_costs), 6)

    run_metrics = {
        "run_id": run_id,
        "total_cost_usd": total_usd,
        "total_latency_s": total_latency,
        "agent_costs": {c.agent_name: c.estimated_usd for c in valid_costs},
        "agent_latencies": {c.agent_name: c.latency_seconds for c in valid_costs},
        "evaluation_score": evaluation.overall_score,
        "citation_coverage": citation_output.coverage_score,
        "corpus_coverage": gap_output.corpus_coverage,
        "query_category": classification.query_category,
    }
    obs_agent = ObservabilityAgent()
    obs_result = obs_agent.run(run_metrics)
    agents_invoked.append("ObservabilityAgent")
    print(f"  Health: {obs_result.get('overall_health','UNKNOWN')} | "
          f"Alert level: {obs_result.get('alert_level','INFO')}")
    if obs_result.get("anomalies_detected"):
        for anomaly in obs_result["anomalies_detected"]:
            print(f"    ANOMALY: {anomaly[:70]}")

    # ── STEP 14: AUDIT LOGGING ────────────────────────────────────────────────
    print("Step 14: Writing audit log...")
    audit_agent = QueryAuditAgent()
    audit_record = audit_agent.run(
        query=query,
        user_role=user_role,
        query_category=classification.query_category,
        sensitivity_accessed=sensitivity_accessed,
        agents_invoked=agents_invoked,
        total_cost_usd=total_usd,
        total_latency_s=total_latency,
        run_id=run_id
    )
    agents_invoked.append("QueryAuditAgent")
    flagged_str = f" [FLAGGED: {audit_record.get('violation_severity')}]" if audit_record.get("flagged") else ""
    print(f"  Audit logged: QRY-{audit_record.get('query_id','?')}{flagged_str}")

    # ── PIPELINE SUMMARY ──────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print(f"PIPELINE COMPLETE — Run ID: {run_id}")
    print(f"Agents invoked: {len(agents_invoked)}/14")
    print(f"Total cost: ${total_usd:.6f}")
    print(f"Total latency: {total_latency:.1f}s")
    print(f"Evaluation: {status} (score: {evaluation.overall_score:.2f})")
    print(f"Corpus coverage: {gap_output.corpus_coverage:.0%}")
    print(f"Citation coverage: {citation_output.coverage_score:.0%}")
    print(f"{'='*60}\n")

    # ── BUILD RESULTS ─────────────────────────────────────────────────────────
    results = {
        "run_id": run_id,
        "query": query,
        "user_role": user_role,
        "query_category": classification.query_category,
        "agents_invoked": agents_invoked,
        "synthesis": synthesis.model_dump(),
        "evaluation": evaluation.model_dump(),
        "confidence": confidence_result,
        "gap_analysis": gap_output.model_dump() if hasattr(gap_output, 'model_dump') else {},
        "framework_mapping": framework_output.model_dump() if framework_output else {},
        "compliance": compliance_output.model_dump() if compliance_output else {},
        "threat_intel": threat_output.model_dump() if threat_output else {},
        "citations": citation_output.model_dump() if hasattr(citation_output, 'model_dump') else {},
        "observability": obs_result,
        "audit": audit_record,
        "total_cost_usd": total_usd,
        "total_latency_s": total_latency,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

    # Save results
    os.makedirs("data", exist_ok=True)
    with open(RESULTS_PATH, "w") as f:
        json.dump(results, f, indent=2, default=str)
    print(f"Results saved to data/last_run_results.json")

    # ── NOTIFY n8n ────────────────────────────────────────────────────────────
    _notify_n8n(results)

    return results


def _build_blocked_result(run_id, query, user_role, confidence_result, all_costs):
    """Return a blocked pipeline result when confidence tracker halts execution."""
    valid_costs = [c for c in all_costs if c is not None]
    total_usd = round(sum(c.estimated_usd for c in valid_costs), 6)
    return {
        "run_id": run_id,
        "query": query,
        "user_role": user_role,
        "status": "BLOCKED",
        "reason": confidence_result.get("confidence_summary", "Low confidence"),
        "total_cost_usd": total_usd,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }


def _notify_n8n(results: dict):
    """Notify n8n webhook with pipeline results (auth header included)."""
    try:
        n8n_secret = os.getenv("N8N_WEBHOOK_SECRET", "")
        headers = {"Content-Type": "application/json"}
        if n8n_secret:
            headers["X-Webhook-Secret"] = n8n_secret

        payload = {
            "run_id": results["run_id"],
            "query_category": results.get("query_category", "unknown"),
            "evaluation_passed": results.get("evaluation", {}).get("passed", False),
            "evaluation_score": results.get("evaluation", {}).get("overall_score", 0),
            "total_cost_usd": results["total_cost_usd"],
            "total_latency_s": results["total_latency_s"],
            "agents_invoked": len(results.get("agents_invoked", [])),
            "corpus_coverage": results.get("gap_analysis", {}).get("corpus_coverage", 0),
            "citation_coverage": results.get("citations", {}).get("coverage_score", 0),
            "flagged": results.get("audit", {}).get("flagged", False),
            "status": "complete"
        }
        r = requests.post(N8N_WEBHOOK_URL, json=payload, headers=headers, timeout=10)
        print(f"n8n notified: {r.status_code}")
    except Exception as e:
        print(f"n8n notification failed: {str(e)}")


if __name__ == "__main__":
    # Test queries
    test_queries = [
        ("What CVEs affect our V2X infrastructure and what is the MITRE ATT&CK mapping?", "ENGINEER"),
        ("Summarize our ISO 21434 compliance status across all vehicle programs", "EXECUTIVE"),
    ]

    query, role = test_queries[0]
    results = run_pipeline(query, role)

    print("\nEXECUTIVE SUMMARY:")
    print(results.get("synthesis", {}).get("executive_summary", "N/A"))
    print("\nKEY INSIGHTS:")
    for insight in results.get("synthesis", {}).get("key_insights", []):
        print(f"  • {insight}")
    print("\nACTION ITEMS:")
    for item in results.get("synthesis", {}).get("action_items", []):
        print(f"  → {item}")
