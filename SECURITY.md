# Security Policy — Enterprise Knowledge Research Agent

## Overview

This system handles enterprise knowledge content that may include RESTRICTED-sensitivity documents covering AV/OT cybersecurity, vulnerability advisories, threat intelligence, and regulatory compliance findings. Security is enforced at every layer — gateway, orchestrator, agent, data, and external tool integration.

This document describes the security posture, threat model, and controls. Vulnerability reports should be directed to the maintainer privately rather than filed as public issues.

---

## Threat Model

The system is designed against the following threats:

| Threat | Vector | Severity |
|---|---|---|
| Prompt injection in user query | Malicious instructions embedded in query text | High |
| Prompt injection in retrieved document | Malicious instructions embedded in corpus content | High |
| Role-based access control bypass | Caller obtains RESTRICTED content without authorization | High |
| Hallucinated citation | Synthesized response invents document IDs or facts | High |
| Webhook forgery | Attacker sends crafted requests to n8n webhooks | High |
| Stolen API key replay | Captured key reused at scale | High |
| Cost runaway | Pathological query consumes budget | Medium |
| Audit log tampering | Modification of historical query records | Medium |
| External dependency outage | NVD/CISA unreachable for extended period | Medium |
| Sensitive content in audit log | RESTRICTED content unredacted in audit JSONL | Medium |

Full risk register with 22 entries, NIST SP 800-30 ratings, and MITRE ATLAS / ATT&CK for ICS mappings is in `docs/EKA_System_Design_LSmith.docx` (Appendix B).

---

## Security Controls

### Authentication & Authorization
- **API key authentication** on every FastAPI endpoint.
- **HMAC signature verification** on every n8n webhook (request signed with `N8N_WEBHOOK_SECRET`).
- **Role-Based Access Control** — ANALYST, ENGINEER, EXECUTIVE roles map to document sensitivity tiers (PUBLIC, INTERNAL, RESTRICTED).
- Bearer token validation before any LLM call.

### Input Validation
- **Prompt-injection filter** at the FastAPI gateway runs queries against a pattern library before any LLM invocation.
- **Input sanitization** — length caps, schema validation, control-character stripping.
- **Sensitivity pre-check** rejects queries containing classified markers from unauthorized roles.
- Every agent's system prompt includes an explicit instruction to disregard embedded directives.

### Output Protection
- **Output redaction filter** on the response path scans for known classified markers and redacts.
- **Citation enforcement** — uncited claims are flagged; responses with <50% citation coverage are blocked.
- **Confidence threshold** — aggregated pipeline confidence < 0.60 routes the response to human review rather than auto-delivery.

### Rate Limiting & Cost Controls
- **10 requests per minute per API key** at the gateway.
- **Per-agent max-token cap** prevents runaway generation.
- **No loops in the orchestrator** — deterministic sequential execution.
- Per-tenant daily spend limits (production deployment).

### Audit & Observability
- **Append-only JSONL audit log** captures every query, classification, agents invoked, citations, evaluation scores, and timestamp.
- **LangSmith trace** on every agent invocation: model, prompt, response, latency, cost.
- **Tamper evidence** in production via periodic hash chain anchoring of the audit log.
- Audit log records are redacted on write — RESTRICTED content does not enter the audit stream verbatim.

### Secret Management
- `.env` file with `chmod 600` (owner-readable only).
- `.env` listed in `.gitignore` — **never committed**.
- Secrets entered via `getpass` to avoid shell history capture.
- n8n credentials stored in n8n's encrypted credential store; **never inline** in workflow node parameters.
- API key rotation supported; old keys revocable at the gateway.

### Evaluation & Drift Detection
- **LLM-as-judge** scores every response on relevance, grounding, completeness, security accuracy, hallucination risk.
- **Golden dataset** of 20 representative queries re-scored every 4 hours by n8n Workflow 2.
- **Drift alerts** fire when scores deviate from baseline by more than three standard deviations.

---

## Reporting a Vulnerability

Email the maintainer directly. Do not open a public issue. Include:
- A description of the vulnerability.
- Reproduction steps.
- The impact you've assessed.
- Any suggested mitigations.

Acknowledgement within 48 hours, with a remediation timeline based on severity.

---

## Compliance Alignment

The system is designed to support evidence collection for:
- SOC 2 (security, availability, confidentiality)
- ISO 27001 (information security management)
- NIST SP 800-30 Rev 1 (risk assessment methodology)
- NIST SP 800-82 Rev 3 (industrial control systems security)
- ISO 21434 (road vehicle cybersecurity engineering)
- UNECE WP.29 R155 / R156 (cybersecurity management / software updates)

Specific framework mappings are produced by the **CybersecurityFrameworkAgent** and **ComplianceAgent** on every relevant query.

---

*Maintained by Lamonte Smith · Milford, MI · 2026*
