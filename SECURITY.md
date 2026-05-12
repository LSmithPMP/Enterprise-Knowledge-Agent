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

## Operational Status (Live Verification)

As of May 11, 2026, the security controls described above are operational
in a deployed environment and have been verified by real end-to-end
execution rather than design review alone.

### Verified Controls

The following controls were exercised during live verification:

- HMAC-SHA256 signature verification over raw request body
- API key authentication on all sensitive endpoints
- Per-key rate limiting
- Prompt-injection pattern filter on inbound queries
- Role-based access control across analyst, engineer, and executive roles
- Output redaction of classification markers on the response path
- Append-only audit logging of all queries and pipeline outcomes
- Observability metrics emission per execution
- Live external threat-intelligence calls with verification of returned data

### Operational Evidence

- Workflow 1 (Enterprise Research Pipeline) succeeded end-to-end in 16.791
  seconds with all sixteen nodes active
  ([screenshot](docs/W1_execution_succeeded_20260511.png))
- Workflow 2 (Threat Surveillance + Eval Drift Monitor) succeeded end-to-end
  in 11.03 seconds with all fifteen nodes active
  ([screenshot](docs/W2_execution_succeeded_20260511.png))
- A live external-tool call during verification returned a real, current
  CISA ICS-CERT advisory, confirming the threat-intelligence integration is
  not stubbed
- Engineering refinements applied during verification are version-controlled
  in the repository's commit history

### Secret Hygiene

Secrets are handled in accordance with industry best practice. No secret
material is committed to the repository. Local copies of any deployment
artifacts that contain substituted secrets are excluded from version
control and protected with restrictive file permissions.

The runtime API key was rotated on May 12, 2026 following a defense-in-depth
review. Prior key material had been briefly visible in plaintext within a
debugging diagnostic during HMAC verification work. Exposure was scoped to
the operator's own workspace, but rotation was performed regardless to
honor the cybersecurity posture documented in this policy.

### Disclosed Limitations

For transparency:

- The reverse-proxy used during live verification was an ephemeral
  quick-tunnel, terminated immediately after evidence capture. Tunnel
  references visible in evidence screenshots are dead and incapable of
  routing to any origin. Production deployment requires a pre-created
  named tunnel, a private network connection, or an authenticated
  reverse-proxy endpoint.
- One advanced configuration feature on the workflow orchestration
  platform is tier-gated by the vendor at a level above the operator's
  current paid plan. As a result, the deployment uses an operator-chosen
  local substitution pattern that is functionally equivalent for the
  verification scenarios documented here. The pattern is intentional and
  documented; it is not the byproduct of an unpaid or unsupported
  configuration.

## Reporting a Vulnerability

Private reports are preferred; public issues are also welcome.
Reach the maintainer through the GitHub profile
[@LSmithPMP](https://github.com/LSmithPMP). Reports should include:

- A description of the vulnerability
- Reproduction steps
- The impact you have assessed
- Any suggested mitigations

Acknowledgment within 48 hours, with a remediation timeline based on severity.


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
