"""
================================================================================
SHARED OUTPUT CONTRACTS
Enterprise Knowledge Research Agent
================================================================================
All agents return structured Pydantic contracts.
Every contract includes cost tracking, audit metadata, and security fields.
================================================================================
"""

from pydantic import BaseModel, Field
from typing import Optional, Literal
from datetime import datetime


# ==============================================================================
# SECURITY & ACCESS CONTROL TYPES
# ==============================================================================

SensitivityLevel = Literal["PUBLIC", "INTERNAL", "RESTRICTED"]
UserRole = Literal["ANALYST", "ENGINEER", "EXECUTIVE"]
QueryCategory = Literal["security", "technical", "operational", "strategic", "compliance", "unknown"]
AlertSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# ==============================================================================
# CORE RESEARCH CONTRACTS
# ==============================================================================

class SourceReference(BaseModel):
    """Traceable reference back to a source document."""
    doc_id:       str
    title:        str
    category:     str
    sensitivity:  SensitivityLevel
    date:         str
    relevance:    float = Field(ge=0.0, le=1.0, description="Relevance score 0.0-1.0")
    excerpt:      str   = Field(description="Relevant excerpt from source document")


class ResearchStep(BaseModel):
    """Single step in the research plan produced by PlannerAgent."""
    step_id:      int
    action:       str   = Field(description="What this step does")
    agent:        str   = Field(description="Which agent executes this step")
    rationale:    str   = Field(description="Why this step is needed")
    completed:    bool  = False


class AgentCost(BaseModel):
    """Cost and latency tracking per agent call."""
    agent_name:      str
    model_used:      str
    input_tokens:    int
    output_tokens:   int
    latency_seconds: float
    estimated_usd:   float
    success:         bool
    error_message:   Optional[str] = None
    timestamp:       str = Field(default_factory=lambda: datetime.utcnow().isoformat())


class QueryAuditLog(BaseModel):
    """Immutable audit record for every query — security compliance requirement."""
    query_id:         str
    user_role:        UserRole
    query_text:       str
    query_category:   QueryCategory
    sensitivity_accessed: list[SensitivityLevel]
    agents_invoked:   list[str]
    total_cost_usd:   float
    total_latency_s:  float
    timestamp:        str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    flagged:          bool = False
    flag_reason:      Optional[str] = None


# ==============================================================================
# AGENT OUTPUT CONTRACTS
# ==============================================================================

class ClassificationOutput(BaseModel):
    """QueryClassifierAgent output — determines retrieval strategy."""
    agent_name:       str = "QueryClassifierAgent"
    query_category:   QueryCategory
    required_agents:  list[str]
    sensitivity_required: SensitivityLevel
    retrieval_strategy: str = Field(description="How to approach retrieval for this query type")
    confidence:       float = Field(ge=0.0, le=1.0)
    cost:             AgentCost


class ResearchPlan(BaseModel):
    """PlannerAgent output — autonomous research decomposition."""
    agent_name:   str = "PlannerAgent"
    query:        str
    steps:        list[ResearchStep]
    estimated_agents: list[str]
    rationale:    str = Field(description="Why this plan was chosen over alternatives")
    cost:         AgentCost


class RetrievalOutput(BaseModel):
    """RetrieverAgent output — RAG search results."""
    agent_name:   str = "RetrieverAgent"
    query:        str
    documents:    list[SourceReference]
    total_found:  int
    filtered_by_role: int = Field(description="Documents filtered due to access control")
    cost:         AgentCost


class WebSearchOutput(BaseModel):
    """WebSearchAgent output — external threat intelligence."""
    agent_name:   str = "WebSearchAgent"
    query:        str
    results:      list[dict]
    source_urls:  list[str]
    search_type:  str = Field(description="Type of external search performed")
    filtered:     bool = Field(description="Whether results were filtered for safety")
    cost:         AgentCost


class ThreatIntelOutput(BaseModel):
    """ThreatIntelAgent output — CVE and MITRE ATT&CK mapping."""
    agent_name:       str = "ThreatIntelAgent"
    cves_identified:  list[str]
    mitre_techniques: list[str]
    affected_systems: list[str]
    severity:         AlertSeverity
    recommendations:  list[str]
    nvd_data:         list[dict]
    cost:             AgentCost


class GapDetectionOutput(BaseModel):
    """GapDetectionAgent output — identifies what corpus does NOT contain."""
    agent_name:       str = "GapDetectionAgent"
    gaps_identified:  list[str]
    missing_topics:   list[str]
    recommended_sources: list[str]
    corpus_coverage:  float = Field(ge=0.0, le=1.0, description="Estimated coverage 0.0-1.0")
    confidence:       float = Field(ge=0.0, le=1.0)
    cost:             AgentCost


class CybersecurityFrameworkOutput(BaseModel):
    """CybersecurityFrameworkAgent output — NIST CSF + MITRE ATT&CK mapping."""
    agent_name:       str = "CybersecurityFrameworkAgent"
    nist_csf_functions: list[str]
    nist_controls:    list[str]
    mitre_techniques: list[str]
    iso_21434_clauses: list[str]
    unece_wp29_refs:  list[str]
    nist_sp800_82_refs: list[str]
    risk_level:       AlertSeverity
    framework_summary: str
    cost:             AgentCost


class ComplianceOutput(BaseModel):
    """ComplianceAgent output — regulatory mapping."""
    agent_name:         str = "ComplianceAgent"
    iso_21434_gaps:     list[str]
    unece_r155_gaps:    list[str]
    unece_r156_gaps:    list[str]
    nist_sp800_82_gaps: list[str]
    compliance_score:   float = Field(ge=0.0, le=1.0)
    remediation_items:  list[str]
    priority:           AlertSeverity
    cost:               AgentCost


class CitationOutput(BaseModel):
    """CitationAgent output — traceable source references."""
    agent_name:   str = "CitationAgent"
    citations:    list[SourceReference]
    citation_count: int
    coverage_score: float = Field(ge=0.0, le=1.0,
        description="Fraction of claims that have traceable citations")
    uncited_claims: list[str]
    cost:         AgentCost


class SynthesisOutput(BaseModel):
    """SynthesizerAgent output — final structured research response."""
    agent_name:       str = "SynthesizerAgent"
    query:            str
    executive_summary: str
    detailed_findings: str
    key_insights:     list[str]
    action_items:     list[str]
    confidence:       float = Field(ge=0.0, le=1.0)
    sources_used:     int
    cost:             AgentCost


# ==============================================================================
# EVALUATION CONTRACT
# ==============================================================================

class EvaluationOutput(BaseModel):
    """EvaluationAgent output — LLM-as-judge quality scoring."""
    agent_name:               str = "EvaluationAgent"
    evaluated_agent:          str
    relevance_score:          float = Field(ge=0.0, le=1.0,
        description="Did the response answer the query?")
    grounding_score:          float = Field(ge=0.0, le=1.0,
        description="Are citations traceable to real corpus documents?")
    completeness_score:       float = Field(ge=0.0, le=1.0,
        description="Did GapDetection identify what was missing?")
    security_compliance_score: float = Field(ge=0.0, le=1.0,
        description="Did ComplianceAgent correctly map findings?")
    hallucination_risk:       float = Field(ge=0.0, le=1.0,
        description="Did the agent invent documents or findings?")
    overall_score:            float = Field(ge=0.0, le=1.0)
    passed:                   bool
    flags:                    list[str]
    judgment:                 str
    cost:                     AgentCost


# ==============================================================================
# PIPELINE RUN CONTRACT
# ==============================================================================

class PipelineRun(BaseModel):
    """Complete pipeline execution record."""
    run_id:               str
    query:                str
    user_role:            UserRole
    query_category:       QueryCategory
    total_agents:         int
    successful_agents:    int
    failed_agents:        int
    total_input_tokens:   int
    total_output_tokens:  int
    total_latency_seconds: float
    total_estimated_usd:  float
    agent_costs:          list[AgentCost]
    synthesis:            Optional[SynthesisOutput] = None
    evaluation:           Optional[EvaluationOutput] = None
    audit_log:            Optional[QueryAuditLog] = None
    timestamp:            str = Field(default_factory=lambda: datetime.utcnow().isoformat())
