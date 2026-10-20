from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.domain.models.core import (
    Applicability,
    ArchitectureFact,
    Confidence,
    MitigationStatus,
    Severity,
    ThreatStatus,
)
from app.domain.workflow.compiler import EvidenceRecord, MitigationRecord, TestCaseSpecification


class ReviewDecisionType(str, Enum):
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    NEEDS_INFO = "NEEDS_INFO"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class ReviewDecision(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    decision: ReviewDecisionType
    reviewer_id: str
    reviewer_name: str
    rationale: str  # MANDATORY: No silent approvals
    assumptions_accepted: list[str] = Field(default_factory=list)
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def validate_rationale(self) -> None:
        if not self.rationale or len(self.rationale.strip()) < 5:
            raise ValueError("A meaningful rationale (min 5 characters) is mandatory for all review decisions.")


class ResidualRisk(BaseModel):
    original_severity: Severity
    residual_severity: Severity
    risk_accepted: bool = False
    acceptance_rationale: str | None = None
    accepted_by: str | None = None
    unresolved_uncertainties: list[str] = Field(default_factory=list)


class ProvenanceNode(BaseModel):
    node_id: str
    node_type: str  # architecture_fact | rule_application | threat_instance | review_decision | mitigation | verification_test | evidence | residual_risk
    label: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = Field(default_factory=dict)


class ProvenanceEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str  # justifies | evaluates_to | decided_by | mitigated_by | verified_by | evidenced_by | yields_residual


class ThreatProvenanceChain(BaseModel):
    """
    Threat-to-Evidence Provenance Graph (Signature P1 Feature).

    Constructs a complete, auditable lineage from architecture facts
    down to verification test evidence and residual risk.
    """

    threat_instance_id: UUID
    rule_id: str
    rule_version: str
    component_id: UUID
    component_name: str
    title: str
    description: str
    applicability: Applicability
    confidence: Confidence
    prerequisites_met: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    architecture_facts: list[ArchitectureFact] = Field(default_factory=list)

    review_decision: ReviewDecision | None = None
    mitigations: list[MitigationRecord] = Field(default_factory=list)
    residual_risk: ResidualRisk | None = None

    def build_provenance_graph(self) -> dict[str, Any]:
        """
        Builds a typed DAG node-link graph suitable for audit rendering
        and visual inspection in the UI.
        """
        nodes: list[ProvenanceNode] = []
        edges: list[ProvenanceEdge] = []

        threat_node_id = f"threat-{self.threat_instance_id}"
        nodes.append(
            ProvenanceNode(
                node_id=threat_node_id,
                node_type="threat_instance",
                label=f"[{self.rule_id}] {self.title}",
                metadata={
                    "applicability": self.applicability.value,
                    "confidence": self.confidence.value,
                    "component": self.component_name,
                },
            )
        )

        # 1. Architecture Facts -> Threat
        for idx, fact in enumerate(self.architecture_facts):
            fact_node_id = f"fact-{self.threat_instance_id}-{idx}"
            nodes.append(
                ProvenanceNode(
                    node_id=fact_node_id,
                    node_type="architecture_fact",
                    label=fact.description,
                    metadata={"fact_type": fact.fact_type, "value": str(fact.value)},
                )
            )
            edges.append(
                ProvenanceEdge(
                    source_id=fact_node_id,
                    target_id=threat_node_id,
                    relationship="justifies",
                )
            )

        # 2. Threat -> Review Decision
        if self.review_decision:
            decision_node_id = f"decision-{self.review_decision.id}"
            nodes.append(
                ProvenanceNode(
                    node_id=decision_node_id,
                    node_type="review_decision",
                    label=f"Decision: {self.review_decision.decision.value} by {self.review_decision.reviewer_name}",
                    metadata={
                        "rationale": self.review_decision.rationale,
                        "decided_at": self.review_decision.decided_at.isoformat(),
                    },
                )
            )
            edges.append(
                ProvenanceEdge(
                    source_id=threat_node_id,
                    target_id=decision_node_id,
                    relationship="decided_by",
                )
            )

        # 3. Decision / Threat -> Mitigations
        for mit in self.mitigations:
            mit_node_id = f"mit-{mit.id}"
            nodes.append(
                ProvenanceNode(
                    node_id=mit_node_id,
                    node_type="mitigation",
                    label=f"Mitigation: {mit.title}",
                    metadata={"status": mit.status.value, "control_type": mit.control_type},
                )
            )
            edges.append(
                ProvenanceEdge(
                    source_id=threat_node_id,
                    target_id=mit_node_id,
                    relationship="mitigated_by",
                )
            )

            # 4. Mitigation -> Tests
            for tc in mit.test_cases:
                tc_node_id = f"tc-{tc.id}"
                nodes.append(
                    ProvenanceNode(
                        node_id=tc_node_id,
                        node_type="verification_test",
                        label=tc.title,
                        metadata={
                            "status": tc.status.value,
                            "expected": tc.expected_result,
                            "action": tc.action,
                        },
                    )
                )
                edges.append(
                    ProvenanceEdge(
                        source_id=mit_node_id,
                        target_id=tc_node_id,
                        relationship="verified_by",
                    )
                )

            # 5. Mitigation -> Evidence Records
            for ev in mit.evidence_records:
                ev_node_id = f"ev-{ev.id}"
                nodes.append(
                    ProvenanceNode(
                        node_id=ev_node_id,
                        node_type="evidence",
                        label=f"Evidence: {ev.summary} ({ev.environment})",
                        metadata={
                            "commit_sha": ev.commit_sha,
                            "recorded_by": ev.recorded_by,
                            "is_stale": ev.is_stale(),
                        },
                    )
                )
                edges.append(
                    ProvenanceEdge(
                        source_id=mit_node_id,
                        target_id=ev_node_id,
                        relationship="evidenced_by",
                    )
                )

        # 6. Residual Risk
        if self.residual_risk:
            risk_node_id = f"risk-{self.threat_instance_id}"
            nodes.append(
                ProvenanceNode(
                    node_id=risk_node_id,
                    node_type="residual_risk",
                    label=f"Residual Severity: {self.residual_risk.residual_severity.value}",
                    metadata={
                        "original": self.residual_risk.original_severity.value,
                        "residual": self.residual_risk.residual_severity.value,
                        "risk_accepted": self.residual_risk.risk_accepted,
                    },
                )
            )
            edges.append(
                ProvenanceEdge(
                    source_id=threat_node_id,
                    target_id=risk_node_id,
                    relationship="yields_residual",
                )
            )

        return {
            "threat_id": str(self.threat_instance_id),
            "nodes": [n.model_dump() for n in nodes],
            "edges": [e.model_dump() for e in edges],
            "node_count": len(nodes),
            "edge_count": len(edges),
        }
