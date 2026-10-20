from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.domain.models.core import Applicability, Confidence, ModelContext, STRIDECategory
from app.domain.rules import RuleEngine
from app.domain.workflow import MitigationCompiler, ThreatProvenanceChain
from app.services.store import GLOBAL_STORE, ModelStore


class ThreatSummary(BaseModel):
    threat_id: UUID = Field(default_factory=uuid4)
    component_id: UUID
    component_name: str
    component_type: str
    rule_id: str
    rule_version: str
    category: str
    methodology: str
    title: str
    description: str
    applicability: str
    confidence: str
    prerequisites_met: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    architecture_facts: list[dict[str, Any]] = Field(default_factory=list)
    mitigation_templates: list[dict[str, Any]] = Field(default_factory=list)
    verification_criteria: list[str] = Field(default_factory=list)
    status: str = "OPEN"


class AnalysisRunResult(BaseModel):
    run_id: UUID = Field(default_factory=uuid4)
    model_version_id: UUID
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    total_evaluations: int
    applicable_count: int
    not_applicable_count: int
    needs_review_count: int
    category_counts: dict[str, int] = Field(default_factory=dict)
    confidence_counts: dict[str, int] = Field(default_factory=dict)
    threats: list[ThreatSummary] = Field(default_factory=list)


class AnalysisService:
    def __init__(self, store: ModelStore = GLOBAL_STORE) -> None:
        self.store = store
        self.engine = RuleEngine()

    def run_analysis(
        self,
        context: ModelContext,
        include_not_applicable: bool = False,
    ) -> AnalysisRunResult:
        raw_results = self.engine.analyze_model(
            context, include_not_applicable=include_not_applicable
        )

        counts = self.engine.count_by_applicability(raw_results)
        category_counts: dict[str, int] = {}
        confidence_counts: dict[str, int] = {}
        threat_summaries: list[ThreatSummary] = []

        for comp, rule, res in raw_results:
            cat = (
                rule.category.value
                if isinstance(rule.category, STRIDECategory)
                else str(rule.category)
            )
            if res.applicability == Applicability.APPLICABLE:
                category_counts[cat] = category_counts.get(cat, 0) + 1
                confidence_counts[res.confidence.value] = (
                    confidence_counts.get(res.confidence.value, 0) + 1
                )

            threat_id = uuid4()
            summary = ThreatSummary(
                threat_id=threat_id,
                component_id=comp.id,
                component_name=comp.name,
                component_type=comp.component_type.value,
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                category=cat,
                methodology=rule.methodology.value,
                title=res.title,
                description=res.description,
                applicability=res.applicability.value,
                confidence=res.confidence.value,
                prerequisites_met=res.prerequisites_met,
                missing_facts=res.missing_facts,
                assumptions=res.assumptions,
                architecture_facts=[f.model_dump() for f in res.architecture_facts],
                mitigation_templates=[m.model_dump() for m in res.mitigation_templates],
                verification_criteria=res.suggested_verification_criteria,
            )
            threat_summaries.append(summary)

            # Persist threat instance and create initial provenance chain
            self.store.threat_instances[threat_id] = summary.model_dump()

            mit_records = [
                MitigationCompiler.compile(threat_id, m, comp)
                for m in res.mitigation_templates
            ]
            for mr in mit_records:
                self.store.mitigations[mr.id] = mr

            chain = ThreatProvenanceChain(
                threat_instance_id=threat_id,
                rule_id=rule.rule_id,
                rule_version=rule.rule_version,
                component_id=comp.id,
                component_name=comp.name,
                title=res.title,
                description=res.description,
                applicability=res.applicability,
                confidence=res.confidence,
                prerequisites_met=res.prerequisites_met,
                missing_facts=res.missing_facts,
                assumptions=res.assumptions,
                architecture_facts=res.architecture_facts,
                mitigations=mit_records,
            )
            self.store.provenance_chains[threat_id] = chain

        result = AnalysisRunResult(
            model_version_id=context.model_version_id,
            total_evaluations=len(raw_results),
            applicable_count=counts.get(Applicability.APPLICABLE.value, 0),
            not_applicable_count=counts.get(Applicability.NOT_APPLICABLE.value, 0),
            needs_review_count=counts.get(Applicability.NEEDS_REVIEW.value, 0),
            category_counts=category_counts,
            confidence_counts=confidence_counts,
            threats=threat_summaries,
        )

        self.store.analysis_runs[result.run_id] = result.model_dump()
        return result
