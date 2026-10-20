from __future__ import annotations

from typing import Any
from uuid import UUID
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from app.domain.graph.diff import DriftReport, semantic_drift_analysis
from app.domain.models.core import ModelContext
from app.domain.rules import RuleEngine
from app.services.store import GLOBAL_STORE

router = APIRouter(prefix="/drift", tags=["Architecture Drift"])
rule_engine = RuleEngine()


class CompareVersionsRequest(BaseModel):
    baseline_version_id: UUID
    current_version_id: UUID


class CompareContextsRequest(BaseModel):
    baseline: ModelContext
    current: ModelContext


def _serialize_drift_report(report: DriftReport) -> dict[str, Any]:
    return {
        "id": str(report.id),
        "baseline_version_id": (
            str(report.baseline_version_id) if report.baseline_version_id else None
        ),
        "current_version_id": (
            str(report.current_version_id) if report.current_version_id else None
        ),
        "added_components": report.added_components,
        "removed_components": report.removed_components,
        "modified_components": report.modified_components,
        "added_flows": report.added_flows,
        "removed_flows": report.removed_flows,
        "modified_flows": report.modified_flows,
        "new_boundary_crossings": report.new_boundary_crossings,
        "changes": [
            {
                "change_type": c.change_type,
                "entity_type": c.entity_type,
                "entity_id": c.entity_id,
                "entity_name": c.entity_name,
                "security_relevance": c.security_relevance.value,
                "threat_impact": c.threat_impact,
                "requires_review": c.requires_review,
                "attribute_deltas": [
                    {
                        "attribute": d.attribute_name,
                        "old": d.old_value,
                        "new": d.new_value,
                        "relevance": d.security_relevance.value,
                        "rationale": d.rationale,
                    }
                    for d in c.attribute_deltas
                ],
            }
            for c in report.changes
        ],
        "security_relevance_score": report.security_relevance_score,
        "requires_review": report.requires_review,
        "newly_applicable_threats": report.newly_applicable_threats,
        "invalidated_threats": report.invalidated_threats,
    }


@router.post("/compare")
def compare_versions(req: CompareVersionsRequest) -> dict[str, Any]:
    baseline = GLOBAL_STORE.get_version(req.baseline_version_id)
    if not baseline:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Baseline version '{req.baseline_version_id}' not found.",
        )

    current = GLOBAL_STORE.get_version(req.current_version_id)
    if not current:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Current version '{req.current_version_id}' not found.",
        )

    report = semantic_drift_analysis(baseline, current, rule_engine=rule_engine)
    GLOBAL_STORE.drift_reports[report.id] = report
    return _serialize_drift_report(report)


@router.post("/compare-contexts")
def compare_contexts(req: CompareContextsRequest) -> dict[str, Any]:
    """
    Compare two architecture contexts on the fly (e.g. unsaved editor canvas vs baseline snapshot).
    """
    report = semantic_drift_analysis(req.baseline, req.current, rule_engine=rule_engine)
    GLOBAL_STORE.drift_reports[report.id] = report
    return _serialize_drift_report(report)
