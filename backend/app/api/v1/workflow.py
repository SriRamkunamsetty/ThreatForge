from __future__ import annotations

from typing import Any
from uuid import UUID, uuid4
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.domain.workflow import (
    AuditEvent,
    EvidenceRecord,
    MitigationRecord,
    ReviewDecision,
    ReviewDecisionType,
    TestCaseSpecification,
    TestStatus,
)
from app.services.store import GLOBAL_STORE

router = APIRouter(tags=["Workflow & Provenance"])


class SubmitReviewRequest(BaseModel):
    decision: ReviewDecisionType
    reviewer_id: str = Field(min_length=1)
    reviewer_name: str = Field(min_length=1)
    rationale: str = Field(min_length=5, description="Mandatory decision rationale")
    assumptions_accepted: list[str] = Field(default_factory=list)


class SubmitEvidenceRequest(BaseModel):
    evidence_type: str = "ci_pipeline"
    summary: str = Field(min_length=5)
    commit_sha: str | None = None
    environment: str = "staging"
    test_run_url: str | None = None
    raw_output: str | None = None
    recorded_by: str = "security_lead"


class UpdateTestStatusRequest(BaseModel):
    status: TestStatus
    actual_result: str
    execution_notes: str | None = None


@router.get("/threats/{threat_id}/provenance")
def get_threat_provenance(threat_id: UUID) -> dict[str, Any]:
    chain = GLOBAL_STORE.provenance_chains.get(threat_id)
    if not chain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Provenance chain for threat '{threat_id}' not found. Make sure analysis has been run.",
        )
    return chain.build_provenance_graph()


@router.post("/threats/{threat_id}/review")
def review_threat(threat_id: UUID, req: SubmitReviewRequest) -> dict[str, Any]:
    chain = GLOBAL_STORE.provenance_chains.get(threat_id)
    if not chain:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat instance '{threat_id}' not found.",
        )

    decision = ReviewDecision(
        decision=req.decision,
        reviewer_id=req.reviewer_id,
        reviewer_name=req.reviewer_name,
        rationale=req.rationale,
        assumptions_accepted=req.assumptions_accepted,
    )
    decision.validate_rationale()
    chain.review_decision = decision

    event = GLOBAL_STORE.audit_logger.record(
        actor_id=req.reviewer_id,
        actor_name=req.reviewer_name,
        event_type="THREAT_REVIEWED",
        entity_type="threat_instance",
        entity_id=str(threat_id),
        rationale=req.rationale,
        payload={"decision": req.decision.value, "assumptions": req.assumptions_accepted},
    )

    return {
        "threat_id": str(threat_id),
        "decision": req.decision.value,
        "reviewer": req.reviewer_name,
        "decided_at": decision.decided_at.isoformat(),
        "audit_event_id": str(event.id),
    }


@router.get("/threats/{threat_id}/mitigations", response_model=list[MitigationRecord])
def list_threat_mitigations(threat_id: UUID) -> list[MitigationRecord]:
    return [
        m for m in GLOBAL_STORE.mitigations.values()
        if m.threat_instance_id == threat_id
    ]


@router.post("/mitigations/{mitigation_id}/tests/{test_id}/execute")
def update_test_status(
    mitigation_id: UUID, test_id: str, req: UpdateTestStatusRequest
) -> MitigationRecord:
    mit = GLOBAL_STORE.mitigations.get(mitigation_id)
    if not mit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mitigation '{mitigation_id}' not found.",
        )

    target_tc: TestCaseSpecification | None = None
    for tc in mit.test_cases:
        if tc.id == test_id:
            target_tc = tc
            break

    if not target_tc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Test case '{test_id}' not found in mitigation '{mitigation_id}'.",
        )

    target_tc.status = req.status
    target_tc.actual_result = req.actual_result
    target_tc.execution_notes = req.execution_notes

    mit.evaluate_verification_status()

    GLOBAL_STORE.audit_logger.record(
        actor_id="tester",
        actor_name="Automated Test Runner",
        event_type="TEST_STATUS_UPDATED",
        entity_type="verification_test",
        entity_id=test_id,
        rationale=f"Test {test_id} status updated to {req.status.value}",
        payload={"actual_result": req.actual_result},
    )

    return mit


@router.post("/mitigations/{mitigation_id}/evidence")
def submit_evidence(
    mitigation_id: UUID, req: SubmitEvidenceRequest
) -> MitigationRecord:
    mit = GLOBAL_STORE.mitigations.get(mitigation_id)
    if not mit:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mitigation '{mitigation_id}' not found.",
        )

    evidence = EvidenceRecord(
        evidence_type=req.evidence_type,
        summary=req.summary,
        commit_sha=req.commit_sha,
        environment=req.environment,
        test_run_url=req.test_run_url,
        raw_output=req.raw_output,
        recorded_by=req.recorded_by,
    )
    mit.evidence_records.append(evidence)
    mit.evaluate_verification_status()

    GLOBAL_STORE.audit_logger.record(
        actor_id=req.recorded_by,
        actor_name=req.recorded_by,
        event_type="EVIDENCE_SUBMITTED",
        entity_type="mitigation",
        entity_id=str(mitigation_id),
        rationale=f"Submitted evidence ({req.evidence_type}) in {req.environment}",
        payload={"commit_sha": req.commit_sha, "new_status": mit.status.value},
    )

    return mit


@router.get("/audit/events", response_model=list[AuditEvent])
def get_audit_trail() -> list[AuditEvent]:
    return GLOBAL_STORE.audit_logger.all_events()
