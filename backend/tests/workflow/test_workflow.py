from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid
import pytest

from app.domain.models.core import (
    Applicability,
    ArchitectureFact,
    Component,
    ComponentType,
    Confidence,
    MitigationStatus,
    MitigationTemplate,
    Severity,
)
from app.domain.workflow import (
    AuditLogger,
    EvidenceRecord,
    MitigationCompiler,
    ResidualRisk,
    ReviewDecision,
    ReviewDecisionType,
    TestCaseSpecification,
    TestStatus,
    ThreatProvenanceChain,
)


def make_id():
    return uuid.uuid4()


def test_mitigation_compiler_generates_test_cases():
    comp = Component(
        model_version_id=make_id(),
        component_type=ComponentType.PROCESS,
        name="CheckoutAPI",
    )
    auth_template = MitigationTemplate(
        template_id="MIT-AUTH-001",
        title="Enforce authentication",
        description="Require JWT tokens on all requests",
        control_type="PREVENTIVE",
        verification_criteria=["Unauthenticated requests receive 401"],
    )

    threat_id = make_id()
    mit_record = MitigationCompiler.compile(threat_id, auth_template, comp)

    assert mit_record.threat_instance_id == threat_id
    assert mit_record.status == MitigationStatus.PROPOSED
    assert len(mit_record.test_cases) >= 2
    assert any("401" in tc.expected_result for tc in mit_record.test_cases)


def test_mitigation_record_status_progression_and_evidence():
    threat_id = make_id()
    comp = Component(
        model_version_id=make_id(),
        component_type=ComponentType.PROCESS,
        name="UserAPI",
    )
    template = MitigationTemplate(
        template_id="MIT-AUTHZ-001",
        title="Enforce RBAC",
        description="Deny unprivileged access",
        control_type="PREVENTIVE",
    )
    record = MitigationCompiler.compile(threat_id, template, comp)

    # Initial status is PROPOSED
    assert record.status == MitigationStatus.PROPOSED

    # Mark all test cases PASSED but no evidence yet
    for tc in record.test_cases:
        tc.status = TestStatus.PASSED
    status = record.evaluate_verification_status()
    assert status == MitigationStatus.IMPLEMENTED

    # Attach fresh evidence -> becomes VERIFIED
    fresh_ev = EvidenceRecord(
        evidence_type="ci_pipeline",
        summary="Automated security test suite run in CI",
        commit_sha="a1b2c3d4",
        environment="staging",
    )
    record.evidence_records.append(fresh_ev)
    status = record.evaluate_verification_status()
    assert status == MitigationStatus.VERIFIED
    assert record.verified_at is not None

    # Attach only stale evidence (>90 days old) -> becomes STALE
    stale_record = MitigationCompiler.compile(threat_id, template, comp)
    for tc in stale_record.test_cases:
        tc.status = TestStatus.PASSED
    stale_ev = EvidenceRecord(
        evidence_type="pen_test",
        summary="Old penetration test report",
        created_at=datetime.now(timezone.utc) - timedelta(days=120),
    )
    stale_record.evidence_records.append(stale_ev)
    stale_status = stale_record.evaluate_verification_status()
    assert stale_status == MitigationStatus.STALE

    # Failed test case -> becomes FAILED
    failed_record = MitigationCompiler.compile(threat_id, template, comp)
    failed_record.test_cases[0].status = TestStatus.FAILED
    assert failed_record.evaluate_verification_status() == MitigationStatus.FAILED


def test_threat_provenance_chain_graph():
    threat_id = make_id()
    comp_id = make_id()
    fact1 = ArchitectureFact(
        fact_type="unencrypted_flow",
        description="Flow from internet to CheckoutAPI is cleartext",
        component_id=comp_id,
    )
    decision = ReviewDecision(
        decision=ReviewDecisionType.APPROVED,
        reviewer_id="sec-eng-01",
        reviewer_name="Alice (Lead AppSec)",
        rationale="Verified architecture exposure; mitigation required prior to launch.",
    )
    mit_record = MitigationCompiler.compile(
        threat_id,
        MitigationTemplate(
            template_id="MIT-ENC-001",
            title="TLS 1.2+ encryption",
            description="Enforce TLS",
            control_type="PREVENTIVE",
        ),
        Component(
            id=comp_id,
            model_version_id=make_id(),
            component_type=ComponentType.PROCESS,
            name="CheckoutAPI",
        ),
    )

    chain = ThreatProvenanceChain(
        threat_instance_id=threat_id,
        rule_id="STRIDE-T-001",
        rule_version="1.0.0",
        component_id=comp_id,
        component_name="CheckoutAPI",
        title="Unencrypted data flow across trust boundary",
        description="Data flow crosses boundary without encryption",
        applicability=Applicability.APPLICABLE,
        confidence=Confidence.HIGH,
        architecture_facts=[fact1],
        review_decision=decision,
        mitigations=[mit_record],
        residual_risk=ResidualRisk(
            original_severity=Severity.HIGH,
            residual_severity=Severity.LOW,
            risk_accepted=False,
        ),
    )

    graph = chain.build_provenance_graph()
    assert graph["node_count"] >= 5
    assert graph["edge_count"] >= 4

    node_types = {n["node_type"] for n in graph["nodes"]}
    assert "threat_instance" in node_types
    assert "architecture_fact" in node_types
    assert "review_decision" in node_types
    assert "mitigation" in node_types
    assert "verification_test" in node_types
    assert "residual_risk" in node_types


def test_review_decision_mandatory_rationale():
    decision = ReviewDecision(
        decision=ReviewDecisionType.APPROVED,
        reviewer_id="user-1",
        reviewer_name="Bob",
        rationale="Valid security concern confirmed after threat model review.",
    )
    decision.validate_rationale()  # should not raise

    invalid_decision = ReviewDecision(
        decision=ReviewDecisionType.APPROVED,
        reviewer_id="user-1",
        reviewer_name="Bob",
        rationale="   ",  # Blank
    )
    with pytest.raises(ValueError, match="mandatory"):
        invalid_decision.validate_rationale()


def test_audit_logger():
    logger = AuditLogger()
    event = logger.record(
        actor_id="user-42",
        actor_name="Carol",
        event_type="THREAT_REVIEWED",
        entity_type="threat_instance",
        entity_id="THR-123",
        rationale="Approved threat and initiated mitigation plan",
    )
    assert event.actor_name == "Carol"
    assert len(logger.all_events()) == 1
    assert len(logger.get_events_for_entity("THR-123")) == 1
    assert len(logger.get_events_for_entity("NON-EXISTENT")) == 0
