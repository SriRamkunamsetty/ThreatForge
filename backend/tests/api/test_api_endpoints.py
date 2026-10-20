from __future__ import annotations

import uuid
from fastapi.testclient import TestClient
import pytest

from app.domain.models.core import (
    Component,
    ComponentProperties,
    ComponentType,
    DataClassification,
    DataFlow,
    DataFlowProperties,
    ModelContext,
)
from app.main import app

client = TestClient(app)


def make_id():
    return uuid.uuid4()


def test_health_and_root():
    res = client.get("/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert int(data["registered_rules"]) >= 11

    root_res = client.get("/")
    assert root_res.status_code == 200
    assert "ThreatForge" in root_res.json()["name"]


def test_full_api_workflow_end_to_end():
    # 1. Create a Threat Model
    create_res = client.post("/api/v1/models", json={
        "name": "E-Commerce Checkout System",
        "description": "Production checkout and order processing pipeline",
    })
    assert create_res.status_code == 201
    model = create_res.json()
    model_id = model["id"]

    # 2. Build and save Version 1 (Baseline: insecure API without auth)
    vid1 = make_id()
    ext = Component(
        model_version_id=vid1,
        component_type=ComponentType.EXTERNAL_ENTITY,
        name="Public User",
        trust_zone="internet",
    )
    api = Component(
        model_version_id=vid1,
        component_type=ComponentType.PROCESS,
        name="PaymentGatewayAPI",
        trust_zone="internal",
        properties=ComponentProperties(
            authentication_required=False,
            authorization_enforced=False,
            internet_facing=True,
            custom={"rate_limiting_enabled": False, "audit_logging_enabled": False},
        ),
    )
    db = Component(
        model_version_id=vid1,
        component_type=ComponentType.DATA_STORE,
        name="CustomerCardsDB",
        trust_zone="internal",
        properties=ComponentProperties(
            stores_pii=True,
            encrypted_at_rest=False,
            allows_anonymous_access=True,
        ),
    )
    flow1 = DataFlow(
        model_version_id=vid1,
        source_component_id=ext.id,
        target_component_id=api.id,
        crosses_trust_boundary=True,
        properties=DataFlowProperties(encrypted=False, data_classification=DataClassification.PII),
    )
    flow2 = DataFlow(
        model_version_id=vid1,
        source_component_id=api.id,
        target_component_id=db.id,
        crosses_trust_boundary=False,
        properties=DataFlowProperties(encrypted=False),
    )
    ctx1 = ModelContext(
        model_version_id=vid1,
        components={ext.id: ext, api.id: api, db.id: db},
        data_flows=[flow1, flow2],
    )

    save_res = client.post(
        f"/api/v1/models/{model_id}/versions",
        json=ctx1.model_dump(mode="json"),
    )
    assert save_res.status_code == 201

    # 3. Run Analysis on Version 1
    analysis_res = client.post(f"/api/v1/analysis/version/{vid1}")
    assert analysis_res.status_code == 200
    analysis = analysis_res.json()
    assert analysis["applicable_count"] >= 3
    assert len(analysis["threats"]) >= 3

    first_threat = analysis["threats"][0]
    threat_id = first_threat["threat_id"]

    # 4. Fetch Threat Provenance Graph
    prov_res = client.get(f"/api/v1/threats/{threat_id}/provenance")
    assert prov_res.status_code == 200
    prov_graph = prov_res.json()
    assert prov_graph["node_count"] >= 2
    assert prov_graph["edge_count"] >= 1

    # 5. Review the Threat (Test validation: reject blank rationale)
    invalid_review = client.post(f"/api/v1/threats/{threat_id}/review", json={
        "decision": "APPROVED",
        "reviewer_id": "eng-1",
        "reviewer_name": "Bob",
        "rationale": "ok",  # too short (< 5 chars)
    })
    assert invalid_review.status_code == 422  # validation error

    valid_review = client.post(f"/api/v1/threats/{threat_id}/review", json={
        "decision": "APPROVED",
        "reviewer_id": "eng-1",
        "reviewer_name": "Bob Senior Architect",
        "rationale": "High-risk unauthenticated flow confirmed across DMZ boundary. Remediation prioritized.",
    })
    assert valid_review.status_code == 200
    assert valid_review.json()["decision"] == "APPROVED"

    # 6. List Compiled Mitigations
    mits_res = client.get(f"/api/v1/threats/{threat_id}/mitigations")
    assert mits_res.status_code == 200
    mits = mits_res.json()
    assert len(mits) >= 1
    first_mit = mits[0]
    mit_id = first_mit["id"]
    test_cases = first_mit["test_cases"]
    assert len(test_cases) >= 1
    first_tc = test_cases[0]

    # 7. Execute All Test Cases in the Mitigation
    for tc in test_cases:
        tc_res = client.post(
            f"/api/v1/mitigations/{mit_id}/tests/{tc['id']}/execute",
            json={
                "status": "PASSED",
                "actual_result": "Passed security check as expected",
                "execution_notes": "Automated security integration test suite passed",
            },
        )
        assert tc_res.status_code == 200

    # 8. Submit Evidence to Promote Status
    ev_res = client.post(
        f"/api/v1/mitigations/{mit_id}/evidence",
        json={
            "evidence_type": "ci_pipeline",
            "summary": "Verified in automated GitHub Actions security gate",
            "commit_sha": "f4b23c91",
            "environment": "staging",
            "recorded_by": "CI System",
        },
    )
    assert ev_res.status_code == 200
    assert ev_res.json()["status"] in ("IMPLEMENTED", "VERIFIED")

    # 9. Verify Append-Only Audit Trail
    audit_res = client.get("/api/v1/audit/events")
    assert audit_res.status_code == 200
    events = audit_res.json()
    assert len(events) >= 3

    # 10. Save Version 2 (Secured: TLS, Auth, Authz enabled) and Run Drift Comparison
    vid2 = make_id()
    api_v2 = Component(
        model_version_id=vid2,
        component_type=ComponentType.PROCESS,
        name="PaymentGatewayAPI",
        trust_zone="internal",
        properties=ComponentProperties(
            authentication_required=True,
            auth_mechanism="JWT",
            authorization_enforced=True,
            internet_facing=True,
            custom={"rate_limiting_enabled": True, "audit_logging_enabled": True},
        ),
    )
    db_v2 = Component(
        model_version_id=vid2,
        component_type=ComponentType.DATA_STORE,
        name="CustomerCardsDB",
        trust_zone="internal",
        properties=ComponentProperties(
            stores_pii=True,
            encrypted_at_rest=True,
            allows_anonymous_access=False,
        ),
    )
    flow1_v2 = DataFlow(
        model_version_id=vid2,
        source_component_id=ext.id,
        target_component_id=api_v2.id,
        crosses_trust_boundary=True,
        properties=DataFlowProperties(encrypted=True, data_classification=DataClassification.PII),
    )
    flow2_v2 = DataFlow(
        model_version_id=vid2,
        source_component_id=api_v2.id,
        target_component_id=db_v2.id,
        crosses_trust_boundary=False,
        properties=DataFlowProperties(encrypted=True),
    )
    ctx2 = ModelContext(
        model_version_id=vid2,
        components={ext.id: ext, api_v2.id: api_v2, db_v2.id: db_v2},
        data_flows=[flow1_v2, flow2_v2],
    )
    client.post(f"/api/v1/models/{model_id}/versions", json=ctx2.model_dump(mode="json"))

    drift_res = client.post("/api/v1/drift/compare", json={
        "baseline_version_id": str(vid1),
        "current_version_id": str(vid2),
    })
    assert drift_res.status_code == 200
    drift = drift_res.json()
    assert drift["security_relevance_score"] >= 0.0
    assert len(drift["invalidated_threats"]) >= 1  # Insecure threats became invalidated!

    # 11. Test Attack Paths Analysis
    paths_res = client.get(f"/api/v1/paths/version/{vid1}")
    assert paths_res.status_code == 200
    paths = paths_res.json()
    assert len(paths) >= 1
    assert paths[0]["entry_point_name"] == "Public User"
    assert paths[0]["target_asset_name"] == "CustomerCardsDB"
