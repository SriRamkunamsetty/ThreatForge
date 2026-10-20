from __future__ import annotations

import uuid
import pytest

from app.domain.graph.builder import ArchitectureGraph
from app.domain.graph.diff import SecurityRelevance, semantic_drift_analysis
from app.domain.graph.paths import AttackPathAnalyzer
from app.domain.models.core import (
    Component,
    ComponentProperties,
    ComponentType,
    DataClassification,
    DataFlow,
    DataFlowProperties,
    ModelContext,
)
from app.domain.rules import RuleEngine


def make_id():
    return uuid.uuid4()


def test_architecture_graph_builder_and_traversal():
    vid = make_id()
    ext = Component(
        model_version_id=vid,
        component_type=ComponentType.EXTERNAL_ENTITY,
        name="User Browser",
        trust_zone="internet",
    )
    api = Component(
        model_version_id=vid,
        component_type=ComponentType.PROCESS,
        name="API Gateway",
        trust_zone="dmz",
        properties=ComponentProperties(internet_facing=True),
    )
    db = Component(
        model_version_id=vid,
        component_type=ComponentType.DATA_STORE,
        name="Customer DB",
        trust_zone="internal",
        properties=ComponentProperties(stores_pii=True, encrypted_at_rest=False),
    )

    flow1 = DataFlow(
        model_version_id=vid,
        source_component_id=ext.id,
        target_component_id=api.id,
        name="HTTPS Request",
        crosses_trust_boundary=True,
    )
    flow2 = DataFlow(
        model_version_id=vid,
        source_component_id=api.id,
        target_component_id=db.id,
        name="SQL Query",
        crosses_trust_boundary=True,
        properties=DataFlowProperties(encrypted=False),
    )

    ctx = ModelContext(
        model_version_id=vid,
        components={ext.id: ext, api.id: api, db.id: db},
        data_flows=[flow1, flow2],
    )

    arch = ArchitectureGraph(ctx)
    entry_points = arch.get_entry_points()
    assert str(ext.id) in entry_points
    assert str(api.id) in entry_points  # internet_facing=True

    stores = arch.get_sensitive_data_stores()
    assert str(db.id) in stores

    paths = arch.find_paths_from_entry_to_target(str(ext.id), str(db.id))
    assert len(paths) == 1
    assert paths[0] == [str(ext.id), str(api.id), str(db.id)]

    crossings = arch.get_boundary_crossing_edges()
    assert len(crossings) == 2


def test_semantic_drift_analysis_security_attribute_change():
    vid1 = make_id()
    vid2 = make_id()
    comp_id = make_id()
    flow_id = make_id()
    db_id = make_id()

    # Baseline: API has authentication required, flow is encrypted
    api_v1 = Component(
        id=comp_id,
        model_version_id=vid1,
        component_type=ComponentType.PROCESS,
        name="PaymentService",
        trust_zone="internal",
        properties=ComponentProperties(
            authentication_required=True,
            authorization_enforced=True,
        ),
    )
    db_v1 = Component(
        id=db_id,
        model_version_id=vid1,
        component_type=ComponentType.DATA_STORE,
        name="PaymentDB",
        trust_zone="internal",
        properties=ComponentProperties(stores_pii=True, encrypted_at_rest=True),
    )
    flow_v1 = DataFlow(
        id=flow_id,
        model_version_id=vid1,
        source_component_id=comp_id,
        target_component_id=db_id,
        crosses_trust_boundary=False,
        properties=DataFlowProperties(encrypted=True),
    )
    ctx1 = ModelContext(
        model_version_id=vid1,
        components={comp_id: api_v1, db_id: db_v1},
        data_flows=[flow_v1],
    )

    # Current: authentication disabled, encryption removed, new external entity added
    api_v2 = Component(
        id=comp_id,
        model_version_id=vid2,
        component_type=ComponentType.PROCESS,
        name="PaymentService",
        trust_zone="internal",
        properties=ComponentProperties(
            authentication_required=False,  # CRITICAL CHANGE
            authorization_enforced=True,
        ),
    )
    flow_v2 = DataFlow(
        id=flow_id,
        model_version_id=vid2,
        source_component_id=comp_id,
        target_component_id=db_id,
        crosses_trust_boundary=False,
        properties=DataFlowProperties(encrypted=False),  # CRITICAL CHANGE
    )
    attacker = Component(
        model_version_id=vid2,
        component_type=ComponentType.EXTERNAL_ENTITY,
        name="ThirdPartyIntegration",
        trust_zone="external",
    )
    attacker_flow = DataFlow(
        model_version_id=vid2,
        source_component_id=attacker.id,
        target_component_id=comp_id,
        crosses_trust_boundary=True,
    )
    ctx2 = ModelContext(
        model_version_id=vid2,
        components={comp_id: api_v2, db_id: db_v1, attacker.id: attacker},
        data_flows=[flow_v2, attacker_flow],
    )

    engine = RuleEngine()
    report = semantic_drift_analysis(ctx1, ctx2, rule_engine=engine)

    assert report.requires_review is True
    assert report.security_relevance_score > 0.7
    assert len(report.added_components) == 1
    assert len(report.modified_components) == 1
    assert len(report.new_boundary_crossings) == 1

    # Check high relevance delta flagged
    mod_comp = report.modified_components[0]
    auth_delta = next(d for d in mod_comp["deltas"] if d["attribute"] == "authentication_required")
    assert auth_delta["relevance"] == SecurityRelevance.HIGH.value
    assert auth_delta["old"] is True
    assert auth_delta["new"] is False

    # Check threat delta computed
    assert len(report.newly_applicable_threats) > 0


def test_attack_path_analysis():
    vid = make_id()
    ext = Component(
        model_version_id=vid,
        component_type=ComponentType.EXTERNAL_ENTITY,
        name="Internet Client",
        trust_zone="internet",
    )
    waf = Component(
        model_version_id=vid,
        component_type=ComponentType.PROCESS,
        name="WAF",
        trust_zone="dmz",
    )
    backend = Component(
        model_version_id=vid,
        component_type=ComponentType.PROCESS,
        name="Backend API",
        trust_zone="internal",
    )
    db = Component(
        model_version_id=vid,
        component_type=ComponentType.DATA_STORE,
        name="Sensitive Customer DB",
        trust_zone="internal",
        properties=ComponentProperties(stores_pii=True),
    )

    f1 = DataFlow(
        model_version_id=vid,
        source_component_id=ext.id,
        target_component_id=waf.id,
        crosses_trust_boundary=True,
    )
    f2 = DataFlow(
        model_version_id=vid,
        source_component_id=waf.id,
        target_component_id=backend.id,
        crosses_trust_boundary=True,
        properties=DataFlowProperties(encrypted=False),
    )
    f3 = DataFlow(
        model_version_id=vid,
        source_component_id=backend.id,
        target_component_id=db.id,
        crosses_trust_boundary=False,
        properties=DataFlowProperties(encrypted=False),
    )

    ctx = ModelContext(
        model_version_id=vid,
        components={ext.id: ext, waf.id: waf, backend.id: backend, db.id: db},
        data_flows=[f1, f2, f3],
    )

    analyzer = AttackPathAnalyzer(ctx)
    paths = analyzer.analyze_paths()

    assert len(paths) >= 1
    path = paths[0]
    assert path.entry_point_name == "Internet Client"
    assert path.target_asset_name == "Sensitive Customer DB"
    assert path.hop_count == 3
    assert path.boundary_crossings == 2
    assert path.unencrypted_hops == 2
    assert path.risk_score >= 80.0
