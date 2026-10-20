from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from uuid import UUID, uuid4

from app.domain.models.core import Applicability, Component, DataFlow, ModelContext
from app.domain.rules.base import RuleEngine


class SecurityRelevance(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    NONE = "NONE"


@dataclass
class AttributeDelta:
    attribute_name: str
    old_value: Any
    new_value: Any
    security_relevance: SecurityRelevance
    rationale: str


@dataclass
class SecurityChange:
    change_type: str  # ADDED | REMOVED | MODIFIED | NEW_BOUNDARY_CROSSING
    entity_type: str  # component | flow | trust_boundary
    entity_id: str
    entity_name: str
    security_relevance: SecurityRelevance
    threat_impact: str
    requires_review: bool
    attribute_deltas: list[AttributeDelta] = field(default_factory=list)
    newly_applicable_rule_ids: list[str] = field(default_factory=list)


@dataclass
class DriftReport:
    id: UUID = field(default_factory=uuid4)
    baseline_version_id: UUID | None = None
    current_version_id: UUID | None = None
    added_components: list[dict[str, Any]] = field(default_factory=list)
    removed_components: list[dict[str, Any]] = field(default_factory=list)
    modified_components: list[dict[str, Any]] = field(default_factory=list)
    added_flows: list[dict[str, Any]] = field(default_factory=list)
    removed_flows: list[dict[str, Any]] = field(default_factory=list)
    modified_flows: list[dict[str, Any]] = field(default_factory=list)
    new_boundary_crossings: list[dict[str, Any]] = field(default_factory=list)
    changes: list[SecurityChange] = field(default_factory=list)
    security_relevance_score: float = 0.0  # 0.0 - 1.0
    requires_review: bool = False
    newly_applicable_threats: list[dict[str, Any]] = field(default_factory=list)
    invalidated_threats: list[dict[str, Any]] = field(default_factory=list)


_CRITICAL_SECURITY_ATTRIBUTES = {
    "authentication_required": (
        "Authentication requirement changed or disabled",
        SecurityRelevance.HIGH,
    ),
    "authorization_enforced": (
        "Server-side authorization enforcement changed or disabled",
        SecurityRelevance.HIGH,
    ),
    "encrypted_at_rest": (
        "Data at rest encryption state changed",
        SecurityRelevance.HIGH,
    ),
    "allows_anonymous_access": (
        "Anonymous access policy changed",
        SecurityRelevance.HIGH,
    ),
    "stores_pii": (
        "Component PII storage classification altered",
        SecurityRelevance.HIGH,
    ),
    "stores_credentials": (
        "Component credential storage posture altered",
        SecurityRelevance.HIGH,
    ),
    "has_human_in_the_loop": (
        "Human-in-the-loop oversight removed or modified",
        SecurityRelevance.HIGH,
    ),
    "tool_permissions": (
        "Tool permission scope expanded or altered",
        SecurityRelevance.HIGH,
    ),
    "trust_zone": (
        "Component trust zone boundary relocated",
        SecurityRelevance.HIGH,
    ),
    "accepts_untrusted_input": (
        "Component untrusted input acceptance status changed",
        SecurityRelevance.HIGH,
    ),
}

_FLOW_SECURITY_ATTRIBUTES = {
    "encrypted": (
        "Data flow encryption in transit altered",
        SecurityRelevance.HIGH,
    ),
    "crosses_trust_boundary": (
        "Flow trust boundary crossing changed",
        SecurityRelevance.HIGH,
    ),
    "carries_credentials": (
        "Flow credentials transmission posture altered",
        SecurityRelevance.HIGH,
    ),
    "carries_pii": (
        "Flow PII transmission posture altered",
        SecurityRelevance.HIGH,
    ),
    "data_classification": (
        "Data classification sensitivity upgraded/downgraded",
        SecurityRelevance.MEDIUM,
    ),
    "protocol": (
        "Communication protocol changed",
        SecurityRelevance.MEDIUM,
    ),
}


def _assess_component_attribute_deltas(
    old_comp: Component, new_comp: Component
) -> list[AttributeDelta]:
    deltas: list[AttributeDelta] = []

    # Check trust zone
    if old_comp.trust_zone != new_comp.trust_zone:
        deltas.append(
            AttributeDelta(
                attribute_name="trust_zone",
                old_value=old_comp.trust_zone,
                new_value=new_comp.trust_zone,
                security_relevance=SecurityRelevance.HIGH,
                rationale="Component moved to different trust zone",
            )
        )

    old_props = old_comp.properties.model_dump()
    new_props = new_comp.properties.model_dump()

    for key, (rationale, relevance) in _CRITICAL_SECURITY_ATTRIBUTES.items():
        if key == "trust_zone":
            continue
        old_val = old_props.get(key)
        new_val = new_props.get(key)
        if old_val != new_val:
            deltas.append(
                AttributeDelta(
                    attribute_name=key,
                    old_value=old_val,
                    new_value=new_val,
                    security_relevance=relevance,
                    rationale=rationale,
                )
            )

    return deltas


def _assess_flow_attribute_deltas(
    old_flow: DataFlow, new_flow: DataFlow
) -> list[AttributeDelta]:
    deltas: list[AttributeDelta] = []
    old_props = old_flow.properties.model_dump()
    new_props = new_flow.properties.model_dump()

    if old_flow.crosses_trust_boundary != new_flow.crosses_trust_boundary:
        deltas.append(
            AttributeDelta(
                attribute_name="crosses_trust_boundary",
                old_value=old_flow.crosses_trust_boundary,
                new_value=new_flow.crosses_trust_boundary,
                security_relevance=SecurityRelevance.HIGH,
                rationale="Flow trust boundary crossing changed",
            )
        )

    for key, (rationale, relevance) in _FLOW_SECURITY_ATTRIBUTES.items():
        if key == "crosses_trust_boundary":
            continue
        old_val = old_props.get(key)
        new_val = new_props.get(key)
        if old_val != new_val:
            deltas.append(
                AttributeDelta(
                    attribute_name=key,
                    old_value=old_val,
                    new_value=new_val,
                    security_relevance=relevance,
                    rationale=rationale,
                )
            )

    return deltas


def semantic_drift_analysis(
    baseline: ModelContext,
    current: ModelContext,
    rule_engine: RuleEngine | None = None,
) -> DriftReport:
    """
    Performs full semantic architecture drift analysis between baseline and current versions.

    Computes:
    - Added, removed, modified components with attribute-level diff
    - Added, removed, modified flows
    - New trust boundary crossings
    - Security relevance scoring and review requirement
    - Newly applicable threats vs invalidated threats
    """
    report = DriftReport(
        baseline_version_id=baseline.model_version_id,
        current_version_id=current.model_version_id,
    )

    baseline_comp_map = baseline.components
    current_comp_map = current.components

    baseline_comp_ids = set(baseline_comp_map.keys())
    current_comp_ids = set(current_comp_map.keys())

    # 1. Structural Component Diff
    added_ids = current_comp_ids - baseline_comp_ids
    removed_ids = baseline_comp_ids - current_comp_ids
    common_ids = current_comp_ids & baseline_comp_ids

    high_relevance_count = 0
    total_change_count = 0

    for cid in added_ids:
        comp = current_comp_map[cid]
        report.added_components.append(comp.model_dump())
        change = SecurityChange(
            change_type="ADDED",
            entity_type="component",
            entity_id=str(cid),
            entity_name=comp.name,
            security_relevance=SecurityRelevance.HIGH,
            threat_impact=f"New component '{comp.name}' ({comp.component_type.value}) introduced into architecture",
            requires_review=True,
        )
        report.changes.append(change)
        high_relevance_count += 1
        total_change_count += 1

    for cid in removed_ids:
        comp = baseline_comp_map[cid]
        report.removed_components.append(comp.model_dump())
        change = SecurityChange(
            change_type="REMOVED",
            entity_type="component",
            entity_id=str(cid),
            entity_name=comp.name,
            security_relevance=SecurityRelevance.MEDIUM,
            threat_impact=f"Component '{comp.name}' removed; existing associated threats may be invalidated",
            requires_review=False,
        )
        report.changes.append(change)
        total_change_count += 1

    # 2. Semantic (Attribute) Component Diff
    for cid in common_ids:
        old_comp = baseline_comp_map[cid]
        new_comp = current_comp_map[cid]
        deltas = _assess_component_attribute_deltas(old_comp, new_comp)
        if deltas:
            max_rel = (
                SecurityRelevance.HIGH
                if any(d.security_relevance == SecurityRelevance.HIGH for d in deltas)
                else SecurityRelevance.MEDIUM
            )
            report.modified_components.append({
                "component_id": str(cid),
                "name": new_comp.name,
                "deltas": [
                    {
                        "attribute": d.attribute_name,
                        "old": d.old_value,
                        "new": d.new_value,
                        "relevance": d.security_relevance.value,
                        "rationale": d.rationale,
                    }
                    for d in deltas
                ],
            })
            change = SecurityChange(
                change_type="MODIFIED",
                entity_type="component",
                entity_id=str(cid),
                entity_name=new_comp.name,
                security_relevance=max_rel,
                threat_impact=f"Security-relevant attributes modified on '{new_comp.name}'",
                requires_review=(max_rel == SecurityRelevance.HIGH),
                attribute_deltas=deltas,
            )
            report.changes.append(change)
            if max_rel == SecurityRelevance.HIGH:
                high_relevance_count += 1
            total_change_count += 1

    # 3. Data Flow Diff
    baseline_flow_map = {f.id: f for f in baseline.data_flows}
    current_flow_map = {f.id: f for f in current.data_flows}

    baseline_flow_ids = set(baseline_flow_map.keys())
    current_flow_ids = set(current_flow_map.keys())

    added_flow_ids = current_flow_ids - baseline_flow_ids
    removed_flow_ids = baseline_flow_ids - current_flow_ids
    common_flow_ids = current_flow_ids & baseline_flow_ids

    for fid in added_flow_ids:
        flow = current_flow_map[fid]
        report.added_flows.append(flow.model_dump())
        is_boundary = flow.crosses_trust_boundary
        rel = SecurityRelevance.HIGH if is_boundary else SecurityRelevance.MEDIUM
        change = SecurityChange(
            change_type="ADDED",
            entity_type="flow",
            entity_id=str(fid),
            entity_name=flow.name or f"Flow {str(fid)[:8]}",
            security_relevance=rel,
            threat_impact=(
                "New cross-boundary data flow added"
                if is_boundary
                else "New data flow added"
            ),
            requires_review=is_boundary,
        )
        report.changes.append(change)
        if rel == SecurityRelevance.HIGH:
            high_relevance_count += 1
        total_change_count += 1

    for fid in removed_flow_ids:
        flow = baseline_flow_map[fid]
        report.removed_flows.append(flow.model_dump())
        total_change_count += 1

    for fid in common_flow_ids:
        old_flow = baseline_flow_map[fid]
        new_flow = current_flow_map[fid]
        deltas = _assess_flow_attribute_deltas(old_flow, new_flow)
        if deltas:
            max_rel = (
                SecurityRelevance.HIGH
                if any(d.security_relevance == SecurityRelevance.HIGH for d in deltas)
                else SecurityRelevance.MEDIUM
            )
            report.modified_flows.append({
                "flow_id": str(fid),
                "name": new_flow.name,
                "deltas": [
                    {
                        "attribute": d.attribute_name,
                        "old": d.old_value,
                        "new": d.new_value,
                        "relevance": d.security_relevance.value,
                        "rationale": d.rationale,
                    }
                    for d in deltas
                ],
            })
            change = SecurityChange(
                change_type="MODIFIED",
                entity_type="flow",
                entity_id=str(fid),
                entity_name=new_flow.name or f"Flow {str(fid)[:8]}",
                security_relevance=max_rel,
                threat_impact="Data flow security properties altered",
                requires_review=(max_rel == SecurityRelevance.HIGH),
                attribute_deltas=deltas,
            )
            report.changes.append(change)
            if max_rel == SecurityRelevance.HIGH:
                high_relevance_count += 1
            total_change_count += 1

    # 4. Trust Boundary Crossing Diff
    baseline_crossings = {
        (f.source_component_id, f.target_component_id)
        for f in baseline.data_flows
        if f.crosses_trust_boundary
    }
    current_crossings = {
        (f.source_component_id, f.target_component_id)
        for f in current.data_flows
        if f.crosses_trust_boundary
    }
    new_crossings = current_crossings - baseline_crossings

    for src_id, tgt_id in new_crossings:
        matching_flows = [
            f for f in current.data_flows
            if f.source_component_id == src_id
            and f.target_component_id == tgt_id
            and f.crosses_trust_boundary
        ]
        for mf in matching_flows:
            report.new_boundary_crossings.append(mf.model_dump())
            change = SecurityChange(
                change_type="NEW_BOUNDARY_CROSSING",
                entity_type="flow",
                entity_id=str(mf.id),
                entity_name=mf.name or f"Flow {str(mf.id)[:8]}",
                security_relevance=SecurityRelevance.HIGH,
                threat_impact="New data flow establishes communication across distinct trust zones",
                requires_review=True,
            )
            report.changes.append(change)
            high_relevance_count += 1
            total_change_count += 1

    # Compute Security Relevance Score (0.0 - 1.0)
    if total_change_count == 0:
        report.security_relevance_score = 0.0
        report.requires_review = False
    else:
        # High relevance changes weighted heavily
        weighted_score = (high_relevance_count * 1.0 + (total_change_count - high_relevance_count) * 0.3) / total_change_count
        report.security_relevance_score = round(min(1.0, weighted_score), 2)
        report.requires_review = (high_relevance_count > 0)

    # 5. Threat Re-evaluation (if rule engine provided)
    if rule_engine is not None:
        baseline_results = rule_engine.analyze_model(baseline)
        current_results = rule_engine.analyze_model(current)

        baseline_threat_keys = {
            (c.id, r.rule_id)
            for c, r, res in baseline_results
            if res.applicability == Applicability.APPLICABLE
        }
        current_threat_keys = {
            (c.id, r.rule_id)
            for c, r, res in current_results
            if res.applicability == Applicability.APPLICABLE
        }

        newly_applicable = current_threat_keys - baseline_threat_keys
        invalidated = baseline_threat_keys - current_threat_keys

        for cid, rid in newly_applicable:
            matching = [
                (c, r, res) for c, r, res in current_results
                if c.id == cid and r.rule_id == rid
            ]
            if matching:
                c, r, res = matching[0]
                report.newly_applicable_threats.append({
                    "component_id": str(cid),
                    "component_name": c.name,
                    "rule_id": rid,
                    "title": res.title,
                    "description": res.description,
                    "confidence": res.confidence.value,
                })

        for cid, rid in invalidated:
            matching = [
                (c, r, res) for c, r, res in baseline_results
                if c.id == cid and r.rule_id == rid
            ]
            if matching:
                c, r, res = matching[0]
                report.invalidated_threats.append({
                    "component_id": str(cid),
                    "component_name": c.name,
                    "rule_id": rid,
                    "title": res.title,
                })

    return report
