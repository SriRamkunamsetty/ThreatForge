from __future__ import annotations
from app.domain.models.core import (
    Applicability, ArchitectureFact, Component, ComponentType, Confidence,
    MitigationTemplate, ModelContext, RuleResult, STRIDECategory, ThreatMethodology,
)
from app.domain.rules.base import ThreatRule, register_rule

_SPOOFING_APPLIES_TO = [
    ComponentType.PROCESS, ComponentType.DATA_STORE, ComponentType.LLM_PROVIDER,
    ComponentType.AGENT, ComponentType.RAG_PIPELINE,
]

_AUTH_MITIGATION = MitigationTemplate(
    template_id="MIT-AUTH-001",
    title="Enforce authentication on all incoming connections",
    description="Require verified identity for all callers using JWT, mTLS, or OAuth2.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Unauthenticated requests receive HTTP 401 Unauthorized",
        "Authentication tokens are validated server-side on every request",
        "Token expiry and revocation are enforced",
    ],
)

_ANON_ACCESS_MITIGATION = MitigationTemplate(
    template_id="MIT-AUTH-002",
    title="Disable anonymous access or document its intent explicitly",
    description="Ensure no sensitive operations are reachable anonymously.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Anonymous identity cannot perform state-changing operations",
        "Anonymous identity cannot access data classified above PUBLIC",
        "Anonymous access is logged and rate-limited",
    ],
)


@register_rule
class SpoofingMissingAuthOnBoundaryRule(ThreatRule):
    rule_id = "STRIDE-S-001"
    rule_version = "1.0.0"
    category = STRIDECategory.SPOOFING
    methodology = ThreatMethodology.STRIDE
    applies_to = _SPOOFING_APPLIES_TO
    description = "Detects missing authentication on data flows crossing trust boundaries."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        cross_boundary_flows = context.get_flows_crossing_boundary_to(component.id)
        if not cross_boundary_flows:
            return self._not_applicable(
                reason=f"Component {component.name!r} receives no cross-boundary flows.",
                facts=[ArchitectureFact(
                    fact_type="no_cross_boundary_inflow",
                    description="No incoming flows cross a trust boundary",
                    component_id=component.id,
                )]
            )
        auth_required = component.properties.authentication_required
        auth_mechanism = component.properties.auth_mechanism
        if auth_required is None and auth_mechanism is None:
            return self._needs_review(
                missing_facts=[
                    f"authentication_required property not set on {component.name!r}",
                    "auth_mechanism property not specified",
                ],
                title=f"STRIDE-S-001 needs review -- missing auth properties on {component.name!r}",
                description=(
                    f"Component {component.name!r} receives {len(cross_boundary_flows)} "
                    "cross-boundary flow(s) but its authentication posture is not declared."
                ),
            )
        no_auth = auth_required is False or auth_mechanism in (None, "NONE", "none")
        if no_auth:
            return self._applicable(
                title=f"Spoofing -- {component.name!r} accepts unauthenticated cross-boundary flows",
                description=(
                    f"Component {component.name!r} receives {len(cross_boundary_flows)} cross-boundary flow(s) "
                    "without requiring authentication. An adversary could forge the identity of any caller."
                ),
                confidence=Confidence.HIGH,
                prerequisites_met=[
                    f"{len(cross_boundary_flows)} cross-boundary inflow(s) confirmed",
                    "authentication_required is False or auth_mechanism is NONE",
                ],
                architecture_facts=[
                    ArchitectureFact(
                        fact_type="cross_boundary_flow",
                        description=f"Flow {f.name or str(f.id)!r} crosses trust boundary to {component.name!r}",
                        component_id=component.id, flow_id=f.id,
                    ) for f in cross_boundary_flows
                ] + [ArchitectureFact(
                    fact_type="missing_attribute",
                    description="Component does not enforce authentication",
                    component_id=component.id, attribute="authentication_required", value=auth_required,
                )],
                mitigation_templates=[_AUTH_MITIGATION],
                verification_criteria=[
                    f"Requests to {component.name!r} without valid credentials receive HTTP 401",
                ],
            )
        return self._not_applicable(
            reason=f"Component {component.name!r} enforces authentication (mechanism: {auth_mechanism}).",
            facts=[ArchitectureFact(
                fact_type="auth_present", description=f"Auth mechanism: {auth_mechanism}",
                component_id=component.id, attribute="auth_mechanism", value=auth_mechanism,
            )]
        )


@register_rule
class SpoofingAnonymousAccessSensitiveRule(ThreatRule):
    rule_id = "STRIDE-S-002"
    rule_version = "1.0.0"
    category = STRIDECategory.SPOOFING
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.PROCESS, ComponentType.DATA_STORE]
    description = "Detects anonymous access to components storing sensitive data."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        allows_anon = component.properties.allows_anonymous_access
        stores_sensitive = context.component_has_sensitive_data(component.id)
        if allows_anon is None and stores_sensitive is None:
            return self._needs_review(missing_facts=[
                f"allows_anonymous_access not set on {component.name!r}",
                f"stores_pii and stores_credentials not set on {component.name!r}",
            ])
        if not allows_anon:
            return self._not_applicable(reason=f"Component {component.name!r} does not allow anonymous access.")
        if stores_sensitive is None:
            return self._needs_review(missing_facts=[
                f"Data sensitivity not declared on {component.name!r}. Set stores_pii or stores_credentials."
            ])
        if allows_anon and stores_sensitive:
            return self._applicable(
                title=f"Spoofing -- anonymous access to sensitive data in {component.name!r}",
                description=f"Component {component.name!r} allows anonymous access while storing sensitive data.",
                confidence=Confidence.HIGH,
                prerequisites_met=["allows_anonymous_access is True", "Component holds PII or credentials"],
                architecture_facts=[ArchitectureFact(
                    fact_type="anonymous_access_to_sensitive_store",
                    description="Anonymous access to component with sensitive data",
                    component_id=component.id, attribute="allows_anonymous_access", value=True,
                )],
                mitigation_templates=[_ANON_ACCESS_MITIGATION],
                verification_criteria=["Anonymous identity cannot read PII or credential data"],
            )
        return self._applicable(
            title=f"Spoofing -- anonymous access to {component.name!r} (non-sensitive)",
            description=f"Component {component.name!r} allows anonymous access but no sensitive data declared.",
            confidence=Confidence.MEDIUM,
            prerequisites_met=["allows_anonymous_access is True"],
            assumptions=["No sensitive data is currently stored (verify this is accurate)"],
            architecture_facts=[ArchitectureFact(
                fact_type="anonymous_access", description="Anonymous access enabled", component_id=component.id,
            )],
            mitigation_templates=[_ANON_ACCESS_MITIGATION],
            verification_criteria=["All access is logged with source identity"],
        )
