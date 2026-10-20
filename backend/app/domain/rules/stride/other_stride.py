from __future__ import annotations
from app.domain.models.core import (
    Applicability, ArchitectureFact, Component, ComponentType, Confidence,
    DataClassification, MitigationTemplate, ModelContext, RuleResult, STRIDECategory, ThreatMethodology,
)
from app.domain.rules.base import ThreatRule, register_rule

_ENCRYPT_MITIGATION = MitigationTemplate(
    template_id="MIT-ENC-001",
    title="Enforce encryption in transit (TLS 1.2+ / mTLS)",
    description="All data flows crossing trust boundaries must use TLS 1.2 or higher.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "TLS version is 1.2 or higher on all cross-boundary connections",
        "Certificate validation is not bypassed",
        "Plaintext connections are rejected",
    ],
)

_AUDIT_MITIGATION = MitigationTemplate(
    template_id="MIT-AUD-001",
    title="Implement tamper-resistant audit logging for sensitive operations",
    description="Log all sensitive operations with actor identity, timestamp, and action details.",
    control_type="DETECTIVE",
    verification_criteria=[
        "All sensitive operations produce log entries",
        "Logs cannot be modified or deleted by application-level users",
        "Logs are retained for a defined period",
    ],
)

_DATA_PROTECT_MITIGATION = MitigationTemplate(
    template_id="MIT-DATA-001",
    title="Encrypt sensitive data at rest and in transit",
    description="Apply encryption at rest (AES-256) for sensitive data stores.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Sensitive data stores use encryption at rest",
        "Encryption keys are managed via a secrets manager",
    ],
)

_RATE_LIMIT_MITIGATION = MitigationTemplate(
    template_id="MIT-DOS-001",
    title="Implement rate limiting and request throttling",
    description="Apply rate limiting at the API gateway and service level.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Excessive requests from a single source receive HTTP 429",
        "Rate limits are applied before expensive operations",
    ],
)

_AUTHZ_MITIGATION = MitigationTemplate(
    template_id="MIT-AUTHZ-001",
    title="Enforce server-side authorization on all sensitive operations",
    description="Deny by default. Require explicit permission grants. Never rely on client-side enforcement.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Lower-privileged identities receive HTTP 403 on privileged resources",
        "Authorization is evaluated server-side on every request",
        "Privilege decisions are logged",
    ],
)


@register_rule
class TamperingUnencryptedCrossBoundaryFlowRule(ThreatRule):
    rule_id = "STRIDE-T-001"
    rule_version = "1.0.0"
    category = STRIDECategory.TAMPERING
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.PROCESS, ComponentType.DATA_STORE, ComponentType.LLM_PROVIDER, ComponentType.AGENT]
    description = "Detects unencrypted data flows crossing trust boundaries."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        cross_boundary_flows = context.get_flows_crossing_boundary_to(component.id)
        if not cross_boundary_flows:
            return self._not_applicable(reason=f"No cross-boundary inflows to {component.name!r}.")
        unencrypted_flows = [f for f in cross_boundary_flows if f.properties.encrypted is False]
        unknown_flows = [f for f in cross_boundary_flows if f.properties.encrypted is None]
        if unknown_flows:
            return self._needs_review(
                missing_facts=[f"encrypted property not set on {len(unknown_flows)} flow(s) entering {component.name!r}"],
                title=f"STRIDE-T-001 needs review -- encryption status unknown on flows to {component.name!r}",
                description="Cannot determine tampering risk without knowing encryption status.",
            )
        if unencrypted_flows:
            sensitive_flows = [f for f in unencrypted_flows if f.properties.data_classification in (
                DataClassification.CONFIDENTIAL, DataClassification.RESTRICTED,
                DataClassification.PII, DataClassification.CREDENTIALS,
            )]
            confidence = Confidence.HIGH if sensitive_flows else Confidence.MEDIUM
            return self._applicable(
                title=f"Tampering -- unencrypted flow(s) to {component.name!r} across trust boundary",
                description=f"{len(unencrypted_flows)} flow(s) entering {component.name!r} cross a trust boundary without encryption.",
                confidence=confidence,
                prerequisites_met=[f"{len(unencrypted_flows)} unencrypted cross-boundary inflow(s) confirmed"],
                architecture_facts=[ArchitectureFact(
                    fact_type="unencrypted_cross_boundary_flow",
                    description=f"Flow is unencrypted across boundary to {component.name!r}",
                    component_id=component.id, flow_id=f.id, attribute="encrypted", value=False,
                ) for f in unencrypted_flows],
                assumptions=["An adversary in the network path could intercept and modify traffic"],
                mitigation_templates=[_ENCRYPT_MITIGATION],
                verification_criteria=["All cross-boundary connections use TLS 1.2 or higher"],
            )
        return self._not_applicable(reason=f"All cross-boundary flows to {component.name!r} are encrypted.")


@register_rule
class RepudiationMissingAuditLogRule(ThreatRule):
    rule_id = "STRIDE-R-001"
    rule_version = "1.0.0"
    category = STRIDECategory.REPUDIATION
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.PROCESS, ComponentType.DATA_STORE, ComponentType.AGENT]
    description = "Detects components performing sensitive operations without audit logging."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        stores_sensitive = context.component_has_sensitive_data(component.id)
        is_internet_facing = component.properties.internet_facing
        audit_logging = component.properties.custom.get("audit_logging_enabled")
        is_target = is_internet_facing or stores_sensitive
        if is_target is None and audit_logging is None:
            return self._needs_review(missing_facts=[
                f"internet_facing not set on {component.name!r}",
                f"stores_pii / stores_credentials not set on {component.name!r}",
                f"audit_logging_enabled not set in custom properties of {component.name!r}",
            ])
        if not is_target:
            return self._not_applicable(reason=f"{component.name!r} is neither internet-facing nor stores sensitive data.")
        if audit_logging is False:
            return self._applicable(
                title=f"Repudiation -- audit logging disabled on {component.name!r}",
                description=f"Component {component.name!r} handles sensitive data but audit_logging_enabled is False.",
                confidence=Confidence.HIGH,
                prerequisites_met=["Component is internet-facing or stores sensitive data", "audit_logging_enabled is False"],
                architecture_facts=[ArchitectureFact(
                    fact_type="missing_control", description="Audit logging is disabled",
                    component_id=component.id, attribute="audit_logging_enabled", value=False,
                )],
                mitigation_templates=[_AUDIT_MITIGATION],
                verification_criteria=["All sensitive operations produce log entries with actor identity, timestamp, action"],
            )
        if audit_logging is None:
            return self._needs_review(missing_facts=[f"audit_logging_enabled not declared on {component.name!r}."])
        return self._not_applicable(reason=f"Audit logging is enabled on {component.name!r}.")


@register_rule
class InfoDisclosureSensitiveDataNotEncryptedAtRestRule(ThreatRule):
    rule_id = "STRIDE-ID-001"
    rule_version = "1.0.0"
    category = STRIDECategory.INFORMATION_DISCLOSURE
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.DATA_STORE, ComponentType.VECTOR_STORE]
    description = "Detects sensitive data stores that lack encryption at rest."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        stores_sensitive = context.component_has_sensitive_data(component.id)
        encrypted_at_rest = component.properties.encrypted_at_rest
        if stores_sensitive is None:
            return self._needs_review(missing_facts=[f"stores_pii and stores_credentials not declared on {component.name!r}"])
        if not stores_sensitive:
            return self._not_applicable(reason=f"{component.name!r} does not store sensitive data.")
        if encrypted_at_rest is None:
            return self._needs_review(missing_facts=[f"encrypted_at_rest not declared on {component.name!r}."])
        if not encrypted_at_rest:
            return self._applicable(
                title=f"Information Disclosure -- {component.name!r} stores sensitive data without encryption at rest",
                description=f"Data store {component.name!r} holds sensitive data but is not encrypted at rest.",
                confidence=Confidence.HIGH,
                prerequisites_met=["Component stores PII or credentials", "encrypted_at_rest is False"],
                architecture_facts=[ArchitectureFact(
                    fact_type="missing_control", description="Sensitive data store lacks encryption at rest",
                    component_id=component.id, attribute="encrypted_at_rest", value=False,
                )],
                mitigation_templates=[_DATA_PROTECT_MITIGATION],
                verification_criteria=["Encryption at rest is enabled using AES-256 or equivalent"],
            )
        return self._not_applicable(reason=f"{component.name!r} stores sensitive data and has encryption at rest enabled.")


@register_rule
class DenialOfServiceInternetFacingNoRateLimitRule(ThreatRule):
    rule_id = "STRIDE-DoS-001"
    rule_version = "1.0.0"
    category = STRIDECategory.DENIAL_OF_SERVICE
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.PROCESS, ComponentType.LLM_PROVIDER, ComponentType.RAG_PIPELINE]
    description = "Detects internet-facing components without rate limiting."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        is_internet_facing = component.properties.internet_facing
        rate_limited = component.properties.custom.get("rate_limiting_enabled")
        if is_internet_facing is None:
            return self._needs_review(missing_facts=[f"internet_facing not declared on {component.name!r}"])
        if not is_internet_facing:
            return self._not_applicable(reason=f"{component.name!r} is not internet-facing.")
        if rate_limited is None:
            return self._needs_review(missing_facts=[f"rate_limiting_enabled not declared in custom properties of {component.name!r}"])
        if not rate_limited:
            return self._applicable(
                title=f"Denial of Service -- internet-facing {component.name!r} has no rate limiting",
                description=f"Component {component.name!r} is internet-facing but lacks rate limiting.",
                confidence=Confidence.HIGH,
                prerequisites_met=["internet_facing is True", "rate_limiting_enabled is False"],
                architecture_facts=[ArchitectureFact(
                    fact_type="missing_control", description="Internet-facing component without rate limiting",
                    component_id=component.id, attribute="rate_limiting_enabled", value=False,
                )],
                mitigation_templates=[_RATE_LIMIT_MITIGATION],
                verification_criteria=["Requests exceeding threshold receive HTTP 429"],
            )
        return self._not_applicable(reason=f"{component.name!r} is internet-facing and has rate limiting enabled.")


@register_rule
class ElevationOfPrivilegeMissingAuthorizationRule(ThreatRule):
    rule_id = "STRIDE-EoP-001"
    rule_version = "1.0.0"
    category = STRIDECategory.ELEVATION_OF_PRIVILEGE
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.PROCESS, ComponentType.DATA_STORE, ComponentType.AGENT]
    description = "Detects missing authorization enforcement on components reachable from lower-trust zones."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        cross_boundary_flows = context.get_flows_crossing_boundary_to(component.id)
        if not cross_boundary_flows:
            return self._not_applicable(reason=f"No cross-boundary inflows to {component.name!r}.")
        authz_enforced = component.properties.authorization_enforced
        if authz_enforced is None:
            return self._needs_review(missing_facts=[f"authorization_enforced not declared on {component.name!r}."])
        if not authz_enforced:
            stores_sensitive = context.component_has_sensitive_data(component.id)
            confidence = Confidence.HIGH if stores_sensitive else Confidence.MEDIUM
            return self._applicable(
                title=f"Elevation of Privilege -- {component.name!r} lacks authorization enforcement",
                description=(
                    f"Component {component.name!r} is reachable across trust boundaries "
                    f"({len(cross_boundary_flows)} flow(s)) but does not enforce server-side authorization."
                ),
                confidence=confidence,
                prerequisites_met=[
                    f"{len(cross_boundary_flows)} cross-boundary inflow(s) confirmed",
                    "authorization_enforced is False",
                ],
                architecture_facts=[
                    ArchitectureFact(
                        fact_type="missing_control", description="Authorization enforcement not declared",
                        component_id=component.id, attribute="authorization_enforced", value=False,
                    )
                ] + [ArchitectureFact(
                    fact_type="cross_boundary_flow",
                    description=f"Flow {f.name or str(f.id)!r} enters from lower-trust zone",
                    component_id=component.id, flow_id=f.id,
                ) for f in cross_boundary_flows],
                assumptions=["Lower-privileged identities can reach this component via the cross-boundary flows"],
                mitigation_templates=[_AUTHZ_MITIGATION],
                verification_criteria=[
                    f"Lower-privileged identity cannot access sensitive resources in {component.name!r}",
                    "HTTP 403 is returned for unauthorized access attempts",
                ],
            )
        return self._not_applicable(reason=f"{component.name!r} enforces server-side authorization.")


@register_rule
class ElevationOfPrivilegeOverPrivilegedAgentRule(ThreatRule):
    rule_id = "STRIDE-EoP-002"
    rule_version = "1.0.0"
    category = STRIDECategory.ELEVATION_OF_PRIVILEGE
    methodology = ThreatMethodology.STRIDE
    applies_to = [ComponentType.AGENT]
    description = "Detects AI agents with excessive tool permissions."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        tool_permissions = component.properties.tool_permissions
        if tool_permissions is None:
            return self._needs_review(missing_facts=[f"tool_permissions not declared on agent {component.name!r}."])
        HIGH_RISK = {"admin", "write_all", "delete", "execute_code", "send_email", "create_user"}
        risky_perms = [p for p in tool_permissions if any(r in p.lower() for r in HIGH_RISK)]
        if not risky_perms:
            return self._not_applicable(reason=f"Agent {component.name!r} holds only scoped, low-risk permissions.")
        has_hitl = component.properties.has_human_in_the_loop
        if has_hitl is None:
            confidence, assumptions = Confidence.MEDIUM, ["Human-in-the-loop status unknown -- assume absent"]
        elif has_hitl:
            confidence, assumptions = Confidence.LOW, ["Human-in-the-loop is present -- reduces but does not eliminate risk"]
        else:
            confidence, assumptions = Confidence.HIGH, []
        return self._applicable(
            title=f"Elevation of Privilege -- agent {component.name!r} has high-risk permissions without least privilege",
            description=f"Agent {component.name!r} holds permissions that could cause significant harm if manipulated: {risky_perms}.",
            confidence=confidence,
            prerequisites_met=[f"High-risk permissions found: {risky_perms}"],
            assumptions=assumptions,
            architecture_facts=[ArchitectureFact(
                fact_type="excessive_permissions", description=f"Agent holds high-risk permissions: {risky_perms}",
                component_id=component.id, attribute="tool_permissions", value=risky_perms,
            )],
            mitigation_templates=[MitigationTemplate(
                template_id="MIT-AGENT-001",
                title="Apply principle of least privilege to agent tool permissions",
                description="Replace broad permissions with scoped, single-purpose tools. Require HITL for irreversible actions.",
                control_type="PREVENTIVE",
                verification_criteria=[
                    "Agent cannot perform operations outside its defined task scope",
                    "Irreversible actions require explicit human approval",
                    "All tool calls are logged",
                ],
            )],
            verification_criteria=[f"Agent {component.name!r} cannot perform delete/write operations without approval"],
        )
