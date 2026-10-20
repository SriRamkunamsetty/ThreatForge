# -*- coding: utf-8 -*-
"""
Test suite for the ThreatForge STRIDE Rule Engine
====================================================
These tests validate the applicability engine across three cases:
  - APPLICABLE: threat scenario is credible given the architecture facts
  - NOT_APPLICABLE: rule clearly does not apply
  - NEEDS_REVIEW: insufficient information to make a confident determination

Test design principles:
  1. One test per applicability case per rule (minimum)
  2. Tests are paired: a scenario and its "safe" counterpart
  3. Assertions check applicability, confidence, AND key field presence
  4. No mocking - tests use real rule instances against real ModelContext
"""

from __future__ import annotations

import uuid
import pytest

# Import rules to trigger registration
import app.domain.rules.stride.spoofing  # noqa: F401
import app.domain.rules.stride.other_stride  # noqa: F401
import app.domain.rules.ai_lm.ai_llm_rules  # noqa: F401

from app.domain.models.core import (
    Applicability,
    Component,
    ComponentProperties,
    ComponentType,
    Confidence,
    DataClassification,
    DataFlow,
    DataFlowProperties,
    ModelContext,
)
from app.domain.rules.base import RULE_REGISTRY, RuleEngine
from app.domain.rules.stride.spoofing import (
    SpoofingAnonymousAccessSensitiveRule,
    SpoofingMissingAuthOnBoundaryRule,
)
from app.domain.rules.stride.other_stride import (
    DenialOfServiceInternetFacingNoRateLimitRule,
    ElevationOfPrivilegeMissingAuthorizationRule,
    ElevationOfPrivilegeOverPrivilegedAgentRule,
    InfoDisclosureSensitiveDataNotEncryptedAtRestRule,
    RepudiationMissingAuditLogRule,
    TamperingUnencryptedCrossBoundaryFlowRule,
)
from app.domain.rules.ai_lm.ai_llm_rules import (
    ExcessiveAgencyNoHITLRule,
    IndirectPromptInjectionRAGRule,
    PromptInjectionDirectRule,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

def make_version_id():
    return uuid.uuid4()


def make_component(
    component_type: ComponentType = ComponentType.PROCESS,
    name: str = "TestComponent",
    trust_zone: str = "internal",
    properties: ComponentProperties | None = None,
    version_id: uuid.UUID | None = None,
) -> Component:
    return Component(
        model_version_id=version_id or make_version_id(),
        component_type=component_type,
        name=name,
        trust_zone=trust_zone,
        properties=properties or ComponentProperties(),
    )


def make_flow(
    source: Component,
    target: Component,
    crosses_boundary: bool = False,
    encrypted: bool | None = None,
    data_class: DataClassification | None = None,
    carries_pii: bool = False,
    version_id: uuid.UUID | None = None,
) -> DataFlow:
    return DataFlow(
        model_version_id=version_id or make_version_id(),
        source_component_id=source.id,
        target_component_id=target.id,
        crosses_trust_boundary=crosses_boundary,
        source_trust_zone=source.trust_zone,
        target_trust_zone=target.trust_zone,
        properties=DataFlowProperties(
            encrypted=encrypted,
            data_classification=data_class,
            carries_pii=carries_pii,
        ),
    )


def make_context(
    components: list[Component],
    flows: list[DataFlow],
    version_id: uuid.UUID | None = None,
) -> ModelContext:
    vid = version_id or make_version_id()
    return ModelContext(
        model_version_id=vid,
        components={c.id: c for c in components},
        data_flows=flows,
    )


# ---------------------------------------------------------------------------
# STRIDE-S-001: Spoofing - Missing Auth on Cross-Boundary Flow
# ---------------------------------------------------------------------------

class TestSpoofingMissingAuthOnBoundary:
    rule = SpoofingMissingAuthOnBoundaryRule()

    def test_applicable_when_cross_boundary_flow_and_no_auth(self):
        """APPLICABLE: cross-boundary flow + no authentication declared."""
        external = make_component(ComponentType.EXTERNAL_ENTITY, "Internet", "internet")
        api = make_component(
            ComponentType.PROCESS, "API",
            properties=ComponentProperties(authentication_required=False)
        )
        flow = make_flow(external, api, crosses_boundary=True)
        ctx = make_context([external, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH
        assert len(result.architecture_facts) > 0
        assert len(result.mitigation_templates) > 0
        assert len(result.suggested_verification_criteria) > 0

    def test_not_applicable_when_no_cross_boundary_flows(self):
        """NOT_APPLICABLE: no flows cross trust boundaries."""
        internal_a = make_component(ComponentType.EXTERNAL_ENTITY, "ServiceA", "internal")
        api = make_component(ComponentType.PROCESS, "API")
        flow = make_flow(internal_a, api, crosses_boundary=False)
        ctx = make_context([internal_a, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_not_applicable_when_auth_present(self):
        """NOT_APPLICABLE: cross-boundary flow but authentication is in place."""
        external = make_component(ComponentType.EXTERNAL_ENTITY, "Internet", "internet")
        api = make_component(
            ComponentType.PROCESS, "API",
            properties=ComponentProperties(
                authentication_required=True,
                auth_mechanism="JWT"
            )
        )
        flow = make_flow(external, api, crosses_boundary=True)
        ctx = make_context([external, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_when_auth_undeclared(self):
        """NEEDS_REVIEW: cross-boundary flow + auth properties not set."""
        external = make_component(ComponentType.EXTERNAL_ENTITY, "Internet", "internet")
        api = make_component(ComponentType.PROCESS, "API")
        # No auth properties set at all
        flow = make_flow(external, api, crosses_boundary=True)
        ctx = make_context([external, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW
        assert len(result.missing_facts) > 0

    def test_not_applicable_on_component_with_no_flows(self):
        """NOT_APPLICABLE: isolated component with no incoming flows."""
        api = make_component(ComponentType.PROCESS, "IsolatedService")
        ctx = make_context([api], [])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# STRIDE-S-002: Spoofing - Anonymous Access to Sensitive Component
# ---------------------------------------------------------------------------

class TestSpoofingAnonymousAccessSensitive:
    rule = SpoofingAnonymousAccessSensitiveRule()

    def test_applicable_high_confidence_when_anon_and_pii(self):
        """APPLICABLE HIGH: anonymous access + PII stored."""
        db = make_component(
            ComponentType.DATA_STORE, "UserDB",
            properties=ComponentProperties(
                allows_anonymous_access=True,
                stores_pii=True,
            )
        )
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH

    def test_applicable_medium_confidence_when_anon_no_sensitive_data(self):
        """APPLICABLE MEDIUM: anonymous access but no sensitive data."""
        pub = make_component(
            ComponentType.PROCESS, "PublicAPI",
            properties=ComponentProperties(
                allows_anonymous_access=True,
                stores_pii=False,
                stores_credentials=False,
            )
        )
        ctx = make_context([pub], [])

        result = self.rule.evaluate(pub, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.MEDIUM

    def test_not_applicable_when_no_anonymous_access(self):
        """NOT_APPLICABLE: component does not allow anonymous access."""
        db = make_component(
            ComponentType.DATA_STORE, "SecureDB",
            properties=ComponentProperties(
                allows_anonymous_access=False,
                stores_pii=True,
            )
        )
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_when_neither_declared(self):
        """NEEDS_REVIEW: neither anonymous access nor data sensitivity declared."""
        db = make_component(ComponentType.DATA_STORE, "UnknownDB")
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW
        assert len(result.missing_facts) >= 2


# ---------------------------------------------------------------------------
# STRIDE-T-001: Tampering - Unencrypted Cross-Boundary Flow
# ---------------------------------------------------------------------------

class TestTamperingUnencryptedFlow:
    rule = TamperingUnencryptedCrossBoundaryFlowRule()

    def test_applicable_high_confidence_with_sensitive_unencrypted_flow(self):
        """APPLICABLE HIGH: unencrypted cross-boundary flow carrying PII."""
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Browser", "internet")
        api = make_component(ComponentType.PROCESS, "API")
        flow = make_flow(ext, api, crosses_boundary=True, encrypted=False,
                         data_class=DataClassification.PII)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH

    def test_applicable_medium_confidence_non_sensitive_unencrypted(self):
        """APPLICABLE MEDIUM: unencrypted cross-boundary but no sensitive classification."""
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Browser", "internet")
        api = make_component(ComponentType.PROCESS, "API")
        flow = make_flow(ext, api, crosses_boundary=True, encrypted=False)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.MEDIUM

    def test_not_applicable_when_all_flows_encrypted(self):
        """NOT_APPLICABLE: all cross-boundary flows are encrypted."""
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Browser", "internet")
        api = make_component(ComponentType.PROCESS, "API")
        flow = make_flow(ext, api, crosses_boundary=True, encrypted=True)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_when_encryption_status_unknown(self):
        """NEEDS_REVIEW: cross-boundary flow but encryption status not declared."""
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Browser", "internet")
        api = make_component(ComponentType.PROCESS, "API")
        flow = make_flow(ext, api, crosses_boundary=True, encrypted=None)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# STRIDE-ID-001: Information Disclosure - Sensitive Data Not Encrypted at Rest
# ---------------------------------------------------------------------------

class TestInfoDisclosureEncryptionAtRest:
    rule = InfoDisclosureSensitiveDataNotEncryptedAtRestRule()

    def test_applicable_pii_store_not_encrypted(self):
        db = make_component(
            ComponentType.DATA_STORE, "UserDB",
            properties=ComponentProperties(stores_pii=True, encrypted_at_rest=False)
        )
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH
        assert any(f.attribute == "encrypted_at_rest" for f in result.architecture_facts)

    def test_not_applicable_pii_store_encrypted(self):
        db = make_component(
            ComponentType.DATA_STORE, "UserDB",
            properties=ComponentProperties(stores_pii=True, encrypted_at_rest=True)
        )
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_not_applicable_non_sensitive_store(self):
        db = make_component(
            ComponentType.DATA_STORE, "PublicCatalog",
            properties=ComponentProperties(stores_pii=False, stores_credentials=False)
        )
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_when_data_sensitivity_unknown(self):
        db = make_component(ComponentType.DATA_STORE, "UnknownDB")
        ctx = make_context([db], [])

        result = self.rule.evaluate(db, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# STRIDE-EoP-001: Elevation of Privilege - Missing Authorization
# ---------------------------------------------------------------------------

class TestElevationOfPrivilegeMissingAuthz:
    rule = ElevationOfPrivilegeMissingAuthorizationRule()

    def test_applicable_cross_boundary_no_authz(self):
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Client", "internet")
        api = make_component(
            ComponentType.PROCESS, "PrivilegedAPI",
            properties=ComponentProperties(authorization_enforced=False, stores_pii=True)
        )
        flow = make_flow(ext, api, crosses_boundary=True)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH  # Sensitive data -> HIGH

    def test_not_applicable_authz_enforced(self):
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Client", "internet")
        api = make_component(
            ComponentType.PROCESS, "SecureAPI",
            properties=ComponentProperties(authorization_enforced=True)
        )
        flow = make_flow(ext, api, crosses_boundary=True)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_authz_undeclared(self):
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Client", "internet")
        api = make_component(ComponentType.PROCESS, "API")
        flow = make_flow(ext, api, crosses_boundary=True)
        ctx = make_context([ext, api], [flow])

        result = self.rule.evaluate(api, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# STRIDE-EoP-002: Elevation of Privilege - Over-Privileged Agent
# ---------------------------------------------------------------------------

class TestElevationOverPrivilegedAgent:
    rule = ElevationOfPrivilegeOverPrivilegedAgentRule()

    def test_applicable_high_confidence_no_hitl_destructive_perms(self):
        agent = make_component(
            ComponentType.AGENT, "SupportAgent",
            properties=ComponentProperties(
                tool_permissions=["read_tickets", "send_email", "delete_record"],
                has_human_in_the_loop=False,
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH

    def test_not_applicable_scoped_permissions(self):
        agent = make_component(
            ComponentType.AGENT, "ReadOnlyAgent",
            properties=ComponentProperties(
                tool_permissions=["read_tickets", "search_kb"]
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_no_tool_permissions_declared(self):
        agent = make_component(ComponentType.AGENT, "UnknownAgent")
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# AI-LLM-001: Prompt Injection Direct
# ---------------------------------------------------------------------------

class TestPromptInjectionDirect:
    rule = PromptInjectionDirectRule()

    def test_applicable_no_defenses(self):
        agent = make_component(
            ComponentType.AGENT, "ChatAgent",
            properties=ComponentProperties(
                accepts_untrusted_input=True,
                custom={"prompt_injection_defenses": []}
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.APPLICABLE

    def test_not_applicable_defenses_present(self):
        agent = make_component(
            ComponentType.AGENT, "SafeAgent",
            properties=ComponentProperties(
                accepts_untrusted_input=True,
                custom={"prompt_injection_defenses": ["input_validation", "output_schema_enforcement"]}
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_not_applicable_no_untrusted_input(self):
        agent = make_component(
            ComponentType.AGENT, "InternalAgent",
            properties=ComponentProperties(accepts_untrusted_input=False)
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_needs_review_untrusted_but_defenses_unknown(self):
        agent = make_component(
            ComponentType.AGENT, "AmbiguousAgent",
            properties=ComponentProperties(accepts_untrusted_input=True)
            # No custom.prompt_injection_defenses set
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NEEDS_REVIEW


# ---------------------------------------------------------------------------
# AI-LLM-003: Excessive Agency - No HITL
# ---------------------------------------------------------------------------

class TestExcessiveAgencyNoHITL:
    rule = ExcessiveAgencyNoHITLRule()

    def test_applicable_destructive_perms_no_hitl(self):
        agent = make_component(
            ComponentType.AGENT, "AutomationAgent",
            properties=ComponentProperties(
                tool_permissions=["execute_code", "send_email", "read_logs"],
                has_human_in_the_loop=False,
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.APPLICABLE
        assert result.confidence == Confidence.HIGH

    def test_not_applicable_hitl_present(self):
        agent = make_component(
            ComponentType.AGENT, "ApprovedAgent",
            properties=ComponentProperties(
                tool_permissions=["execute_code", "delete"],
                has_human_in_the_loop=True,
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE

    def test_not_applicable_no_destructive_perms(self):
        agent = make_component(
            ComponentType.AGENT, "SafeAgent",
            properties=ComponentProperties(
                tool_permissions=["read_docs", "search_kb"],
                has_human_in_the_loop=False,
            )
        )
        ctx = make_context([agent], [])

        result = self.rule.evaluate(agent, ctx)

        assert result.applicability == Applicability.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# Rule Engine Integration Tests
# ---------------------------------------------------------------------------

class TestRuleEngineIntegration:
    engine = RuleEngine()

    def test_all_rules_are_registered(self):
        """Verify all expected rule IDs are present in the registry."""
        expected_ids = {
            "STRIDE-S-001", "STRIDE-S-002",
            "STRIDE-T-001",
            "STRIDE-R-001",
            "STRIDE-ID-001",
            "STRIDE-DoS-001",
            "STRIDE-EoP-001", "STRIDE-EoP-002",
            "AI-LLM-001", "AI-LLM-002", "AI-LLM-003",
        }
        registered_ids = {r.rule_id for r in RULE_REGISTRY.all_rules()}
        missing = expected_ids - registered_ids
        assert not missing, f"Rules not registered: {missing}"

    def test_full_model_analysis_risky_architecture(self):
        """
        Integration: analyze a deliberately insecure architecture.
        Expect multiple APPLICABLE results and zero errors.
        """
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Internet", "internet")
        api = make_component(
            ComponentType.PROCESS, "UnsecuredAPI",
            properties=ComponentProperties(
                authentication_required=False,
                authorization_enforced=False,
                internet_facing=True,
                custom={"rate_limiting_enabled": False, "audit_logging_enabled": False}
            )
        )
        db = make_component(
            ComponentType.DATA_STORE, "UserDB",
            properties=ComponentProperties(
                stores_pii=True,
                encrypted_at_rest=False,
                allows_anonymous_access=True,
            )
        )
        flow1 = make_flow(ext, api, crosses_boundary=True, encrypted=False,
                          data_class=DataClassification.PII)
        flow2 = make_flow(api, db, crosses_boundary=False, encrypted=False)
        ctx = make_context([ext, api, db], [flow1, flow2])

        results = self.engine.analyze_model(ctx)
        applicable = [(c, r, res) for c, r, res in results
                      if res.applicability == Applicability.APPLICABLE]

        assert len(applicable) >= 4, (
            f"Expected at least 4 APPLICABLE threats in insecure architecture, got {len(applicable)}. "
            f"Results: {[(c.name, r.rule_id, res.applicability) for c, r, res in results]}"
        )

    def test_full_model_analysis_secure_architecture(self):
        """
        Integration: analyze a well-secured architecture.
        Expect zero APPLICABLE threats and minimal NEEDS_REVIEW.
        """
        ext = make_component(ComponentType.EXTERNAL_ENTITY, "Browser", "internet")
        api = make_component(
            ComponentType.PROCESS, "SecuredAPI",
            properties=ComponentProperties(
                authentication_required=True,
                auth_mechanism="JWT",
                authorization_enforced=True,
                internet_facing=True,
                custom={
                    "rate_limiting_enabled": True,
                    "audit_logging_enabled": True,
                }
            )
        )
        db = make_component(
            ComponentType.DATA_STORE, "SecureUserDB",
            properties=ComponentProperties(
                stores_pii=True,
                encrypted_at_rest=True,
                allows_anonymous_access=False,
            )
        )
        flow1 = make_flow(ext, api, crosses_boundary=True, encrypted=True,
                          data_class=DataClassification.PII)
        flow2 = make_flow(api, db, crosses_boundary=False, encrypted=True)
        ctx = make_context([ext, api, db], [flow1, flow2])

        results = self.engine.analyze_model(ctx)
        applicable = [(c, r, res) for c, r, res in results
                      if res.applicability == Applicability.APPLICABLE]

        assert len(applicable) == 0, (
            f"Expected 0 APPLICABLE threats in secure architecture, got {len(applicable)}: "
            f"{[(c.name, r.rule_id) for c, r, _ in applicable]}"
        )

    def test_ai_agent_architecture_full_analysis(self):
        """
        Integration: AI agent architecture with RAG pipeline.
        Expect prompt injection and excessive agency threats.
        """
        vector_db = make_component(ComponentType.VECTOR_STORE, "CustomerDocs", "secured")
        rag = make_component(
            ComponentType.RAG_PIPELINE, "SupportRAG",
            properties=ComponentProperties(
                accepts_untrusted_input=True,
                custom={"prompt_injection_defenses": [], "output_sanitization_enabled": False}
            )
        )
        agent = make_component(
            ComponentType.AGENT, "SupportAgent",
            properties=ComponentProperties(
                accepts_untrusted_input=True,
                tool_permissions=["send_email", "delete_ticket", "read_customer_data"],
                has_human_in_the_loop=False,
                custom={"prompt_injection_defenses": []}
            )
        )
        rag_flow = make_flow(vector_db, rag, crosses_boundary=False)
        agent_flow = make_flow(rag, agent, crosses_boundary=False)
        ctx = make_context([vector_db, rag, agent], [rag_flow, agent_flow])

        results = self.engine.analyze_model(ctx)
        applicable_ids = {r.rule_id for _, r, res in results if res.applicability == Applicability.APPLICABLE}

        assert "AI-LLM-001" in applicable_ids, "Direct prompt injection should be detected"
        assert "AI-LLM-002" in applicable_ids, "Indirect RAG injection should be detected"
        assert "AI-LLM-003" in applicable_ids, "Excessive agency should be detected"

    def test_count_by_applicability_returns_correct_totals(self):
        """Verify the count helper works correctly."""
        agent = make_component(
            ComponentType.AGENT, "TestAgent",
            properties=ComponentProperties(
                accepts_untrusted_input=True,
                tool_permissions=["delete"],
                has_human_in_the_loop=False,
                custom={"prompt_injection_defenses": []}
            )
        )
        ctx = make_context([agent], [])

        results = self.engine.analyze_model(ctx)
        counts = self.engine.count_by_applicability(results)

        assert isinstance(counts, dict)
        assert "APPLICABLE" in counts
        assert "NOT_APPLICABLE" in counts
        assert "NEEDS_REVIEW" in counts
        total = sum(counts.values())
        assert total == len(results)
