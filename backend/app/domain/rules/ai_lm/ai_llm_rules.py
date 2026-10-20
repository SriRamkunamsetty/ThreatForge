from __future__ import annotations

from app.domain.models.core import (
    Applicability,
    ArchitectureFact,
    Component,
    ComponentType,
    Confidence,
    MitigationTemplate,
    ModelContext,
    RuleResult,
    STRIDECategory,
    ThreatMethodology,
)
from app.domain.rules.base import ThreatRule, register_rule

_PROMPT_INJECTION_MITIGATION = MitigationTemplate(
    template_id="MIT-AI-001",
    title="Implement multi-layer prompt injection defense and output filtering",
    description="Use dual-LLM verification, input schema validation, prompt boundary markers, and output sanitization.",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Input validation filters known injection patterns and delimiters",
        "Output schemas enforce structured, non-executable content",
        "Secondary evaluation checks for system prompt leakage",
    ],
)

_HITL_MITIGATION = MitigationTemplate(
    template_id="MIT-AI-002",
    title="Enforce Human-in-the-Loop (HITL) authorization for destructive actions",
    description="Require explicit human approval for high-impact tool invocations (write, execute, delete, send).",
    control_type="PREVENTIVE",
    verification_criteria=[
        "Destructive tool calls transition to PENDING_APPROVAL state",
        "Human reviewer must sign off before tool execution continues",
        "Audit log captures approval decision, reviewer ID, and parameters",
    ],
)

_DESTRUCTIVE_KEYWORDS = {
    "execute",
    "execute_code",
    "delete",
    "delete_ticket",
    "delete_record",
    "send_email",
    "write",
    "modify",
    "drop",
    "truncate",
    "kill",
    "admin",
}


@register_rule
class PromptInjectionDirectRule(ThreatRule):
    rule_id = "AI-LLM-001"
    rule_version = "1.0.0"
    category = STRIDECategory.TAMPERING
    methodology = ThreatMethodology.AI_LLM
    applies_to = [ComponentType.AGENT, ComponentType.LLM_PROVIDER, ComponentType.RAG_PIPELINE]
    description = "Detects direct prompt injection risk on components processing untrusted input without defenses."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        accepts_untrusted = component.properties.accepts_untrusted_input

        if accepts_untrusted is False:
            return self._not_applicable(
                f"Component {component.name!r} does not accept untrusted input.",
                facts=[ArchitectureFact(
                    fact_type="safe_input_boundary",
                    description="accepts_untrusted_input is False",
                    component_id=component.id,
                )],
            )

        if accepts_untrusted is None:
            return self._needs_review(
                missing_facts=["accepts_untrusted_input"],
                title=f"Missing untrusted input declaration for {component.name}",
                description="Cannot verify prompt injection exposure without knowing if input is untrusted.",
            )

        defenses = component.properties.custom.get("prompt_injection_defenses")
        if defenses is None:
            return self._needs_review(
                missing_facts=["custom.prompt_injection_defenses"],
                title=f"Missing prompt injection defense details for {component.name}",
                description=f"Component {component.name!r} accepts untrusted input but defenses are not specified.",
            )

        if isinstance(defenses, list) and len(defenses) > 0:
            return self._not_applicable(
                f"Component {component.name!r} implements prompt injection defenses.",
                facts=[ArchitectureFact(
                    fact_type="prompt_injection_defenses",
                    description=f"Defenses declared: {', '.join(str(d) for d in defenses)}",
                    component_id=component.id,
                )],
            )

        return self._applicable(
            title=f"Direct Prompt Injection Vulnerability on {component.name}",
            description=(
                f"Component {component.name!r} accepts untrusted input but declares no prompt "
                "injection defenses, exposing it to jailbreaks, instruction overriding, and data exfiltration."
            ),
            confidence=Confidence.HIGH,
            prerequisites_met=[
                "Component accepts untrusted input",
                "Prompt injection defenses list is empty or absent",
            ],
            architecture_facts=[
                ArchitectureFact(
                    fact_type="untrusted_input",
                    description="accepts_untrusted_input is True",
                    component_id=component.id,
                ),
                ArchitectureFact(
                    fact_type="missing_defense",
                    description="prompt_injection_defenses is empty",
                    component_id=component.id,
                ),
            ],
            assumptions=["Adversary can supply natural language inputs to this component"],
            mitigation_templates=[_PROMPT_INJECTION_MITIGATION],
            verification_criteria=_PROMPT_INJECTION_MITIGATION.verification_criteria,
        )


@register_rule
class IndirectPromptInjectionRAGRule(ThreatRule):
    rule_id = "AI-LLM-002"
    rule_version = "1.0.0"
    category = STRIDECategory.TAMPERING
    methodology = ThreatMethodology.AI_LLM
    applies_to = [ComponentType.RAG_PIPELINE, ComponentType.AGENT]
    description = "Detects indirect prompt injection risks in RAG pipelines and knowledge-retrieval systems."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        if component.component_type != ComponentType.RAG_PIPELINE:
            rag_inflows = [
                f for f in context.get_incoming_flows(component.id)
                if context.components.get(f.source_component_id)
                and context.components[f.source_component_id].component_type in (
                    ComponentType.RAG_PIPELINE, ComponentType.VECTOR_STORE
                )
            ]
            if not rag_inflows:
                return self._not_applicable(f"Component {component.name!r} is not a RAG pipeline and has no RAG inflows.")

        defenses = component.properties.custom.get("prompt_injection_defenses")
        output_sanitized = component.properties.custom.get("output_sanitization_enabled")
        accepts_untrusted = component.properties.accepts_untrusted_input

        if defenses is None and output_sanitized is None and accepts_untrusted is None:
            return self._needs_review(
                missing_facts=["accepts_untrusted_input", "custom.prompt_injection_defenses", "custom.output_sanitization_enabled"],
                title=f"Missing RAG security posture for {component.name}",
            )

        is_defended = (isinstance(defenses, list) and len(defenses) > 0) and output_sanitized is True
        if is_defended:
            return self._not_applicable(f"RAG pipeline {component.name!r} has injection defenses and output sanitization.")

        if (isinstance(defenses, list) and len(defenses) == 0) or output_sanitized is False or accepts_untrusted is True:
            return self._applicable(
                title=f"Indirect Prompt Injection in RAG pipeline on {component.name}",
                description=(
                    f"RAG pipeline {component.name!r} processes external or untrusted documents "
                    "without verified sanitization or prompt injection defenses."
                ),
                confidence=Confidence.HIGH,
                prerequisites_met=["Component processes retrieved content", "Sanitization or defenses are absent/disabled"],
                architecture_facts=[
                    ArchitectureFact(
                        fact_type="rag_pipeline_component",
                        description=f"Component is {component.component_type.value}",
                        component_id=component.id,
                    )
                ],
                assumptions=["Retrieved documents may contain adversarial instructions"],
                mitigation_templates=[_PROMPT_INJECTION_MITIGATION],
                verification_criteria=_PROMPT_INJECTION_MITIGATION.verification_criteria,
            )

        return self._needs_review(
            missing_facts=["custom.output_sanitization_enabled"],
            title=f"Review RAG output sanitization for {component.name}",
        )


@register_rule
class ExcessiveAgencyNoHITLRule(ThreatRule):
    rule_id = "AI-LLM-003"
    rule_version = "1.0.0"
    category = STRIDECategory.ELEVATION_OF_PRIVILEGE
    methodology = ThreatMethodology.AI_LLM
    applies_to = [ComponentType.AGENT]
    description = "Detects autonomous agents with destructive tool permissions that lack Human-in-the-Loop oversight."

    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        perms = component.properties.tool_permissions

        if perms is None:
            return self._needs_review(
                missing_facts=["tool_permissions"],
                title=f"Tool permissions undeclared for agent {component.name}",
                description="Cannot assess agency risk without declared tool permissions.",
            )

        has_destructive = any(
            any(kw in str(p).lower() for kw in _DESTRUCTIVE_KEYWORDS)
            for p in perms
        )

        if not has_destructive:
            return self._not_applicable(
                f"Agent {component.name!r} has only scoped, non-destructive permissions.",
                facts=[ArchitectureFact(
                    fact_type="scoped_agent_permissions",
                    description=f"Permissions: {', '.join(str(p) for p in perms)}",
                    component_id=component.id,
                )],
            )

        hitl = component.properties.has_human_in_the_loop
        if hitl is True:
            return self._not_applicable(
                f"Agent {component.name!r} has Human-in-the-Loop approval for tool invocations.",
                facts=[ArchitectureFact(
                    fact_type="hitl_enforced",
                    description="has_human_in_the_loop is True",
                    component_id=component.id,
                )],
            )

        if hitl is False:
            destructive_found = [
                str(p) for p in perms if any(kw in str(p).lower() for kw in _DESTRUCTIVE_KEYWORDS)
            ]
            return self._applicable(
                title=f"Excessive Agency without Human-in-the-Loop on {component.name}",
                description=(
                    f"Agent {component.name!r} is granted destructive tool permissions ({', '.join(destructive_found)}) "
                    "with no Human-in-the-Loop approval mechanism. Adversarial manipulation or model errors can lead to unauthorized actions."
                ),
                confidence=Confidence.HIGH,
                prerequisites_met=[
                    "Agent has destructive tool permissions",
                    "has_human_in_the_loop is False",
                ],
                architecture_facts=[
                    ArchitectureFact(
                        fact_type="destructive_permissions",
                        description=f"Destructive tools: {', '.join(destructive_found)}",
                        component_id=component.id,
                    ),
                    ArchitectureFact(
                        fact_type="no_hitl",
                        description="has_human_in_the_loop is False",
                        component_id=component.id,
                    ),
                ],
                assumptions=["Agent may be manipulated by user input or adversarial context"],
                mitigation_templates=[_HITL_MITIGATION],
                verification_criteria=_HITL_MITIGATION.verification_criteria,
            )

        return self._needs_review(
            missing_facts=["has_human_in_the_loop"],
            title=f"Unknown Human-in-the-Loop posture for agent {component.name}",
            description=f"Agent {component.name!r} has destructive tools but HITL status is not declared.",
        )
