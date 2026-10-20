from __future__ import annotations
from abc import ABC, abstractmethod
from uuid import UUID
from app.domain.models.core import (
    Applicability, ArchitectureFact, Component, ComponentType, Confidence,
    DataFlow, MitigationTemplate, ModelContext, RuleResult, STRIDECategory, ThreatMethodology,
)


class ThreatRule(ABC):
    rule_id: str
    rule_version: str
    category: STRIDECategory | str
    methodology: ThreatMethodology
    applies_to: list[ComponentType]
    description: str

    def can_evaluate(self, component: Component) -> bool:
        return component.component_type in self.applies_to

    @abstractmethod
    def evaluate(self, component: Component, context: ModelContext) -> RuleResult:
        raise NotImplementedError

    def _not_applicable(self, reason: str, facts: list[ArchitectureFact] | None = None) -> RuleResult:
        return RuleResult(
            applicability=Applicability.NOT_APPLICABLE,
            confidence=Confidence.HIGH,
            title=f"[Not Applicable] {self.rule_id}",
            description=reason,
            architecture_facts=facts or [],
        )

    def _needs_review(self, missing_facts: list[str], title: str | None = None, description: str | None = None) -> RuleResult:
        return RuleResult(
            applicability=Applicability.NEEDS_REVIEW,
            confidence=Confidence.INSUFFICIENT_DATA,
            title=title or f"[Needs Review] {self.rule_id} -- insufficient information",
            description=description or "Please provide missing architectural details.",
            missing_facts=missing_facts,
        )

    def _applicable(
        self,
        title: str,
        description: str,
        confidence: Confidence,
        prerequisites_met: list[str],
        architecture_facts: list[ArchitectureFact],
        assumptions: list[str] | None = None,
        mitigation_templates: list[MitigationTemplate] | None = None,
        verification_criteria: list[str] | None = None,
    ) -> RuleResult:
        return RuleResult(
            applicability=Applicability.APPLICABLE,
            confidence=confidence,
            title=title,
            description=description,
            prerequisites_met=prerequisites_met,
            assumptions=assumptions or [],
            architecture_facts=architecture_facts,
            mitigation_templates=mitigation_templates or [],
            suggested_verification_criteria=verification_criteria or [],
        )


class RuleRegistry:
    def __init__(self) -> None:
        self._rules: dict[str, ThreatRule] = {}

    def register(self, rule: ThreatRule) -> None:
        if rule.rule_id in self._rules:
            raise ValueError(f"Duplicate rule_id: {rule.rule_id}")
        self._rules[rule.rule_id] = rule

    def get(self, rule_id: str) -> ThreatRule | None:
        return self._rules.get(rule_id)

    def all_rules(self) -> list[ThreatRule]:
        return list(self._rules.values())

    def rules_for_component(self, component: Component) -> list[ThreatRule]:
        return [r for r in self._rules.values() if r.can_evaluate(component)]


RULE_REGISTRY = RuleRegistry()


def register_rule(rule_class: type[ThreatRule]) -> type[ThreatRule]:
    RULE_REGISTRY.register(rule_class())
    return rule_class


class RuleEngine:
    def __init__(self, registry: RuleRegistry = RULE_REGISTRY) -> None:
        self.registry = registry

    def analyze_component(self, component: Component, context: ModelContext, include_not_applicable: bool = False) -> list[tuple[ThreatRule, RuleResult]]:
        results: list[tuple[ThreatRule, RuleResult]] = []
        for rule in self.registry.rules_for_component(component):
            result = rule.evaluate(component, context)
            if include_not_applicable or result.applicability != Applicability.NOT_APPLICABLE:
                results.append((rule, result))
        return results

    def analyze_model(self, context: ModelContext, include_not_applicable: bool = False) -> list[tuple[Component, ThreatRule, RuleResult]]:
        all_results: list[tuple[Component, ThreatRule, RuleResult]] = []
        for component in context.components.values():
            for rule, result in self.analyze_component(component, context, include_not_applicable):
                all_results.append((component, rule, result))
        return all_results

    def count_by_applicability(self, results: list[tuple[Component, ThreatRule, RuleResult]]) -> dict[str, int]:
        counts: dict[str, int] = {a.value: 0 for a in Applicability}
        for _, _, result in results:
            counts[result.applicability.value] += 1
        return counts
