"""
ThreatForge Domain Rules Package.

Importing this package automatically registers all default rule packs
(STRIDE and AI/LLM rules) into the global RULE_REGISTRY.
"""

from app.domain.rules.base import (
    RULE_REGISTRY,
    RuleEngine,
    RuleRegistry,
    ThreatRule,
    register_rule,
)
from app.domain.rules.stride import spoofing, other_stride  # noqa: F401
from app.domain.rules.ai_lm import ai_llm_rules  # noqa: F401

__all__ = [
    "RULE_REGISTRY",
    "RuleEngine",
    "RuleRegistry",
    "ThreatRule",
    "register_rule",
]
