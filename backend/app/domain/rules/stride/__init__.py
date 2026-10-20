"""
STRIDE rule pack for ThreatForge.

Import this module to register all STRIDE rules into the global RULE_REGISTRY.
"""

from app.domain.rules.stride import spoofing, other_stride  # noqa: F401
