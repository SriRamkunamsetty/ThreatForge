from __future__ import annotations
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import UUID
from pydantic import BaseModel, Field, field_validator


class ComponentType(str, Enum):
    PROCESS = "process"
    DATA_STORE = "data_store"
    EXTERNAL_ENTITY = "external_entity"
    TRUST_BOUNDARY = "trust_boundary"
    LLM_PROVIDER = "llm_provider"
    RAG_PIPELINE = "rag_pipeline"
    VECTOR_STORE = "vector_store"
    AGENT = "agent"
    TOOL = "tool"
    SYSTEM_PROMPT = "system_prompt"
    UNTRUSTED_INPUT = "untrusted_input"

class DataClassification(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"
    PII = "PII"
    PHI = "PHI"
    CREDENTIALS = "CREDENTIALS"

class Applicability(str, Enum):
    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NEEDS_REVIEW = "NEEDS_REVIEW"

class Confidence(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"

class STRIDECategory(str, Enum):
    SPOOFING = "Spoofing"
    TAMPERING = "Tampering"
    REPUDIATION = "Repudiation"
    INFORMATION_DISCLOSURE = "InformationDisclosure"
    DENIAL_OF_SERVICE = "DenialOfService"
    ELEVATION_OF_PRIVILEGE = "ElevationOfPrivilege"

class ThreatMethodology(str, Enum):
    STRIDE = "STRIDE"
    LINDDUN = "LINDDUN"
    PASTA = "PASTA"
    AI_LLM = "AI_LLM"
    CUSTOM = "CUSTOM"

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class MitigationStatus(str, Enum):
    PROPOSED = "PROPOSED"
    ACCEPTED = "ACCEPTED"
    IMPLEMENTED = "IMPLEMENTED"
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    STALE = "STALE"
    WONT_FIX = "WONT_FIX"

class ThreatStatus(str, Enum):
    OPEN = "OPEN"
    ACCEPTED_RISK = "ACCEPTED_RISK"
    MITIGATED = "MITIGATED"
    VERIFIED = "VERIFIED"
    INVALID = "INVALID"
    WONT_FIX = "WONT_FIX"

class ComponentPosition(BaseModel):
    x: float = 0.0
    y: float = 0.0

class ComponentProperties(BaseModel):
    authentication_required: bool | None = None
    authorization_enforced: bool | None = None
    auth_mechanism: str | None = None
    encrypted_at_rest: bool | None = None
    encrypted_in_transit: bool | None = None
    internet_facing: bool | None = None
    allows_anonymous_access: bool | None = None
    stores_pii: bool | None = None
    stores_credentials: bool | None = None
    runs_as_privileged: bool | None = None
    privilege_level: str | None = None
    accepts_untrusted_input: bool | None = None
    has_human_in_the_loop: bool | None = None
    tool_permissions: list[str] | None = None
    llm_model: str | None = None
    custom: dict[str, Any] = Field(default_factory=dict)

class Component(BaseModel):
    id: UUID = Field(default_factory=uuid.uuid4)
    model_version_id: UUID
    component_type: ComponentType
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None
    trust_zone: str | None = None
    properties: ComponentProperties = Field(default_factory=ComponentProperties)
    position: ComponentPosition = Field(default_factory=ComponentPosition)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("name")
    @classmethod
    def name_not_empty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Component name cannot be blank")
        return v.strip()

class DataFlowProperties(BaseModel):
    protocol: str | None = None
    port: int | None = None
    encrypted: bool | None = None
    mutual_tls: bool | None = None
    authenticated: bool | None = None
    carries_credentials: bool = False
    data_classification: DataClassification | None = None
    carries_pii: bool = False
    flow_number: int | None = None
    custom: dict[str, Any] = Field(default_factory=dict)

class DataFlow(BaseModel):
    id: UUID = Field(default_factory=uuid.uuid4)
    model_version_id: UUID
    source_component_id: UUID
    target_component_id: UUID
    name: str | None = None
    crosses_trust_boundary: bool = False
    source_trust_zone: str | None = None
    target_trust_zone: str | None = None
    properties: DataFlowProperties = Field(default_factory=DataFlowProperties)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ModelContext(BaseModel):
    model_version_id: UUID
    components: dict[UUID, Component] = Field(default_factory=dict)
    data_flows: list[DataFlow] = Field(default_factory=list)
    trust_zones: list[str] = Field(default_factory=list)

    def get_incoming_flows(self, component_id: UUID) -> list[DataFlow]:
        return [f for f in self.data_flows if f.target_component_id == component_id]

    def get_outgoing_flows(self, component_id: UUID) -> list[DataFlow]:
        return [f for f in self.data_flows if f.source_component_id == component_id]

    def get_flows_crossing_boundary_to(self, component_id: UUID) -> list[DataFlow]:
        return [f for f in self.data_flows if f.target_component_id == component_id and f.crosses_trust_boundary]

    def get_flows_crossing_boundary_from(self, component_id: UUID) -> list[DataFlow]:
        return [f for f in self.data_flows if f.source_component_id == component_id and f.crosses_trust_boundary]

    def get_flows_between(self, source_id: UUID, target_id: UUID) -> list[DataFlow]:
        return [f for f in self.data_flows if f.source_component_id == source_id and f.target_component_id == target_id]

    def component_has_sensitive_data(self, component_id: UUID) -> bool | None:
        comp = self.components.get(component_id)
        if comp is None:
            return None
        props = comp.properties
        if props.stores_pii is None and props.stores_credentials is None:
            return None
        return bool(props.stores_pii or props.stores_credentials)

    def flows_carrying_pii_to(self, component_id: UUID) -> list[DataFlow]:
        return [f for f in self.get_incoming_flows(component_id)
                if f.properties.carries_pii or f.properties.data_classification == DataClassification.PII]

    model_config = {"arbitrary_types_allowed": True}

class ArchitectureFact(BaseModel):
    fact_type: str
    description: str
    component_id: UUID | None = None
    flow_id: UUID | None = None
    attribute: str | None = None
    value: Any = None

class MitigationTemplate(BaseModel):
    template_id: str
    title: str
    description: str
    control_type: str
    verification_criteria: list[str] = Field(default_factory=list)

class RuleResult(BaseModel):
    applicability: Applicability
    confidence: Confidence
    title: str
    description: str
    prerequisites_met: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    architecture_facts: list[ArchitectureFact] = Field(default_factory=list)
    mitigation_templates: list[MitigationTemplate] = Field(default_factory=list)
    suggested_verification_criteria: list[str] = Field(default_factory=list)

class RiskAssessment(BaseModel):
    severity: Severity
    impact_rationale: str = Field(min_length=10)
    likelihood_rationale: str = Field(min_length=10)
    confidence: Confidence
    impact_dimensions: list[str] = Field(default_factory=list)
    existing_controls: list[str] = Field(default_factory=list)

class ThreatInstance(BaseModel):
    id: UUID = Field(default_factory=uuid.uuid4)
    analysis_run_id: UUID
    rule_id: str
    rule_version: str
    rule_methodology: ThreatMethodology
    category: STRIDECategory | str
    affected_component_id: UUID | None = None
    affected_flow_id: UUID | None = None
    title: str
    description: str
    applicability: Applicability
    confidence: Confidence
    prerequisites_met: list[str] = Field(default_factory=list)
    missing_facts: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    architecture_facts: list[ArchitectureFact] = Field(default_factory=list)
    ai_generated: bool = False
    risk_assessment: RiskAssessment | None = None
    status: ThreatStatus = ThreatStatus.OPEN
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AnalysisRun(BaseModel):
    id: UUID = Field(default_factory=uuid.uuid4)
    threat_model_id: UUID
    model_version_id: UUID
    rule_pack_id: str
    rule_pack_version: str
    ai_model_version: str | None = None
    threat_count: int = 0
    applicable_count: int = 0
    needs_review_count: int = 0
    not_applicable_count: int = 0
    duration_ms: int | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
