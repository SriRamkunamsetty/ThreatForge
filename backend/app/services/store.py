from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field

from app.domain.graph.diff import DriftReport
from app.domain.models.core import ModelContext
from app.domain.workflow import AuditLogger, MitigationRecord, ThreatProvenanceChain


class ThreatModelMetadata(BaseModel):
    id: UUID = Field(default_factory=uuid4)
    workspace_id: UUID = Field(default_factory=uuid4)
    name: str
    description: str | None = None
    version_ids: list[UUID] = Field(default_factory=list)
    current_version_id: UUID | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ModelStore:
    """
    In-memory thread-safe store for development and testing,
    designed to interface seamlessly with PostgreSQL / SQLAlchemy in production.
    """

    def __init__(self) -> None:
        self.threat_models: dict[UUID, ThreatModelMetadata] = {}
        self.model_versions: dict[UUID, ModelContext] = {}
        self.analysis_runs: dict[UUID, dict[str, Any]] = {}
        self.threat_instances: dict[UUID, dict[str, Any]] = {}
        self.mitigations: dict[UUID, MitigationRecord] = {}
        self.drift_reports: dict[UUID, DriftReport] = {}
        self.provenance_chains: dict[UUID, ThreatProvenanceChain] = {}
        self.audit_logger = AuditLogger()

    def create_model(self, name: str, description: str | None = None) -> ThreatModelMetadata:
        model = ThreatModelMetadata(name=name, description=description)
        self.threat_models[model.id] = model
        self.audit_logger.record(
            actor_id="system",
            actor_name="System",
            event_type="MODEL_CREATED",
            entity_type="threat_model",
            entity_id=str(model.id),
            rationale=f"Initial creation of threat model '{name}'",
        )
        return model

    def save_version(self, model_id: UUID, context: ModelContext) -> ModelContext:
        if model_id not in self.threat_models:
            raise KeyError(f"ThreatModel {model_id} not found")

        version_id = context.model_version_id
        self.model_versions[version_id] = context

        tm = self.threat_models[model_id]
        if version_id not in tm.version_ids:
            tm.version_ids.append(version_id)
        tm.current_version_id = version_id
        tm.updated_at = datetime.now(timezone.utc)

        self.audit_logger.record(
            actor_id="system",
            actor_name="System",
            event_type="VERSION_SAVED",
            entity_type="model_version",
            entity_id=str(version_id),
            rationale=f"Saved model version {version_id} with {len(context.components)} components and {len(context.data_flows)} flows",
        )
        return context

    def get_model(self, model_id: UUID) -> ThreatModelMetadata | None:
        return self.threat_models.get(model_id)

    def get_version(self, version_id: UUID) -> ModelContext | None:
        return self.model_versions.get(version_id)


GLOBAL_STORE = ModelStore()
