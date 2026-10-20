from __future__ import annotations

from datetime import datetime, timezone
from typing import Any
from uuid import UUID, uuid4
from pydantic import BaseModel, Field


class AuditEvent(BaseModel):
    """
    Append-only, immutable audit event record.
    """

    id: UUID = Field(default_factory=uuid4)
    workspace_id: UUID | None = None
    actor_id: str
    actor_name: str
    event_type: str  # MODEL_CREATED | MODEL_UPDATED | THREAT_REVIEWED | MITIGATION_ADDED | EVIDENCE_SUBMITTED | DRIFT_ANALYZED
    entity_type: str  # threat_model | model_version | threat_instance | mitigation | verification_test
    entity_id: str
    rationale: str | None = None
    payload: dict[str, Any] = Field(default_factory=dict)
    ip_address: str | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_log_entry(self) -> str:
        return (
            f"[{self.created_at.isoformat()}] [{self.event_type}] "
            f"actor={self.actor_name} entity={self.entity_type}:{self.entity_id} "
            f"rationale={self.rationale or 'N/A'}"
        )


class AuditLogger:
    """
    In-memory append-only audit trail accumulator.
    Persisted to database audit_events table.
    """

    def __init__(self) -> None:
        self._events: list[AuditEvent] = []

    def record(
        self,
        actor_id: str,
        actor_name: str,
        event_type: str,
        entity_type: str,
        entity_id: str,
        rationale: str | None = None,
        payload: dict[str, Any] | None = None,
        workspace_id: UUID | None = None,
    ) -> AuditEvent:
        event = AuditEvent(
            workspace_id=workspace_id,
            actor_id=actor_id,
            actor_name=actor_name,
            event_type=event_type,
            entity_type=entity_type,
            entity_id=entity_id,
            rationale=rationale,
            payload=payload or {},
        )
        self._events.append(event)
        return event

    def get_events_for_entity(self, entity_id: str) -> list[AuditEvent]:
        return [e for e in self._events if e.entity_id == entity_id]

    def all_events(self) -> list[AuditEvent]:
        return list(self._events)
