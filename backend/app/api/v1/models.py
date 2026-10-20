from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, Field

from app.domain.models.core import ModelContext
from app.services.store import GLOBAL_STORE, ThreatModelMetadata

router = APIRouter(prefix="/models", tags=["Threat Models"])


class CreateModelRequest(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = None


@router.post("", response_model=ThreatModelMetadata, status_code=status.HTTP_201_CREATED)
def create_threat_model(req: CreateModelRequest) -> ThreatModelMetadata:
    return GLOBAL_STORE.create_model(name=req.name, description=req.description)


@router.get("", response_model=list[ThreatModelMetadata])
def list_threat_models() -> list[ThreatModelMetadata]:
    return list(GLOBAL_STORE.threat_models.values())


@router.get("/{model_id}", response_model=ThreatModelMetadata)
def get_threat_model(model_id: UUID) -> ThreatModelMetadata:
    tm = GLOBAL_STORE.get_model(model_id)
    if not tm:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat model with id '{model_id}' was not found.",
        )
    return tm


@router.post("/{model_id}/versions", response_model=ModelContext, status_code=status.HTTP_201_CREATED)
def save_model_version(model_id: UUID, context: ModelContext) -> ModelContext:
    try:
        return GLOBAL_STORE.save_version(model_id, context)
    except KeyError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat model with id '{model_id}' was not found.",
        )


@router.get("/{model_id}/versions/{version_id}", response_model=ModelContext)
def get_model_version(model_id: UUID, version_id: UUID) -> ModelContext:
    tm = GLOBAL_STORE.get_model(model_id)
    if not tm or version_id not in tm.version_ids:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version_id}' for model '{model_id}' was not found.",
        )
    ctx = GLOBAL_STORE.get_version(version_id)
    if not ctx:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version_id}' data not found.",
        )
    return ctx
