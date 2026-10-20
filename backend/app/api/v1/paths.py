from __future__ import annotations

from typing import Any
from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, status

from app.domain.graph.paths import AttackPath, AttackPathAnalyzer
from app.domain.models.core import ModelContext
from app.services.store import GLOBAL_STORE

router = APIRouter(prefix="/paths", tags=["Attack Paths"])


def _serialize_path(p: AttackPath) -> dict[str, Any]:
    return {
        "path_id": p.path_id,
        "entry_point_id": p.entry_point_id,
        "entry_point_name": p.entry_point_name,
        "target_asset_id": p.target_asset_id,
        "target_asset_name": p.target_asset_name,
        "hop_count": p.hop_count,
        "risk_score": p.risk_score,
        "unencrypted_hops": p.unencrypted_hops,
        "boundary_crossings": p.boundary_crossings,
        "description": p.description,
        "steps": [
            {
                "step_number": s.step_number,
                "source_id": s.source_component_id,
                "source_name": s.source_component_name,
                "target_id": s.target_component_id,
                "target_name": s.target_component_name,
                "flow_id": s.flow_id,
                "crosses_boundary": s.crosses_boundary,
                "encrypted": s.encrypted,
                "protocol": s.protocol,
            }
            for s in p.steps
        ],
    }


@router.get("/version/{version_id}")
def analyze_version_attack_paths(
    version_id: UUID,
    max_depth: int = Query(default=8, ge=2, le=15),
) -> list[dict[str, Any]]:
    context = GLOBAL_STORE.get_version(version_id)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version_id}' not found.",
        )
    analyzer = AttackPathAnalyzer(context)
    paths = analyzer.analyze_paths(max_depth=max_depth)
    return [_serialize_path(p) for p in paths]


@router.post("/ad-hoc")
def analyze_ad_hoc_attack_paths(
    context: ModelContext,
    max_depth: int = Query(default=8, ge=2, le=15),
) -> list[dict[str, Any]]:
    analyzer = AttackPathAnalyzer(context)
    paths = analyzer.analyze_paths(max_depth=max_depth)
    return [_serialize_path(p) for p in paths]
