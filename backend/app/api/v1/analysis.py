from __future__ import annotations

from uuid import UUID
from fastapi import APIRouter, HTTPException, Query, status

from app.domain.models.core import ModelContext
from app.services.analysis_service import AnalysisRunResult, AnalysisService
from app.services.store import GLOBAL_STORE

router = APIRouter(prefix="/analysis", tags=["Threat Analysis"])
analysis_service = AnalysisService()


@router.post("/version/{version_id}", response_model=AnalysisRunResult)
def analyze_version(
    version_id: UUID,
    include_not_applicable: bool = Query(
        default=False, description="Include NOT_APPLICABLE rule results in response"
    ),
) -> AnalysisRunResult:
    context = GLOBAL_STORE.get_version(version_id)
    if not context:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Model version '{version_id}' not found.",
        )
    return analysis_service.run_analysis(
        context, include_not_applicable=include_not_applicable
    )


@router.post("/ad-hoc", response_model=AnalysisRunResult)
def analyze_ad_hoc(
    context: ModelContext,
    include_not_applicable: bool = Query(
        default=False, description="Include NOT_APPLICABLE rule results in response"
    ),
) -> AnalysisRunResult:
    """
    Run immediate threat analysis on an ad-hoc architecture graph.
    Useful for interactive real-time visual canvas editing.
    """
    return analysis_service.run_analysis(
        context, include_not_applicable=include_not_applicable
    )


@router.get("/{run_id}", response_model=AnalysisRunResult)
def get_analysis_run(run_id: UUID) -> AnalysisRunResult:
    run = GLOBAL_STORE.analysis_runs.get(run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Analysis run '{run_id}' not found.",
        )
    return AnalysisRunResult(**run)
