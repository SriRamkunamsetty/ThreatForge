from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.analysis import router as analysis_router
from app.api.v1.drift import router as drift_router
from app.api.v1.models import router as models_router
from app.api.v1.paths import router as paths_router
from app.api.v1.workflow import router as workflow_router
from app.domain.rules.base import RULE_REGISTRY

app = FastAPI(
    title="ThreatForge API",
    version="1.0.0",
    description=(
        "Production Threat Modeling Platform Engine — Continuous, Change-Aware, "
        "and Verifiable Threat Intelligence."
    ),
)

# CORS configuration strictly bound for local dev / secure frontends
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include v1 API Routers
app.include_router(models_router, prefix="/api/v1")
app.include_router(analysis_router, prefix="/api/v1")
app.include_router(drift_router, prefix="/api/v1")
app.include_router(paths_router, prefix="/api/v1")
app.include_router(workflow_router, prefix="/api/v1")


@app.get("/health", tags=["System"])
def health_check() -> dict[str, str]:
    return {
        "status": "healthy",
        "service": "ThreatForge Core API",
        "registered_rules": str(len(RULE_REGISTRY.all_rules())),
    }


@app.get("/", tags=["System"])
def root_info() -> dict[str, object]:
    return {
        "name": "ThreatForge API",
        "version": "1.0.0",
        "registered_rules_count": len(RULE_REGISTRY.all_rules()),
        "differentiators": [
            "Architecture Drift Intelligence (Semantic graph diff)",
            "Threat-to-Evidence Provenance Graph",
            "Mitigation-to-Test Compiler",
            "First-Class AI/Agentic System Modeling",
        ],
        "docs_url": "/docs",
        "openapi_url": "/openapi.json",
    }
