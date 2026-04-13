"""FastAPI application — VN-PQC Readiness Analyzer API."""

from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.api.routes import scanner, benchmarker, roadmap, reports

app = FastAPI(
    title="VN-PQC Readiness Analyzer",
    description="API for assessing post-quantum cryptography readiness.",
    version="0.3.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scanner.router, prefix="/api/v1", tags=["Scanner"])
app.include_router(benchmarker.router, prefix="/api/v1", tags=["Benchmarker"])
app.include_router(roadmap.router, prefix="/api/v1", tags=["Roadmap"])
app.include_router(reports.router, prefix="/api/v1", tags=["Reports"])


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "version": "0.3.0"}
