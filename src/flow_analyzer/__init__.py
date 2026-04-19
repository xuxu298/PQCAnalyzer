"""Flow analysis module — PCAP HNDL assessment.

Parses TLS/SSH handshakes from captured traffic, aggregates into flows,
and scores Harvest-Now-Decrypt-Later exposure using V x S x R x E formula.

See docs/flow-analysis.md and docs/hndl-scoring.md.
"""

from __future__ import annotations

from src.flow_analyzer.models import (
    AggregateStats,
    CryptoPrimitive,
    DataSensitivity,
    Flow,
    FlowAnalysisReport,
    HNDLScore,
    Protocol,
    RetentionClass,
    RiskBand,
)

__all__ = [
    "AggregateStats",
    "CryptoPrimitive",
    "DataSensitivity",
    "Flow",
    "FlowAnalysisReport",
    "HNDLScore",
    "Protocol",
    "RetentionClass",
    "RiskBand",
]
