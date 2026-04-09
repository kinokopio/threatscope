"""Threat intelligence service package.

Backward-compatible shim — re-exports ThreatIntelService from the legacy
implementation. Will be replaced with the full provider architecture in Task 8.
"""

from src.threatscope.analysis.services.threat_intel_legacy import ThreatIntelService  # noqa: F401

__all__ = ["ThreatIntelService"]
