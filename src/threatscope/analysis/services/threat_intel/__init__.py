"""Threat intelligence service package.

Public API — ThreatIntelService and ThreatIntelResult import paths are unchanged
from the old threat_intel.py; build_service is new:

    from src.threatscope.analysis.services.threat_intel import ThreatIntelService
    from src.threatscope.analysis.services.threat_intel import ThreatIntelResult
    from src.threatscope.analysis.services.threat_intel import build_service
"""

from src.threatscope.analysis.services.threat_intel.base import ThreatIntelResult
from src.threatscope.analysis.services.threat_intel.service import ThreatIntelService, build_service

__all__ = ["ThreatIntelService", "ThreatIntelResult", "build_service"]
