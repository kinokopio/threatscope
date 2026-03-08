import asyncio
import base64
import json
import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from src.threatscope.analysis.repository import TaskRepository
from src.threatscope.api.schemas import TaskStatus
from src.threatscope.api.v1.tasks.service import TaskService
from src.threatscope.core.config import get_settings
from src.threatscope.core.dependencies import get_coordinator

mcp = FastMCP(
    name="ThreatScope",
    instructions="""Malware analysis server for AI agents.

Workflow:
1. submit_analysis() - Submit file for analysis, returns task_id immediately
2. get_result() - Poll for progress/results (analysis takes 2-15 minutes)
3. lookup() - Query threat intelligence or search historical analyses

For long-running analysis, submit first, then periodically check get_result().""",
)


def _get_db() -> TaskRepository:
    settings = get_settings()
    return TaskRepository(settings.database.path)


def _get_service() -> TaskService:
    settings = get_settings()
    coordinator = get_coordinator(settings)
    db = _get_db()
    return TaskService(coordinator, db)


@mcp.tool
async def submit_analysis(
    file_content: str,
    filename: str,
    quick: bool = False,
) -> dict[str, Any]:
    """Submit a file for malware analysis.

    Args:
        file_content: Base64-encoded file content
        filename: Original filename (used for type detection)
        quick: If True, skip Ghidra deep analysis (faster, 1-2 min vs 5-15 min)

    Returns:
        task_id: UUID to track analysis progress
        status: Initial status (pending)
        estimated_time: Estimated completion time
    """
    try:
        file_bytes = base64.b64decode(file_content)
    except Exception:
        return {"error": "Invalid base64 encoding"}

    if len(file_bytes) > 100 * 1024 * 1024:
        return {"error": "File too large (max 100MB)"}

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)

    task_id = str(uuid.uuid4())
    file_path = temp_dir / f"{task_id}_{filename}"
    file_path.write_bytes(file_bytes)

    service = _get_service()
    db = _get_db()

    db.create_task(
        task_id=task_id,
        file_path=str(file_path),
        file_name=filename,
        options={
            "enable_ghidra": not quick,
            "enable_dynamic": True,
            "enable_threat_intel": True,
        },
    )

    asyncio.create_task(
        service._run_analysis_background(
            task_id,
            file_path,
            {
                "enable_ghidra": not quick,
                "enable_dynamic": True,
                "enable_threat_intel": True,
            },
        )
    )

    return {
        "task_id": task_id,
        "status": "pending",
        "estimated_time": "1-2 minutes" if quick else "5-15 minutes",
        "message": "Analysis started. Use get_result(task_id) to check progress.",
    }


@mcp.tool
async def get_result(task_id: str) -> dict[str, Any]:
    """Get analysis progress or results.

    Args:
        task_id: Task ID from submit_analysis()

    Returns:
        status: pending | running | completed | failed
        progress: Current step and completed steps (if running)
        result: Full analysis result (if completed)
    """
    db = _get_db()
    task = db.get_task(task_id)

    if not task:
        return {"error": f"Task not found: {task_id}"}

    status = task["status"]
    response: dict[str, Any] = {
        "task_id": task_id,
        "status": status,
        "file_name": task.get("file_name"),
    }

    if status == TaskStatus.FAILED.value:
        response["error"] = task.get("error")
        return response

    if status == TaskStatus.COMPLETED.value:
        response["result"] = {
            "verdict": None,
            "confidence": None,
            "severity": None,
            "summary": None,
        }
        if task.get("unified_report"):
            report = task["unified_report"]
            if isinstance(report, dict):
                response["result"] = {
                    "verdict": report.get("verdict"),
                    "confidence": report.get("confidence"),
                    "severity": report.get("severity"),
                    "summary": report.get("executive_summary"),
                    "classification": report.get("classification"),
                    "mitre_mapping": report.get("mitre_mapping"),
                    "iocs": report.get("iocs"),
                    "recommendations": report.get("recommendations"),
                }
        response["hashes"] = task.get("hashes")
        response["file_type"] = task.get("file_type")
        return response

    steps_status = task.get("steps_status") or {}
    running_steps = [
        step_id for step_id, info in steps_status.items() if info.get("status") == "running"
    ]
    completed_steps = [
        step_id for step_id, info in steps_status.items() if info.get("status") == "completed"
    ]
    failed_steps = [
        step_id for step_id, info in steps_status.items() if info.get("status") == "failed"
    ]

    response["progress"] = {
        "current_step": task.get("current_step"),
        "running_steps": running_steps,
        "completed_steps": completed_steps,
        "failed_steps": failed_steps,
        "steps_detail": steps_status,
    }

    if task.get("hashes"):
        response["partial_results"] = {"hashes": task["hashes"]}
        if task.get("file_type"):
            response["partial_results"]["file_type"] = task["file_type"]

    return response


@mcp.tool
async def lookup(
    hash: str | None = None,
    domain: str | None = None,
    ip: str | None = None,
) -> dict[str, Any]:
    """Query threat intelligence or search historical analyses.

    Args:
        hash: File hash (MD5, SHA1, SHA256) - checks threat intel + local DB
        domain: Domain to check in threat intel
        ip: IP address to check in threat intel

    Returns:
        Threat intelligence results and/or matching local analyses
    """
    if not any([hash, domain, ip]):
        return {"error": "Provide at least one: hash, domain, or ip"}

    from src.threatscope.analysis import AnalysisCoordinator

    settings = get_settings()
    coordinator = AnalysisCoordinator(settings)
    results: dict[str, Any] = {}

    if hash:
        db = _get_db()
        local_tasks = db.get_all_tasks(limit=100)
        for t in local_tasks:
            if t.get("hashes"):
                hashes = t["hashes"]
                if isinstance(hashes, dict):
                    if hash.lower() in [
                        str(hashes.get("md5", "")).lower(),
                        str(hashes.get("sha1", "")).lower(),
                        str(hashes.get("sha256", "")).lower(),
                    ]:
                        results["local_analysis"] = {
                            "task_id": t["id"],
                            "status": t["status"],
                            "file_name": t.get("file_name"),
                        }
                        if t.get("unified_report"):
                            report = t["unified_report"]
                            if isinstance(report, dict):
                                results["local_analysis"]["verdict"] = report.get("verdict")
                                results["local_analysis"]["confidence"] = report.get("confidence")
                        break

        hash_results = await coordinator.threat_intel.query_hash(hash)
        results["threat_intel"] = {
            source: {"found": r.found, "data": r.data if r.found else None}
            for source, r in hash_results.items()
        }

    if domain or ip:
        ioc_results = await coordinator.threat_intel.query_iocs(
            domains=[domain] if domain else None,
            ips=[ip] if ip else None,
        )
        results["ioc_lookup"] = {
            ioc_type: [{"found": r.found, "data": r.data if r.found else None} for r in ioc_list]
            for ioc_type, ioc_list in ioc_results.items()
            if ioc_list
        }

    return results


@mcp.tool
async def list_analyses(
    limit: int = 10,
    status: str | None = None,
    verdict: str | None = None,
) -> dict[str, Any]:
    """List recent analyses.

    Args:
        limit: Max results (default 10, max 100)
        status: Filter by status (pending, completed, failed)
        verdict: Filter by verdict (malicious, suspicious, benign)

    Returns:
        List of recent analyses with summary info
    """
    limit = min(limit, 100)
    db = _get_db()
    tasks = db.get_all_tasks(limit=limit, status=status)

    analyses = []
    for t in tasks:
        analysis = {
            "task_id": t["id"],
            "status": t["status"],
            "file_name": t.get("file_name"),
        }

        if t.get("unified_report"):
            report = t["unified_report"]
            if isinstance(report, dict):
                analysis["verdict"] = report.get("verdict")
                analysis["confidence"] = report.get("confidence")
                analysis["severity"] = report.get("severity")

                if verdict and report.get("verdict") != verdict:
                    continue

        analyses.append(analysis)

    return {"analyses": analyses, "total": len(analyses)}


@mcp.resource("config://threatscope")
def get_config() -> str:
    """Get ThreatScope configuration."""
    settings = get_settings()
    config = {
        "version": "0.2.0",
        "capabilities": {
            "ghidra_analysis": settings.analysis.enable_ghidra_analysis,
            "dynamic_analysis": settings.analysis.enable_dynamic_analysis,
        },
        "threat_intel_sources": ["MalwareBazaar", "ThreatFox", "URLhaus"],
        "estimated_analysis_time": {
            "quick": "1-2 minutes",
            "full": "5-15 minutes",
        },
    }
    return json.dumps(config, indent=2)


# Legacy compatibility
class ThreatScopeMCPServer:
    def __init__(self):
        self._mcp = mcp
        self._tools = {
            "submit_analysis": submit_analysis,
            "get_result": get_result,
            "lookup": lookup,
            "list_analyses": list_analyses,
        }

    def get_tools(self) -> list[dict[str, Any]]:
        return [{"name": name, "description": fn.__doc__ or ""} for name, fn in self._tools.items()]

    async def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        tool = self._tools.get(name)
        if not tool:
            return {"error": f"Unknown tool: {name}"}
        return await tool(**arguments)


_mcp_server: ThreatScopeMCPServer | None = None


def get_mcp_server() -> ThreatScopeMCPServer:
    global _mcp_server
    if _mcp_server is None:
        _mcp_server = ThreatScopeMCPServer()
    return _mcp_server


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000, path="/api/v1/mcp")
