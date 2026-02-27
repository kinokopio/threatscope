"""REST API for ThreatScope."""

import tempfile
import uuid
from pathlib import Path
from typing import Any

from fastapi import BackgroundTasks, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from api.websocket import (
    router as websocket_router,
    notify_step_started,
    notify_step_completed,
    notify_step_progress,
    notify_task_started,
    notify_task_completed,
)
from core import (
    AnalysisCoordinator,
    ScheduledCoordinator,
    SchedulerConfig,
    TaskStatus,
    TaskProgress,
)
from core.database import get_database, TaskDatabase

_coordinator: AnalysisCoordinator | None = None
_scheduled_coordinator: ScheduledCoordinator | None = None


def get_db() -> TaskDatabase:
    """Get database instance."""
    return get_database()

def get_coordinator() -> AnalysisCoordinator:
    global _coordinator
    if _coordinator is None:
        _coordinator = AnalysisCoordinator()
    return _coordinator


def get_scheduled_coordinator() -> ScheduledCoordinator:
    global _scheduled_coordinator, _coordinator
    if _scheduled_coordinator is None:
        coordinator = get_coordinator()
        config = SchedulerConfig(
            stage_1_4_workers=4,
            stage_6_workers=4,
            ghidra_pool_size=1,
        )
        _scheduled_coordinator = ScheduledCoordinator(coordinator, config)
    return _scheduled_coordinator


class AnalysisOptions(BaseModel):
    enable_ghidra: bool = True
    enable_dynamic: bool = True
    enable_threat_intel: bool = True


class TaskResponse(BaseModel):
    task_id: str
    status: str
    message: str | None = None


class AnalysisResponse(BaseModel):
    task_id: str
    status: str
    result: dict[str, Any] | None = None
    error: str | None = None


class BatchSubmitRequest(BaseModel):
    file_paths: list[str]
    options: AnalysisOptions | None = None


class BatchSubmitResponse(BaseModel):
    task_ids: list[str]
    message: str


class QueueStatsResponse(BaseModel):
    pending: int
    ghidra_waiting: int
    report_waiting: int
    total_tasks: int
    completed: int
    failed: int


app = FastAPI(
    title="ThreatScope API",
    description="AI-driven malware analysis framework",
    version="0.2.0",
)

# CORS middleware - allow frontend to access API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register WebSocket router
app.include_router(websocket_router)

@app.on_event("startup")
async def startup_event():
    scheduler = get_scheduled_coordinator()
    await scheduler.start()


@app.on_event("shutdown")
async def shutdown_event():
    if _scheduled_coordinator:
        await _scheduled_coordinator.stop()


@app.get("/health")
async def health_check():
    return {"status": "healthy"}


@app.post("/analyze", response_model=TaskResponse)
async def analyze_file(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    enable_ghidra: bool = True,
    enable_dynamic: bool = True,
    enable_threat_intel: bool = True,
):
    """Upload and analyze a file."""
    import logging
    logger = logging.getLogger(__name__)
    
    task_id = str(uuid.uuid4())[:8]
    logger.info(f"Creating task {task_id}")

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    content = await file.read()
    file_path.write_bytes(content)
    logger.info(f"File saved to {file_path}")

    # Save to database
    db = get_db()
    db.create_task(
        task_id=task_id,
        file_path=str(file_path),
        file_name=file.filename,
        options={
            "enable_ghidra": enable_ghidra,
            "enable_dynamic": enable_dynamic,
            "enable_threat_intel": enable_threat_intel,
        },
    )
    logger.info(f"Task {task_id} created in database")

    # Use BackgroundTasks with a SYNC function - FastAPI runs it in threadpool
    print(f"=== ADDING BACKGROUND TASK === task_id={task_id}, enable_ghidra={enable_ghidra}", flush=True)
    logger.info(f"=== ADDING BACKGROUND TASK === task_id={task_id}, enable_ghidra={enable_ghidra}")
    background_tasks.add_task(
        run_analysis_task_sync,  # SYNC function, not async!
        task_id,
        str(file_path),
        enable_ghidra,
        enable_dynamic,
        enable_threat_intel,
    )
    print(f"=== BACKGROUND TASK ADDED === task_id={task_id}", flush=True)
    logger.info(f"=== BACKGROUND TASK ADDED === task_id={task_id}")
    return TaskResponse(
        task_id=task_id,
        status=TaskStatus.PENDING.value,
        message="Analysis started",
    )


def run_analysis_task_sync(
    task_id: str,
    file_path_str: str,
    enable_ghidra: bool,
    enable_dynamic: bool,
    enable_threat_intel: bool,
):
    """
    Synchronous wrapper for analysis task.
    FastAPI runs this in a threadpool, so it won't block the event loop.
    """
    import asyncio
    import logging
    logger = logging.getLogger(__name__)
    
    print(f"=== RUN_ANALYSIS_TASK_SYNC CALLED === task_id={task_id}, enable_ghidra={enable_ghidra}", flush=True)
    logger.info(f"=== RUN_ANALYSIS_TASK_SYNC CALLED === task_id={task_id}, enable_ghidra={enable_ghidra}")
    # Create a new event loop for this thread
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    
    try:
        loop.run_until_complete(
            run_analysis_task(
                task_id,
                Path(file_path_str),
                enable_ghidra,
                enable_dynamic,
                enable_threat_intel,
            )
        )
    except Exception as e:
        logger.error(f"Task {task_id} failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        db = get_db()
        db.update_task_status(task_id, "failed", str(e))
    finally:
        loop.close()

async def run_stage_1_4_with_saving(
    coordinator,
    task_id: str,
    file_path: Path,
    enable_dynamic: bool,
    enable_threat_intel: bool,
    progress_callback,
    save_step_result,
    logger,
) -> dict[str, Any]:
    """Run Stage 1-4 with step-by-step database saving.
    
    Each step result is saved to the database immediately after completion,
    allowing the frontend to display progress in real-time.
    """
    from tools.base import AnalysisResult
    
    static_analyzer = coordinator.static_analyzer
    output: dict[str, Any] = {
        "file_path": str(file_path),
        "file_name": file_path.name,
        "file_size": file_path.stat().st_size if file_path.exists() else 0,
    }
    
    # Step 1: Hash calculation
    await progress_callback("hash", "Hash Calculation", "running", None)
    hash_result = await static_analyzer.hash_calculator.analyze(file_path)
    if isinstance(hash_result, AnalysisResult) and hash_result.success:
        output["hashes"] = hash_result.data
        await save_step_result("hashes", hash_result.data)
        await progress_callback("hash", "Hash Calculation", "completed", {
            "md5": hash_result.data.get("md5", "")[:16] + "...",
            "sha256": hash_result.data.get("sha256", "")[:16] + "...",
        })
    else:
        output["hashes"] = {"error": str(hash_result)}
        await save_step_result("hashes", {"error": str(hash_result)})
        await progress_callback("hash", "Hash Calculation", "failed", None)
    
    # Step 2: String extraction
    await progress_callback("strings", "String Extraction", "running", None)
    string_result = await static_analyzer.string_extractor.analyze(file_path)
    if isinstance(string_result, AnalysisResult) and string_result.success:
        output["strings"] = string_result.data
        await save_step_result("strings", string_result.data)
        await progress_callback("strings", "String Extraction", "completed", {
            "urls": len(string_result.data.get("urls", [])),
            "ips": len(string_result.data.get("ips", [])),
            "domains": len(string_result.data.get("domains", [])),
        })
    else:
        output["strings"] = {"error": str(string_result)}
        await save_step_result("strings", {"error": str(string_result)})
        await progress_callback("strings", "String Extraction", "failed", None)
    
    # Step 3: ELF parsing
    await progress_callback("elf", "ELF Parsing", "running", None)
    elf_result = await static_analyzer.elf_parser.analyze(file_path)
    if isinstance(elf_result, AnalysisResult) and elf_result.success:
        output["elf"] = elf_result.data
        await save_step_result("elf", elf_result.data)
        await progress_callback("elf", "ELF Parsing", "completed", {
            "format": elf_result.data.get("format", ""),
            "arch": elf_result.data.get("arch", ""),
            "imports": len(elf_result.data.get("imports", [])),
        })
        
        # Step 4: Function classification (depends on ELF)
        imports = elf_result.data.get("imports", [])
        if imports:
            await progress_callback("func_class", "Function Classification", "running", None)
            output["function_categories"] = static_analyzer.function_classifier.get_category_summary(imports)
            await save_step_result("function_categories", output["function_categories"])
            categories_found = [k for k, v in output["function_categories"].items() if v]
            await progress_callback("func_class", "Function Classification", "completed", {
                "categories": len(categories_found),
            })
            
            # Step 5: MITRE ATT&CK mapping (depends on ELF)
            await progress_callback("mitre", "MITRE ATT&CK Mapping", "running", None)
            output["mitre_mapping"] = static_analyzer.mitre_mapper.get_mapping_summary(imports)
            await save_step_result("mitre_mapping", output["mitre_mapping"])
            techniques = output["mitre_mapping"].get("techniques", [])
            await progress_callback("mitre", "MITRE ATT&CK Mapping", "completed", {
                "techniques": len(techniques) if isinstance(techniques, list) else 0,
            })
        else:
            # No imports - mark as skipped
            await progress_callback("func_class", "Function Classification", "completed", {"reason": "No imports"})
            await progress_callback("mitre", "MITRE ATT&CK Mapping", "completed", {"reason": "No imports"})
    else:
        output["elf"] = {"error": str(elf_result)}
        await save_step_result("elf", {"error": str(elf_result)})
        await progress_callback("elf", "ELF Parsing", "failed", None)
    
    # Step 6: YARA scanning
    await progress_callback("yara", "YARA Scanning", "running", None)
    yara_result = await static_analyzer.yara_scanner.analyze(file_path)
    if isinstance(yara_result, AnalysisResult) and yara_result.success:
        output["yara"] = yara_result.data
        await save_step_result("yara", yara_result.data)
        matches = yara_result.data.get("matches", [])
        await progress_callback("yara", "YARA Scanning", "completed", {
            "matches": len(matches),
            "rules": matches[:3] if matches else [],
        })
    else:
        output["yara"] = {"error": str(yara_result)}
        await save_step_result("yara", {"error": str(yara_result)})
        await progress_callback("yara", "YARA Scanning", "failed", None)
    
    # Step 7: Threat intelligence
    if enable_threat_intel:
        await progress_callback("threat_intel", "Threat Intelligence", "running", None)
        threat_intel_results = await coordinator._query_threat_intel(output)
        output["threat_intel"] = threat_intel_results
        await save_step_result("threat_intel", threat_intel_results)
        found_count = sum(
            1 for source in threat_intel_results.get("hash_lookup", {}).values()
            if isinstance(source, dict) and source.get("found")
        )
        await progress_callback("threat_intel", "Threat Intelligence", "completed", {
            "sources_found": found_count,
        })
    
    # Step 8: Dynamic analysis
    if enable_dynamic:
        await progress_callback("dynamic", "Dynamic Analysis", "running", None)
        dynamic_results = await coordinator._run_dynamic_analysis(file_path, output)
        output["dynamic_analysis"] = dynamic_results
        await save_step_result("dynamic_analysis", dynamic_results)
        syscalls = dynamic_results.get("syscalls", [])
        await progress_callback("dynamic", "Dynamic Analysis", "completed", {
            "syscalls": len(syscalls) if isinstance(syscalls, list) else 0,
            "success": dynamic_results.get("success", False),
        })
    else:
        output["dynamic_analysis"] = {}
        await save_step_result("dynamic_analysis", {})
        await progress_callback("dynamic", "Dynamic Analysis", "completed", {"skipped": True})
    
    return output



async def run_analysis_task(
    task_id: str,
    file_path: Path,
    enable_ghidra: bool,
    enable_dynamic: bool,
    enable_threat_intel: bool,
):
    """Async analysis task - runs in a separate thread's event loop."""
    db = get_db()
    import logging
    logger = logging.getLogger(__name__)
    
    logger.info(f"=== RUN_ANALYSIS_TASK STARTED === task_id={task_id}, enable_ghidra={enable_ghidra}")
    # Create progress callback that saves each step to database immediately
    async def progress_callback(step_id: str, step_name: str, status: str, preview: dict | None):
        """Save each step result to database as it completes."""
        logger.info(f"Task {task_id}: Step {step_id} - {status}")
        
        # Notify WebSocket clients
        if status == "running":
            await notify_step_progress(task_id, step_id, step_name, "running", None)
        elif status == "completed":
            await notify_step_progress(task_id, step_id, step_name, "completed", preview)
        elif status == "failed":
            await notify_step_progress(task_id, step_id, step_name, "failed", preview)
    
    # Callback to save step results to database
    async def save_step_result(key: str, value: dict):
        """Save individual step result to database."""
        db.merge_stage_1_4_result(task_id, key, value)
        logger.info(f"Task {task_id}: Saved {key} to database")
    
    try:
        logger.info(f"Task {task_id}: Starting analysis for {file_path}")
        
        coordinator = get_coordinator()
        
        # ========== Stage 1-4: Static + Threat Intel + Dynamic ==========
        db.update_task_status(task_id, TaskStatus.STAGE_1_4.value)
        
        # Run static analysis with step-by-step saving
        stage_1_4_results = await run_stage_1_4_with_saving(
            coordinator=coordinator,
            task_id=task_id,
            file_path=file_path,
            enable_dynamic=enable_dynamic,
            enable_threat_intel=enable_threat_intel,
            progress_callback=progress_callback,
            save_step_result=save_step_result,
            logger=logger,
        )
        
        await notify_step_completed(task_id, "stage_1_4", "completed")
        logger.info(f"Task {task_id}: Stage 1-4 completed")
        
        # ========== Stage 5: Ghidra Analysis ==========
        ghidra_results = {}
        logger.info(f"Task {task_id}: enable_ghidra={enable_ghidra}")
        if enable_ghidra:
            logger.info(f"Task {task_id}: Starting Stage 5 Ghidra analysis")
            db.update_task_status(task_id, TaskStatus.STAGE_5.value)
            await notify_step_progress(task_id, "ghidra", "Ghidra Deep Analysis", "running", None)
            
            ghidra_results = await coordinator.run_stage_5(
                static_results=stage_1_4_results,
                file_path=file_path,
                progress_callback=progress_callback,
            )
            
            # Save Ghidra results immediately
            db.update_task_result(task_id, "ghidra_results", ghidra_results)
            ai_analysis = ghidra_results.get("ai_analysis", {})
            await notify_step_progress(task_id, "ghidra", "Ghidra Deep Analysis", "completed", {
                "functions_analyzed": len(ai_analysis.get("analyzed_functions", [])),
                "key_findings": len(ai_analysis.get("key_findings", [])),
            })
            logger.info(f"Task {task_id}: Stage 5 (Ghidra) completed")
        else:
            await notify_step_progress(task_id, "ghidra", "Ghidra Deep Analysis", "skipped", None)
        
        # ========== Stage 6: Report Generation ==========
        db.update_task_status(task_id, TaskStatus.STAGE_6.value)
        await notify_step_progress(task_id, "report", "AI Report Generation", "running", None)
        
        report_result = await coordinator.run_stage_6(
            static_results=stage_1_4_results,
            ghidra_results=ghidra_results,
        )
        
        # Save report immediately
        report = report_result.get("report", report_result)
        db.update_task_result(task_id, "report", report)
        await notify_step_progress(task_id, "report", "AI Report Generation", "completed", {
            "verdict": report.get("verdict", "unknown"),
            "confidence": report.get("confidence", 0),
        })
        logger.info(f"Task {task_id}: Stage 6 (Report) completed")
        
        # ========== Mark Completed ==========
        db.update_task_status(task_id, TaskStatus.COMPLETED.value)
        
        verdict = report.get("verdict", "unknown")
        await notify_task_completed(task_id, "completed", {"verdict": verdict})
        logger.info(f"Task {task_id}: Completed with verdict: {verdict}")

    except Exception as e:
        import traceback
        logger.error(f"Task {task_id}: Failed with error: {e}")
        logger.error(traceback.format_exc())
        db.update_task_status(task_id, TaskStatus.FAILED.value, error=str(e))
        await notify_task_completed(task_id, "failed", {"error": str(e)})

    finally:
        try:
            file_path.unlink()
        except Exception:
            pass


@app.get("/tasks/{task_id}", response_model=AnalysisResponse)
async def get_task_status(task_id: str):
    db = get_db()
    task = db.get_task(task_id)
    
    if not task:
        # Try scheduled coordinator
        scheduled = get_scheduled_coordinator()
        task_status = scheduled.get_task_status(task_id)
        if task_status:
            return AnalysisResponse(
                task_id=task_id,
                status=task_status["status"],
                result=None,
                error=task_status.get("error"),
            )
        raise HTTPException(status_code=404, detail="Task not found")

    return AnalysisResponse(
        task_id=task_id,
        status=task["status"],
        result=task.get("result"),
        error=task.get("error"),
    )



def _extract_result_summary(result: dict[str, Any] | None) -> dict[str, Any] | None:
    """Extract summary from result for list view."""
    if not result:
        return None
    
    summary = {}
    
    # Extract malware report summary
    if "malware_report" in result:
        report = result["malware_report"]
        if isinstance(report, dict):
            summary["malware_report"] = {
                "verdict": report.get("verdict"),
                "confidence": report.get("confidence"),
                "family": report.get("family"),
            }
    
    return summary if summary else None


@app.get("/tasks")
async def list_tasks():
    db = get_db()
    tasks = db.get_all_tasks(limit=100)
    stats = db.get_stats()
    
    # Map stats to expected format
    queue_stats = {
        "pending": stats.get("pending", 0),
        "ghidra_waiting": stats.get("queued", 0),
        "report_waiting": stats.get("stage_6", 0),
        "total_tasks": stats.get("total", 0),
        "completed": stats.get("completed", 0),
        "failed": stats.get("failed", 0),
    }

    return {
        "tasks": [
            {
                "id": t["id"],
                "status": t["status"],
                "file_name": t.get("file_name"),
                "result": _extract_result_summary(t.get("result")),
            }
            for t in tasks
        ],
        "queue_stats": queue_stats,
    }


@app.delete("/tasks/{task_id}")
async def delete_task(task_id: str):
    db = get_db()
    if not db.delete_task(task_id):
        raise HTTPException(status_code=404, detail="Task not found")
    return {"message": "Task deleted"}


@app.post("/batch/submit", response_model=BatchSubmitResponse)
async def submit_batch(request: BatchSubmitRequest):
    scheduled = get_scheduled_coordinator()
    task_ids = await scheduled.submit_batch(request.file_paths)

    return BatchSubmitResponse(
        task_ids=task_ids,
        message=f"Submitted {len(task_ids)} tasks for analysis",
    )


@app.get("/batch/stats", response_model=QueueStatsResponse)
async def get_queue_stats():
    scheduled = get_scheduled_coordinator()
    stats = scheduled.get_queue_stats()

    return QueueStatsResponse(**stats)


@app.post("/analyze/sync", response_model=AnalysisResponse)
async def analyze_file_sync(
    file: UploadFile = File(...),
    enable_ghidra: bool = True,
    enable_dynamic: bool = True,
    enable_threat_intel: bool = True,
):
    task_id = str(uuid.uuid4())[:8]

    temp_dir = Path(tempfile.gettempdir()) / "threatscope"
    temp_dir.mkdir(exist_ok=True)
    file_path = temp_dir / f"{task_id}_{file.filename}"

    try:
        content = await file.read()
        file_path.write_bytes(content)

        coordinator = get_coordinator()
        result = await coordinator.analyze(
            file_path=file_path,
            enable_ghidra=enable_ghidra,
            enable_dynamic=enable_dynamic,
            enable_threat_intel=enable_threat_intel,
        )

        return AnalysisResponse(
            task_id=task_id,
            status=TaskStatus.COMPLETED.value,
            result=result,
        )

    except Exception as e:
        return AnalysisResponse(
            task_id=task_id,
            status=TaskStatus.FAILED.value,
            error=str(e),
        )

    finally:
        try:
            file_path.unlink()
        except Exception:
            pass


def create_app() -> FastAPI:
    return app
