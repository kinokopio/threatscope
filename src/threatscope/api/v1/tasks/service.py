import asyncio
import logging
import uuid
from pathlib import Path

from src.threatscope.api.schemas import TaskStatus

logger = logging.getLogger(__name__)


class TaskService:
    def __init__(self, coordinator, db):
        self.coordinator = coordinator
        self.db = db

    async def create_task_async(
        self,
        file_path: Path,
        file_name: str,
        options: dict,
    ) -> str:
        task_id = str(uuid.uuid4())
        logger.info(f"Creating analysis task {task_id} for {file_name}")

        self.db.create_task(
            task_id=task_id,
            file_path=str(file_path),
            file_name=file_name,
            options=options,
        )

        asyncio.create_task(self._run_analysis_background(task_id, file_path, options))

        return task_id

    async def _run_analysis_background(
        self,
        task_id: str,
        file_path: Path,
        options: dict,
    ) -> None:
        if self.coordinator is None:
            logger.error(f"Coordinator is None for task {task_id}")
            self.db.update_task_status(
                task_id, TaskStatus.FAILED.value, error="Coordinator not initialized"
            )
            return

        async def save_progress(
            step_id: str,
            step_name: str,
            status: str,
            preview: dict | None,
            current_results: dict | None,
        ):
            self.db.update_step_status(task_id, step_id, status, preview)

            if status == "running":
                self.db.update_current_step(task_id, step_name)

                step_to_status = {
                    "ghidra": TaskStatus.GHIDRA_ANALYSIS.value,
                    "ghidra_analysis": TaskStatus.GHIDRA_ANALYSIS.value,
                    "report": TaskStatus.REPORT_GENERATION.value,
                    "report_generation": TaskStatus.REPORT_GENERATION.value,
                }
                new_status = step_to_status.get(step_id)
                if new_status:
                    self.db.update_task_status(task_id, new_status)
                    logger.debug(f"Updated task status to {new_status}")

            if status in ("completed", "failed", "skipped") and current_results:
                step_to_field = {
                    "hash": "hashes",
                    "hashing": "hashes",
                    "file_type": "file_type",
                    "file_identification": "file_type",
                    "capa": "capa",
                    "capability_analysis": "capa",
                    "strings": "strings",
                    "string_extraction": "strings",
                    "yara": "yara",
                    "yara_scanning": "yara",
                    "threat_intel": "threat_intel",
                    "dynamic": "dynamic_analysis",
                    "dynamic_analysis": "dynamic_analysis",
                    "ghidra": "ghidra_analysis",
                    "ghidra_analysis": "ghidra_analysis",
                    "report": "unified_report",
                    "report_generation": "unified_report",
                }

                field = step_to_field.get(step_id)
                has_field = field in current_results if field else False
                logger.info(f"save_progress: {step_id=}, {status=}, {field=}, {has_field=}")
                if field and current_results and field in current_results:
                    self.db.update_task_result(task_id, field, current_results[field])
                    logger.info(f"Saved {field} to database for task {task_id}")
                else:
                    keys = list(current_results.keys()) if current_results else None
                    logger.warning(f"Did not save {step_id}: {field=}, result_keys={keys}")

        def to_bool(value, default: bool = True) -> bool:
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.lower() not in ("false", "0", "no", "off")
            return default

        try:
            self.db.update_task_status(task_id, TaskStatus.STATIC_ANALYSIS.value)

            result = await self.coordinator.analyze(
                file_path=file_path,
                enable_ghidra=to_bool(options.get("enable_ghidra"), True),
                enable_dynamic=to_bool(options.get("enable_dynamic"), True),
                enable_threat_intel=to_bool(options.get("enable_threat_intel"), True),
                enable_capa=to_bool(options.get("enable_capa"), True),
                enable_strings=to_bool(options.get("enable_strings"), True),
                enable_yara=to_bool(options.get("enable_yara"), True),
                progress_callback=save_progress,
            )

            if "error" in result:
                self.db.update_task_status(task_id, TaskStatus.FAILED.value, error=result["error"])
            else:
                static = result.get("static_analysis", {})
                for field in [
                    "hashes",
                    "file_type",
                    "capa",
                    "strings",
                    "yara",
                    "threat_intel",
                    "dynamic_analysis",
                ]:
                    if static.get(field):
                        self.db.update_task_result(task_id, field, static[field])

                if result.get("ghidra_analysis"):
                    self.db.update_task_result(
                        task_id, "ghidra_analysis", result["ghidra_analysis"]
                    )
                if result.get("report"):
                    self.db.update_task_result(task_id, "unified_report", result["report"])

                self.db.update_task_status(task_id, TaskStatus.COMPLETED.value)

        except Exception as e:
            logger.exception(f"Background analysis failed for {task_id}")
            self.db.update_task_status(task_id, TaskStatus.FAILED.value, error=str(e))

        finally:
            try:
                file_path.unlink()
            except Exception:
                pass
