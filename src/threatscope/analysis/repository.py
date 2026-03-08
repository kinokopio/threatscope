"""Task repository with Repository pattern.

This module provides data access for analysis tasks using the
Repository pattern, separating data access from business logic.

Updated for static analysis refactor:
- Added file_type field (diec output)
- Added capa field (capability detection)
- Removed elf, function_categories, mitre_mapping (replaced by capa)
"""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from src.threatscope.api.schemas import TaskStatus


class TaskRepository:
    """Repository for analysis task persistence.

    Uses SQLite with WAL mode for better concurrency.
    Implements the Repository pattern for clean data access.
    """

    def __init__(self, db_path: str | Path = ".threatscope/tasks.db"):
        """Initialize repository.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _init_schema(self) -> None:
        """Initialize database schema."""
        with self._connection() as conn:
            # Check if table exists and has correct schema
            cursor = conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='tasks'"
            )
            table_exists = cursor.fetchone() is not None

            if not table_exists:
                # Create new table with current schema
                conn.execute("""
                    CREATE TABLE tasks (
                        id TEXT PRIMARY KEY,
                        file_path TEXT NOT NULL,
                        file_name TEXT,
                        status TEXT NOT NULL DEFAULT 'pending',
                        current_step TEXT,
                        created_at TEXT NOT NULL,
                        updated_at TEXT NOT NULL,
                        error TEXT,
                        retry_count INTEGER DEFAULT 0,
                        -- Static analysis results (new structure)
                        hashes TEXT,
                        file_type TEXT,           -- diec output (format, arch, packers, etc.)
                        capa TEXT,                -- capa output (capabilities, attack, mbc)
                        strings TEXT,
                        yara TEXT,
                        -- Threat intelligence
                        threat_intel TEXT,
                        -- Dynamic analysis
                        dynamic_analysis TEXT,
                        -- Ghidra analysis
                        ghidra_analysis TEXT,
                        -- Final report (unified report)
                        unified_report TEXT,
                        -- Options
                        options TEXT,
                        -- Step-level progress tracking for parallel execution
                        steps_status TEXT
                    )
                """)
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at)")
                conn.commit()

    @contextmanager
    def _connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with proper configuration."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    # =========================================================================
    # CRUD Operations
    # =========================================================================

    def create_task(
        self,
        task_id: str,
        file_path: str,
        file_name: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new task.

        Args:
            task_id: Unique task identifier.
            file_path: Path to the file being analyzed.
            file_name: Original file name.
            options: Analysis options.

        Returns:
            Created task as dictionary.
        """
        now = datetime.now().isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                INSERT INTO tasks
                    (id, file_path, file_name, status, created_at, updated_at, options)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    task_id,
                    file_path,
                    file_name,
                    TaskStatus.PENDING.value,
                    now,
                    now,
                    json.dumps(options) if options else None,
                ),
            )
            conn.commit()
        return self.get_task(task_id)  # type: ignore[return-value]

    def get_task(self, task_id: str) -> dict[str, Any] | None:
        """Get task by ID.

        Args:
            task_id: Task identifier.

        Returns:
            Task as dictionary or None if not found.
        """
        with self._connection() as conn:
            row = conn.execute("SELECT * FROM tasks WHERE id = ?", (task_id,)).fetchone()
            if row:
                return self._row_to_dict(row)
        return None

    def get_all_tasks(
        self,
        limit: int = 100,
        offset: int = 0,
        status: str | None = None,
        verdict: str | None = None,
        file_type: str | None = None,
        from_date: str | None = None,
        to_date: str | None = None,
        search: str | None = None,
    ) -> list[dict[str, Any]]:
        """Get all tasks with optional filtering."""
        with self._connection() as conn:
            conditions = []
            params: list[Any] = []

            if status:
                conditions.append("status = ?")
                params.append(status)

            if verdict:
                conditions.append("json_extract(unified_report, '$.verdict') = ?")
                params.append(verdict)

            if file_type:
                conditions.append(
                    "(json_extract(file_type, '$.category') = ? OR json_extract(file_type, '$.format') = ?)"
                )
                params.extend([file_type, file_type])

            if from_date:
                conditions.append("created_at >= ?")
                params.append(from_date)

            if to_date:
                conditions.append("created_at <= ?")
                params.append(to_date + " 23:59:59")

            if search:
                search_pattern = f"%{search}%"
                conditions.append(
                    "(file_name LIKE ? OR json_extract(unified_report, '$.family') LIKE ? OR json_extract(hashes, '$.sha256') LIKE ?)"
                )
                params.extend([search_pattern, search_pattern, search_pattern])

            where_clause = " AND ".join(conditions) if conditions else "1=1"
            params.extend([limit, offset])

            rows = conn.execute(
                f"""
                SELECT * FROM tasks
                WHERE {where_clause}
                ORDER BY created_at DESC
                LIMIT ? OFFSET ?
                """,
                params,
            ).fetchall()
            return [self._row_to_dict(row) for row in rows]

    def update_task_status(
        self,
        task_id: str,
        status: str,
        error: str | None = None,
    ) -> None:
        """Update task status.

        Args:
            task_id: Task identifier.
            status: New status value.
            error: Error message if failed.
        """
        now = datetime.now().isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET status = ?, updated_at = ?, error = ?
                WHERE id = ?
                """,
                (status, now, error, task_id),
            )
            conn.commit()

    def update_task_result(
        self,
        task_id: str,
        result_type: str,
        result: dict[str, Any],
    ) -> None:
        """Update task result for a specific step.

        Args:
            task_id: Task identifier.
            result_type: Type of result (hashes, file_type, capa, strings, yara,
                         threat_intel, dynamic_analysis, ghidra_analysis,
                         malware_report).
            result: Result data.

        Raises:
            ValueError: If result_type is invalid.
        """
        valid_types = (
            "hashes",
            "file_type",
            "capa",
            "strings",
            "yara",
            "threat_intel",
            "dynamic_analysis",
            "ghidra_analysis",
            "unified_report",
        )
        if result_type not in valid_types:
            raise ValueError(f"Invalid result type: {result_type}. Must be one of {valid_types}")

        now = datetime.now().isoformat()
        with self._connection() as conn:
            conn.execute(
                f"""
                UPDATE tasks
                SET {result_type} = ?, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(result), now, task_id),
            )
            conn.commit()

    def update_current_step(self, task_id: str, step_name: str) -> None:
        """Update the current step being executed.

        Args:
            task_id: Task identifier.
            step_name: Name of the current step.
        """
        now = datetime.now().isoformat()
        with self._connection() as conn:
            conn.execute(
                """
                UPDATE tasks
                SET current_step = ?, updated_at = ?
                WHERE id = ?
                """,
                (step_name, now, task_id),
            )
            conn.commit()

    def update_step_status(
        self,
        task_id: str,
        step_id: str,
        status: str,
        preview: dict[str, Any] | None = None,
    ) -> None:
        """Update status for a specific analysis step.

        Supports parallel execution tracking - each step has independent status.

        Args:
            task_id: Task identifier.
            step_id: Step identifier (e.g., 'capa', 'strings', 'yara').
            status: Step status ('pending', 'running', 'completed', 'failed', 'skipped').
            preview: Optional preview data for the step.
        """
        now = datetime.now().isoformat()
        with self._connection() as conn:
            row = conn.execute("SELECT steps_status FROM tasks WHERE id = ?", (task_id,)).fetchone()

            current = json.loads(row["steps_status"]) if row and row["steps_status"] else {}

            current[step_id] = {
                "status": status,
                "updated_at": now,
            }
            if preview:
                current[step_id]["preview"] = preview

            conn.execute(
                """
                UPDATE tasks
                SET steps_status = ?, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(current), now, task_id),
            )
            conn.commit()

    def get_steps_status(self, task_id: str) -> dict[str, Any]:
        """Get status of all analysis steps.

        Args:
            task_id: Task identifier.

        Returns:
            Dictionary mapping step_id to status info.
        """
        with self._connection() as conn:
            row = conn.execute("SELECT steps_status FROM tasks WHERE id = ?", (task_id,)).fetchone()

            if row and row["steps_status"]:
                return json.loads(row["steps_status"])
        return {}

    def delete_task(self, task_id: str) -> bool:
        """Delete a task.

        Args:
            task_id: Task identifier.

        Returns:
            True if deleted, False if not found.
        """
        with self._connection() as conn:
            cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            return cursor.rowcount > 0

    # =========================================================================
    # Statistics
    # =========================================================================

    def get_stats(self) -> dict[str, Any]:
        """Get task statistics.

        Returns:
            Dictionary with task counts by status and verdict distribution.
        """
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT status, COUNT(*) as count
                FROM tasks
                GROUP BY status
                """
            ).fetchall()
            stats: dict[str, Any] = {row["status"]: row["count"] for row in rows}

            total = conn.execute("SELECT COUNT(*) as count FROM tasks").fetchone()
            stats["total"] = total["count"] if total else 0

            verdict_row = conn.execute(
                """
                SELECT
                    SUM(CASE WHEN json_extract(unified_report, '$.verdict') = 'malicious' THEN 1 ELSE 0 END) as malicious,
                    SUM(CASE WHEN json_extract(unified_report, '$.verdict') = 'suspicious' THEN 1 ELSE 0 END) as suspicious,
                    SUM(CASE WHEN json_extract(unified_report, '$.verdict') = 'benign' THEN 1 ELSE 0 END) as benign
                FROM tasks
                WHERE unified_report IS NOT NULL
                """
            ).fetchone()

            stats["verdict_stats"] = {
                "malicious": verdict_row["malicious"] or 0 if verdict_row else 0,
                "suspicious": verdict_row["suspicious"] or 0 if verdict_row else 0,
                "benign": verdict_row["benign"] or 0 if verdict_row else 0,
            }

        return stats

    # =========================================================================
    # Helpers
    # =========================================================================

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert database row to dictionary.

        Args:
            row: Database row.

        Returns:
            Task as dictionary with parsed JSON fields.
        """
        data = dict(row)

        # Parse JSON fields
        json_fields = (
            "hashes",
            "file_type",
            "capa",
            "strings",
            "yara",
            "threat_intel",
            "dynamic_analysis",
            "ghidra_analysis",
            "unified_report",
            "options",
            "steps_status",
        )
        for field in json_fields:
            if data.get(field):
                try:
                    data[field] = json.loads(data[field])
                except json.JSONDecodeError:
                    data[field] = None

        # Build result field for API compatibility
        result = {}
        if data.get("hashes"):
            result["hashes"] = data["hashes"]
        if data.get("file_type"):
            result["file_type"] = data["file_type"]
        if data.get("capa"):
            result["capa"] = data["capa"]
        if data.get("strings"):
            result["strings"] = data["strings"]
        if data.get("yara"):
            result["yara"] = data["yara"]
        if data.get("threat_intel"):
            result["threat_intel"] = data["threat_intel"]
        if data.get("dynamic_analysis"):
            result["dynamic_analysis"] = data["dynamic_analysis"]
        if data.get("ghidra_analysis"):
            result["ghidra_analysis"] = data["ghidra_analysis"]
        if data.get("unified_report"):
            result["unified_report"] = data["unified_report"]

        data["result"] = result if result else None
        return data
