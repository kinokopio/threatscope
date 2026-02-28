"""Task repository with Repository pattern.

This module provides data access for analysis tasks using the
Repository pattern, separating data access from business logic.
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_name TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    current_step TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error TEXT,
                    retry_count INTEGER DEFAULT 0,
                    -- Static analysis results (each step separate)
                    hashes TEXT,
                    strings TEXT,
                    elf TEXT,
                    yara TEXT,
                    function_categories TEXT,
                    mitre_mapping TEXT,
                    -- Threat intelligence
                    threat_intel TEXT,
                    -- Dynamic analysis
                    dynamic_analysis TEXT,
                    -- Ghidra analysis
                    ghidra_analysis TEXT,
                    -- Final report
                    malware_report TEXT,
                    -- Options
                    options TEXT
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
        return self.get_task(task_id)

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
    ) -> list[dict[str, Any]]:
        """Get all tasks with optional filtering.

        Args:
            limit: Maximum number of tasks to return.
            offset: Number of tasks to skip.
            status: Filter by status.

        Returns:
            List of tasks as dictionaries.
        """
        with self._connection() as conn:
            if status:
                rows = conn.execute(
                    """
                    SELECT * FROM tasks
                    WHERE status = ?
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (status, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM tasks
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                    """,
                    (limit, offset),
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
            result_type: Type of result (hashes, strings, elf, yara, function_categories,
                         mitre_mapping, threat_intel, dynamic_analysis, ghidra_analysis,
                         malware_report).
            result: Result data.

        Raises:
            ValueError: If result_type is invalid.
        """
        valid_types = (
            "hashes", "strings", "elf", "yara", "function_categories",
            "mitre_mapping", "threat_intel", "dynamic_analysis",
            "ghidra_analysis", "malware_report"
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

    def get_stats(self) -> dict[str, int]:
        """Get task statistics.

        Returns:
            Dictionary with task counts by status.
        """
        with self._connection() as conn:
            rows = conn.execute(
                """
                SELECT status, COUNT(*) as count
                FROM tasks
                GROUP BY status
                """
            ).fetchall()
            stats = {row["status"]: row["count"] for row in rows}

            total = conn.execute("SELECT COUNT(*) as count FROM tasks").fetchone()
            stats["total"] = total["count"] if total else 0

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
            "hashes", "strings", "elf", "yara", "function_categories",
            "mitre_mapping", "threat_intel", "dynamic_analysis",
            "ghidra_analysis", "malware_report", "options"
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
        if data.get("strings"):
            result["strings"] = data["strings"]
        if data.get("elf"):
            result["elf"] = data["elf"]
        if data.get("yara"):
            result["yara"] = data["yara"]
        if data.get("function_categories"):
            result["function_categories"] = data["function_categories"]
        if data.get("mitre_mapping"):
            result["mitre_mapping"] = data["mitre_mapping"]
        if data.get("threat_intel"):
            result["threat_intel"] = data["threat_intel"]
        if data.get("dynamic_analysis"):
            result["dynamic_analysis"] = data["dynamic_analysis"]
        if data.get("ghidra_analysis"):
            result["ghidra_analysis"] = data["ghidra_analysis"]
        if data.get("malware_report"):
            result["malware_report"] = data["malware_report"]

        data["result"] = result if result else None
        return data
