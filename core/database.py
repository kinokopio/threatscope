"""SQLite database for task persistence."""

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator

from core.task import AnalysisTask, TaskStatus


class TaskDatabase:
    """SQLite database for persisting analysis tasks."""

    def __init__(self, db_path: str | Path = ".threatscope/tasks.db"):
        """Initialize database.

        Args:
            db_path: Path to SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        """Initialize database schema."""
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tasks (
                    id TEXT PRIMARY KEY,
                    file_path TEXT NOT NULL,
                    file_name TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    error TEXT,
                    retry_count INTEGER DEFAULT 0,
                    stage_1_4_results TEXT,
                    ghidra_results TEXT,
                    report TEXT,
                    options TEXT
                )
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status)
            """)
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_tasks_created_at ON tasks(created_at)
            """)
            conn.commit()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Get database connection with context manager."""
        conn = sqlite3.connect(
            str(self.db_path),
            timeout=30.0,  # Wait up to 30 seconds for locks
            check_same_thread=False,
        )
        conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrency
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=30000")
        try:
            yield conn
        finally:
            conn.close()

    def create_task(
        self,
        task_id: str,
        file_path: str,
        file_name: str | None = None,
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Create a new task.

        Args:
            task_id: Unique task ID.
            file_path: Path to the file being analyzed.
            file_name: Original file name.
            options: Analysis options.

        Returns:
            Created task as dictionary.
        """
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO tasks (id, file_path, file_name, status, created_at, updated_at, options)
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
            task_id: Task ID.

        Returns:
            Task as dictionary or None if not found.
        """
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
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
        with self._get_connection() as conn:
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
            task_id: Task ID.
            status: New status.
            error: Error message if failed.
        """
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
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
        """Update task result.

        Args:
            task_id: Task ID.
            result_type: Type of result (stage_1_4_results, ghidra_results, report).
            result: Result data.
        """
        if result_type not in ("stage_1_4_results", "ghidra_results", "report"):
            raise ValueError(f"Invalid result type: {result_type}")

        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            conn.execute(
                f"""
                UPDATE tasks 
                SET {result_type} = ?, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(result), now, task_id),
            )
            conn.commit()


    def merge_stage_1_4_result(
        self,
        task_id: str,
        key: str,
        value: Any,
    ) -> None:
        """Merge a single result into stage_1_4_results.

        This allows incremental updates as each analysis step completes.

        Args:
            task_id: Task ID.
            key: Result key (e.g., 'hashes', 'strings', 'elf').
            value: Result value.
        """
        now = datetime.now().isoformat()
        with self._get_connection() as conn:
            # Get existing results
            row = conn.execute(
                "SELECT stage_1_4_results FROM tasks WHERE id = ?", (task_id,)
            ).fetchone()
            
            existing = {}
            if row and row["stage_1_4_results"]:
                try:
                    existing = json.loads(row["stage_1_4_results"])
                except json.JSONDecodeError:
                    existing = {}
            
            # Merge new result
            existing[key] = value
            
            # Save back
            conn.execute(
                """
                UPDATE tasks 
                SET stage_1_4_results = ?, updated_at = ?
                WHERE id = ?
                """,
                (json.dumps(existing), now, task_id),
            )
            conn.commit()
    def delete_task(self, task_id: str) -> bool:
        """Delete a task.

        Args:
            task_id: Task ID.

        Returns:
            True if deleted, False if not found.
        """
        with self._get_connection() as conn:
            cursor = conn.execute("DELETE FROM tasks WHERE id = ?", (task_id,))
            conn.commit()
            return cursor.rowcount > 0

    def get_stats(self) -> dict[str, int]:
        """Get task statistics.

        Returns:
            Dictionary with task counts by status.
        """
        with self._get_connection() as conn:
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

    def _row_to_dict(self, row: sqlite3.Row) -> dict[str, Any]:
        """Convert database row to dictionary.

        Args:
            row: Database row.

        Returns:
            Task as dictionary.
        """
        data = dict(row)

        # Parse JSON fields
        for field in ("stage_1_4_results", "ghidra_results", "report", "options"):
            if data.get(field):
                try:
                    data[field] = json.loads(data[field])
                except json.JSONDecodeError:
                    data[field] = None

        # Build result field for API compatibility
        result = None
        if data.get("report") or data.get("stage_1_4_results"):
            result = {}
            if data.get("stage_1_4_results"):
                result.update(data["stage_1_4_results"])
                result["metadata"] = {
                    "file_name": data.get("file_name"),
                    "hashes": data["stage_1_4_results"].get("hashes", {}),
                }
            if data.get("report"):
                result["malware_report"] = data["report"]
            if data.get("ghidra_results"):
                result["ghidra_analysis"] = data["ghidra_results"]

        data["result"] = result

        return data


# Global database instance
_db: TaskDatabase | None = None


def get_database(db_path: str | Path = ".threatscope/tasks.db") -> TaskDatabase:
    """Get or create global database instance.

    Args:
        db_path: Path to database file.

    Returns:
        TaskDatabase instance.
    """
    global _db
    if _db is None:
        _db = TaskDatabase(db_path)
    return _db
