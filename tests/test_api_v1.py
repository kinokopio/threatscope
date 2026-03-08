import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from fastapi.testclient import TestClient


@pytest.fixture
def mock_db():
    db = MagicMock()
    db.get_stats.return_value = {
        "total": 10,
        "completed": 5,
        "pending": 3,
        "failed": 2,
        "verdict_stats": {
            "malicious": 3,
            "suspicious": 1,
            "benign": 1,
        },
    }
    db.get_all_tasks.return_value = [
        {
            "id": "task-1",
            "status": "completed",
            "file_name": "test.exe",
            "created_at": "2026-03-08 10:00:00",
            "file_type": {"category": "pe", "format": "PE32"},
            "unified_report": {"verdict": "malicious", "family": "TestMalware"},
        },
        {
            "id": "task-2",
            "status": "pending",
            "file_name": "sample.elf",
            "created_at": "2026-03-08 11:00:00",
            "file_type": {"category": "elf", "format": "ELF64"},
            "unified_report": None,
        },
    ]
    db.get_task.return_value = {
        "id": "task-1",
        "status": "completed",
        "file_name": "test.exe",
        "file_path": "/tmp/test.exe",
        "created_at": "2026-03-08 10:00:00",
        "hashes": {"md5": "abc123", "sha256": "def456"},
        "file_type": {"category": "pe", "format": "PE32"},
        "unified_report": {"verdict": "malicious"},
    }
    return db


@pytest.fixture
def mock_coordinator():
    coordinator = MagicMock()
    coordinator.get_queue_stats.return_value = {
        "pending": 2,
        "ghidra_waiting": 1,
        "report_waiting": 0,
    }
    return coordinator


class TestSystemStats:
    def test_verdict_stats_schema(self):
        from src.threatscope.api.v1.system.schemas import VerdictStats, SystemStatsResponse

        stats = VerdictStats(malicious=5, suspicious=3, benign=2)
        assert stats.malicious == 5
        assert stats.suspicious == 3
        assert stats.benign == 2

        response = SystemStatsResponse(
            queue_stats={"pending": 1},
            database_stats={"total": 10},
            verdict_stats=stats,
        )
        assert response.verdict_stats.malicious == 5


class TestTaskListItem:
    def test_extended_fields(self):
        from src.threatscope.api.v1.tasks.schemas import TaskListItem
        from src.threatscope.api.schemas import TaskStatus

        item = TaskListItem(
            id="task-1",
            status=TaskStatus.COMPLETED,
            file_name="test.exe",
            created_at="2026-03-08 10:00:00",
            file_type="PE32",
            result_summary={"verdict": "malicious", "family": "TestMalware"},
        )
        assert item.created_at == "2026-03-08 10:00:00"
        assert item.file_type == "PE32"
        assert item.result_summary["family"] == "TestMalware"


class TestTaskCreateOptions:
    def test_new_options(self):
        from src.threatscope.api.v1.tasks.schemas import TaskCreateOptions

        options = TaskCreateOptions()
        assert options.enable_ghidra is True
        assert options.enable_dynamic is True
        assert options.enable_threat_intel is True
        assert options.enable_capa is True
        assert options.enable_strings is True
        assert options.enable_yara is True

        options_disabled = TaskCreateOptions(
            enable_capa=False,
            enable_strings=False,
            enable_yara=False,
        )
        assert options_disabled.enable_capa is False
        assert options_disabled.enable_strings is False
        assert options_disabled.enable_yara is False


class TestRepositoryGetStats:
    def test_verdict_stats_query(self, tmp_path):
        from src.threatscope.analysis.repository import TaskRepository

        db_path = tmp_path / "test.db"
        repo = TaskRepository(str(db_path))

        repo.create_task(
            task_id="task-1",
            file_path="/tmp/test.exe",
            file_name="test.exe",
        )
        repo.update_task_result("task-1", "unified_report", {"verdict": "malicious"})

        repo.create_task(
            task_id="task-2",
            file_path="/tmp/test2.exe",
            file_name="test2.exe",
        )
        repo.update_task_result("task-2", "unified_report", {"verdict": "benign"})

        stats = repo.get_stats()
        assert "verdict_stats" in stats
        assert stats["verdict_stats"]["malicious"] == 1
        assert stats["verdict_stats"]["benign"] == 1
        assert stats["verdict_stats"]["suspicious"] == 0


class TestRepositoryFiltering:
    def test_filter_by_verdict(self, tmp_path):
        from src.threatscope.analysis.repository import TaskRepository

        db_path = tmp_path / "test.db"
        repo = TaskRepository(str(db_path))

        repo.create_task(task_id="task-1", file_path="/tmp/a.exe", file_name="a.exe")
        repo.update_task_result("task-1", "unified_report", {"verdict": "malicious"})

        repo.create_task(task_id="task-2", file_path="/tmp/b.exe", file_name="b.exe")
        repo.update_task_result("task-2", "unified_report", {"verdict": "benign"})

        malicious_tasks = repo.get_all_tasks(verdict="malicious")
        assert len(malicious_tasks) == 1
        assert malicious_tasks[0]["id"] == "task-1"

        benign_tasks = repo.get_all_tasks(verdict="benign")
        assert len(benign_tasks) == 1
        assert benign_tasks[0]["id"] == "task-2"

    def test_filter_by_file_type(self, tmp_path):
        from src.threatscope.analysis.repository import TaskRepository

        db_path = tmp_path / "test.db"
        repo = TaskRepository(str(db_path))

        repo.create_task(task_id="task-1", file_path="/tmp/a.exe", file_name="a.exe")
        repo.update_task_result("task-1", "file_type", {"category": "pe", "format": "PE32"})

        repo.create_task(task_id="task-2", file_path="/tmp/b.elf", file_name="b.elf")
        repo.update_task_result("task-2", "file_type", {"category": "elf", "format": "ELF64"})

        pe_tasks = repo.get_all_tasks(file_type="pe")
        assert len(pe_tasks) == 1
        assert pe_tasks[0]["id"] == "task-1"

        elf_tasks = repo.get_all_tasks(file_type="elf")
        assert len(elf_tasks) == 1
        assert elf_tasks[0]["id"] == "task-2"

    def test_filter_by_search(self, tmp_path):
        from src.threatscope.analysis.repository import TaskRepository

        db_path = tmp_path / "test.db"
        repo = TaskRepository(str(db_path))

        repo.create_task(task_id="task-1", file_path="/tmp/malware.exe", file_name="malware.exe")
        repo.create_task(task_id="task-2", file_path="/tmp/clean.exe", file_name="clean.exe")

        results = repo.get_all_tasks(search="malware")
        assert len(results) == 1
        assert results[0]["file_name"] == "malware.exe"

    def test_filter_by_date_range(self, tmp_path):
        from src.threatscope.analysis.repository import TaskRepository

        db_path = tmp_path / "test.db"
        repo = TaskRepository(str(db_path))

        repo.create_task(task_id="task-1", file_path="/tmp/a.exe", file_name="a.exe")
        repo.create_task(task_id="task-2", file_path="/tmp/b.exe", file_name="b.exe")

        results = repo.get_all_tasks(from_date="2026-03-01", to_date="2026-03-31")
        assert len(results) == 2


class TestHelperFunctions:
    def test_extract_file_type(self):
        from src.threatscope.api.v1.tasks.router import _extract_file_type

        task_with_format = {"file_type": {"category": "pe", "format": "PE32"}}
        assert _extract_file_type(task_with_format) == "PE32"

        task_with_category_only = {"file_type": {"category": "elf"}}
        assert _extract_file_type(task_with_category_only) == "elf"

        task_without_file_type = {}
        assert _extract_file_type(task_without_file_type) is None

        task_with_none = {"file_type": None}
        assert _extract_file_type(task_with_none) is None

    def test_extract_result_summary(self):
        from src.threatscope.api.v1.tasks.router import _extract_result_summary

        task_with_report = {
            "unified_report": {
                "verdict": "malicious",
                "confidence": 0.95,
                "severity": "high",
                "family": "Emotet",
            }
        }
        summary = _extract_result_summary(task_with_report)
        assert summary["verdict"] == "malicious"
        assert summary["confidence"] == 0.95
        assert summary["family"] == "Emotet"

        task_without_report = {}
        assert _extract_result_summary(task_without_report) is None

        task_with_none_report = {"unified_report": None}
        assert _extract_result_summary(task_with_none_report) is None


class TestGhidraMcpCheck:
    @pytest.mark.asyncio
    async def test_ghidra_check_returns_false_when_unavailable(self):
        from src.threatscope.api.v1.system.router import _check_ghidra_mcp

        result = await _check_ghidra_mcp()
        assert result is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
