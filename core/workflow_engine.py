"""Workflow Engine - YAML-based analysis pipeline orchestration.

This module provides a flexible workflow engine that executes analysis
pipelines defined in YAML files. It supports:
- Sequential and parallel step execution
- Conditional branching based on results
- Step dependencies and data flow
- Error handling and retries
"""

import asyncio
import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable

import yaml

logger = logging.getLogger(__name__)


class StepStatus(Enum):
    """Status of a workflow step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


@dataclass
class StepResult:
    """Result of a workflow step execution."""

    step_id: str
    status: StepStatus
    data: dict[str, Any] = field(default_factory=dict)
    error: str | None = None
    duration_ms: int = 0


@dataclass
class WorkflowStep:
    """A single step in a workflow."""

    id: str
    name: str
    tool: str
    params: dict[str, Any] = field(default_factory=dict)
    depends_on: list[str] = field(default_factory=list)
    condition: str | None = None
    on_error: str = "fail"  # fail, skip, continue
    timeout: int = 300
    retries: int = 0


@dataclass
class WorkflowDefinition:
    """Definition of a complete workflow."""

    name: str
    description: str
    version: str
    steps: list[WorkflowStep]
    parallel_groups: list[list[str]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class WorkflowEngine:
    """Engine for executing YAML-defined workflows.

    The workflow engine loads workflow definitions from YAML files and
    executes them with proper dependency resolution, parallelization,
    and error handling.
    """

    def __init__(self, tools_registry: dict[str, Callable] | None = None):
        """Initialize workflow engine.

        Args:
            tools_registry: Dictionary mapping tool names to callable functions.
        """
        self._tools: dict[str, Callable] = tools_registry or {}
        self._results: dict[str, StepResult] = {}
        self._context: dict[str, Any] = {}

    def register_tool(self, name: str, func: Callable) -> None:
        """Register a tool function.

        Args:
            name: Tool name as referenced in workflow YAML.
            func: Async callable that implements the tool.
        """
        self._tools[name] = func

    def load_workflow(self, path: str | Path) -> WorkflowDefinition:
        """Load workflow definition from YAML file.

        Args:
            path: Path to workflow YAML file.

        Returns:
            Parsed WorkflowDefinition.
        """
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Workflow file not found: {path}")

        with open(path) as f:
            data = yaml.safe_load(f)

        return self._parse_workflow(data)

    def _parse_workflow(self, data: dict) -> WorkflowDefinition:
        """Parse workflow data into WorkflowDefinition.

        Args:
            data: Raw YAML data.

        Returns:
            WorkflowDefinition instance.
        """
        steps = []
        for step_data in data.get("steps", []):
            step = WorkflowStep(
                id=step_data["id"],
                name=step_data.get("name", step_data["id"]),
                tool=step_data["tool"],
                params=step_data.get("params", {}),
                depends_on=step_data.get("depends_on", []),
                condition=step_data.get("condition"),
                on_error=step_data.get("on_error", "fail"),
                timeout=step_data.get("timeout", 300),
                retries=step_data.get("retries", 0),
            )
            steps.append(step)

        return WorkflowDefinition(
            name=data.get("name", "unnamed"),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            steps=steps,
            parallel_groups=data.get("parallel_groups", []),
            metadata=data.get("metadata", {}),
        )

    async def execute(
        self,
        workflow: WorkflowDefinition,
        initial_context: dict[str, Any] | None = None,
        progress_callback: Callable[[str, StepStatus, dict], None] | None = None,
    ) -> dict[str, StepResult]:
        """Execute a workflow.

        Args:
            workflow: Workflow definition to execute.
            initial_context: Initial context data (e.g., file_path).
            progress_callback: Optional callback for progress updates.

        Returns:
            Dictionary of step results keyed by step ID.
        """
        self._results = {}
        self._context = initial_context or {}

        logger.info(f"Starting workflow: {workflow.name}")

        # Build dependency graph
        pending_steps = {step.id: step for step in workflow.steps}
        completed_steps: set[str] = set()

        while pending_steps:
            # Find steps that can run (all dependencies satisfied)
            ready_steps = []
            for step_id, step in pending_steps.items():
                if all(dep in completed_steps for dep in step.depends_on):
                    ready_steps.append(step)

            if not ready_steps:
                # Check for circular dependencies
                remaining = list(pending_steps.keys())
                raise RuntimeError(f"Circular dependency detected: {remaining}")

            # Check for parallel groups
            parallel_batch = self._get_parallel_batch(ready_steps, workflow.parallel_groups)

            # Execute batch (parallel or sequential)
            if len(parallel_batch) > 1:
                results = await asyncio.gather(
                    *[self._execute_step(step, progress_callback) for step in parallel_batch],
                    return_exceptions=True,
                )
                for step, result in zip(parallel_batch, results):
                    if isinstance(result, Exception):
                        self._results[step.id] = StepResult(
                            step_id=step.id,
                            status=StepStatus.FAILED,
                            error=str(result),
                        )
                    else:
                        self._results[step.id] = result
            else:
                for step in parallel_batch:
                    result = await self._execute_step(step, progress_callback)
                    self._results[step.id] = result

            # Update completed steps
            for step in parallel_batch:
                completed_steps.add(step.id)
                del pending_steps[step.id]

                # Check if we should abort on failure
                result = self._results[step.id]
                if result.status == StepStatus.FAILED and step.on_error == "fail":
                    logger.error(f"Workflow aborted due to step failure: {step.id}")
                    return self._results

        logger.info(f"Workflow completed: {workflow.name}")
        return self._results

    def _get_parallel_batch(
        self, ready_steps: list[WorkflowStep], parallel_groups: list[list[str]]
    ) -> list[WorkflowStep]:
        """Get batch of steps that can run in parallel.

        Args:
            ready_steps: Steps that are ready to run.
            parallel_groups: Defined parallel groups from workflow.

        Returns:
            List of steps to run in this batch.
        """
        ready_ids = {step.id for step in ready_steps}

        # Check if any parallel group is fully ready
        for group in parallel_groups:
            group_set = set(group)
            if group_set.issubset(ready_ids):
                return [step for step in ready_steps if step.id in group_set]

        # Otherwise, return first ready step
        return [ready_steps[0]] if ready_steps else []

    async def _execute_step(
        self,
        step: WorkflowStep,
        progress_callback: Callable[[str, StepStatus, dict], None] | None = None,
    ) -> StepResult:
        """Execute a single workflow step.

        Args:
            step: Step to execute.
            progress_callback: Optional progress callback.

        Returns:
            StepResult with execution outcome.
        """
        import time

        start_time = time.time()

        # Check condition
        if step.condition and not self._evaluate_condition(step.condition):
            logger.info(f"Skipping step {step.id}: condition not met")
            return StepResult(
                step_id=step.id,
                status=StepStatus.SKIPPED,
            )

        # Notify progress
        if progress_callback:
            progress_callback(step.id, StepStatus.RUNNING, {})

        logger.info(f"Executing step: {step.id} ({step.tool})")

        # Get tool function
        tool_func = self._tools.get(step.tool)
        if not tool_func:
            error = f"Tool not found: {step.tool}"
            logger.error(error)
            return StepResult(
                step_id=step.id,
                status=StepStatus.FAILED,
                error=error,
            )

        # Resolve parameters with context
        params = self._resolve_params(step.params)

        # Execute with retries
        last_error = None
        for attempt in range(step.retries + 1):
            try:
                result_data = await asyncio.wait_for(
                    tool_func(**params),
                    timeout=step.timeout,
                )

                # Store result in context for dependent steps
                self._context[f"results.{step.id}"] = result_data

                duration = int((time.time() - start_time) * 1000)

                if progress_callback:
                    progress_callback(step.id, StepStatus.COMPLETED, result_data)

                return StepResult(
                    step_id=step.id,
                    status=StepStatus.COMPLETED,
                    data=result_data,
                    duration_ms=duration,
                )

            except asyncio.TimeoutError:
                last_error = f"Step timed out after {step.timeout}s"
                logger.warning(f"Step {step.id} timeout (attempt {attempt + 1})")
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Step {step.id} failed (attempt {attempt + 1}): {e}")

        # All retries exhausted
        duration = int((time.time() - start_time) * 1000)

        if progress_callback:
            progress_callback(step.id, StepStatus.FAILED, {"error": last_error})

        return StepResult(
            step_id=step.id,
            status=StepStatus.FAILED,
            error=last_error,
            duration_ms=duration,
        )

    def _evaluate_condition(self, condition: str) -> bool:
        """Evaluate a condition expression.

        Args:
            condition: Condition string (e.g., "results.static.yara_matches")

        Returns:
            Boolean result of condition evaluation.
        """
        try:
            # Simple dot-notation lookup
            parts = condition.split(".")
            value = self._context
            for part in parts:
                if isinstance(value, dict):
                    value = value.get(part)
                else:
                    return False
            return bool(value)
        except Exception:
            return False

    def _resolve_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Resolve parameter references to actual values.

        Args:
            params: Parameter dictionary with possible references.

        Returns:
            Resolved parameters.
        """
        resolved = {}
        for key, value in params.items():
            if isinstance(value, str) and value.startswith("$"):
                # Reference to context value
                ref_path = value[1:]  # Remove $
                resolved[key] = self._get_context_value(ref_path)
            elif isinstance(value, dict):
                resolved[key] = self._resolve_params(value)
            else:
                resolved[key] = value
        return resolved

    def _get_context_value(self, path: str) -> Any:
        """Get value from context by dot-notation path.

        Args:
            path: Dot-notation path (e.g., "results.static.hashes")

        Returns:
            Value at path or None.
        """
        parts = path.split(".")
        value = self._context
        for part in parts:
            if isinstance(value, dict):
                value = value.get(part)
            else:
                return None
        return value

    def get_results(self) -> dict[str, StepResult]:
        """Get all step results.

        Returns:
            Dictionary of step results.
        """
        return self._results.copy()

    def get_context(self) -> dict[str, Any]:
        """Get current workflow context.

        Returns:
            Context dictionary.
        """
        return self._context.copy()


def create_default_tools_registry() -> dict[str, Callable]:
    """Create default tools registry with standard analysis tools.

    Returns:
        Dictionary mapping tool names to functions.
    """
    from clients.threat_intel import ThreatIntelClient
    from tools.static.analyzer import StaticAnalyzer

    registry = {}

    # Static analysis tools
    async def run_static_analysis(file_path: str, **kwargs) -> dict:
        analyzer = StaticAnalyzer()
        return await analyzer.analyze(file_path)

    registry["static_analysis"] = run_static_analysis

    # Threat intelligence
    async def run_threat_intel(hashes: dict, **kwargs) -> dict:
        client = ThreatIntelClient()
        return await client.query_all(hashes)

    registry["threat_intel"] = run_threat_intel

    # Hash calculation
    async def calculate_hashes(file_path: str, **kwargs) -> dict:
        from tools.static.hash_calculator import HashCalculator

        calc = HashCalculator()
        return calc.calculate(file_path)

    registry["hash_calculator"] = calculate_hashes

    # String extraction
    async def extract_strings(file_path: str, **kwargs) -> dict:
        from tools.static.string_extractor import StringExtractor

        extractor = StringExtractor()
        return extractor.extract(file_path)

    registry["string_extractor"] = extract_strings

    # ELF parsing
    async def parse_elf(file_path: str, **kwargs) -> dict:
        from tools.static.elf_parser import ELFParser

        parser = ELFParser()
        return parser.parse(file_path)

    registry["elf_parser"] = parse_elf

    # YARA scanning
    async def scan_yara(file_path: str, rules_path: str = "", **kwargs) -> dict:
        from tools.static.yara_scanner import YaraScanner

        scanner = YaraScanner(rules_path) if rules_path else YaraScanner()
        return scanner.scan(file_path)

    registry["yara_scanner"] = scan_yara

    # Function classification
    async def classify_functions(imports: list, **kwargs) -> dict:
        from tools.static.function_classifier import FunctionClassifier

        classifier = FunctionClassifier()
        return classifier.classify(imports)

    registry["function_classifier"] = classify_functions

    # MITRE mapping
    async def map_mitre(functions: dict, **kwargs) -> dict:
        from tools.static.mitre_mapper import MitreMapper

        mapper = MitreMapper()
        return mapper.map(functions)

    registry["mitre_mapper"] = map_mitre

    return registry
