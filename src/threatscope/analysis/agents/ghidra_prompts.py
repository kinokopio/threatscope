"""Prompt building logic for Ghidra AI analysis."""

import json
from pathlib import Path


def build_analysis_prompt(
    static_results: dict,
    file_path: str,
    cached_functions: list[str],
    previous_findings: list[dict],
    ghidra_info: dict,
) -> str:
    parts = [
        "分析以下二进制文件。",
        "",
        "## 二进制信息",
        f"```json\n{json.dumps(ghidra_info, indent=2)}\n```",
        "",
        "## 静态分析结果",
        f"```json\n{json.dumps(static_results, indent=2, ensure_ascii=False)[:8000]}\n```",
        "",
        f"## 样本路径\n{file_path}",
        "",
    ]

    if cached_functions:
        parts.extend(
            [
                f"## Previously Analyzed Functions ({len(cached_functions)})",
                "Check mcp__memory__memory_get_function before re-analyzing these:",
                ", ".join(cached_functions[:30]),
                "",
            ]
        )

    if previous_findings:
        findings_summary = "\n".join(
            [
                f"- [{f.get('severity', 'unknown')}] "
                f"{f.get('type', 'unknown')}: {f.get('summary', '')}"
                for f in previous_findings[:10]
            ]
        )
        parts.extend(
            [
                "## Previous Findings",
                findings_summary,
                "",
            ]
        )

    suspicious_funcs = _extract_suspicious_functions(static_results)
    if suspicious_funcs:
        parts.extend(
            [
                "## 可疑函数",
                ", ".join(suspicious_funcs[:20]),
                "",
            ]
        )

    return "\n".join(parts)


def _extract_suspicious_functions(static_results: dict) -> list[str]:
    suspicious_funcs = []
    capa_result = static_results.get("capa", {})
    capabilities = capa_result.get("capabilities", [])
    for cap in capabilities:
        if any(
            kw in cap.get("namespace", "").lower()
            for kw in ["network", "crypto", "anti", "persistence"]
        ):
            suspicious_funcs.append(cap.get("name", ""))
    return suspicious_funcs


def load_system_prompt(project_dir: Path, prompt_name: str = "ghidra_agent") -> str:
    prompts_dir = project_dir / "prompts"
    prompt_file = prompts_dir / f"{prompt_name}.md"

    if not prompt_file.exists():
        raise FileNotFoundError(f"System prompt not found: {prompt_file}")

    return prompt_file.read_text()
