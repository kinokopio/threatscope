# ThreatScope

AI-driven malware analysis framework.

## Features

- **Automated Analysis Pipeline**: Static → Threat Intel → Dynamic → Ghidra → AI Report
- **AI-Powered Deep Analysis**: GhidraAgent for reverse engineering, MalwareAnalysisAgent for report generation
- **Hybrid Parallel Processing**: Stage 1-4 fully parallel, Stage 5 (Ghidra) pool-limited

## Architecture

```
Stage 1-4: Workflow (Deterministic)
  ├── Static Analysis (hash, strings, ELF parsing, YARA)
  ├── Feature Analysis (function classification, MITRE mapping)
  ├── Threat Intelligence (MalwareBazaar, ThreatFox, URLhaus)
  └── Dynamic Analysis (sandbox execution, syscall tracing)

Stage 5-6: AI (Reasoning Required)
  ├── GhidraAgent (deep reverse engineering)
  └── MalwareAnalysisAgent (final report generation)
```

## Installation

```bash
pip install -e ".[all]"
```

## Configuration

Copy `config.yaml` and set environment variables:

```bash
export ANTHROPIC_API_KEY="your-api-key"
```

## License

MIT
