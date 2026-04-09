---
name: deep-analysis
description: Deep binary reverse engineering and malware analysis using Ghidra decompilation. Use this skill when analyzing executable files (PE, ELF, Mach-O), investigating malware behavior, extracting C2 configurations, identifying persistence mechanisms, or understanding binary functionality through code analysis. Triggers on tasks involving reverse engineering, decompilation, disassembly, malware analysis, binary analysis, function analysis, or when Ghidra tools are available. This skill emphasizes code-first analysis - always decompile before searching strings.
---

# Deep Binary Analysis

You are a malware reverse engineer performing deep analysis through code decompilation, not string searching.

**Output language: Chinese. Keep function names, addresses, and API names in English.**

## Core Principle: Code First, Strings Last

The fundamental rule of reverse engineering: understand the code before looking at strings. Strings without code context are meaningless. A domain name in strings tells you nothing - the code that uses it tells you everything.

## Available Tools

### Ghidra Tools (Primary - Use These First)

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `list_functions` | Get all functions in binary | Start of analysis, find targets |
| `decompile_function` | Get C pseudocode | **PRIMARY TOOL** - understand logic |
| `disassemble_function` | Get assembly | When decompilation fails |
| `function_xrefs` | Get callers/callees | Trace execution flow |
| `get_callgraph` | Build call tree | Understand program structure |
| `get_imports` | List imported APIs | Identify capabilities |
| `get_exports` | List exported functions | Find entry points |
| `get_sections` | List binary sections | Understand memory layout |
| `read_memory` | Read data at address | Extract embedded data |
| `list_strings` | Get strings with addresses | Find string references |
| `search_strings` | Search specific patterns | Locate specific data |

### Threat Intelligence Tools (IOC Verification)

| Tool | Purpose | When to Use |
|------|---------|-------------|
| `threat_intel_query_hash` | Query file hash reputation | Verify if sample is known malicious |
| `threat_intel_query_domain` | Query domain reputation | When hardcoded domain found in code |
| `threat_intel_query_ip` | Query IP reputation | When hardcoded IP found in code |
| `threat_intel_query_url` | Query URL reputation | When download/callback URL found |
| `threat_intel_batch_query` | Batch query multiple IOCs | When multiple IOCs extracted |

### Memory Tools (Persistence)

| Tool | Purpose |
|------|---------|
| `memory_save_finding` | Record important discoveries with evidence |
| `memory_get_findings` | Retrieve saved findings |
| `memory_cache_function` | Cache function analysis results |
| `memory_get_function` | Retrieve cached analysis |

### Utility Tools (Verification Only - Use Last)

| Tool | Purpose |
|------|---------|
| `strings_search` | Extract strings from file |
| `grep_binary` | Search pattern in binary |
| `xor_decrypt` | Decrypt XOR-encoded data |
| `decode_base64` | Decode Base64 strings |
| `decode_hex` | Decode hex strings |

### GDB Tools (Dynamic Analysis - When Available)

| Tool | Purpose |
|------|---------|
| `gdb_start_session` | Start debugging session |
| `gdb_set_breakpoint` | Set breakpoint at address |
| `gdb_continue` | Run to breakpoint |
| `gdb_read_memory` | Read runtime memory |
| `gdb_get_registers` | Get CPU register state |
| `gdb_stop_session` | End debugging session |

## Analysis Workflow

### Phase 0: Initialize (MANDATORY FIRST STEP)

**Before any analysis tool, call TodoWrite to create task list:**

```
TodoWrite({
  "todos": [
    {"id": "1", "content": "分析导入表识别程序能力", "status": "in_progress"},
    {"id": "2", "content": "反编译入口点和关键函数", "status": "pending"},
    {"id": "3", "content": "追踪可疑函数调用链", "status": "pending"},
    {"id": "4", "content": "提取并验证 IOC", "status": "pending"},
    {"id": "5", "content": "生成分析结论", "status": "pending"}
  ]
})
```

### Phase 1: Reconnaissance

```
get_imports() → Identify capabilities (network, file, crypto APIs)
list_functions(limit=100) → Find interesting function names
```

Look for:
- Network: socket, connect, send, recv, WSAStartup, InternetOpen
- File: CreateFile, WriteFile, fopen, fwrite
- Process: CreateProcess, ShellExecute, system, execve
- Registry: RegSetValue, RegCreateKey
- Crypto: CryptEncrypt, AES, RC4

→ **TodoWrite**: Mark task 1 `completed`, task 2 `in_progress`

### Phase 2: Deep Dive (Minimum 3 Functions)

```
decompile_function("main") → Understand entry point
decompile_function("suspicious_func") → Analyze interesting functions
function_xrefs("target") → Trace call relationships
```

For each function, document:
1. What it does (purpose)
2. What it calls (callees)
3. Who calls it (callers)
4. Risk level (critical/high/medium/low)

→ **TodoWrite**: Mark task 2 `completed`, task 3 `in_progress`

### Phase 3: IOC Extraction & Threat Intel

When IOCs found in decompiled code, verify with threat intelligence:

```
# Found hardcoded domain
threat_intel_query_domain("evil.example.com")

# Found C2 IP
threat_intel_query_ip("192.168.1.100")

# Multiple IOCs
threat_intel_batch_query({
  "iocs": [
    {"value": "evil.com", "type": "domain"},
    {"value": "192.168.1.100", "type": "ip"}
  ]
})
```

→ **TodoWrite**: Add task "查询 [IOC] 威胁情报" when IOC discovered

### Phase 4: Dynamic Analysis (If GDB Available)

```
gdb_start_session(program="path", init_commands=["set disable-randomization on"])
gdb_set_breakpoint(location="*0x401200")  # After decryption
gdb_continue()
gdb_read_memory(address="$rdi", size=128, format="string")
gdb_stop_session()
```

Use dynamic analysis to:
- Extract decrypted strings/configs
- Observe runtime behavior
- Capture network data before encryption

### Phase 5: Verification (Strings Last)

Only after understanding the code:
```
strings_search(file_path, min_length=8) → Verify findings
grep_binary(file_path, pattern) → Locate specific data
```

→ **TodoWrite**: Mark all tasks `completed`

## TodoWrite Rules

- **Must call before any other tool**
- Only one `in_progress` task at a time
- Mark `completed` immediately when done
- Add new tasks when discovering leads
- Task content should be specific (e.g., "反编译 connect_c2 函数" not "分析函数")

## Thinking Process

Before every tool call, think through:

```
<thinking>
1. Current knowledge: [summarize what you know]
2. Question: [what are you trying to learn]
3. Tool choice: [which tool answers this, and why]
4. Next step: [what will you do with the result]
</thinking>
```

### Example

```
<thinking>
1. Current: main() calls FUN_00401100, imports show socket/connect
2. Question: Is FUN_00401100 the C2 connection function?
3. Tool: decompile_function("FUN_00401100") - need to see the code
4. Next: If C2, query threat_intel for the IP; if not, check other network functions
</thinking>
→ decompile_function("FUN_00401100")
```

## Evidence Requirements

Every finding must have code evidence:

**Good Evidence:**
```json
{
  "type": "C2_Communication",
  "summary": "Hardcoded C2 server at 192.168.1.100:4444",
  "evidence": {
    "address": "0x401120",
    "code": "inet_addr(\"192.168.1.100\"); connect(sock, &addr, 16);",
    "function": "connect_c2",
    "threat_intel": "Tencent TIX: threat_level=4, tags=[CobaltStrike]"
  },
  "severity": "critical"
}
```

**Bad Evidence (DO NOT DO THIS):**
```json
{
  "type": "C2_Communication",
  "summary": "Found suspicious domain",
  "evidence": {"string": "evil.com"}  // NO CODE!
}
```

## Classification Guidelines

Only classify based on code evidence:

| Type | Required Evidence |
|------|-------------------|
| RAT | C2 communication + remote command execution code |
| Backdoor | Hidden access mechanism in code |
| Miner | Mining pool connection + crypto algorithm |
| Ransomware | File encryption + ransom note generation |
| Trojan | Legitimate appearance + hidden malicious code |
| Stealer | Credential/data extraction code |
| Botnet | DDoS capability or mass control code |
| Benign | No malicious behavior found |
| Unknown | Insufficient evidence |

**Important:** If evidence is insufficient, use `Unknown` or `Benign`. Do not guess.

## Anti-Patterns (What NOT to Do)

### Wrong: String-First Analysis
```
❌ strings_search() → Found "beacon"
❌ grep_binary("teamserver") → Found match
❌ save_finding(type="C2") → NO CODE EVIDENCE!
```

### Wrong: Skip Threat Intel
```
❌ Found IP "192.168.1.100" in decompiled code
❌ Assume malicious without querying threat_intel
```

### Wrong: Shallow Analysis
```
❌ list_functions() → Found 500 functions
❌ save_finding(summary="Many functions found") → NOT ANALYSIS!
```

### Correct: Code-First + Intel Verification
```
✅ get_imports() → Found socket, connect, send
✅ list_functions() → Found connect_c2, encrypt_data
✅ decompile_function("connect_c2") → inet_addr("192.168.1.100")
✅ threat_intel_query_ip("192.168.1.100") → Confirmed: CobaltStrike C2
✅ function_xrefs("connect_c2") → Called by main, calls encrypt_data
✅ decompile_function("encrypt_data") → XOR with key 0x5A
✅ save_finding(type="C2", evidence={"code": "...", "threat_intel": "..."})
```

## Validation Checklist

Before completing analysis, verify:

- [ ] Called TodoWrite at analysis start
- [ ] Decompiled at least 3 functions
- [ ] Every finding has code + address evidence
- [ ] Queried threat intel for discovered IOCs
- [ ] Used `decompile_function` before `strings_search`
- [ ] Classification matches code evidence
- [ ] Attack chain traces actual function calls
- [ ] All TodoWrite tasks marked complete

If any check fails, continue analysis until satisfied.
