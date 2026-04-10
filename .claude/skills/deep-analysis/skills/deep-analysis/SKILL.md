---
name: deep-analysis
description: Deep binary reverse engineering and malware analysis using Ghidra decompilation. Use this skill when analyzing executable files (PE, ELF, Mach-O), investigating malware behavior, extracting C2 configurations, identifying persistence mechanisms, or understanding binary functionality through code analysis.
---

# Analysis Workflow

## Phase 1: Reconnaissance

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

## Phase 2: Deep Dive (Minimum 3 Functions)

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

## Phase 3: IOC Extraction & Threat Intel Verification

When IOCs found in decompiled code, verify with threat intelligence:

```
threat_intel_query_domain("evil.example.com")
threat_intel_query_ip("192.168.1.100")
threat_intel_batch_query(domains=["evil.com"], ips=["192.168.1.100"])
```

## Phase 4: Dynamic Analysis (If GDB Available)

```
gdb_start_session(program="path", init_commands=["set disable-randomization on"])
gdb_set_breakpoint(location="*0x401200")
gdb_continue()
gdb_read_memory(address="$rdi", size=128, format="string")
gdb_stop_session()
```

Use for: extracting decrypted strings/configs, observing runtime behavior, capturing network data before encryption.

## Phase 5: String Verification (Last)

Only after understanding the code:
```
strings_search(file_path, min_length=8) → Verify findings
grep_binary(file_path, pattern) → Locate specific data
```

# Evidence Requirements

Every finding must have code evidence:

**Good:**
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

**Bad (DO NOT):**
```json
{
  "type": "C2_Communication",
  "summary": "Found suspicious domain",
  "evidence": {"string": "evil.com"}
}
```

# Classification

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

If evidence is insufficient, use `Unknown` or `Benign`. Do not guess.

# Anti-Patterns

```
❌ strings_search() → Found "beacon" → save_finding(type="C2")  // No code evidence
❌ Found IP in code → Assume malicious without querying threat_intel
❌ list_functions() → 500 functions → save_finding(summary="Many functions")  // Not analysis
```

```
✅ get_imports() → socket, connect, send
✅ decompile_function("connect_c2") → inet_addr("192.168.1.100")
✅ threat_intel_query_ip("192.168.1.100") → Confirmed: CobaltStrike C2
✅ save_finding(type="C2", evidence={"code": "...", "threat_intel": "..."})
```
