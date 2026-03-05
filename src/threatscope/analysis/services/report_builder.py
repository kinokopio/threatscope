"""Report Builder - Aggregates analysis data into UnifiedReport.

This module implements the ReportBuilder class that:
1. Extracts key findings and functions directly from Ghidra results
2. Aggregates IOCs from all analysis phases
3. Generates MITRE ATT&CK mappings from findings and capa
4. Calculates verdict, confidence, and severity
5. Uses AI only for generating summaries and recommendations
"""

import json
import logging
from typing import Any

from pydantic import BaseModel, Field

from src.threatscope.analysis.models.report import (
    AnalyzedFunction,
    DataSources,
    IoCs,
    IoCItem,
    KeyFinding,
    MalwareClassification,
    MitreMapping,
    Recommendation,
    TechnicalDetails,
    UnifiedReport,
)

logger = logging.getLogger(__name__)


# =============================================================================
# MITRE ATT&CK Mapping Tables
# =============================================================================

CATEGORY_TO_MITRE: dict[str, dict[str, Any]] = {
    "命令与控制": {
        "tactic": "Command and Control",
        "techniques": [
            ("T1071", "Application Layer Protocol"),
            ("T1573", "Encrypted Channel"),
            ("T1095", "Non-Application Layer Protocol"),
            ("T1571", "Non-Standard Port"),
        ],
    },
    "执行": {
        "tactic": "Execution",
        "techniques": [
            ("T1059", "Command and Scripting Interpreter"),
            ("T1106", "Native API"),
            ("T1053", "Scheduled Task/Job"),
        ],
    },
    "防御规避": {
        "tactic": "Defense Evasion",
        "techniques": [
            ("T1070", "Indicator Removal"),
            ("T1027", "Obfuscated Files or Information"),
            ("T1140", "Deobfuscate/Decode Files or Information"),
            ("T1562", "Impair Defenses"),
        ],
    },
    "持久化": {
        "tactic": "Persistence",
        "techniques": [
            ("T1543", "Create or Modify System Process"),
            ("T1547", "Boot or Logon Autostart Execution"),
            ("T1053", "Scheduled Task/Job"),
        ],
    },
    "发现": {
        "tactic": "Discovery",
        "techniques": [
            ("T1082", "System Information Discovery"),
            ("T1057", "Process Discovery"),
            ("T1083", "File and Directory Discovery"),
            ("T1016", "System Network Configuration Discovery"),
        ],
    },
    "收集": {
        "tactic": "Collection",
        "techniques": [
            ("T1005", "Data from Local System"),
            ("T1056", "Input Capture"),
            ("T1113", "Screen Capture"),
        ],
    },
    "渗出": {
        "tactic": "Exfiltration",
        "techniques": [
            ("T1041", "Exfiltration Over C2 Channel"),
            ("T1048", "Exfiltration Over Alternative Protocol"),
        ],
    },
    "凭据访问": {
        "tactic": "Credential Access",
        "techniques": [
            ("T1003", "OS Credential Dumping"),
            ("T1555", "Credentials from Password Stores"),
        ],
    },
    "横向移动": {
        "tactic": "Lateral Movement",
        "techniques": [
            ("T1021", "Remote Services"),
            ("T1570", "Lateral Tool Transfer"),
        ],
    },
    "影响": {
        "tactic": "Impact",
        "techniques": [
            ("T1486", "Data Encrypted for Impact"),
            ("T1489", "Service Stop"),
            ("T1529", "System Shutdown/Reboot"),
        ],
    },
}

# Malware type detection keywords
MALWARE_TYPE_KEYWORDS: dict[str, list[str]] = {
    "RAT": ["远程控制", "remote access", "rat", "beacon", "c2", "命令与控制", "远程命令"],
    "Backdoor": ["后门", "backdoor", "reverse shell", "bind shell"],
    "Miner": ["挖矿", "miner", "xmrig", "cryptominer", "stratum", "矿池"],
    "Ransomware": ["勒索", "ransomware", "encrypt", "加密文件", "赎金"],
    "Trojan": ["木马", "trojan", "downloader", "dropper"],
    "Worm": ["蠕虫", "worm", "自我复制", "propagate"],
    "Rootkit": ["rootkit", "隐藏进程", "hook", "内核"],
    "Keylogger": ["键盘记录", "keylogger", "keystroke", "input capture"],
    "Stealer": ["窃取", "stealer", "credential", "password", "凭据"],
    "Botnet": ["僵尸网络", "botnet", "bot", "ddos"],
}


# =============================================================================
# AI Summary Generation Models
# =============================================================================


class AISummaryOutput(BaseModel):
    """Structured output for AI summary generation."""

    summary: str = Field(description="3-5 sentence detailed summary in Chinese")
    executive_summary: str = Field(description="1 sentence summary for executives in Chinese")
    recommendations: list[dict[str, str]] = Field(
        description="List of recommendations with priority, category, action, details"
    )


# =============================================================================
# ReportBuilder Class
# =============================================================================


class ReportBuilder:
    """Builds UnifiedReport by aggregating data from all analysis phases.

    This class:
    1. Extracts key findings and functions directly from Ghidra results (no re-analysis)
    2. Aggregates IOCs from static, dynamic, and Ghidra analysis
    3. Generates MITRE ATT&CK mappings from findings and capa results
    4. Calculates verdict, confidence, and severity based on findings
    5. Uses AI only for generating summaries and recommendations (saves 80% tokens)
    """

    def __init__(self):
        """Initialize ReportBuilder."""
        self._ai_client = None

    async def build(
        self,
        static_results: dict[str, Any],
        ghidra_results: dict[str, Any],
        dynamic_results: dict[str, Any] | None = None,
        threat_intel: dict[str, Any] | None = None,
    ) -> UnifiedReport:
        """Build unified report from all analysis phases.

        Args:
            static_results: Static analysis results (hashes, strings, capa, yara, file_type)
            ghidra_results: Ghidra analysis results (ai_analysis with findings and functions)
            dynamic_results: Dynamic analysis results (syscalls, network, etc.)
            threat_intel: Threat intelligence results (malwarebazaar, threatfox)

        Returns:
            UnifiedReport instance with all data aggregated
        """
        logger.info("Building unified report from analysis results")

        # 1. Extract key findings directly from Ghidra (no re-analysis)
        key_findings = self._extract_key_findings(ghidra_results)
        logger.info(f"Extracted {len(key_findings)} key findings from Ghidra")

        # 2. Extract analyzed functions directly from Ghidra
        analyzed_functions = self._extract_functions(ghidra_results)
        logger.info(f"Extracted {len(analyzed_functions)} analyzed functions from Ghidra")

        # 3. Extract attack chain directly from Ghidra
        attack_chain = self._extract_attack_chain(ghidra_results)

        # 4. Aggregate IOCs from all sources
        iocs = self._aggregate_iocs(static_results, ghidra_results, dynamic_results)
        logger.info(
            f"Aggregated IOCs: {len(iocs.domains)} domains, {len(iocs.ips)} IPs, "
            f"{len(iocs.urls)} URLs, {len(iocs.file_hashes)} hashes"
        )

        # 5. Generate MITRE mappings from findings and capa
        mitre_mapping = self._generate_mitre_mapping(key_findings, static_results)
        logger.info(f"Generated {len(mitre_mapping)} MITRE ATT&CK mappings")

        # 6. Calculate verdict, confidence, and severity
        verdict, confidence, severity = self._calculate_verdict(
            key_findings, static_results, threat_intel
        )
        logger.info(
            f"Calculated verdict: {verdict} (confidence: {confidence:.2f}, severity: {severity})"
        )

        # 7. Extract technical details
        technical_details = self._extract_technical_details(static_results, ghidra_results)

        # 8. Classify malware type
        classification = self._classify_malware(key_findings, threat_intel, attack_chain)
        logger.info(
            f"Classified malware: type={classification.type}, family={classification.family}"
        )

        # 9. Generate AI summary and recommendations
        summary, executive_summary, recommendations = await self._generate_ai_summary(
            verdict=verdict,
            severity=severity,
            findings=key_findings,
            attack_chain=attack_chain,
            technical_details=technical_details,
            classification=classification,
            iocs=iocs,
        )

        # 10. Build data sources info
        data_sources = DataSources(
            static_analysis=True,
            dynamic_analysis=dynamic_results is not None
            and not dynamic_results.get("skipped", True),
            ghidra_analysis=ghidra_results.get("status") == "completed",
            threat_intel=threat_intel is not None,
            ghidra_functions_analyzed=len(analyzed_functions),
            ghidra_findings_count=len(key_findings),
        )

        # 11. Assemble final report
        return UnifiedReport(
            verdict=verdict,
            confidence=confidence,
            severity=severity,
            summary=summary,
            executive_summary=executive_summary,
            classification=classification,
            key_findings=key_findings,
            analyzed_functions=analyzed_functions,
            attack_chain=attack_chain,
            mitre_mapping=mitre_mapping,
            iocs=iocs,
            technical_details=technical_details,
            recommendations=recommendations,
            data_sources=data_sources,
        )

    def _extract_key_findings(self, ghidra_results: dict[str, Any]) -> list[KeyFinding]:
        """Extract key findings directly from Ghidra results.

        Args:
            ghidra_results: Ghidra analysis results

        Returns:
            List of KeyFinding objects
        """
        findings = []
        ai_analysis = ghidra_results.get("ai_analysis", {})
        raw_findings = ai_analysis.get("key_findings", [])

        for raw in raw_findings:
            try:
                # Map severity to valid enum value
                severity = raw.get("severity", "MEDIUM").upper()
                if severity not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                    severity = "MEDIUM"

                finding = KeyFinding(
                    id=raw.get("id", f"finding_{len(findings) + 1:03d}"),
                    title=raw.get("title", "Unknown Finding"),
                    category=raw.get("category", "未分类"),
                    severity=severity,
                    description=raw.get("description", ""),
                    evidence=raw.get("evidence", []),
                    impact=raw.get("impact", ""),
                    recommendation=raw.get("recommendation", ""),
                    mitre_technique=raw.get("mitre_technique"),
                )
                findings.append(finding)
            except Exception as e:
                logger.warning(f"Failed to parse finding: {e}")
                continue

        return findings

    def _extract_functions(self, ghidra_results: dict[str, Any]) -> list[AnalyzedFunction]:
        """Extract analyzed functions directly from Ghidra results.

        Args:
            ghidra_results: Ghidra analysis results

        Returns:
            List of AnalyzedFunction objects
        """
        functions = []
        ai_analysis = ghidra_results.get("ai_analysis", {})
        raw_functions = ai_analysis.get("analyzed_functions", [])

        for raw in raw_functions:
            try:
                # Map risk to valid enum value
                risk = raw.get("risk", "medium").lower()
                if risk not in ("critical", "high", "medium", "low"):
                    risk = "medium"

                func = AnalyzedFunction(
                    name=raw.get("name", "unknown"),
                    address=raw.get("address", "0x0"),
                    purpose=raw.get("purpose", ""),
                    analysis=raw.get("analysis", ""),
                    risk=risk,
                    category=raw.get("category"),
                )
                functions.append(func)
            except Exception as e:
                logger.warning(f"Failed to parse function: {e}")
                continue

        return functions

    def _extract_attack_chain(self, ghidra_results: dict[str, Any]) -> str | None:
        """Extract attack chain from Ghidra results.

        Args:
            ghidra_results: Ghidra analysis results

        Returns:
            Attack chain string or None
        """
        ai_analysis = ghidra_results.get("ai_analysis", {})
        return ai_analysis.get("attack_chain")

    def _aggregate_iocs(
        self,
        static_results: dict[str, Any],
        ghidra_results: dict[str, Any],
        dynamic_results: dict[str, Any] | None,
    ) -> IoCs:
        """Aggregate IOCs from all analysis sources.

        Args:
            static_results: Static analysis results
            ghidra_results: Ghidra analysis results
            dynamic_results: Dynamic analysis results

        Returns:
            IoCs object with all indicators
        """
        iocs = IoCs()

        # Extract from static analysis strings
        strings = static_results.get("strings", {})

        # Domains from strings
        for domain in strings.get("domains", []):
            if domain and isinstance(domain, str):
                iocs.domains.append(
                    IoCItem(value=domain, type="domain", source="strings", confidence="medium")
                )

        # IPs from strings
        for ip in strings.get("ips", []):
            if ip and isinstance(ip, str):
                iocs.ips.append(IoCItem(value=ip, type="ip", source="strings", confidence="medium"))

        # URLs from strings
        for url in strings.get("urls", []):
            if url and isinstance(url, str):
                iocs.urls.append(
                    IoCItem(value=url, type="url", source="strings", confidence="medium")
                )

        # File hashes
        hashes = static_results.get("hashes", {})
        if hashes.get("md5"):
            iocs.file_hashes.append(
                IoCItem(
                    value=hashes["md5"],
                    type="md5",
                    source="static",
                    confidence="high",
                )
            )
        if hashes.get("sha256"):
            iocs.file_hashes.append(
                IoCItem(
                    value=hashes["sha256"],
                    type="sha256",
                    source="static",
                    confidence="high",
                )
            )

        # Extract C2 domains from Ghidra findings (high confidence)
        ai_analysis = ghidra_results.get("ai_analysis", {})
        for finding in ai_analysis.get("key_findings", []):
            if finding.get("category") in ("命令与控制", "Command and Control"):
                # Look for domains in evidence
                for evidence in finding.get("evidence", []):
                    # Simple domain extraction from evidence strings
                    if "." in evidence and any(
                        tld in evidence.lower()
                        for tld in [".com", ".net", ".org", ".io", ".cc", ".cn"]
                    ):
                        # Extract domain-like strings
                        import re

                        domain_pattern = r"[a-zA-Z0-9][-a-zA-Z0-9]*\.[a-zA-Z]{2,}"
                        matches = re.findall(domain_pattern, evidence)
                        for match in matches:
                            if not any(d.value == match for d in iocs.domains):
                                iocs.domains.append(
                                    IoCItem(
                                        value=match,
                                        type="domain",
                                        context="C2 Server",
                                        source="ghidra",
                                        confidence="high",
                                    )
                                )

        # Extract from dynamic analysis
        if dynamic_results and not dynamic_results.get("skipped", True):
            network_connections = dynamic_results.get("network_connections", [])
            for conn in network_connections[:20]:  # Limit to 20
                if isinstance(conn, str) and ":" in conn:
                    # Parse IP:port format
                    parts = conn.split(":")
                    if len(parts) >= 1:
                        ip = parts[0]
                        if not any(i.value == ip for i in iocs.ips):
                            iocs.ips.append(
                                IoCItem(
                                    value=ip,
                                    type="ip",
                                    context="Network Connection",
                                    source="dynamic",
                                    confidence="high",
                                )
                            )

        # Deduplicate domains (keep highest confidence)
        iocs.domains = self._deduplicate_iocs(iocs.domains)
        iocs.ips = self._deduplicate_iocs(iocs.ips)
        iocs.urls = self._deduplicate_iocs(iocs.urls)

        return iocs

    def _deduplicate_iocs(self, items: list[IoCItem]) -> list[IoCItem]:
        """Deduplicate IOC items, keeping highest confidence.

        Args:
            items: List of IOC items

        Returns:
            Deduplicated list
        """
        seen: dict[str, IoCItem] = {}
        confidence_order = {"high": 3, "medium": 2, "low": 1}

        for item in items:
            key = item.value.lower()
            if key not in seen:
                seen[key] = item
            else:
                # Keep higher confidence
                existing_conf = confidence_order.get(seen[key].confidence, 0)
                new_conf = confidence_order.get(item.confidence, 0)
                if new_conf > existing_conf:
                    seen[key] = item

        return list(seen.values())

    def _generate_mitre_mapping(
        self,
        findings: list[KeyFinding],
        static_results: dict[str, Any],
    ) -> list[MitreMapping]:
        """Generate MITRE ATT&CK mappings from findings and capa.

        Args:
            findings: Key findings from Ghidra
            static_results: Static analysis results (contains capa)

        Returns:
            List of MITRE mappings
        """
        mappings: list[MitreMapping] = []
        seen_techniques: set[str] = set()

        # 1. Map from Ghidra findings categories
        for finding in findings:
            category = finding.category
            if category in CATEGORY_TO_MITRE:
                mitre_info = CATEGORY_TO_MITRE[category]
                # Add first matching technique for this finding
                for tech_id, tech_name in mitre_info["techniques"][:1]:
                    if tech_id not in seen_techniques:
                        mappings.append(
                            MitreMapping(
                                tactic=mitre_info["tactic"],
                                technique_id=tech_id,
                                technique_name=tech_name,
                                evidence=finding.description[:200],
                                confidence="high",
                                source=f"ghidra_{finding.id}",
                            )
                        )
                        seen_techniques.add(tech_id)

        # 2. Add from capa ATT&CK results
        capa_result = static_results.get("capa", {})
        capa_attack = capa_result.get("attack", {})
        for tech in capa_attack.get("techniques", []):
            tech_id = tech.get("id", "")
            if tech_id and tech_id not in seen_techniques:
                mappings.append(
                    MitreMapping(
                        tactic="",  # capa doesn't provide tactic
                        technique_id=tech_id,
                        technique_name=tech.get("name", ""),
                        evidence="Detected by capa capability analysis",
                        confidence="medium",
                        source="capa",
                    )
                )
                seen_techniques.add(tech_id)

        return mappings

    def _calculate_verdict(
        self,
        findings: list[KeyFinding],
        static_results: dict[str, Any],
        threat_intel: dict[str, Any] | None,
    ) -> tuple[str, float, str]:
        """Calculate verdict, confidence, and severity.

        Args:
            findings: Key findings from analysis
            static_results: Static analysis results
            threat_intel: Threat intelligence results

        Returns:
            Tuple of (verdict, confidence, severity)
        """
        confidence = 0.3
        severity = "info"

        # Count findings by severity
        critical_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")
        medium_count = sum(1 for f in findings if f.severity == "MEDIUM")

        # Check YARA matches
        yara_matches = static_results.get("yara", {}).get("matches", [])
        has_yara_match = len(yara_matches) > 0

        # Check threat intel
        ti_found = False
        if threat_intel:
            ti_found = threat_intel.get("malwarebazaar", {}).get("found", False)

        # Calculate verdict and confidence
        if ti_found:
            verdict = "malicious"
            confidence = 0.95
            severity = "critical"
        elif critical_count > 0:
            verdict = "malicious"
            confidence = min(0.9, 0.7 + critical_count * 0.1)
            severity = "critical"
        elif high_count >= 2 or has_yara_match:
            verdict = "malicious"
            confidence = min(0.85, 0.6 + high_count * 0.1)
            severity = "high"
        elif high_count == 1 or medium_count >= 3:
            verdict = "suspicious"
            confidence = min(0.7, 0.5 + medium_count * 0.05)
            severity = "medium"
        elif medium_count > 0:
            verdict = "suspicious"
            confidence = 0.5
            severity = "low"
        else:
            verdict = "benign"
            confidence = 0.4
            severity = "info"

        return verdict, round(confidence, 2), severity

    def _extract_technical_details(
        self,
        static_results: dict[str, Any],
        ghidra_results: dict[str, Any],
    ) -> TechnicalDetails:
        """Extract technical details from analysis results.

        Args:
            static_results: Static analysis results
            ghidra_results: Ghidra analysis results

        Returns:
            TechnicalDetails object
        """
        file_type = static_results.get("file_type", {})
        ghidra_info = ghidra_results.get("ghidra_info", {})
        capa_result = static_results.get("capa", {})

        # Extract capabilities from capa
        capabilities = []
        for cap in capa_result.get("capabilities", []):
            cap_name = cap.get("name", "")
            if cap_name:
                capabilities.append(cap_name)

        # Extract packers/protectors from file_type
        packers = [p.get("name", "") for p in file_type.get("packers", []) if p.get("name")]
        protectors = [p.get("name", "") for p in file_type.get("protectors", []) if p.get("name")]

        # Detect C2 protocol and encryption from findings
        c2_protocol = None
        encryption = None
        ai_analysis = ghidra_results.get("ai_analysis", {})
        for finding in ai_analysis.get("key_findings", []):
            desc_lower = finding.get("description", "").lower()
            if "dns" in desc_lower or "端口53" in desc_lower or "port 53" in desc_lower:
                c2_protocol = "DNS"
            elif "http" in desc_lower:
                c2_protocol = "HTTP"
            elif "tcp" in desc_lower:
                c2_protocol = "TCP"

            if "rsa" in desc_lower:
                encryption = "RSA"
            elif "aes" in desc_lower:
                encryption = "AES"
            elif "xor" in desc_lower:
                encryption = "XOR"

        return TechnicalDetails(
            file_format=file_type.get("format", ghidra_info.get("format", "Unknown")),
            architecture=file_type.get("arch", ghidra_info.get("arch", "Unknown")),
            platform=file_type.get("platform", "Unknown"),
            file_size=ghidra_info.get("size", 0),
            compiler=ghidra_info.get("compiler"),
            packers=packers,
            protectors=protectors,
            c2_protocol=c2_protocol,
            encryption=encryption,
            capabilities=capabilities[:20],  # Limit to 20
        )

    def _classify_malware(
        self,
        findings: list[KeyFinding],
        threat_intel: dict[str, Any] | None,
        attack_chain: str | None,
    ) -> MalwareClassification:
        """Classify malware type and family.

        Args:
            findings: Key findings from analysis
            threat_intel: Threat intelligence results
            attack_chain: Attack chain description

        Returns:
            MalwareClassification object
        """
        # Get family from threat intel
        family = None
        if threat_intel:
            family = threat_intel.get("malwarebazaar", {}).get("family")

        # Detect type from findings and attack chain
        malware_type = "Unknown"
        all_text = " ".join(
            [f.title + " " + f.description for f in findings]
            + ([attack_chain] if attack_chain else [])
        ).lower()

        for mtype, keywords in MALWARE_TYPE_KEYWORDS.items():
            if any(kw.lower() in all_text for kw in keywords):
                malware_type = mtype
                break

        # If we have C2 and command execution, it's likely a RAT
        has_c2 = any(f.category == "命令与控制" for f in findings)
        has_exec = any(f.category == "执行" for f in findings)
        if has_c2 and has_exec and malware_type == "Unknown":
            malware_type = "RAT"

        return MalwareClassification(
            type=malware_type,
            family=family,
            variant=None,
            aliases=[],
        )

    async def _generate_ai_summary(
        self,
        verdict: str,
        severity: str,
        findings: list[KeyFinding],
        attack_chain: str | None,
        technical_details: TechnicalDetails,
        classification: MalwareClassification,
        iocs: IoCs,
    ) -> tuple[str, str, list[Recommendation]]:
        """Generate AI summary and recommendations.

        This is the ONLY place where AI is used - for generating human-readable
        summaries and actionable recommendations. All other data is extracted
        directly from analysis results.

        Args:
            verdict: Analysis verdict
            severity: Severity level
            findings: Key findings
            attack_chain: Attack chain description
            technical_details: Technical details
            classification: Malware classification
            iocs: Indicators of compromise

        Returns:
            Tuple of (summary, executive_summary, recommendations)
        """
        # Build context for AI
        findings_summary = "\n".join(
            f"- [{f.severity}] {f.title}: {f.description[:100]}..." for f in findings[:5]
        )

        c2_domains = [d.value for d in iocs.domains if d.context == "C2 Server"]

        prompt = f"""基于以下恶意软件分析结果，生成中文摘要和安全建议。

## 判定结果
- Verdict: {verdict}
- Severity: {severity}
- Type: {classification.type}
- Family: {classification.family or "未知"}

## 关键发现 ({len(findings)} 个)
{findings_summary}

## 攻击链
{attack_chain or "未识别"}

## 技术特征
- 文件格式: {technical_details.file_format}
- 架构: {technical_details.architecture}
- 平台: {technical_details.platform}
- C2协议: {technical_details.c2_protocol or "未知"}
- 加密: {technical_details.encryption or "未知"}
- C2域名: {", ".join(c2_domains) if c2_domains else "未发现"}

请生成:
1. summary: 3-5句详细中文摘要，包含恶意软件类型、主要行为、攻击目标、威胁等级
2. executive_summary: 1句话摘要给管理层
3. recommendations: 具体可操作的安全建议列表，每个建议包含 priority (immediate/high/medium/low), category (containment/eradication/recovery/prevention), action, details

只返回JSON格式:
{{
  "summary": "...",
  "executive_summary": "...",
  "recommendations": [
    {{"priority": "immediate", "category": "containment", "action": "...", "details": "..."}}
  ]
}}"""

        try:
            # Try to use Claude SDK for AI generation
            from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient

            from src.threatscope.core.config import get_settings

            settings = get_settings()
            if not settings.llm.api_key:
                raise ValueError("No API key configured")

            options = ClaudeAgentOptions(
                system_prompt="你是一个专业的恶意软件分析师，负责生成分析报告摘要。只返回JSON格式的响应。",
                model=settings.llm.model,
                max_turns=1,
            )

            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                response_text = ""
                async for message in client.receive_response():
                    if hasattr(message, "content"):
                        for block in message.content:
                            if hasattr(block, "text"):
                                response_text = block.text
                                break

                # Parse JSON response
                # Find JSON in response
                import re

                json_match = re.search(r"\{[\s\S]*\}", response_text)
                if json_match:
                    result = json.loads(json_match.group())
                    recommendations = [
                        Recommendation(
                            priority=r.get("priority", "medium"),
                            category=r.get("category", "prevention"),
                            action=r.get("action", ""),
                            details=r.get("details"),
                        )
                        for r in result.get("recommendations", [])
                    ]
                    return (
                        result.get(
                            "summary",
                            self._generate_fallback_summary(verdict, classification, findings),
                        ),
                        result.get("executive_summary", f"检测到{classification.type}类型恶意软件"),
                        recommendations,
                    )

        except Exception as e:
            logger.warning(f"AI summary generation failed: {e}, using fallback")

        # Fallback: generate summary without AI
        return self._generate_fallback_content(verdict, severity, classification, findings, iocs)

    def _generate_fallback_summary(
        self,
        verdict: str,
        classification: MalwareClassification,
        findings: list[KeyFinding],
    ) -> str:
        """Generate fallback summary without AI."""
        finding_titles = [f.title for f in findings[:3]]
        return (
            f"该样本被判定为{verdict}，类型为{classification.type}"
            f"{'，家族为' + classification.family if classification.family else ''}。"
            f"主要发现包括：{', '.join(finding_titles)}。"
            f"共检测到{len(findings)}个安全问题。"
        )

    def _generate_fallback_content(
        self,
        verdict: str,
        severity: str,
        classification: MalwareClassification,
        findings: list[KeyFinding],
        iocs: IoCs,
    ) -> tuple[str, str, list[Recommendation]]:
        """Generate fallback content without AI.

        Args:
            verdict: Analysis verdict
            severity: Severity level
            classification: Malware classification
            findings: Key findings
            iocs: IOCs

        Returns:
            Tuple of (summary, executive_summary, recommendations)
        """
        # Generate summary
        finding_titles = [f.title for f in findings[:3]]
        summary = (
            f"该样本被判定为{verdict}，威胁等级为{severity}。"
            f"恶意软件类型为{classification.type}"
            f"{'，家族为' + classification.family if classification.family else ''}。"
            f"主要发现包括：{', '.join(finding_titles) if finding_titles else '无明显恶意行为'}。"
            f"共检测到{len(findings)}个安全问题，"
            f"{len(iocs.domains)}个可疑域名，{len(iocs.ips)}个可疑IP。"
        )

        # Generate executive summary
        executive_summary = (
            f"检测到{classification.type}类型{'恶意' if verdict == 'malicious' else '可疑'}软件，"
            f"威胁等级{severity}，需要{'立即' if severity in ('critical', 'high') else ''}处理。"
        )

        # Generate recommendations based on verdict and findings
        recommendations: list[Recommendation] = []

        if verdict == "malicious":
            recommendations.append(
                Recommendation(
                    priority="immediate",
                    category="containment",
                    action="立即隔离受感染系统，断开网络连接",
                    details="防止恶意软件与C2服务器通信或横向移动",
                )
            )

        # Add C2 blocking recommendation if C2 domains found
        c2_domains = [d.value for d in iocs.domains if d.context == "C2 Server"]
        if c2_domains:
            recommendations.append(
                Recommendation(
                    priority="immediate",
                    category="containment",
                    action=f"封锁C2域名: {', '.join(c2_domains[:3])}",
                    details="在防火墙和DNS层面阻断与C2服务器的通信",
                )
            )

        if verdict in ("malicious", "suspicious"):
            recommendations.append(
                Recommendation(
                    priority="high",
                    category="eradication",
                    action="保留取证证据后清除恶意文件",
                    details="在删除前保存样本和相关日志用于后续分析",
                )
            )
            recommendations.append(
                Recommendation(
                    priority="high",
                    category="recovery",
                    action="检查网络中其他主机是否存在类似感染",
                    details="使用IOC进行全网扫描",
                )
            )
            recommendations.append(
                Recommendation(
                    priority="medium",
                    category="prevention",
                    action="更新安全策略和检测规则",
                    details="将本次分析的IOC添加到安全设备中",
                )
            )

        return summary, executive_summary, recommendations
