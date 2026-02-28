import type { StepStatus, AnalysisResult, TaskStatus } from '../../../shared/types';

export interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

/**
 * Infer step states from analysis result
 * This is extracted from TaskDetail to be reusable and testable
 */
export function inferStepStates(
  result: AnalysisResult | undefined,
  currentStates: Record<string, StepState>
): Record<string, StepState> {
  if (!result) return currentStates;

  const newStates = { ...currentStates };

  // Hash Calculation
  if (result.hashes && !newStates.hash?.status) {
    const hashes = result.hashes;
    newStates.hash = {
      status: 'completed',
      preview: {
        md5: String(hashes?.md5 || '').slice(0, 12) + '...',
        sha256: String(hashes?.sha256 || '').slice(0, 12) + '...',
      },
    };
  }

  // String Extraction
  if (result.strings && !newStates.strings?.status) {
    const strings = result.strings;
    newStates.strings = {
      status: 'completed',
      preview: {
        urls: strings?.urls?.length || 0,
        ips: strings?.ips?.length || 0,
        domains: strings?.domains?.length || 0,
        suspicious: strings?.suspicious?.length || 0,
      },
    };
  }

  // ELF Parsing
  if (result.elf && !newStates.elf?.status) {
    const elf = result.elf;
    if (elf?.error) {
      newStates.elf = { status: 'failed', preview: { error: 'Not an ELF file' } };
    } else {
      newStates.elf = {
        status: 'completed',
        preview: {
          format: String(elf?.format || 'N/A'),
          arch: String(elf?.arch || 'N/A'),
          imports: Array.isArray(elf?.imports) ? elf.imports.length : 0,
        },
      };
    }
  }

  // Function Classification
  if (!newStates.func_class?.status) {
    if (result.function_categories) {
      const categories = result.function_categories;
      const categoryCount = Object.values(categories).filter(
        (v) => Array.isArray(v) && v.length > 0
      ).length;
      newStates.func_class = {
        status: 'completed',
        preview: { categories: categoryCount },
      };
    } else if (result.elf && !result.elf.error) {
      newStates.func_class = {
        status: 'skipped',
        preview: { reason: 'Static binary' },
      };
    }
  }

  // MITRE ATT&CK Mapping
  if (!newStates.mitre?.status) {
    if (result.mitre_mapping) {
      const mitre = result.mitre_mapping;
      newStates.mitre = {
        status: 'completed',
        preview: { techniques: mitre?.techniques?.length || 0 },
      };
    } else if (result.elf && !result.elf.error) {
      newStates.mitre = {
        status: 'skipped',
        preview: { reason: 'Static binary' },
      };
    }
  }

  // YARA Scanning
  if (result.yara && !newStates.yara?.status) {
    const yara = result.yara;
    if (yara?.error) {
      newStates.yara = { status: 'failed', preview: { error: 'No rules loaded' } };
    } else {
      const matches = yara?.matches || [];
      newStates.yara = {
        status: 'completed',
        preview: {
          matches: matches.length,
          rules: matches.slice(0, 3).join(', ') || 'None',
        },
      };
    }
  }

  // Threat Intelligence
  if (result.threat_intel && !newStates.threat_intel?.status) {
    const intel = result.threat_intel;
    const hashLookup = intel?.hash_lookup || {};
    const foundCount = Object.values(hashLookup).filter((v) => v?.found).length;
    newStates.threat_intel = {
      status: 'completed',
      preview: {
        sources_checked: Object.keys(hashLookup).length,
        found: foundCount,
      },
    };
  }

  // Dynamic Analysis
  if (result.dynamic_analysis !== undefined && !newStates.dynamic?.status) {
    const dynamic = result.dynamic_analysis;
    if (!dynamic || Object.keys(dynamic).length === 0) {
      newStates.dynamic = { status: 'completed', preview: { status: 'Skipped' } };
    } else if (dynamic.error) {
      newStates.dynamic = { status: 'completed', preview: { status: 'Skipped', reason: dynamic.error } };
    } else {
      const syscalls = dynamic?.syscalls || [];
      newStates.dynamic = {
        status: 'completed',
        preview: {
          syscalls: Array.isArray(syscalls) ? syscalls.length : 0,
          network: Array.isArray(dynamic?.network_activity) ? dynamic.network_activity.length : 0,
        },
      };
    }
  }

  // Ghidra Analysis
  if (result.ghidra_analysis && !newStates.ghidra?.status) {
    const ghidra = result.ghidra_analysis;
    // Handle both direct fields and nested ai_analysis structure
    const analyzedFunctions = ghidra?.ai_analysis?.analyzed_functions || ghidra?.analyzed_functions || [];
    const keyFindings = ghidra?.ai_analysis?.key_findings || ghidra?.key_findings || [];
    
    if (ghidra.status === 'ghidra_unavailable' || !ghidra.ghidra_available) {
      newStates.ghidra = {
        status: 'skipped',
        preview: { status: 'Ghidra unavailable' },
      };
    } else {
      newStates.ghidra = {
        status: 'completed',
        preview: {
          functions: analyzedFunctions.length,
          findings: keyFindings.length,
        },
      };
    }
  }

  // AI Report
  if (result.malware_report && !newStates.report?.status) {
    const report = result.malware_report;
    // Handle confidence as decimal (0.3) or percentage (30)
    const confidence = report?.confidence || 0;
    const confidencePercent = confidence <= 1 ? Math.round(confidence * 100) : Math.round(confidence);
    newStates.report = {
      status: 'completed',
      preview: {
        verdict: report?.verdict || 'unknown',
        confidence: `${confidencePercent}%`,
        family: report?.family || 'N/A',
      },
    };
  }

  return newStates;
}

/**
 * Get effective step status based on current task status and step states
 */
export function getEffectiveStepStatus(
  stepId: string,
  stepGroup: string,
  currentStatus: TaskStatus,
  stepStates: Record<string, StepState>
): StepStatus {
  const STAGE_ORDER = ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6', 'completed'];
  const currentStageIndex = STAGE_ORDER.indexOf(currentStatus);

  // If task is completed, all steps are completed
  if (currentStatus === 'completed') return 'completed';
  if (currentStatus === 'failed') return 'pending';

  const wsStatus = stepStates[stepId]?.status;

  // Stage 1-4 steps (static, intel, dynamic)
  if (stepGroup === 'static' || stepGroup === 'intel' || stepGroup === 'dynamic') {
    if (currentStageIndex > STAGE_ORDER.indexOf('stage_1_4')) {
      return 'completed';
    }
    if (currentStatus === 'stage_1_4') {
      if (wsStatus && wsStatus !== 'pending') {
        return wsStatus;
      }
      return 'pending';
    }
    return 'pending';
  }

  // Ghidra step
  if (stepGroup === 'ghidra') {
    if (currentStageIndex > STAGE_ORDER.indexOf('stage_5')) {
      return 'completed';
    }
    if (currentStatus === 'stage_5') {
      return wsStatus || 'running';
    }
    return 'pending';
  }

  // Report step
  if (stepGroup === 'report') {
    if (currentStatus === 'stage_6') {
      return wsStatus || 'running';
    }
    return 'pending';
  }

  return 'pending';
}
