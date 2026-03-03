import type { StepStatus, AnalysisResult, TaskStatus } from '../../../shared/types';

export interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

export function inferStepStates(
  result: AnalysisResult | undefined,
  currentStates: Record<string, StepState>,
  currentStep?: string,
  taskStatus?: TaskStatus
): Record<string, StepState> {
  const newStates = { ...currentStates };

  // Set running state for ghidra/report based on task status
  if (taskStatus === 'ghidra_analysis' && currentStep && !result?.ghidra_analysis) {
    newStates.ghidra = {
      status: 'running',
      preview: { currentStep },
    };
  }

  if (taskStatus === 'report_generation' && currentStep && !result?.malware_report) {
    newStates.report = {
      status: 'running',
      preview: { currentStep },
    };
  }

  if (!result) return newStates;

  // Hash Calculation - always update if data exists
  if (result.hashes) {
    const hashes = result.hashes;
    newStates.hash = {
      status: 'completed',
      preview: {
        md5: String(hashes?.md5 || '').slice(0, 12) + '...',
        sha256: String(hashes?.sha256 || '').slice(0, 12) + '...',
      },
    };
  }

  // File Type Identification
  if (result.file_type) {
    const fileType = result.file_type;
    if (fileType?.error) {
      newStates.file_type = { status: 'failed', preview: { error: fileType.error } };
    } else {
      newStates.file_type = {
        status: 'completed',
        preview: {
          format: fileType?.format || 'Unknown',
          category: fileType?.category || 'unknown',
          platform: fileType?.platform || 'unknown',
          packers: fileType?.packers?.length || 0,
        },
      };
    }
  }

  // Capability Analysis (capa)
  if (result.capa) {
    const capa = result.capa;
    if (capa.error) {
      newStates.capa = { status: 'failed', preview: { error: capa.error } };
    } else if (capa.skipped) {
      newStates.capa = { status: 'skipped', preview: { reason: capa.reason || 'Skipped' } };
    } else {
      newStates.capa = {
        status: 'completed',
        preview: {
          capabilities: capa.capabilities?.length || 0,
          techniques: capa.attack?.techniques?.length || 0,
          behaviors: capa.mbc?.behaviors?.length || 0,
        },
      };
    }
  }

  // String Extraction
  if (result.strings) {
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

  // YARA Scanning
  if (result.yara) {
    const yara = result.yara;
    if (yara?.error) {
      newStates.yara = { status: 'failed', preview: { error: 'No rules loaded' } };
    } else {
      const matches = yara?.matches || [];
      newStates.yara = {
        status: 'completed',
        preview: {
          matches: matches.length,
          rules: matches.slice(0, 3).map((m) => m.rule || 'unknown').join(', ') || 'None',
        },
      };
    }
  }

  // Threat Intelligence
  if (result.threat_intel) {
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
  if (result.dynamic_analysis) {
    const dynamic = result.dynamic_analysis;
    
    if (dynamic.skipped || dynamic.error) {
      newStates.dynamic = {
        status: dynamic.skipped ? 'skipped' : 'completed',
        preview: {
          status: 'Skipped',
          reason: dynamic.error || 'Not available',
        },
      };
    } else if (dynamic.success !== undefined) {
      const syscallCount = dynamic.syscall_summary?.total_count || 
        (Array.isArray(dynamic.syscalls) ? dynamic.syscalls.length : 0);
      const networkCount = dynamic.network_summary?.total_connections || 
        (Array.isArray(dynamic.network_activity) ? dynamic.network_activity.length : 0);
      
      newStates.dynamic = {
        status: 'completed',
        preview: {
          duration: dynamic.duration_seconds ? `${dynamic.duration_seconds.toFixed(1)}s` : undefined,
          events: dynamic.raw_events_count || 0,
          security_alerts: Array.isArray(dynamic.security_events) ? dynamic.security_events.length : 0,
          syscalls: syscallCount,
          network: networkCount,
        },
      };
    }
  }

  // Ghidra Analysis
  if (result.ghidra_analysis) {
    const ghidra = result.ghidra_analysis;
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
  if (result.malware_report) {
    const report = result.malware_report;
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

export function getEffectiveStepStatus(
  stepId: string,
  stepGroup: string,
  currentStatus: TaskStatus,
  stepStates: Record<string, StepState>,
  _allSteps?: { id: string; group: string }[]
): StepStatus {
  const STAGE_ORDER = [
    'pending',
    'queued',
    'hashing',
    'static_analysis',  // Phase 2: all parallel (capa, strings, yara, threat_intel, dynamic)
    'ghidra_analysis',
    'report_generation',
    'completed',
  ];
  const currentStageIndex = STAGE_ORDER.indexOf(currentStatus);

  // Terminal states
  if (currentStatus === 'completed') return stepStates[stepId]?.status || 'completed';
  if (currentStatus === 'failed') return stepStates[stepId]?.status || 'pending';

  const wsStatus = stepStates[stepId]?.status;

  // Phase 1: hashing step (hash + file_type)
  if (stepId === 'hash' || stepId === 'file_type') {
    // If we have a status from result, use it
    if (wsStatus && wsStatus !== 'pending') {
      return wsStatus;
    }
    if (currentStatus === 'hashing') {
      return 'running';
    }
    if (currentStageIndex > STAGE_ORDER.indexOf('hashing')) {
      return 'completed';
    }
    return 'pending';
  }

  // Phase 2: All parallel steps (static, intel, dynamic groups)
  // capa, strings, yara, threat_intel, dynamic all run in parallel during static_analysis
  if (stepGroup === 'static' || stepGroup === 'intel' || stepGroup === 'dynamic') {
    // If we have a status from result, use it (completed/skipped/failed)
    if (wsStatus && wsStatus !== 'pending') {
      return wsStatus;
    }
    if (currentStageIndex > STAGE_ORDER.indexOf('static_analysis')) {
      return 'completed';
    }
    if (currentStatus === 'static_analysis') {
      return 'running';
    }
    return 'pending';
  }

  // Ghidra step
  if (stepGroup === 'ghidra') {
    if (wsStatus && wsStatus !== 'pending') {
      return wsStatus;
    }
    if (currentStageIndex > STAGE_ORDER.indexOf('ghidra_analysis')) {
      return 'completed';
    }
    if (currentStatus === 'ghidra_analysis') {
      return 'running';
    }
    return 'pending';
  }

  // Report step
  if (stepGroup === 'report') {
    if (wsStatus && wsStatus !== 'pending') {
      return wsStatus;
    }
    if (currentStageIndex > STAGE_ORDER.indexOf('report_generation')) {
      return 'completed';
    }
    if (currentStatus === 'report_generation') {
      return 'running';
    }
    return 'pending';
  }

  return 'pending';
}
