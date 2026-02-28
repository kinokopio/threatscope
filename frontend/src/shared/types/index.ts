// Re-export all types from the original types file
// This maintains backward compatibility while organizing into feature-based structure

export interface AnalysisTask {
  id?: string;
  task_id?: string;
  status: TaskStatus;
  file_name?: string;
  result?: AnalysisResult;
  error?: string;
}

export type TaskStatus =
  | 'pending'
  | 'static_analysis'
  | 'queued'
  | 'ghidra_analysis'
  | 'report_generation'
  | 'completed'
  | 'failed';

export interface AnalysisResult {
  metadata?: {
    file_name?: string;
    hashes?: {
      md5?: string;
      sha256?: string;
    };
  };
  hashes?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
  strings?: {
    urls?: string[];
    ips?: string[];
    domains?: string[];
    suspicious?: string[];
  };
  elf?: {
    format?: string;
    arch?: string;
    entry_point?: string;
    imports?: string[];
    error?: string;
  };
  yara?: {
    matches?: string[];
    error?: string;
  };
  function_categories?: Record<string, string[]>;
  mitre_mapping?: {
    techniques?: MitreMapping[];
  };
  threat_intel?: ThreatIntel;
  dynamic_analysis?: DynamicAnalysis;
  static_analysis?: StaticAnalysis;
  ghidra_analysis?: GhidraAnalysis;
  malware_report?: MalwareReport;
}

export interface StaticAnalysis {
  hashes: {
    md5: string;
    sha1: string;
    sha256: string;
  };
  strings: {
    urls: string[];
    ips: string[];
    domains: string[];
    suspicious: string[];
  };
  elf?: {
    format: string;
    arch: string;
    entry_point: string;
  };
  yara: {
    matches: string[];
  };
  function_categories: {
    classifications: Record<string, string[]>;
  };
  mitre_mapping: {
    mappings: MitreMapping[];
  };
}

export interface ThreatIntel {
  malwarebazaar?: {
    found: boolean;
    family?: string;
    tags?: string[];
  };
  threatfox?: {
    iocs: Array<{
      type: string;
      value: string;
      malware: string;
    }>;
  };
  hash_lookup?: Record<string, { found?: boolean }>;
}

export interface DynamicAnalysis {
  syscalls?: string[];
  network_connections?: string[];
  file_operations?: string[];
  error?: string;
  help?: string;
}

export interface GhidraAnalysis {
  status: string;
  ghidra_available: boolean;
  ai_analysis?: {
    analyzed_functions: AnalyzedFunction[];
    key_findings: string[];
  };
}

export interface AnalyzedFunction {
  name: string;
  address: string;
  summary?: string;
  behavior?: {
    actions: string[];
    risk_level: string;
  };
}

export interface MalwareReport {
  verdict: 'malicious' | 'suspicious' | 'benign';
  confidence: number;
  family: string | null;
  variant?: string | null;
  capabilities: string[];
  summary: string;
  technical_details: {
    infection_vector?: string;
    persistence_mechanism?: string;
    c2_protocol?: string;
    encryption?: string;
    file_type?: string;
    architecture?: string;
  };
  iocs: {
    domains: string[];
    ips: string[];
    urls: string[];
    file_hashes: string[];
  };
  mitre_mapping: MitreMapping[];
  recommendations: string[];
}

export interface MitreMapping {
  tactic: string;
  technique_id: string;
  technique_name: string;
  evidence: string;
}

export interface QueueStats {
  pending: number;
  ghidra_waiting: number;
  report_waiting: number;
  total_tasks: number;
  completed: number;
  failed: number;
}

export interface TaskListResponse {
  tasks: AnalysisTask[];
  queue_stats: QueueStats;
}

export interface ProgressMessage {
  task_id: string;
  event:
    | 'task_started'
    | 'step_started'
    | 'step_completed'
    | 'step_progress'
    | 'task_completed'
    | 'error';
  data: {
    file_path?: string;
    step_id?: string;
    step_name?: string;
    status?: string;
    duration_ms?: number;
    error?: string;
    result_summary?: Record<string, unknown>;
    result_preview?: {
      tool?: string;
      tool_call_count?: number;
      function?: string;
      pattern?: string;
      functions_analyzed?: number;
      findings_saved?: number;
      total_tool_calls?: number;
    };
  };
  timestamp: string;
}

// Step status type for analysis progress
export type StepStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

export interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}
