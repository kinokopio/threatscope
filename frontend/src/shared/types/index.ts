// Re-export all types from the original types file
// This maintains backward compatibility while organizing into feature-based structure

export interface AnalysisTask {
  id?: string;
  task_id?: string;
  status: TaskStatus;
  current_step?: string;
  file_name?: string;
  result?: AnalysisResult;
  error?: string;
}

export type TaskStatus =
  | 'pending'
  | 'queued'
  | 'hashing'
  | 'file_identification'
  | 'static_analysis'
  | 'threat_intel'
  | 'dynamic_analysis'
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
  // New: file_type from diec
  file_type?: FileTypeResult;
  // New: capa capabilities
  capa?: CapaResult;
  yara?: {
    matches?: YaraMatch[];
    error?: string;
  };
  threat_intel?: ThreatIntel;
  dynamic_analysis?: DynamicAnalysis;
  static_analysis?: StaticAnalysis;
  ghidra_analysis?: GhidraAnalysis;
  malware_report?: MalwareReport;
}

// New: File type identification result from diec
export interface FileTypeResult {
  format?: string;
  arch?: string;
  category?: string;  // pe, elf, script:python, unknown
  platform?: string;  // windows, linux, cross
  packers?: Array<{ name: string; version?: string }>;
  compilers?: Array<{ name: string; version?: string }>;
  protectors?: Array<{ name: string; version?: string }>;
  libraries?: Array<{ name: string; version?: string }>;
  script_language?: string;
  is_fallback?: boolean;
  error?: string;
}

// New: Capa capability detection result
export interface CapaResult {
  format?: string;
  arch?: string;
  os?: string;
  capabilities?: CapaCapability[];
  attack?: {
    tactics?: string[];
    techniques?: Array<{ id: string; name: string }>;
  };
  mbc?: {
    objectives?: string[];
    behaviors?: Array<{ id: string; name: string }>;
  };
  analysis_time?: number;
  rule_count?: number;
  skipped?: boolean;
  reason?: string;
  error?: string;
}

export interface CapaCapability {
  name: string;
  namespace?: string;
  matches?: number;
}

export interface YaraMatch {
  rule?: string;
  tags?: string[];
  meta?: Record<string, string>;
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
  file_type?: FileTypeResult;
  capa?: CapaResult;
  yara: {
    matches: YaraMatch[];
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
  success?: boolean;
  skipped?: boolean;
  syscalls?: string[];
  syscall_summary?: {
    total_count?: number;
  };
  network_connections?: string[];
  network_activity?: Array<unknown>;
  network_summary?: {
    total_connections?: number;
  };
  file_operations?: string[];
  security_events?: Array<unknown>;
  raw_events_count?: number;
  duration_seconds?: number;
  error?: string;
  help?: string;
}

export interface GhidraAnalysis {
  status: string;
  ghidra_available: boolean;
  ghidra_info?: {
    file?: string;
    format?: string;
    arch?: string;
    bits?: number;
    endian?: string;
    compiler?: string;
    size?: number;
    human_size?: string;
  };
  ai_analysis?: {
    analyzed_functions?: Array<{
      name: string;
      address?: string;
      purpose?: string;
      analysis?: string;
      risk?: string;
    }>;
    key_findings?: Array<{
      id?: string;
      title?: string;
      category?: string;
      description: string;
      severity?: string;
      evidence?: string[];
      impact?: string;
      recommendation?: string;
    }>;
    malware_classification?: {
      type?: string;
      family?: string;
      severity?: string;
    };
  };
  analyzed_functions?: Array<{
    name: string;
    address?: string;
    analysis?: string;
  }>;
  key_findings?: Array<{
    type?: string;
    description: string;
    severity?: string;
  }>;
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
    platform?: string;
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
