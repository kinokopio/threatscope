export interface AnalysisTask {
  id: string;
  status: TaskStatus;
  file_name?: string;
  result?: AnalysisResult;
  error?: string;
}

export type TaskStatus = 
  | 'pending'
  | 'stage_1_4'
  | 'queued'
  | 'stage_5'
  | 'stage_6'
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
  // Direct fields (from stage_1_4_results)
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
  };
  yara?: {
    matches?: string[];
  };
  function_categories?: Record<string, string[]>;
  mitre_mapping?: {
    techniques?: MitreMapping[];
  };
  threat_intel?: ThreatIntel;
  dynamic_analysis?: DynamicAnalysis;
  // Nested fields
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
}

export interface DynamicAnalysis {
  syscalls: string[];
  network_connections: string[];
  file_operations: string[];
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

// WebSocket progress message
export interface ProgressMessage {
  task_id: string;
  event: 'task_started' | 'step_started' | 'step_completed' | 'task_completed' | 'error';
  data: {
    file_path?: string;
    step_id?: string;
    step_name?: string;
    status?: string;
    duration_ms?: number;
    error?: string;
    result_summary?: Record<string, unknown>;
  };
  timestamp: string;
}
