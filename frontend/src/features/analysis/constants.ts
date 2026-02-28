import type { TaskStatus } from '../../shared/types';
import {
  Hash,
  FileText,
  Code,
  Shield,
  Target,
  Search,
  Globe,
  Activity,
  Brain,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

// Analysis step definition
export interface AnalysisStep {
  id: string;
  name: string;
  description: string;
  icon: LucideIcon;
  group: 'static' | 'intel' | 'dynamic' | 'ghidra' | 'report';
}

// Complete analysis steps - hoisted outside component to avoid re-creation
export const ANALYSIS_STEPS: AnalysisStep[] = [
  { id: 'hash', name: 'Hash Calculation', description: 'MD5, SHA1, SHA256', icon: Hash, group: 'static' },
  { id: 'strings', name: 'String Extraction', description: 'URLs, IPs, Domains, Suspicious strings', icon: FileText, group: 'static' },
  { id: 'elf', name: 'ELF Parsing', description: 'Architecture, Entry point, Imports', icon: Code, group: 'static' },
  { id: 'func_class', name: 'Function Classification', description: '9 categories analysis', icon: Shield, group: 'static' },
  { id: 'mitre', name: 'MITRE ATT&CK Mapping', description: 'Tactics and techniques', icon: Target, group: 'static' },
  { id: 'yara', name: 'YARA Scanning', description: 'Rule matching', icon: Search, group: 'static' },
  { id: 'threat_intel', name: 'Threat Intelligence', description: 'MalwareBazaar, ThreatFox, URLhaus', icon: Globe, group: 'intel' },
  { id: 'dynamic', name: 'Dynamic Analysis', description: 'Emulation and syscall tracing', icon: Activity, group: 'dynamic' },
  { id: 'ghidra', name: 'Ghidra Deep Analysis', description: 'AI-driven reverse engineering', icon: Brain, group: 'ghidra' },
  { id: 'report', name: 'AI Report Generation', description: 'Final malware analysis report', icon: FileText, group: 'report' },
];

// Status display mapping - hoisted outside component
export const STATUS_DISPLAY: Record<TaskStatus, { label: string; color: string }> = {
  pending: { label: 'Pending', color: 'text-slate-400' },
  static_analysis: { label: 'Static Analysis', color: 'text-cyan-400' },
  queued: { label: 'Waiting for Ghidra', color: 'text-yellow-400' },
  ghidra_analysis: { label: 'Ghidra Analysis', color: 'text-purple-400' },
  report_generation: { label: 'Report Generation', color: 'text-emerald-400' },
  completed: { label: 'Completed', color: 'text-green-400' },
  failed: { label: 'Failed', color: 'text-red-400' },
};

// Helper function to check if task is in progress
export function isInProgress(status: TaskStatus): boolean {
  return ['pending', 'static_analysis', 'queued', 'ghidra_analysis', 'report_generation'].includes(status);
}

// Stage order for validation
export const STAGE_ORDER = ['pending', 'static_analysis', 'queued', 'ghidra_analysis', 'report_generation', 'completed'] as const;
