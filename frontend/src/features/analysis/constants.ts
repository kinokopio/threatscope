import type { TaskStatus } from '../../shared/types';
import {
  Hash,
  FileText,
  FileType,
  Cpu,
  Shield,
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

// Complete analysis steps - updated for new architecture
export const ANALYSIS_STEPS: AnalysisStep[] = [
  { id: 'hash', name: 'Hash Calculation', description: 'MD5, SHA1, SHA256', icon: Hash, group: 'static' },
  { id: 'file_type', name: 'File Type Identification', description: 'Format, architecture, packers', icon: FileType, group: 'static' },
  { id: 'capa', name: 'Capability Analysis', description: 'ATT&CK techniques, behaviors', icon: Cpu, group: 'static' },
  { id: 'strings', name: 'String Extraction', description: 'URLs, IPs, Domains, Suspicious strings', icon: FileText, group: 'static' },
  { id: 'yara', name: 'YARA Scanning', description: 'Rule matching', icon: Search, group: 'static' },
  { id: 'threat_intel', name: 'Threat Intelligence', description: 'MalwareBazaar, ThreatFox, URLhaus', icon: Globe, group: 'intel' },
  { id: 'dynamic', name: 'Dynamic Analysis', description: 'Tracee eBPF sandbox', icon: Activity, group: 'dynamic' },
  { id: 'ghidra', name: 'Ghidra Deep Analysis', description: 'AI-driven reverse engineering', icon: Brain, group: 'ghidra' },
  { id: 'report', name: 'AI Report Generation', description: 'Final malware analysis report', icon: Shield, group: 'report' },
];

// Status display mapping
export const STATUS_DISPLAY: Record<TaskStatus, { label: string; color: string }> = {
  pending: { label: 'Pending', color: 'text-slate-400' },
  static_analysis: { label: 'Static Analysis', color: 'text-cyan-400' },
  queued: { label: 'Waiting for Ghidra', color: 'text-yellow-400' },
  dynamic_analysis: { label: 'Dynamic Analysis', color: 'text-orange-400' },
  ghidra_analysis: { label: 'Ghidra Analysis', color: 'text-purple-400' },
  report_generation: { label: 'Report Generation', color: 'text-emerald-400' },
  completed: { label: 'Completed', color: 'text-green-400' },
  failed: { label: 'Failed', color: 'text-red-400' },
};

// Helper function to check if task is in progress
export function isInProgress(status: TaskStatus): boolean {
  return ['pending', 'static_analysis', 'dynamic_analysis', 'queued', 'ghidra_analysis', 'report_generation'].includes(status);
}

// Stage order for validation
export const STAGE_ORDER = ['pending', 'static_analysis', 'dynamic_analysis', 'queued', 'ghidra_analysis', 'report_generation', 'completed'] as const;
