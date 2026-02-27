import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  AlertCircle, 
  Loader2, 
  ArrowLeft, 
  CheckCircle2, 
  Circle,
  Hash,
  FileText,
  Code,
  Shield,
  Brain,
  Globe,
  Activity,
  Search,
  Target,
  SkipForward,
  ChevronDown,
  ChevronRight
} from 'lucide-react';
import { getTask } from '../api/client';
import type { AnalysisTask, TaskStatus, AnalysisResult } from '../types';
import ReportView from '../components/ReportView';
import DynamicAnalysisView from '../components/DynamicAnalysisView';

const POLL_INTERVAL_MS = 1000; // Poll every 1 second for faster updates

// Complete analysis steps
const ANALYSIS_STEPS = [
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

// Step status type
type StepStatus = 'pending' | 'running' | 'completed' | 'failed' | 'skipped';

interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

// Status display mapping
const STATUS_DISPLAY: Record<TaskStatus, { label: string; color: string }> = {
  pending: { label: 'Pending', color: 'text-slate-400' },
  stage_1_4: { label: 'Static Analysis', color: 'text-cyan-400' },
  queued: { label: 'Waiting for Ghidra', color: 'text-yellow-400' },
  stage_5: { label: 'Ghidra Analysis', color: 'text-purple-400' },
  stage_6: { label: 'Report Generation', color: 'text-emerald-400' },
  completed: { label: 'Completed', color: 'text-green-400' },
  failed: { label: 'Failed', color: 'text-red-400' },
};

function isInProgress(status: TaskStatus): boolean {
  return ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6'].includes(status);
}

// Get status icon component
function StepStatusIcon({ status }: { status: StepStatus }) {
  switch (status) {
    case 'completed':
      return <CheckCircle2 className="w-5 h-5 text-emerald-400" />;
    case 'running':
      return <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />;
    case 'failed':
      return <AlertCircle className="w-5 h-5 text-red-400" />;
    case 'skipped':
      return <SkipForward className="w-5 h-5 text-slate-500" />;
    default:
      return <Circle className="w-5 h-5 text-slate-600" />;
  }
}

// Format preview value for display
function formatPreviewValue(value: unknown): string {
  if (typeof value === 'number') return value.toString();
  if (typeof value === 'string') return value;
  if (typeof value === 'boolean') return value ? 'Yes' : 'No';
  if (Array.isArray(value)) return value.slice(0, 3).join(', ') + (value.length > 3 ? '...' : '');
  return JSON.stringify(value);
}

// Step preview component (compact summary)
function StepPreview({ preview }: { preview?: Record<string, unknown> }) {
  if (!preview || Object.keys(preview).length === 0) return null;

  return (
    <div className="mt-2 flex flex-wrap gap-2">
      {Object.entries(preview).map(([key, value]) => (
        <span 
          key={key} 
          className="text-[10px] px-2 py-0.5 bg-slate-700/50 rounded text-slate-300"
        >
          {key}: <span className="text-cyan-300">{formatPreviewValue(value)}</span>
        </span>
      ))}
    </div>
  );
}

// Detailed step content component
function StepDetailContent({ stepId, result }: { stepId: string; result: AnalysisResult }) {
  const renderValue = (value: unknown, depth = 0): React.ReactNode => {
    if (value === null || value === undefined) return <span className="text-slate-500">N/A</span>;
    if (typeof value === 'boolean') return <span className={value ? 'text-emerald-400' : 'text-red-400'}>{value ? 'Yes' : 'No'}</span>;
    if (typeof value === 'number') return <span className="text-cyan-300">{value}</span>;
    if (typeof value === 'string') {
      if (value.length > 500) return <span className="text-slate-300 break-all">{value.slice(0, 500)}...</span>;
      return <span className="text-slate-300 break-all">{value}</span>;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) return <span className="text-slate-500">Empty</span>;
      if (depth > 2) return <span className="text-slate-400">[{value.length} items]</span>;
      return (
        <div className="space-y-1 ml-2">
          {value.map((item, i) => (
            <div key={i} className="text-xs">{renderValue(item, depth + 1)}</div>
          ))}
        </div>
      );
    }
    if (typeof value === 'object') {
      if (depth > 3) return <span className="text-slate-400">{'{...}'}</span>;
      return (
        <div className="space-y-1 ml-2">
          {Object.entries(value as Record<string, unknown>).map(([k, v]) => (
            <div key={k} className="text-xs">
              <span className="text-purple-400">{k}:</span> {renderValue(v, depth + 1)}
            </div>
          ))}
        </div>
      );
    }
    return <span className="text-slate-400">{String(value)}</span>;
  };

  // Get data for each step
  const getStepData = (): unknown => {
    switch (stepId) {
      case 'hash': return result.hashes;
      case 'strings': return result.strings;
      case 'elf': return result.elf;
      case 'func_class': return result.function_categories;
      case 'mitre': return result.mitre_mapping;
      case 'yara': return result.yara;
      case 'threat_intel': return result.threat_intel;
      case 'dynamic': return result.dynamic_analysis;
      case 'ghidra': return result.ghidra_analysis;
      case 'report': return result.malware_report;
      default: return null;
    }
  };

  const data = getStepData();

  // Show helpful message for missing data
  if (!data) {
    const messages: Record<string, string> = {
      func_class: 'No imported functions found (binary may be statically linked)',
      mitre: 'No imported functions to map (binary may be statically linked)',
      dynamic: 'Dynamic analysis requires Docker or QEMU user-mode emulator',
      ghidra: 'Ghidra analysis was not performed',
    };
    const message = messages[stepId] || 'No data available';
    return <div className="text-slate-500 text-sm py-2">{message}</div>;
  }

  // Special handling for dynamic analysis - use dedicated component
  if (stepId === 'dynamic' && typeof data === 'object' && data !== null) {
    const dynData = data as Record<string, unknown>;
    
    // Check for error with help message
    if (dynData.error && dynData.help) {
      return (
        <div className="mt-3 pt-3 border-t border-slate-700/50">
          <div className="bg-yellow-900/20 rounded-lg p-3 border border-yellow-800/50">
            <p className="text-yellow-400 text-sm font-medium">⚠️ {String(dynData.error)}</p>
            <p className="text-slate-400 text-xs mt-2">{String(dynData.help)}</p>
          </div>
        </div>
      );
    }

    // Use dedicated DynamicAnalysisView component
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    return (
      <div className="mt-3 pt-3 border-t border-slate-700/50">
        <DynamicAnalysisView data={dynData as any} />
      </div>
    );
  }

  return (
    <div className="mt-3 pt-3 border-t border-slate-700/50">
      <div className="bg-slate-900/50 rounded-lg p-3 max-h-[600px] overflow-y-auto">
        <div className="text-xs font-mono">
          {renderValue(data)}
        </div>
      </div>
    </div>
  );
}

export default function TaskDetail() {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<AnalysisTask | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [stepStates, setStepStates] = useState<Record<string, StepState>>({});
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  // Toggle step expansion
  const toggleStepExpansion = (stepId: string) => {
    setExpandedSteps(prev => {
      const newSet = new Set(prev);
      if (newSet.has(stepId)) {
        newSet.delete(stepId);
      } else {
        newSet.add(stepId);
      }
      return newSet;
    });
  };

  // WebSocket disabled - using polling instead
  // The polling is handled by fetchTaskStatus below

  const fetchTaskStatus = useCallback(async (id: string) => {
    try {
      const data = await getTask(id);
      setTask(data);
      setLoading(false);
      
      if (data.status === 'failed' && data.error) {
        setErrorMessage(data.error);
      }

      // Infer step states from task result if WebSocket didn't provide them
      if (data.result) {
        setStepStates(prev => {
          const newStates = { ...prev };
          const result = data.result;
          
          // Hash Calculation
          if (result?.hashes && !newStates.hash?.status) {
            const hashes = result.hashes as Record<string, string>;
            newStates.hash = { 
              status: 'completed', 
              preview: { 
                md5: String(hashes?.md5 || '').slice(0, 12) + '...',
                sha256: String(hashes?.sha256 || '').slice(0, 12) + '...'
              } 
            };
          }
          
          // String Extraction
          if (result?.strings && !newStates.strings?.status) {
            const strings = result.strings as Record<string, unknown[]>;
            newStates.strings = { 
              status: 'completed', 
              preview: { 
                urls: strings?.urls?.length || 0,
                ips: strings?.ips?.length || 0,
                domains: strings?.domains?.length || 0,
                suspicious: strings?.suspicious?.length || 0,
              } 
            };
          }
          
          // ELF Parsing
          if (result?.elf && !newStates.elf?.status) {
            const elf = result.elf as Record<string, unknown>;
            if (elf?.error) {
              newStates.elf = { status: 'failed', preview: { error: 'Not an ELF file' } };
            } else {
              newStates.elf = { 
                status: 'completed', 
                preview: { 
                  format: String(elf?.format || 'N/A'),
                  arch: String(elf?.arch || 'N/A'),
                  imports: Array.isArray(elf?.imports) ? elf.imports.length : 0,
                } 
              };
            }
          }
          
          // Function Classification
          if (!newStates.func_class?.status) {
            if (result?.function_categories) {
              const categories = result.function_categories as Record<string, string[]>;
              const categoryCount = Object.values(categories).filter(v => Array.isArray(v) && v.length > 0).length;
              newStates.func_class = { 
                status: 'completed',
                preview: { categories: categoryCount }
              };
            } else if (result?.elf && !(result.elf as Record<string, unknown>).error) {
              // ELF parsed but no function categories - likely static binary
              newStates.func_class = { 
                status: 'skipped',
                preview: { reason: 'Static binary' }
              };
            }
          }
          
          // MITRE ATT&CK Mapping
          if (!newStates.mitre?.status) {
            if (result?.mitre_mapping) {
              const mitre = result.mitre_mapping as Record<string, unknown[]>;
              newStates.mitre = { 
                status: 'completed',
                preview: { techniques: mitre?.techniques?.length || 0 }
              };
            } else if (result?.elf && !(result.elf as Record<string, unknown>).error) {
              // ELF parsed but no MITRE mapping - likely static binary
              newStates.mitre = { 
                status: 'skipped',
                preview: { reason: 'Static binary' }
              };
            }
          }
          
          // YARA Scanning
          if (result?.yara && !newStates.yara?.status) {
            const yara = result.yara as Record<string, unknown>;
            if (yara?.error) {
              newStates.yara = { status: 'failed', preview: { error: 'No rules loaded' } };
            } else {
              const matches = yara?.matches as string[] || [];
              newStates.yara = { 
                status: 'completed', 
                preview: { 
                  matches: matches.length,
                  rules: matches.slice(0, 3).join(', ') || 'None'
                } 
              };
            }
          }
          
          // Threat Intelligence
          if (result?.threat_intel && !newStates.threat_intel?.status) {
            const intel = result.threat_intel as Record<string, unknown>;
            const hashLookup = intel?.hash_lookup as Record<string, { found?: boolean }> || {};
            const foundCount = Object.values(hashLookup).filter(v => v?.found).length;
            newStates.threat_intel = { 
              status: 'completed',
              preview: { 
                sources_checked: Object.keys(hashLookup).length,
                found: foundCount,
              }
            };
          }
          
          // Dynamic Analysis
          if (result?.dynamic_analysis !== undefined && !newStates.dynamic?.status) {
            const dynamic = result.dynamic_analysis;
            if (!dynamic || Object.keys(dynamic).length === 0) {
              newStates.dynamic = { status: 'completed', preview: { status: 'Skipped' } };
            } else {
              const syscalls = dynamic?.syscalls || [];
              newStates.dynamic = { 
                status: 'completed',
                preview: { 
                  syscalls: syscalls.length,
                  network: dynamic?.network_connections?.length || 0
                }
              };
            }
          }
          
          // Ghidra Analysis
          if (result?.ghidra_analysis && !newStates.ghidra?.status) {
            const ghidra = result.ghidra_analysis;
            const aiAnalysis = ghidra?.ai_analysis;
            newStates.ghidra = { 
              status: 'completed',
              preview: { 
                functions: aiAnalysis?.analyzed_functions?.length || 0,
                findings: aiAnalysis?.key_findings?.length || 0,
              }
            };
          }
          
          // AI Report
          if (result?.malware_report && !newStates.report?.status) {
            const report = result.malware_report;
            newStates.report = { 
              status: 'completed',
              preview: { 
                verdict: report?.verdict || 'unknown',
                confidence: `${report?.confidence || 0}%`,
                family: report?.family || 'N/A',
              }
            };
          }
          
          return newStates;
        });
      }
    } catch (err: unknown) {
      console.error('Failed to fetch task:', err);
      const error = err as { response?: { status: number } };
      if (error.response?.status === 404) {
        setErrorMessage('Task not found.');
      } else {
        setErrorMessage('Failed to fetch task status.');
      }
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!taskId) return;

    // Initial fetch
    fetchTaskStatus(taskId);

    // Polling for in-progress tasks
    const interval = setInterval(() => {
      setTask((currentTask) => {
        if (!currentTask || isInProgress(currentTask.status)) {
          fetchTaskStatus(taskId);
        } else {
          clearInterval(interval);
        }
        return currentTask;
      });
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [taskId, fetchTaskStatus]);

  const currentStatus = task?.status || 'pending';
  const statusInfo = STATUS_DISPLAY[currentStatus] || STATUS_DISPLAY.pending;

  // Determine which steps should be shown as running based on current status
  const getEffectiveStepStatus = (stepId: string): StepStatus => {
    const step = ANALYSIS_STEPS.find(s => s.id === stepId);
    if (!step) return 'pending';

    // If task is completed, all steps are completed
    if (currentStatus === 'completed') return 'completed';
    if (currentStatus === 'failed') return 'pending';

    // If we have explicit state from WebSocket, use it (but validate against stage)
    const wsStatus = stepStates[stepId]?.status;
    
    // Define stage order for validation
    const stageOrder = ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6', 'completed'];
    const currentStageIndex = stageOrder.indexOf(currentStatus);
    
    // Stage 1-4 steps (static, intel, dynamic)
    if (step.group === 'static' || step.group === 'intel' || step.group === 'dynamic') {
      // If we're past stage_1_4, these are all completed
      if (currentStageIndex > stageOrder.indexOf('stage_1_4')) {
        return 'completed';
      }
      // If we're in stage_1_4, trust WebSocket status or infer
      if (currentStatus === 'stage_1_4') {
        if (wsStatus && wsStatus !== 'pending') {
          return wsStatus;
        }
        // Infer: find first step without completed status and mark as running
        const stage14Steps = ANALYSIS_STEPS.filter(s => 
          s.group === 'static' || s.group === 'intel' || s.group === 'dynamic'
        );
        for (const gs of stage14Steps) {
          const gsStatus = stepStates[gs.id]?.status;
          if (!gsStatus || gsStatus === 'pending' || gsStatus === 'running') {
            return gs.id === stepId ? 'running' : 'pending';
          }
        }
        // All previous steps completed, this one should be running or completed
        return wsStatus || 'pending';
      }
      return 'pending';
    }
    
    // Ghidra step
    if (step.group === 'ghidra') {
      if (currentStageIndex > stageOrder.indexOf('stage_5')) {
        return 'completed';
      }
      if (currentStatus === 'stage_5') {
        return wsStatus || 'running';
      }
      return 'pending';
    }
    
    // Report step
    if (step.group === 'report') {
      if (currentStatus === 'stage_6') {
        return wsStatus || 'running';
      }
      return 'pending';
    }

    return 'pending';
  };

  return (
    <div className="max-w-7xl mx-auto">
      {/* Back Button */}
      <button
        onClick={() => navigate(-1)}
        className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4 mr-2" /> Back
      </button>

      {/* Loading State */}
      {loading && (
        <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
          <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
          <h3 className="text-2xl font-bold text-white">Loading...</h3>
        </div>
      )}

      {/* Error State (no task found) */}
      {!loading && errorMessage && !task && (
        <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
          <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
          <h3 className="text-2xl font-bold text-red-400">Error</h3>
          <p className="text-red-200 mt-2">{errorMessage}</p>
        </div>
      )}

      {/* Task Content */}
      {!loading && task && (
        <div className="animate-in fade-in duration-500 space-y-6">
          {/* Header */}
          <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h2 className="text-2xl font-bold text-white flex items-center">
                  <Shield className="w-6 h-6 mr-2 text-emerald-400" />
                  {isInProgress(task.status) ? 'Analysis in Progress' : 
                   task.status === 'completed' ? 'Analysis Complete' : 'Analysis Failed'}
                </h2>
                {task.file_name && (
                  <p className="text-slate-400 mt-1">
                    File: <span className="font-mono text-slate-300">{task.file_name}</span>
                  </p>
                )}
              </div>
              <div className="flex items-center gap-3">
                {isInProgress(task.status) && (
                  <Loader2 className="animate-spin w-8 h-8 text-cyan-400" />
                )}
                {task.status === 'completed' && (
                  <CheckCircle2 className="w-8 h-8 text-emerald-400" />
                )}
                {task.status === 'failed' && (
                  <AlertCircle className="w-8 h-8 text-red-400" />
                )}
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <span className="text-slate-400">Status:</span>
              <span className={`font-semibold ${statusInfo.color}`}>{statusInfo.label}</span>
            </div>
          </div>

          {/* Failed State Error */}
          {task.status === 'failed' && (
            <div className="bg-red-900/20 p-6 rounded-xl border border-red-800">
              <p className="text-red-200">{task.error || 'An unknown error occurred.'}</p>
            </div>
          )}

          {/* Analysis Steps - Always show for in-progress and completed */}
          {(isInProgress(task.status) || task.status === 'completed') && (
            <div className="space-y-2">
              <h3 className="text-lg font-semibold text-white mb-3">Analysis Steps</h3>
              {ANALYSIS_STEPS.map((step) => {
                const effectiveStatus = getEffectiveStepStatus(step.id);
                const stepState = stepStates[step.id];
                const Icon = step.icon;
                const isExpanded = expandedSteps.has(step.id);
                const canExpand = effectiveStatus === 'completed' && task?.result;
                
                return (
                  <div 
                    key={step.id}
                    className={`bg-slate-800 rounded-xl border transition-all duration-300 ${
                      effectiveStatus === 'running' 
                        ? 'border-cyan-500/50 shadow-lg shadow-cyan-500/10' 
                        : effectiveStatus === 'completed'
                        ? 'border-emerald-500/30'
                        : effectiveStatus === 'failed'
                        ? 'border-red-500/30'
                        : 'border-slate-700/50'
                    }`}
                  >
                    {/* Clickable Header */}
                    <div 
                      className={`p-4 ${canExpand ? 'cursor-pointer hover:bg-slate-700/30' : ''}`}
                      onClick={() => canExpand && toggleStepExpansion(step.id)}
                    >
                      <div className="flex items-start gap-3">
                        {/* Status Icon */}
                        <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${
                          effectiveStatus === 'completed' 
                            ? 'bg-emerald-500/20' 
                            : effectiveStatus === 'running'
                            ? 'bg-cyan-500/20'
                            : effectiveStatus === 'failed'
                            ? 'bg-red-500/20'
                            : 'bg-slate-700/30'
                        }`}>
                          <StepStatusIcon status={effectiveStatus} />
                        </div>
                        
                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Icon className={`w-4 h-4 ${
                              effectiveStatus === 'completed' 
                                ? 'text-emerald-400' 
                                : effectiveStatus === 'running'
                                ? 'text-cyan-400'
                                : effectiveStatus === 'failed'
                                ? 'text-red-400'
                                : 'text-slate-500'
                            }`} />
                            <h3 className={`font-medium text-sm ${
                              effectiveStatus === 'completed' 
                                ? 'text-emerald-400' 
                                : effectiveStatus === 'running'
                                ? 'text-cyan-400'
                                : effectiveStatus === 'failed'
                                ? 'text-red-400'
                                : 'text-slate-500'
                            }`}>
                              {step.name}
                            </h3>
                            {/* Expand/Collapse Icon */}
                            {canExpand && (
                              <span className="ml-auto">
                                {isExpanded ? (
                                  <ChevronDown className="w-4 h-4 text-slate-400" />
                                ) : (
                                  <ChevronRight className="w-4 h-4 text-slate-400" />
                                )}
                              </span>
                            )}
                          </div>
                          <p className={`text-xs mt-0.5 ${
                            effectiveStatus === 'pending' ? 'text-slate-600' : 'text-slate-400'
                          }`}>
                            {step.description}
                          </p>
                          
                          {/* Step Preview (only when collapsed) */}
                          {!isExpanded && effectiveStatus === 'completed' && stepState?.preview && (
                            <StepPreview preview={stepState.preview} />
                          )}
                        </div>
                      </div>
                    </div>
                    
                    {/* Expanded Detail Content */}
                    {isExpanded && task?.result && (
                      <div className="px-4 pb-4">
                        <StepDetailContent stepId={step.id} result={task.result} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* Completed State - Show Full Report */}
          {task.status === 'completed' && task.result && (
            <div>
              <h3 className="text-lg font-semibold text-white mb-3">Analysis Report</h3>
              <ReportView result={task.result} fileName={task.file_name} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
