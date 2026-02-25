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
  SkipForward
} from 'lucide-react';
import { getTask } from '../api/client';
import type { AnalysisTask, TaskStatus } from '../types';
import ReportView from '../components/ReportView';

const POLL_INTERVAL_MS = 2000;

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

// Step preview component
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

export default function TaskDetail() {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<AnalysisTask | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [stepStates, setStepStates] = useState<Record<string, StepState>>({});
  const [wsConnected, setWsConnected] = useState(false);

  // WebSocket connection for real-time updates
  useEffect(() => {
    if (!taskId) return;

    const wsUrl = `${import.meta.env.VITE_API_URL?.replace('http', 'ws') || 'ws://localhost:8000'}/ws/progress`;
    let ws: WebSocket | null = null;
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          setWsConnected(true);
          // Subscribe to task updates
          ws?.send(JSON.stringify({ action: 'subscribe', task_id: taskId }));
        };

        ws.onmessage = (event) => {
          try {
            const message = JSON.parse(event.data);
            
            if (message.event === 'step_progress' && message.task_id === taskId) {
              const { step_id, status, result_preview } = message.data;
              setStepStates(prev => ({
                ...prev,
                [step_id]: { status, preview: result_preview }
              }));
            }
          } catch (e) {
            console.error('Failed to parse WebSocket message:', e);
          }
        };

        ws.onclose = () => {
          setWsConnected(false);
          // Reconnect after 3 seconds
          reconnectTimeout = setTimeout(connect, 3000);
        };

        ws.onerror = () => {
          ws?.close();
        };
      } catch (e) {
        console.error('WebSocket connection failed:', e);
      }
    };

    connect();

    return () => {
      clearTimeout(reconnectTimeout);
      ws?.close();
    };
  }, [taskId]);

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
          
          // Static analysis steps - check if we have the data
          if (data.result?.hashes && !newStates.hash?.status) {
            newStates.hash = { status: 'completed', preview: { md5: String(data.result.hashes?.md5 || '').slice(0, 8) + '...' } };
          }
          if (data.result?.strings && !newStates.strings?.status) {
            const strings = data.result.strings as Record<string, string[]>;
            newStates.strings = { 
              status: 'completed', 
              preview: { 
                urls: strings?.urls?.length || 0,
                ips: strings?.ips?.length || 0,
              } 
            };
          }
          if (data.result?.elf && !newStates.elf?.status) {
            const elf = data.result.elf as Record<string, unknown>;
            newStates.elf = { status: 'completed', preview: { arch: String(elf?.arch || ''), format: String(elf?.format || '') } };
          }
          if (data.result?.function_categories && !newStates.func_class?.status) {
            newStates.func_class = { status: 'completed' };
          }
          if (data.result?.mitre_mapping && !newStates.mitre?.status) {
            newStates.mitre = { status: 'completed' };
          }
          if (data.result?.yara && !newStates.yara?.status) {
            const yara = data.result.yara as Record<string, string[]>;
            newStates.yara = { status: 'completed', preview: { matches: yara?.matches?.length || 0 } };
          }
          if (data.result?.threat_intel && !newStates.threat_intel?.status) {
            newStates.threat_intel = { status: 'completed' };
          }
          if (data.result?.dynamic_analysis && !newStates.dynamic?.status) {
            newStates.dynamic = { status: 'completed' };
          }
          
          // Ghidra
          if (data.result?.ghidra_analysis && !newStates.ghidra?.status) {
            const ghidra = data.result.ghidra_analysis;
            newStates.ghidra = { 
              status: 'completed',
              preview: { functions: ghidra?.ai_analysis?.analyzed_functions?.length || 0 }
            };
          }
          
          // Report
          if (data.result?.malware_report && !newStates.report?.status) {
            const report = data.result.malware_report;
            newStates.report = { 
              status: 'completed',
              preview: { verdict: report?.verdict || '', confidence: report?.confidence }
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
    // If we have explicit state from WebSocket or inferred from result, use it
    if (stepStates[stepId]?.status) {
      return stepStates[stepId].status;
    }

    // Otherwise infer from task status
    const step = ANALYSIS_STEPS.find(s => s.id === stepId);
    if (!step) return 'pending';

    if (currentStatus === 'completed') return 'completed';
    if (currentStatus === 'failed') return 'pending';

    // Infer based on group and current stage
    if (currentStatus === 'stage_1_4') {
      if (step.group === 'static' || step.group === 'intel' || step.group === 'dynamic') {
        // Show first uncompleted step as running
        const groupSteps = ANALYSIS_STEPS.filter(s => 
          s.group === 'static' || s.group === 'intel' || s.group === 'dynamic'
        );
        for (const gs of groupSteps) {
          if (!stepStates[gs.id]?.status || stepStates[gs.id]?.status === 'pending') {
            if (gs.id === stepId) return 'running';
            break;
          }
        }
      }
    }
    if (currentStatus === 'stage_5' && step.group === 'ghidra') return 'running';
    if (currentStatus === 'stage_6' && step.group === 'report') return 'running';

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
        <div className="animate-in fade-in duration-500">
          {/* In Progress State - Show all steps */}
          {isInProgress(task.status) && (
            <div className="space-y-4">
              {/* Header */}
              <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
                <div className="flex items-center justify-between mb-4">
                  <div>
                    <h2 className="text-2xl font-bold text-white flex items-center">
                      <Shield className="w-6 h-6 mr-2 text-emerald-400" />
                      Analysis in Progress
                    </h2>
                    {task.file_name && (
                      <p className="text-slate-400 mt-1">
                        File: <span className="font-mono text-slate-300">{task.file_name}</span>
                      </p>
                    )}
                  </div>
                  <div className="flex items-center gap-3">
                    {wsConnected && (
                      <span className="text-xs text-emerald-400 flex items-center">
                        <span className="w-2 h-2 bg-emerald-400 rounded-full mr-1 animate-pulse" />
                        Live
                      </span>
                    )}
                    <Loader2 className="animate-spin w-8 h-8 text-cyan-400" />
                  </div>
                </div>
                
                <div className="flex items-center gap-2">
                  <span className="text-slate-400">Current Stage:</span>
                  <span className={`font-semibold ${statusInfo.color}`}>{statusInfo.label}</span>
                </div>
              </div>

              {/* Analysis Steps Grid */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {ANALYSIS_STEPS.map((step) => {
                  const effectiveStatus = getEffectiveStepStatus(step.id);
                  const stepState = stepStates[step.id];
                  const Icon = step.icon;
                  
                  return (
                    <div 
                      key={step.id}
                      className={`bg-slate-800 p-4 rounded-xl border transition-all duration-300 ${
                        effectiveStatus === 'running' 
                          ? 'border-cyan-500/50 shadow-lg shadow-cyan-500/10' 
                          : effectiveStatus === 'completed'
                          ? 'border-emerald-500/30'
                          : effectiveStatus === 'failed'
                          ? 'border-red-500/30'
                          : 'border-slate-700/50'
                      }`}
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
                          </div>
                          <p className={`text-xs mt-0.5 ${
                            effectiveStatus === 'pending' ? 'text-slate-600' : 'text-slate-400'
                          }`}>
                            {step.description}
                          </p>
                          
                          {/* Step Preview */}
                          {effectiveStatus === 'completed' && stepState?.preview && (
                            <StepPreview preview={stepState.preview} />
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Failed State */}
          {task.status === 'failed' && (
            <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
              <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
              <h3 className="text-2xl font-bold text-red-400">Analysis Failed</h3>
              <p className="text-red-200 mt-2">{task.error || 'An unknown error occurred.'}</p>
            </div>
          )}

          {/* Completed State - Show Full Report */}
          {task.status === 'completed' && task.result && (
            <ReportView result={task.result} fileName={task.file_name} />
          )}
        </div>
      )}
    </div>
  );
}
