import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  AlertCircle, 
  Loader2, 
  ArrowLeft, 
  CheckCircle2, 
  Circle,
  FileSearch,
  Shield,
  Brain,
  FileText
} from 'lucide-react';
import { getTask } from '../api/client';
import type { AnalysisTask, TaskStatus } from '../types';
import ReportView from '../components/ReportView';

// Type for analyzed function in stage 5
interface AnalyzedFunctionPreview {
  name: string;
  behavior?: {
    risk_level: string;
  };
}

const POLL_INTERVAL_MS = 2000;

// Stage definitions with icons and descriptions
const STAGES = [
  { 
    id: 'stage_1_4', 
    label: 'Static Analysis', 
    description: 'Hashes, strings, ELF parsing, threat intel, dynamic analysis',
    icon: FileSearch,
    resultKey: 'static_analysis'
  },
  { 
    id: 'stage_5', 
    label: 'Ghidra Analysis', 
    description: 'AI-driven deep binary analysis',
    icon: Brain,
    resultKey: 'ghidra_analysis'
  },
  { 
    id: 'stage_6', 
    label: 'Report Generation', 
    description: 'AI malware analysis report',
    icon: FileText,
    resultKey: 'malware_report'
  },
];

// Status display mapping
const STATUS_DISPLAY: Record<TaskStatus, { label: string; color: string; stageIndex: number }> = {
  pending: { label: 'Pending', color: 'text-slate-400', stageIndex: -1 },
  stage_1_4: { label: 'Static Analysis', color: 'text-cyan-400', stageIndex: 0 },
  queued: { label: 'Waiting for Ghidra', color: 'text-yellow-400', stageIndex: 0 },
  stage_5: { label: 'Ghidra Analysis', color: 'text-purple-400', stageIndex: 1 },
  stage_6: { label: 'Report Generation', color: 'text-emerald-400', stageIndex: 2 },
  completed: { label: 'Completed', color: 'text-green-400', stageIndex: 3 },
  failed: { label: 'Failed', color: 'text-red-400', stageIndex: -1 },
};

function isInProgress(status: TaskStatus): boolean {
  return ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6'].includes(status);
}

// Component to display stage results preview
function StageResultPreview({ stage, result }: { stage: typeof STAGES[0]; result: Record<string, unknown> | undefined }) {
  if (!result) return null;

  const renderPreviewContent = () => {
    switch (stage.id) {
      case 'stage_1_4': {
        const hashes = result.hashes as Record<string, string> | undefined;
        const strings = result.strings as Record<string, string[]> | undefined;
        const elf = result.elf as Record<string, string> | undefined;
        const yaraMatches = (result.yara as Record<string, string[]> | undefined)?.matches || [];
        
        return (
          <div className="space-y-3">
            {/* Hashes */}
            {hashes && (
              <div>
                <div className="text-xs text-slate-400 mb-1">Hashes</div>
                <div className="font-mono text-[10px] text-slate-300 break-all">
                  <div>MD5: {hashes.md5}</div>
                  <div>SHA256: {hashes.sha256}</div>
                </div>
              </div>
            )}
            
            {/* ELF Info */}
            {elf && (
              <div>
                <div className="text-xs text-slate-400 mb-1">Binary Info</div>
                <div className="flex flex-wrap gap-2">
                  <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-cyan-300">
                    {elf.format || 'Unknown'}
                  </span>
                  <span className="px-2 py-0.5 bg-slate-700 rounded text-xs text-purple-300">
                    {elf.arch || 'Unknown'}
                  </span>
                </div>
              </div>
            )}
            
            {/* Strings Summary */}
            {strings && (
              <div>
                <div className="text-xs text-slate-400 mb-1">Extracted Strings</div>
                <div className="flex flex-wrap gap-2 text-xs">
                  {strings.urls?.length > 0 && (
                    <span className="px-2 py-0.5 bg-red-900/50 rounded text-red-300">
                      {strings.urls.length} URLs
                    </span>
                  )}
                  {strings.ips?.length > 0 && (
                    <span className="px-2 py-0.5 bg-orange-900/50 rounded text-orange-300">
                      {strings.ips.length} IPs
                    </span>
                  )}
                  {strings.domains?.length > 0 && (
                    <span className="px-2 py-0.5 bg-yellow-900/50 rounded text-yellow-300">
                      {strings.domains.length} Domains
                    </span>
                  )}
                </div>
              </div>
            )}
            
            {/* YARA Matches */}
            {yaraMatches.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-1">YARA Matches</div>
                <div className="flex flex-wrap gap-1">
                  {yaraMatches.slice(0, 5).map((match, idx) => (
                    <span key={idx} className="px-2 py-0.5 bg-red-900/50 rounded text-xs text-red-300">
                      {match}
                    </span>
                  ))}
                  {yaraMatches.length > 5 && (
                    <span className="text-xs text-slate-500">+{yaraMatches.length - 5} more</span>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      }
      
      case 'stage_5': {
        const aiAnalysis = result.ai_analysis as Record<string, unknown> | undefined;
        const analyzedFunctions = (aiAnalysis?.analyzed_functions as AnalyzedFunctionPreview[]) || [];
        const keyFindings = (aiAnalysis?.key_findings as string[]) || [];
        
        return (
          <div className="space-y-3">
            {analyzedFunctions.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-1">
                  Analyzed Functions ({analyzedFunctions.length})
                </div>
                <div className="space-y-1">
                  {analyzedFunctions.slice(0, 3).map((func, idx) => (
                    <div key={idx} className="text-xs">
                      <span className="font-mono text-cyan-300">{func.name}</span>
                      {func.behavior?.risk_level && (
                        <span className={`ml-2 px-1.5 py-0.5 rounded text-[10px] ${
                          func.behavior.risk_level === 'high' 
                            ? 'bg-red-900/50 text-red-300' 
                            : 'bg-slate-700 text-slate-300'
                        }`}>
                          {func.behavior.risk_level}
                        </span>
                      )}
                    </div>
                  ))}
                  {analyzedFunctions.length > 3 && (
                    <div className="text-xs text-slate-500">+{analyzedFunctions.length - 3} more</div>
                  )}
                </div>
              </div>
            )}
            
            {keyFindings.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-1">Key Findings</div>
                <ul className="text-xs text-slate-300 space-y-1">
                  {keyFindings.slice(0, 3).map((finding, idx) => (
                    <li key={idx} className="truncate">• {finding}</li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        );
      }
      
      case 'stage_6': {
        const verdict = result.verdict as string;
        const confidence = result.confidence as number;
        const family = result.family as string;
        const capabilities = result.capabilities as string[];
        
        return (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-2">
              <span className={`px-2 py-1 rounded text-xs font-bold uppercase ${
                verdict === 'malicious' ? 'bg-red-900 text-red-100' :
                verdict === 'suspicious' ? 'bg-orange-800 text-orange-100' :
                'bg-green-900 text-green-100'
              }`}>
                {verdict}
              </span>
              {confidence && (
                <span className="px-2 py-1 rounded text-xs bg-slate-700 text-slate-200">
                  {(confidence * 100).toFixed(0)}% confidence
                </span>
              )}
              {family && (
                <span className="px-2 py-1 rounded text-xs bg-cyan-900/50 text-cyan-300">
                  {family}
                </span>
              )}
            </div>
            
            {capabilities && capabilities.length > 0 && (
              <div>
                <div className="text-xs text-slate-400 mb-1">Capabilities</div>
                <div className="flex flex-wrap gap-1">
                  {capabilities.slice(0, 4).map((cap, idx) => (
                    <span key={idx} className="px-2 py-0.5 bg-purple-900/50 rounded text-xs text-purple-300">
                      {cap}
                    </span>
                  ))}
                  {capabilities.length > 4 && (
                    <span className="text-xs text-slate-500">+{capabilities.length - 4} more</span>
                  )}
                </div>
              </div>
            )}
          </div>
        );
      }
      
      default:
        return null;
    }
  };

  return (
    <div className="mt-3 p-3 bg-slate-900/50 rounded-lg border border-slate-700/50">
      {renderPreviewContent()}
    </div>
  );
}

export default function TaskDetail() {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<AnalysisTask | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchTaskStatus = async (id: string) => {
    try {
      const data = await getTask(id);
      setTask(data);
      setLoading(false);
      
      if (data.status === 'failed' && data.error) {
        setErrorMessage(data.error);
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
  };

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
  }, [taskId]);

  const currentStatus = task?.status || 'pending';
  const statusInfo = STATUS_DISPLAY[currentStatus] || STATUS_DISPLAY.pending;

  // Get stage completion status
  const getStageStatus = (stageIndex: number): 'completed' | 'current' | 'pending' => {
    if (currentStatus === 'failed') return 'pending';
    if (currentStatus === 'completed') return 'completed';
    
    const currentStageIndex = statusInfo.stageIndex;
    if (stageIndex < currentStageIndex) return 'completed';
    if (stageIndex === currentStageIndex) return 'current';
    return 'pending';
  };

  // Get result for a stage
  const getStageResult = (stage: typeof STAGES[0]): Record<string, unknown> | undefined => {
    if (!task?.result) return undefined;
    return task.result[stage.resultKey as keyof typeof task.result] as Record<string, unknown> | undefined;
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
          {/* In Progress State - Show stages with results */}
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
                  <Loader2 className="animate-spin w-8 h-8 text-cyan-400" />
                </div>
                
                <p className="text-slate-400">
                  AI Agents are analyzing the binary. Results will appear as each stage completes.
                </p>
              </div>

              {/* Stages */}
              <div className="space-y-3">
                {STAGES.map((stage, index) => {
                  const stageStatus = getStageStatus(index);
                  const stageResult = getStageResult(stage);
                  const Icon = stage.icon;
                  
                  return (
                    <div 
                      key={stage.id}
                      className={`bg-slate-800 p-4 rounded-xl border transition-all duration-300 ${
                        stageStatus === 'current' 
                          ? 'border-cyan-500/50 shadow-lg shadow-cyan-500/10' 
                          : stageStatus === 'completed'
                          ? 'border-emerald-500/30'
                          : 'border-slate-700'
                      }`}
                    >
                      <div className="flex items-start gap-4">
                        {/* Status Icon */}
                        <div className={`flex-shrink-0 w-10 h-10 rounded-full flex items-center justify-center ${
                          stageStatus === 'completed' 
                            ? 'bg-emerald-500/20' 
                            : stageStatus === 'current'
                            ? 'bg-cyan-500/20'
                            : 'bg-slate-700/50'
                        }`}>
                          {stageStatus === 'completed' ? (
                            <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                          ) : stageStatus === 'current' ? (
                            <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />
                          ) : (
                            <Circle className="w-5 h-5 text-slate-500" />
                          )}
                        </div>
                        
                        {/* Content */}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <Icon className={`w-4 h-4 ${
                              stageStatus === 'completed' 
                                ? 'text-emerald-400' 
                                : stageStatus === 'current'
                                ? 'text-cyan-400'
                                : 'text-slate-500'
                            }`} />
                            <h3 className={`font-semibold ${
                              stageStatus === 'completed' 
                                ? 'text-emerald-400' 
                                : stageStatus === 'current'
                                ? 'text-cyan-400'
                                : 'text-slate-500'
                            }`}>
                              {stage.label}
                            </h3>
                            {stageStatus === 'completed' && (
                              <span className="text-xs text-emerald-400/70">✓ Complete</span>
                            )}
                            {stageStatus === 'current' && (
                              <span className="text-xs text-cyan-400/70">Processing...</span>
                            )}
                          </div>
                          <p className={`text-sm mt-1 ${
                            stageStatus === 'pending' ? 'text-slate-600' : 'text-slate-400'
                          }`}>
                            {stage.description}
                          </p>
                          
                          {/* Stage Result Preview */}
                          {stageStatus === 'completed' && stageResult && (
                            <StageResultPreview stage={stage} result={stageResult} />
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
