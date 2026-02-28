import { memo } from 'react';
import { Shield, Loader2, CheckCircle2, AlertCircle } from 'lucide-react';
import type { TaskStatus, StepStatus } from '../../../shared/types';
import { STATUS_DISPLAY, isInProgress, ANALYSIS_STEPS } from '../constants';

interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

interface TaskHeaderProps {
  status: TaskStatus;
  fileName?: string;
  stepStates?: Record<string, StepState>;
}

/**
 * Task detail header showing status and file info
 */
export const TaskHeader = memo(function TaskHeader({ status, fileName, stepStates }: TaskHeaderProps) {
  const statusInfo = STATUS_DISPLAY[status] || STATUS_DISPLAY.pending;
  const inProgress = isInProgress(status);

  const getTitle = () => {
    if (inProgress) return 'Analysis in Progress';
    if (status === 'completed') return 'Analysis Complete';
    return 'Analysis Failed';
  };

  // Find the current running step based on task status and completed steps
  const getCurrentStep = (): string | null => {
    if (!inProgress) return null;
    
    // Define step groups by stage
    const stageSteps: Record<string, string[]> = {
      stage_1_4: ['hash', 'strings', 'elf', 'func_class', 'mitre', 'yara', 'threat_intel', 'dynamic'],
      stage_5: ['ghidra'],
      stage_6: ['report'],
    };
    
    // Get steps for current stage
    const currentStageSteps = stageSteps[status] || [];
    if (currentStageSteps.length === 0) return null;
    
    // If we have stepStates, find the first non-completed step in current stage
    if (stepStates) {
      for (const stepId of currentStageSteps) {
        const state = stepStates[stepId];
        const step = ANALYSIS_STEPS.find(s => s.id === stepId);
        if (!state || state.status === 'pending' || state.status === 'running') {
          return step?.name || null;
        }
      }
    }
    
    // Fallback: return first step of current stage
    const firstStepId = currentStageSteps[0];
    const firstStep = ANALYSIS_STEPS.find(s => s.id === firstStepId);
    return firstStep?.name || null;
  };

  const currentStep = getCurrentStep();

  return (
    <div className="bg-slate-800 p-6 rounded-xl border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <div>
          <h2 className="text-2xl font-bold text-white flex items-center">
            <Shield className="w-6 h-6 mr-2 text-emerald-400" />
            {getTitle()}
          </h2>
          {fileName && (
            <p className="text-slate-400 mt-1">
              File: <span className="font-mono text-slate-300">{fileName}</span>
            </p>
          )}
        </div>
        <div className="flex items-center gap-3">
          {inProgress && <Loader2 className="animate-spin w-8 h-8 text-cyan-400" />}
          {status === 'completed' && <CheckCircle2 className="w-8 h-8 text-emerald-400" />}
          {status === 'failed' && <AlertCircle className="w-8 h-8 text-red-400" />}
        </div>
      </div>

      <div className="flex items-center gap-2">
        <span className="text-slate-400">Status:</span>
        {currentStep ? (
          <span className={`font-semibold ${statusInfo.color}`}>{currentStep}</span>
        ) : (
          <span className={`font-semibold ${statusInfo.color}`}>{statusInfo.label}</span>
        )}
      </div>
    </div>
  );
});

export default TaskHeader;
