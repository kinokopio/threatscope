import { memo, useState, useCallback } from 'react';
import type { StepStatus, AnalysisResult, TaskStatus } from '../../../shared/types';
import { ANALYSIS_STEPS } from '../constants';
import { getEffectiveStepStatus } from '../hooks/useStepStates';
import { StepItem } from './StepItem';

interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

interface AnalysisStepsListProps {
  currentStatus: TaskStatus;
  stepStates: Record<string, StepState>;
  result?: AnalysisResult;
}

/**
 * List of all analysis steps with their current status
 * Manages expansion state internally
 */
export const AnalysisStepsList = memo(function AnalysisStepsList({
  currentStatus,
  stepStates,
  result,
}: AnalysisStepsListProps) {
  const [expandedSteps, setExpandedSteps] = useState<Set<string>>(new Set());

  const toggleStepExpansion = useCallback((stepId: string) => {
    setExpandedSteps((prev) => {
      const newSet = new Set(prev);
      if (newSet.has(stepId)) {
        newSet.delete(stepId);
      } else {
        newSet.add(stepId);
      }
      return newSet;
    });
  }, []);

  return (
    <div className="space-y-2">
      <h3 className="text-lg font-semibold text-white mb-3">Analysis Steps</h3>
      {ANALYSIS_STEPS.map((step) => {
        const effectiveStatus = getEffectiveStepStatus(
          step.id,
          step.group,
          currentStatus,
          stepStates
        );
        const stepState = stepStates[step.id];
        const isExpanded = expandedSteps.has(step.id);
        const canExpand = effectiveStatus === 'completed' && !!result;

        return (
          <StepItem
            key={step.id}
            step={step}
            effectiveStatus={effectiveStatus}
            stepState={stepState}
            isExpanded={isExpanded}
            canExpand={canExpand}
            result={result}
            onToggle={toggleStepExpansion}
          />
        );
      })}
    </div>
  );
});

export default AnalysisStepsList;
