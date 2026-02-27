import { memo, useCallback } from 'react';
import { ChevronDown, ChevronRight } from 'lucide-react';
import { StepStatusIcon } from '../../../shared/ui';
import type { StepStatus, AnalysisResult } from '../../../shared/types';
import type { AnalysisStep } from '../constants';
import { StepPreview } from './StepPreview';
import { StepDetailContent } from './StepDetailContent';

interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

interface StepItemProps {
  step: AnalysisStep;
  effectiveStatus: StepStatus;
  stepState?: StepState;
  isExpanded: boolean;
  canExpand: boolean;
  result?: AnalysisResult;
  onToggle: (stepId: string) => void;
}

// Status-based style mappings - hoisted outside component
const STATUS_BORDER_STYLES: Record<StepStatus, string> = {
  running: 'border-cyan-500/50 shadow-lg shadow-cyan-500/10',
  completed: 'border-emerald-500/30',
  failed: 'border-red-500/30',
  skipped: 'border-slate-700/50',
  pending: 'border-slate-700/50',
};

const STATUS_BG_STYLES: Record<StepStatus, string> = {
  completed: 'bg-emerald-500/20',
  running: 'bg-cyan-500/20',
  failed: 'bg-red-500/20',
  skipped: 'bg-slate-700/30',
  pending: 'bg-slate-700/30',
};

const STATUS_TEXT_STYLES: Record<StepStatus, string> = {
  completed: 'text-emerald-400',
  running: 'text-cyan-400',
  failed: 'text-red-400',
  skipped: 'text-slate-500',
  pending: 'text-slate-500',
};

/**
 * Individual analysis step item
 * Memoized to prevent re-renders when other steps change
 */
export const StepItem = memo(function StepItem({
  step,
  effectiveStatus,
  stepState,
  isExpanded,
  canExpand,
  result,
  onToggle,
}: StepItemProps) {
  const Icon = step.icon;

  const handleClick = useCallback(() => {
    if (canExpand) {
      onToggle(step.id);
    }
  }, [canExpand, onToggle, step.id]);

  const borderStyle = STATUS_BORDER_STYLES[effectiveStatus];
  const bgStyle = STATUS_BG_STYLES[effectiveStatus];
  const textStyle = STATUS_TEXT_STYLES[effectiveStatus];

  return (
    <div
      className={`bg-slate-800 rounded-xl border transition-all duration-300 ${borderStyle}`}
    >
      {/* Clickable Header */}
      <div
        className={`p-4 ${canExpand ? 'cursor-pointer hover:bg-slate-700/30' : ''}`}
        onClick={handleClick}
      >
        <div className="flex items-start gap-3">
          {/* Status Icon */}
          <div
            className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center ${bgStyle}`}
          >
            <StepStatusIcon status={effectiveStatus} />
          </div>

          {/* Content */}
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2">
              <Icon className={`w-4 h-4 ${textStyle}`} />
              <h3 className={`font-medium text-sm ${textStyle}`}>{step.name}</h3>
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
            <p
              className={`text-xs mt-0.5 ${
                effectiveStatus === 'pending' ? 'text-slate-600' : 'text-slate-400'
              }`}
            >
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
      {isExpanded && result && (
        <div className="px-4 pb-4">
          <StepDetailContent stepId={step.id} result={result} />
        </div>
      )}
    </div>
  );
});

export default StepItem;
