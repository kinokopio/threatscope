import { memo } from 'react';
import { formatPreviewValue } from '../../../shared/utils';

interface StepPreviewProps {
  preview?: Record<string, unknown>;
}

/**
 * Compact preview of step results
 * Memoized to prevent unnecessary re-renders
 */
export const StepPreview = memo(function StepPreview({ preview }: StepPreviewProps) {
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
});

export default StepPreview;
