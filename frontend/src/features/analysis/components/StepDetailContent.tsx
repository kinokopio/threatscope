import { memo } from 'react';
import type { AnalysisResult } from '../../../shared/types';
import DynamicAnalysisView from './DynamicAnalysisView';

interface StepDetailContentProps {
  stepId: string;
  result: AnalysisResult;
}

// Helper messages for missing data
const MISSING_DATA_MESSAGES: Record<string, string> = {
  func_class: 'No imported functions found (binary may be statically linked)',
  mitre: 'No imported functions to map (binary may be statically linked)',
  dynamic: 'Dynamic analysis requires Docker or QEMU user-mode emulator',
  ghidra: 'Ghidra analysis was not performed',
};

/**
 * Renders detailed content for a specific analysis step
 * Memoized to prevent unnecessary re-renders when other steps change
 */
export const StepDetailContent = memo(function StepDetailContent({
  stepId,
  result,
}: StepDetailContentProps) {
  // Recursive value renderer
  const renderValue = (value: unknown, depth = 0): React.ReactNode => {
    if (value === null || value === undefined) {
      return <span className="text-slate-500">N/A</span>;
    }
    if (typeof value === 'boolean') {
      return (
        <span className={value ? 'text-emerald-400' : 'text-red-400'}>
          {value ? 'Yes' : 'No'}
        </span>
      );
    }
    if (typeof value === 'number') {
      return <span className="text-cyan-300">{value}</span>;
    }
    if (typeof value === 'string') {
      if (value.length > 500) {
        return <span className="text-slate-300 break-all">{value.slice(0, 500)}...</span>;
      }
      return <span className="text-slate-300 break-all">{value}</span>;
    }
    if (Array.isArray(value)) {
      if (value.length === 0) return <span className="text-slate-500">Empty</span>;
      if (depth > 2) return <span className="text-slate-400">[{value.length} items]</span>;
      return (
        <div className="space-y-1 ml-2">
          {value.map((item, i) => (
            <div key={i} className="text-xs">
              {renderValue(item, depth + 1)}
            </div>
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
      case 'hash':
        return result.hashes;
      case 'strings':
        return result.strings;
      case 'elf':
        return result.elf;
      case 'func_class':
        return result.function_categories;
      case 'mitre':
        return result.mitre_mapping;
      case 'yara':
        return result.yara;
      case 'threat_intel':
        return result.threat_intel;
      case 'dynamic':
        return result.dynamic_analysis;
      case 'ghidra':
        return result.ghidra_analysis;
      case 'report':
        return result.malware_report;
      default:
        return null;
    }
  };

  const data = getStepData();

  // Show helpful message for missing data
  if (!data) {
    const message = MISSING_DATA_MESSAGES[stepId] || 'No data available';
    return <div className="text-slate-500 text-sm py-2">{message}</div>;
  }

  // Special handling for dynamic analysis
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
    return (
      <div className="mt-3 pt-3 border-t border-slate-700/50">
        {/* eslint-disable-next-line @typescript-eslint/no-explicit-any */}
        <DynamicAnalysisView data={dynData as any} />
      </div>
    );
  }

  return (
    <div className="mt-3 pt-3 border-t border-slate-700/50">
      <div className="bg-slate-900/50 rounded-lg p-3 max-h-[600px] overflow-y-auto">
        <div className="text-xs font-mono">{renderValue(data)}</div>
      </div>
    </div>
  );
});

export default StepDetailContent;
