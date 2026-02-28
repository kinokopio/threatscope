import { memo, useState } from 'react';
import { Shield, ChevronRight } from 'lucide-react';
import type { GhidraAnalysis } from '../../../shared/types';

interface GhidraSectionProps {
  analysis: GhidraAnalysis;
}

const RISK_LEVEL_STYLES: Record<string, string> = {
  high: 'bg-red-900 text-red-100',
  critical: 'bg-red-900 text-red-100',
  medium: 'bg-orange-800 text-orange-100',
  low: 'bg-slate-600 text-slate-200',
};

export const GhidraSection = memo(function GhidraSection({ analysis }: GhidraSectionProps) {
  const [isOpen, setIsOpen] = useState(false);

  if (!analysis.ai_analysis) return null;

  const { analyzed_functions, key_findings } = analysis.ai_analysis;

  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
          <Shield className="w-6 h-6 mr-2" />
          Ghidra Deep Analysis
          {analyzed_functions && (
            <span className="ml-2 text-sm text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
              {analyzed_functions.length} functions
            </span>
          )}
        </h2>
        <button
          onClick={() => setIsOpen(!isOpen)}
          aria-expanded={isOpen}
          className="text-slate-200 bg-slate-800/60 hover:bg-slate-800 px-2 py-1 rounded flex items-center justify-center transition-colors"
        >
          <ChevronRight
            className={`w-4 h-4 transform transition-transform ${isOpen ? 'rotate-90' : ''}`}
          />
        </button>
      </div>

      {key_findings && key_findings.length > 0 && (
        <div className="bg-slate-700/50 p-4 rounded border-l-4 border-rose-500 mb-4">
          <h3 className="font-bold text-lg text-white mb-2">Key Findings</h3>
          <ul className="list-disc list-inside space-y-1 text-slate-300">
            {key_findings.map((finding, idx) => (
              <li key={finding.id || idx}>
                <span className="font-medium">{finding.title || finding.category || 'Finding'}</span>
                {finding.severity && (
                  <span className={`ml-2 text-xs px-1.5 py-0.5 rounded ${
                    finding.severity.toLowerCase() === 'critical' || finding.severity.toLowerCase() === 'high'
                      ? 'bg-red-500/20 text-red-400'
                      : finding.severity.toLowerCase() === 'medium'
                      ? 'bg-orange-500/20 text-orange-400'
                      : 'bg-slate-500/20 text-slate-400'
                  }`}>
                    {finding.severity}
                  </span>
                )}
                <span className="text-slate-400 ml-2">- {finding.description}</span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {isOpen && analyzed_functions && (
        <div className="space-y-3">
          {analyzed_functions.map((func, idx) => (
            <div
              key={idx}
              className="bg-slate-700/50 p-4 rounded border border-slate-600"
            >
              <div className="flex items-start justify-between">
                <div>
                  <span className="font-mono text-cyan-300">{func.name}</span>
                  {func.address && func.address !== 'UNKNOWN' && (
                    <span className="text-slate-500 text-sm ml-2">@ {func.address}</span>
                  )}
                </div>
                {func.risk && (
                  <span
                    className={`px-2 py-0.5 rounded text-xs font-bold uppercase ${
                      RISK_LEVEL_STYLES[func.risk.toLowerCase().split(' ')[0]] || RISK_LEVEL_STYLES.low
                    }`}
                  >
                    {func.risk}
                  </span>
                )}
              </div>
              {func.purpose && (
                <p className="text-slate-300 text-sm mt-2">{func.purpose}</p>
              )}
              {func.analysis && (
                <p className="text-slate-400 text-xs mt-1">{func.analysis}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
});

export default GhidraSection;
