import { memo, useState } from 'react';
import { Target, ChevronRight } from 'lucide-react';
import type { MitreMapping } from '../../../shared/types';

interface MitreSectionProps {
  mappings: MitreMapping[];
}

export const MitreSection = memo(function MitreSection({ mappings }: MitreSectionProps) {
  const [isOpen, setIsOpen] = useState(false);

  if (!mappings || mappings.length === 0) return null;

  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-2xl font-bold text-emerald-400 flex items-center">
          <Target className="w-6 h-6 mr-2" />
          MITRE ATT&CK Mapping
          <span className="ml-2 text-sm text-slate-400 bg-slate-700 px-2 py-0.5 rounded">
            {mappings.length}
          </span>
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

      {isOpen && (
        <div className="space-y-3">
          {mappings.map((mapping, idx) => (
            <div
              key={idx}
              className="bg-slate-700/50 p-4 rounded border border-slate-600"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <span className="font-mono text-cyan-300">{mapping.technique_id}</span>
                  <span className="text-slate-200 ml-2">{mapping.technique_name}</span>
                </div>
                <span className="px-2 py-0.5 rounded text-xs font-semibold bg-slate-600 text-slate-200">
                  {mapping.tactic}
                </span>
              </div>
              {mapping.evidence && (
                <p className="text-slate-400 text-sm mt-2">{mapping.evidence}</p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
});

export default MitreSection;
