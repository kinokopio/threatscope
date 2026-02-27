import { memo } from 'react';
import { AlertTriangle } from 'lucide-react';

interface YaraSectionProps {
  matches: string[];
}

export const YaraSection = memo(function YaraSection({ matches }: YaraSectionProps) {
  if (!matches || matches.length === 0) return null;

  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
        <AlertTriangle className="w-6 h-6 mr-2" />
        YARA Matches
      </h2>
      <div className="flex flex-wrap gap-2">
        {matches.map((match, idx) => (
          <span
            key={idx}
            className="px-3 py-1 rounded text-sm bg-red-900/50 text-red-200 border border-red-700"
          >
            {match}
          </span>
        ))}
      </div>
    </div>
  );
});

export default YaraSection;
