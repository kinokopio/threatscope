import { Shield, AlertTriangle, CheckCircle } from 'lucide-react';

interface YaraViewProps {
  data: {
    matches?: Array<{
      rule: string;
      namespace?: string;
      tags?: string[];
      meta?: Record<string, string>;
      strings?: Array<{ identifier: string; data: string; offset: number }>;
    }>;
    rule_count?: number;
    match_count?: number;
    message?: string;
    error?: string;
  };
}

export function YaraView({ data }: YaraViewProps) {
  if (data.error) {
    return (
      <div className="bg-yellow-900/20 rounded-lg p-4 border border-yellow-800/50">
        <p className="text-yellow-400 text-sm">⚠️ {data.error}</p>
      </div>
    );
  }

  const matches = data.matches || [];

  if (matches.length === 0) {
    return (
      <div className="bg-emerald-900/20 rounded-lg p-4 border border-emerald-800/50">
        <div className="flex items-center gap-2">
          <CheckCircle className="w-5 h-5 text-emerald-400" />
          <div>
            <p className="text-emerald-400 font-medium">No YARA Rules Matched</p>
            <p className="text-slate-400 text-sm mt-1">
              {data.rule_count ? `Scanned against ${data.rule_count} rules` : 'No malicious patterns detected'}
            </p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 mb-2">
        <AlertTriangle className="w-5 h-5 text-orange-400" />
        <span className="text-orange-400 font-medium">{matches.length} Rule{matches.length > 1 ? 's' : ''} Matched</span>
      </div>

      {matches.map((match, i) => (
        <div key={i} className="bg-orange-900/20 rounded-lg border border-orange-800/50 p-4">
          <div className="flex items-start justify-between mb-2">
            <div className="flex items-center gap-2">
              <Shield className="w-4 h-4 text-orange-400" />
              <span className="text-orange-300 font-medium">{match.rule}</span>
            </div>
            {match.namespace && (
              <span className="text-xs text-slate-500 bg-slate-800 px-2 py-0.5 rounded">
                {match.namespace}
              </span>
            )}
          </div>

          {match.tags && match.tags.length > 0 && (
            <div className="flex flex-wrap gap-1 mb-2">
              {match.tags.map((tag, j) => (
                <span key={j} className="text-xs bg-orange-800/50 text-orange-300 px-2 py-0.5 rounded">
                  {tag}
                </span>
              ))}
            </div>
          )}

          {match.meta && Object.keys(match.meta).length > 0 && (
            <div className="mt-2 pt-2 border-t border-orange-800/30">
              <div className="grid grid-cols-2 gap-2 text-xs">
                {Object.entries(match.meta).slice(0, 4).map(([key, value]) => (
                  <div key={key}>
                    <span className="text-slate-500">{key}: </span>
                    <span className="text-slate-300">{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
