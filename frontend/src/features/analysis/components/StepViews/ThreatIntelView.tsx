import { Database, CheckCircle, XCircle, AlertTriangle } from 'lucide-react';

interface ThreatIntelViewProps {
  data: {
    hash_lookup?: Record<string, {
      found: boolean;
      data?: Record<string, unknown>;
      error?: string;
    }>;
    ioc_lookup?: Record<string, Array<{
      found: boolean;
      data?: Record<string, unknown>;
      error?: string;
    }>>;
  };
}

export function ThreatIntelView({ data }: ThreatIntelViewProps) {
  const hashLookup = data.hash_lookup || {};
  const sources = Object.entries(hashLookup);

  if (sources.length === 0) {
    return (
      <div className="text-center py-6 text-slate-500">
        <Database className="w-8 h-8 mx-auto mb-2 opacity-50" />
        <p>No threat intelligence data available</p>
      </div>
    );
  }

  const foundSources = sources.filter(([, result]) => result.found);
  const notFoundSources = sources.filter(([, result]) => !result.found && !result.error);
  const errorSources = sources.filter(([, result]) => result.error);

  return (
    <div className="space-y-4">
      {/* Summary */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-red-900/20 rounded-lg p-3 border border-red-800/50 text-center">
          <p className="text-2xl font-bold text-red-400">{foundSources.length}</p>
          <p className="text-xs text-slate-400">Found</p>
        </div>
        <div className="bg-emerald-900/20 rounded-lg p-3 border border-emerald-800/50 text-center">
          <p className="text-2xl font-bold text-emerald-400">{notFoundSources.length}</p>
          <p className="text-xs text-slate-400">Clean</p>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 border border-slate-700/50 text-center">
          <p className="text-2xl font-bold text-slate-400">{errorSources.length}</p>
          <p className="text-xs text-slate-400">Errors</p>
        </div>
      </div>

      {/* Found Results */}
      {foundSources.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-red-400 flex items-center gap-2">
            <AlertTriangle className="w-4 h-4" />
            Detected in Threat Databases
          </h4>
          {foundSources.map(([source, result]) => (
            <div key={source} className="bg-red-900/20 rounded-lg p-4 border border-red-800/50">
              <div className="flex items-center gap-2 mb-2">
                <XCircle className="w-4 h-4 text-red-400" />
                <span className="text-red-300 font-medium">{formatSourceName(source)}</span>
              </div>
              {result.data && (
                <div className="text-xs text-slate-300 bg-slate-900/50 rounded p-2 mt-2">
                  <pre className="whitespace-pre-wrap">
                    {JSON.stringify(result.data, null, 2).slice(0, 500)}
                  </pre>
                </div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Clean Results */}
      {notFoundSources.length > 0 && (
        <div className="space-y-2">
          <h4 className="text-sm font-medium text-emerald-400 flex items-center gap-2">
            <CheckCircle className="w-4 h-4" />
            Not Found (Clean)
          </h4>
          <div className="flex flex-wrap gap-2">
            {notFoundSources.map(([source]) => (
              <span 
                key={source} 
                className="text-xs bg-emerald-900/30 text-emerald-400 px-3 py-1.5 rounded-full border border-emerald-800/50"
              >
                {formatSourceName(source)}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function formatSourceName(source: string): string {
  return source
    .replace(/_/g, ' ')
    .replace(/\b\w/g, c => c.toUpperCase());
}
