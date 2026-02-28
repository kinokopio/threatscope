import { Brain, AlertTriangle, CheckCircle, Shield, Zap } from 'lucide-react';

interface GhidraViewProps {
  data: {
    status?: string;
    ghidra_available?: boolean;
    analyzed_functions?: Array<{
      name: string;
      address?: string;
      analysis?: string;
      risk_level?: string;
    }>;
    key_findings?: Array<{
      type: string;
      description: string;
      severity?: string;
    }>;
    ai_analysis?: {
      analyzed_functions?: Array<unknown>;
      key_findings?: Array<unknown>;
    };
  };
}

export function GhidraView({ data }: GhidraViewProps) {
  if (data.status === 'ghidra_unavailable' || !data.ghidra_available) {
    return (
      <div className="bg-yellow-900/20 rounded-lg p-4 border border-yellow-800/50">
        <div className="flex items-center gap-2">
          <AlertTriangle className="w-5 h-5 text-yellow-400" />
          <div>
            <p className="text-yellow-400 font-medium">Ghidra Not Available</p>
            <p className="text-slate-400 text-sm mt-1">Deep binary analysis was skipped</p>
          </div>
        </div>
      </div>
    );
  }

  const functions = data.analyzed_functions || data.ai_analysis?.analyzed_functions || [];
  const findings = data.key_findings || data.ai_analysis?.key_findings || [];

  if (functions.length === 0 && findings.length === 0) {
    return (
      <div className="bg-emerald-900/20 rounded-lg p-4 border border-emerald-800/50">
        <div className="flex items-center gap-2">
          <CheckCircle className="w-5 h-5 text-emerald-400" />
          <div>
            <p className="text-emerald-400 font-medium">Analysis Complete</p>
            <p className="text-slate-400 text-sm mt-1">No suspicious patterns detected</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Key Findings */}
      {findings.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-purple-400 flex items-center gap-2 mb-3">
            <Zap className="w-4 h-4" />
            Key Findings ({findings.length})
          </h4>
          <div className="space-y-2">
            {(findings as Array<{ type: string; description: string; severity?: string }>).map((finding, i) => (
              <div 
                key={i} 
                className={`rounded-lg p-3 border ${
                  finding.severity === 'high' 
                    ? 'bg-red-900/20 border-red-800/50' 
                    : finding.severity === 'medium'
                    ? 'bg-orange-900/20 border-orange-800/50'
                    : 'bg-slate-800/50 border-slate-700/50'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Shield className={`w-4 h-4 ${
                    finding.severity === 'high' ? 'text-red-400' : 
                    finding.severity === 'medium' ? 'text-orange-400' : 'text-slate-400'
                  }`} />
                  <span className="text-sm font-medium text-slate-200">{finding.type}</span>
                </div>
                <p className="text-xs text-slate-400">{finding.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Analyzed Functions */}
      {functions.length > 0 && (
        <div>
          <h4 className="text-sm font-medium text-cyan-400 flex items-center gap-2 mb-3">
            <Brain className="w-4 h-4" />
            Analyzed Functions ({functions.length})
          </h4>
          <div className="space-y-2 max-h-60 overflow-y-auto">
            {(functions as Array<{ name: string; address?: string; analysis?: string }>).slice(0, 10).map((func, i) => (
              <div key={i} className="bg-slate-900/50 rounded-lg p-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-cyan-400 font-mono text-sm">{func.name}</span>
                  {func.address && (
                    <span className="text-xs text-slate-500 font-mono">@ {func.address}</span>
                  )}
                </div>
                {func.analysis && (
                  <p className="text-xs text-slate-400 line-clamp-2">{func.analysis}</p>
                )}
              </div>
            ))}
            {functions.length > 10 && (
              <p className="text-xs text-slate-500 text-center py-2">
                +{functions.length - 10} more functions analyzed
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
