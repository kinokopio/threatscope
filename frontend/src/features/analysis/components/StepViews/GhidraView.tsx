import { Brain, AlertTriangle, CheckCircle, Shield, Zap } from 'lucide-react';

interface AnalyzedFunction {
  name: string;
  address?: string;
  // Different AI outputs use different field names
  analysis?: string;
  purpose?: string;
  description?: string;  // AI sometimes uses this instead of analysis/purpose
  risk?: string;
  risk_level?: string;
  severity?: string;  // AI sometimes uses this instead of risk
  type?: string;  // Function type (entry_point, persistence, etc.)
}

interface KeyFinding {
  id?: string;
  type?: string;
  title?: string;
  category?: string;
  description: string;
  severity?: string;
  evidence?: string[] | string;  // Can be array or string depending on AI output
  impact?: string;
  recommendation?: string;
}

interface GhidraViewProps {
  data: {
    status?: string;
    ghidra_available?: boolean;
    analyzed_functions?: AnalyzedFunction[];
    key_findings?: KeyFinding[];
    ai_analysis?: {
      analyzed_functions?: AnalyzedFunction[];
      key_findings?: KeyFinding[];
    };
  };
}

// Normalize severity to lowercase for styling
function normalizeSeverity(severity?: string): 'critical' | 'high' | 'medium' | 'low' | undefined {
  if (!severity) return undefined;
  const lower = severity.toLowerCase();
  if (lower === 'critical' || lower === 'high') return lower as 'critical' | 'high';
  if (lower === 'medium') return 'medium';
  if (lower === 'low') return 'low';
  return undefined;
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

  // Parse ai_analysis - handle case where $defs contains JSON string
  let aiAnalysis = data.ai_analysis;
  if (aiAnalysis && '$defs' in aiAnalysis) {
    const defs = (aiAnalysis as Record<string, unknown>)['$defs'];
    if (typeof defs === 'string') {
      try {
        aiAnalysis = JSON.parse(defs);
      } catch {
        aiAnalysis = undefined;
      }
    } else if (typeof defs === 'object' && defs !== null) {
      aiAnalysis = defs as typeof aiAnalysis;
    }
  }

  // Prefer ai_analysis data if available, fallback to top-level
  const functions = (aiAnalysis?.analyzed_functions?.length ? aiAnalysis.analyzed_functions : data.analyzed_functions) || [];
  const findings = (aiAnalysis?.key_findings?.length ? aiAnalysis.key_findings : data.key_findings) || [];
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
            {findings.map((finding, i) => {
              const severity = normalizeSeverity(finding.severity);
              const title = finding.title || finding.type || finding.category || 'Finding';
              return (
                <div 
                  key={finding.id || i} 
                  className={`rounded-lg p-3 border ${
                    severity === 'critical' || severity === 'high'
                      ? 'bg-red-900/20 border-red-800/50' 
                      : severity === 'medium'
                      ? 'bg-orange-900/20 border-orange-800/50'
                      : 'bg-slate-800/50 border-slate-700/50'
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Shield className={`w-4 h-4 ${
                      severity === 'critical' || severity === 'high' ? 'text-red-400' : 
                      severity === 'medium' ? 'text-orange-400' : 'text-slate-400'
                    }`} />
                    <span className="text-sm font-medium text-slate-200">{title}</span>
                    {severity && (
                      <span className={`text-xs px-1.5 py-0.5 rounded ${
                        severity === 'critical' ? 'bg-red-500/20 text-red-400' :
                        severity === 'high' ? 'bg-red-500/20 text-red-400' :
                        severity === 'medium' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-slate-500/20 text-slate-400'
                      }`}>
                        {severity.toUpperCase()}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-400">{finding.description}</p>
                  {finding.evidence && (
                    <div className="mt-2 text-xs">
                      <span className="text-slate-500">Evidence: </span>
                      <span className="text-slate-400">
                        {Array.isArray(finding.evidence)
                          ? finding.evidence.slice(0, 3).join(', ')
                          : String(finding.evidence).slice(0, 200)}
                        {Array.isArray(finding.evidence) && finding.evidence.length > 3 && (
                          <span className="text-slate-500"> +{finding.evidence.length - 3} more</span>
                        )}
                      </span>
                    </div>
                  )}
                </div>
              );
            })}
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
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {functions.slice(0, 15).map((func, i) => {
              // Normalize field names - AI uses different names in different runs
              const risk = normalizeSeverity(func.risk || func.risk_level || func.severity);
              const description = func.purpose || func.analysis || func.description;
              return (
                <div key={i} className="bg-slate-900/50 rounded-lg p-3">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-cyan-400 font-mono text-sm">{func.name}</span>
                    {func.address && func.address.toLowerCase() !== 'unknown' && (
                      <span className="text-xs text-slate-500 font-mono">@ {func.address}</span>
                    )}
                    {func.type && (
                      <span className="text-xs px-1.5 py-0.5 rounded bg-slate-700/50 text-slate-400">
                        {func.type.replace(/_/g, ' ')}
                      </span>
                    )}
                    {risk && (
                      <span className={`text-xs px-1.5 py-0.5 rounded ml-auto ${
                        risk === 'critical' || risk === 'high' ? 'bg-red-500/20 text-red-400' :
                        risk === 'medium' ? 'bg-orange-500/20 text-orange-400' :
                        'bg-slate-500/20 text-slate-400'
                      }`}>
                        {risk.toUpperCase()}
                      </span>
                    )}
                  </div>
                  {description && (
                    <p className="text-xs text-slate-400 line-clamp-2">{description}</p>
                  )}
                </div>
              );
            })}
            {functions.length > 15 && (
              <p className="text-xs text-slate-500 text-center py-2">
                +{functions.length - 15} more functions analyzed
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
