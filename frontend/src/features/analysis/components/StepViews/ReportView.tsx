import { FileWarning, Shield, AlertTriangle, CheckCircle, Target, Lightbulb } from 'lucide-react';

interface ReportViewProps {
  data: {
    verdict?: string;
    confidence?: number;
    family?: string;
    summary?: string;
    capabilities?: string[];
    iocs?: Record<string, unknown> | string[];
    mitre_techniques?: string[];
    recommendations?: string[];
  };
}

const VERDICT_CONFIG: Record<string, { color: string; bgColor: string; icon: typeof Shield }> = {
  malicious: { 
    color: 'text-red-400', 
    bgColor: 'bg-red-900/30 border-red-800/50',
    icon: AlertTriangle
  },
  suspicious: { 
    color: 'text-orange-400', 
    bgColor: 'bg-orange-900/30 border-orange-800/50',
    icon: FileWarning
  },
  benign: { 
    color: 'text-emerald-400', 
    bgColor: 'bg-emerald-900/30 border-emerald-800/50',
    icon: CheckCircle
  },
};

export function ReportView({ data }: ReportViewProps) {
  const verdict = data.verdict?.toLowerCase() || 'unknown';
  const config = VERDICT_CONFIG[verdict] || { 
    color: 'text-slate-400', 
    bgColor: 'bg-slate-800/50 border-slate-700/50',
    icon: Shield
  };
  const VerdictIcon = config.icon;
  
  const confidence = data.confidence || 0;
  const confidencePercent = confidence <= 1 ? Math.round(confidence * 100) : Math.round(confidence);

  return (
    <div className="space-y-4">
      {/* Verdict Banner */}
      <div className={`rounded-xl p-5 border ${config.bgColor}`}>
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <VerdictIcon className={`w-8 h-8 ${config.color}`} />
            <div>
              <p className={`text-2xl font-bold capitalize ${config.color}`}>{verdict}</p>
              {data.family && data.family !== 'Unknown' && (
                <p className="text-slate-400 text-sm">Family: <span className="text-slate-200">{data.family}</span></p>
              )}
            </div>
          </div>
          <div className="text-right">
            <p className="text-3xl font-bold text-white">{confidencePercent}%</p>
            <p className="text-xs text-slate-500">Confidence</p>
          </div>
        </div>
      </div>

      {/* Summary */}
      {data.summary && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <h4 className="text-sm font-medium text-slate-300 mb-2">Summary</h4>
          <p className="text-sm text-slate-400 leading-relaxed">{data.summary}</p>
        </div>
      )}

      {/* Capabilities */}
      {data.capabilities && data.capabilities.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <h4 className="text-sm font-medium text-purple-400 flex items-center gap-2 mb-3">
            <Target className="w-4 h-4" />
            Capabilities
          </h4>
          <div className="flex flex-wrap gap-2">
            {data.capabilities.map((cap, i) => (
              <span 
                key={i} 
                className="text-xs bg-purple-900/30 text-purple-300 px-3 py-1.5 rounded-full border border-purple-800/50"
              >
                {cap}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* MITRE Techniques */}
      {data.mitre_techniques && data.mitre_techniques.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <h4 className="text-sm font-medium text-cyan-400 flex items-center gap-2 mb-3">
            <Shield className="w-4 h-4" />
            MITRE ATT&CK Techniques
          </h4>
          <div className="flex flex-wrap gap-2">
            {data.mitre_techniques.map((tech, i) => (
              <span 
                key={i} 
                className="text-xs font-mono bg-cyan-900/30 text-cyan-300 px-2 py-1 rounded border border-cyan-800/50"
              >
                {tech}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {data.recommendations && data.recommendations.length > 0 && (
        <div className="bg-slate-900/50 rounded-lg p-4">
          <h4 className="text-sm font-medium text-emerald-400 flex items-center gap-2 mb-3">
            <Lightbulb className="w-4 h-4" />
            Recommendations
          </h4>
          <ul className="space-y-2">
            {data.recommendations.map((rec, i) => (
              <li key={i} className="text-sm text-slate-400 flex items-start gap-2">
                <span className="text-emerald-400 mt-1">•</span>
                {rec}
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
