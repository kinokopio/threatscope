import type { MalwareReport } from '../types';
import { 
  ShieldAlert, 
  ShieldCheck, 
  ShieldQuestion,
  AlertTriangle,
  Globe,
  Server,
  Link,
  Hash,
  Target,
  Lightbulb
} from 'lucide-react';

interface ReportViewerProps {
  report: MalwareReport;
}

const verdictConfig = {
  malicious: {
    icon: ShieldAlert,
    color: 'text-accent-red',
    bgColor: 'bg-accent-red/20',
    borderColor: 'border-accent-red/50',
    label: 'MALICIOUS',
  },
  suspicious: {
    icon: ShieldQuestion,
    color: 'text-accent-amber',
    bgColor: 'bg-accent-amber/20',
    borderColor: 'border-accent-amber/50',
    label: 'SUSPICIOUS',
  },
  benign: {
    icon: ShieldCheck,
    color: 'text-accent-green',
    bgColor: 'bg-accent-green/20',
    borderColor: 'border-accent-green/50',
    label: 'BENIGN',
  },
};

export function ReportViewer({ report }: ReportViewerProps) {
  const verdict = verdictConfig[report.verdict];
  const VerdictIcon = verdict.icon;

  return (
    <div className="space-y-6">
      {/* Verdict Banner */}
      <div className={`${verdict.bgColor} ${verdict.borderColor} border rounded-xl p-6`}>
        <div className="flex items-center gap-4">
          <VerdictIcon className={`w-12 h-12 ${verdict.color}`} />
          <div>
            <h2 className={`text-2xl font-bold ${verdict.color}`}>
              {verdict.label}
            </h2>
            <p className="text-gray-300 mt-1">
              Confidence: {(report.confidence * 100).toFixed(0)}%
            </p>
          </div>
          {report.family && (
            <div className="ml-auto text-right">
              <p className="text-sm text-gray-400">Family</p>
              <p className="text-xl font-semibold text-gray-200">{report.family}</p>
            </div>
          )}
        </div>
      </div>

      {/* Summary */}
      <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
        <h3 className="text-lg font-semibold text-gray-200 mb-3">Summary</h3>
        <p className="text-gray-300 leading-relaxed">{report.summary}</p>
      </div>

      {/* Capabilities */}
      {report.capabilities.length > 0 && (
        <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
          <h3 className="text-lg font-semibold text-gray-200 mb-3 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-accent-amber" />
            Capabilities
          </h3>
          <div className="flex flex-wrap gap-2">
            {report.capabilities.map((cap, i) => (
              <span
                key={i}
                className="px-3 py-1.5 bg-accent-amber/20 text-accent-amber rounded-lg text-sm"
              >
                {cap}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* IoCs */}
      <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
        <h3 className="text-lg font-semibold text-gray-200 mb-4">
          Indicators of Compromise (IoCs)
        </h3>
        <div className="grid md:grid-cols-2 gap-4">
          {/* Domains */}
          {report.iocs.domains.length > 0 && (
            <div className="bg-cyber-900 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                <Globe className="w-4 h-4" />
                Domains ({report.iocs.domains.length})
              </h4>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {report.iocs.domains.map((domain, i) => (
                  <p key={i} className="text-sm text-accent-cyan font-mono">{domain}</p>
                ))}
              </div>
            </div>
          )}

          {/* IPs */}
          {report.iocs.ips.length > 0 && (
            <div className="bg-cyber-900 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                <Server className="w-4 h-4" />
                IP Addresses ({report.iocs.ips.length})
              </h4>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {report.iocs.ips.map((ip, i) => (
                  <p key={i} className="text-sm text-accent-cyan font-mono">{ip}</p>
                ))}
              </div>
            </div>
          )}

          {/* URLs */}
          {report.iocs.urls.length > 0 && (
            <div className="bg-cyber-900 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                <Link className="w-4 h-4" />
                URLs ({report.iocs.urls.length})
              </h4>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {report.iocs.urls.map((url, i) => (
                  <p key={i} className="text-sm text-accent-cyan font-mono break-all">{url}</p>
                ))}
              </div>
            </div>
          )}

          {/* Hashes */}
          {report.iocs.file_hashes.length > 0 && (
            <div className="bg-cyber-900 rounded-lg p-4">
              <h4 className="text-sm font-medium text-gray-400 mb-2 flex items-center gap-2">
                <Hash className="w-4 h-4" />
                File Hashes ({report.iocs.file_hashes.length})
              </h4>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {report.iocs.file_hashes.map((hash, i) => (
                  <p key={i} className="text-sm text-gray-300 font-mono break-all">{hash}</p>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* MITRE ATT&CK */}
      {report.mitre_mapping.length > 0 && (
        <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
          <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
            <Target className="w-5 h-5 text-accent-red" />
            MITRE ATT&CK Mapping
          </h3>
          <div className="space-y-3">
            {report.mitre_mapping.map((mapping, i) => (
              <div key={i} className="bg-cyber-900 rounded-lg p-4">
                <div className="flex items-start gap-3">
                  <span className="px-2 py-1 bg-accent-red/20 text-accent-red text-xs font-mono rounded">
                    {mapping.technique_id}
                  </span>
                  <div className="flex-1">
                    <p className="font-medium text-gray-200">{mapping.technique_name}</p>
                    <p className="text-sm text-gray-400 mt-1">Tactic: {mapping.tactic}</p>
                    {mapping.evidence && (
                      <p className="text-sm text-gray-500 mt-2">{mapping.evidence}</p>
                    )}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recommendations */}
      {report.recommendations.length > 0 && (
        <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
          <h3 className="text-lg font-semibold text-gray-200 mb-4 flex items-center gap-2">
            <Lightbulb className="w-5 h-5 text-accent-amber" />
            Recommendations
          </h3>
          <ul className="space-y-2">
            {report.recommendations.map((rec, i) => (
              <li key={i} className="flex items-start gap-3">
                <span className="w-6 h-6 rounded-full bg-accent-amber/20 text-accent-amber text-sm flex items-center justify-center flex-shrink-0">
                  {i + 1}
                </span>
                <p className="text-gray-300">{rec}</p>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
