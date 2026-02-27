import { memo } from 'react';
import ReactMarkdown from 'react-markdown';
import { Shield, XCircle, AlertTriangle, CheckCircle, Info } from 'lucide-react';
import type { MalwareReport } from '../../../shared/types';

interface SummarySectionProps {
  report: MalwareReport;
}

const VERDICT_BADGE_STYLES: Record<string, string> = {
  malicious: 'bg-red-900 text-red-100',
  suspicious: 'bg-orange-700 text-orange-100',
  benign: 'bg-green-900 text-green-100',
};

const CONFIDENCE_COLORS: Record<string, string> = {
  high: 'text-red-400',
  medium: 'text-orange-400',
  low: 'text-green-400',
};

function getConfidenceColor(confidence: number): string {
  if (confidence >= 0.8) return CONFIDENCE_COLORS.high;
  if (confidence >= 0.5) return CONFIDENCE_COLORS.medium;
  return CONFIDENCE_COLORS.low;
}

function VerdictIcon({ verdict }: { verdict: string }) {
  switch (verdict) {
    case 'malicious':
      return <XCircle className="w-4 h-4 mr-2" />;
    case 'suspicious':
      return <AlertTriangle className="w-4 h-4 mr-2" />;
    case 'benign':
      return <CheckCircle className="w-4 h-4 mr-2" />;
    default:
      return null;
  }
}

export const SummarySection = memo(function SummarySection({ report }: SummarySectionProps) {
  const badgeStyle = VERDICT_BADGE_STYLES[report.verdict] || 'bg-slate-700 text-slate-200';

  return (
    <div className="bg-slate-800 p-6 rounded-lg shadow-lg border border-slate-700">
      <h2 className="text-2xl font-bold mb-4 text-emerald-400 flex items-center">
        <Shield className="w-6 h-6 mr-2" />
        Analysis Summary
      </h2>

      <div className="space-y-4">
        <div className="flex flex-wrap gap-4 mb-4">
          <span
            className={`px-4 py-2 rounded text-sm font-bold uppercase flex items-center ${badgeStyle}`}
          >
            <VerdictIcon verdict={report.verdict} />
            {report.verdict}
          </span>
          <span className="px-4 py-2 rounded text-sm font-bold bg-slate-700 text-slate-200">
            Confidence:{' '}
            <span className={getConfidenceColor(report.confidence)}>
              {(report.confidence * 100).toFixed(0)}%
            </span>
          </span>
          {report.family && (
            <span className="px-4 py-2 rounded text-sm font-bold bg-slate-700 text-cyan-300">
              Family: {report.family}
            </span>
          )}
        </div>

        <div className="bg-slate-700/50 p-4 rounded border-l-4 border-cyan-500">
          <h3 className="font-bold text-lg text-white mb-2 flex items-center">
            <Info className="w-5 h-5 mr-2" />
            Summary
          </h3>
          <div className="prose prose-invert prose-sm max-w-none">
            <ReactMarkdown>{report.summary}</ReactMarkdown>
          </div>
        </div>

        {report.capabilities && report.capabilities.length > 0 && (
          <div className="bg-slate-700/50 p-4 rounded border-l-4 border-purple-500">
            <h3 className="font-bold text-lg text-white mb-2">Capabilities</h3>
            <div className="flex flex-wrap gap-2">
              {report.capabilities.map((cap, idx) => (
                <span
                  key={idx}
                  className="px-3 py-1 rounded text-sm bg-purple-900/50 text-purple-200 border border-purple-700"
                >
                  {cap}
                </span>
              ))}
            </div>
          </div>
        )}

        {report.technical_details && Object.keys(report.technical_details).length > 0 && (
          <div className="bg-slate-700/50 p-4 rounded border-l-4 border-blue-500">
            <h3 className="font-bold text-lg text-white mb-2">Technical Details</h3>
            <div className="grid grid-cols-2 gap-3 text-sm">
              {Object.entries(report.technical_details).map(
                ([key, value]) =>
                  value && (
                    <div key={key} className="bg-slate-800 p-2 rounded">
                      <span className="block text-slate-400 text-xs capitalize">
                        {key.replace(/_/g, ' ')}
                      </span>
                      <span className="font-mono text-slate-200">{value}</span>
                    </div>
                  )
              )}
            </div>
          </div>
        )}

        {report.recommendations && report.recommendations.length > 0 && (
          <div className="bg-slate-700/50 p-4 rounded border-l-4 border-yellow-500">
            <h3 className="font-bold text-lg text-white mb-2">Recommendations</h3>
            <ul className="list-disc list-inside space-y-1 text-slate-300">
              {report.recommendations.map((rec, idx) => (
                <li key={idx}>{rec}</li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
});

export default SummarySection;
