import { memo } from 'react';
import { AlertCircle, AlertTriangle, CheckCircle } from 'lucide-react';

interface VerdictStatsProps {
  maliciousCount: number;
  suspiciousCount: number;
  benignCount: number;
}

export const VerdictStats = memo(function VerdictStats({
  maliciousCount,
  suspiciousCount,
  benignCount,
}: VerdictStatsProps) {
  return (
    <div className="grid grid-cols-3 gap-4 mb-6">
      <div className="bg-red-900/20 p-4 rounded-xl border border-red-800/50 flex items-center justify-between">
        <div>
          <p className="text-red-300 text-sm">Malicious</p>
          <p className="text-2xl font-bold text-red-400">{maliciousCount}</p>
        </div>
        <AlertCircle className="w-8 h-8 text-red-400/30" />
      </div>
      <div className="bg-yellow-900/20 p-4 rounded-xl border border-yellow-800/50 flex items-center justify-between">
        <div>
          <p className="text-yellow-300 text-sm">Suspicious</p>
          <p className="text-2xl font-bold text-yellow-400">{suspiciousCount}</p>
        </div>
        <AlertTriangle className="w-8 h-8 text-yellow-400/30" />
      </div>
      <div className="bg-emerald-900/20 p-4 rounded-xl border border-emerald-800/50 flex items-center justify-between">
        <div>
          <p className="text-emerald-300 text-sm">Benign</p>
          <p className="text-2xl font-bold text-emerald-400">{benignCount}</p>
        </div>
        <CheckCircle className="w-8 h-8 text-emerald-400/30" />
      </div>
    </div>
  );
});

export default VerdictStats;
