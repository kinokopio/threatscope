import { memo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { FileText } from 'lucide-react';
import { VerdictIcon } from '../../../shared/ui';

interface TaskItemProps {
  id: string;
  fileName?: string;
  verdict?: string;
  confidence?: number;
  family?: string | null;
}

const VERDICT_BADGE_STYLES: Record<string, string> = {
  malicious: 'bg-red-900/30 text-red-400 border-red-800',
  suspicious: 'bg-yellow-900/30 text-yellow-400 border-yellow-800',
  benign: 'bg-emerald-900/30 text-emerald-400 border-emerald-800',
  unknown: 'bg-slate-800 text-slate-400 border-slate-700',
};

const VERDICT_BG_STYLES: Record<string, string> = {
  malicious: 'bg-red-500/20',
  suspicious: 'bg-yellow-500/20',
  benign: 'bg-emerald-500/20',
  unknown: 'bg-slate-700/50',
};

function capitalize(str: string): string {
  if (!str) return 'Unknown';
  return str.charAt(0).toUpperCase() + str.slice(1);
}

export const TaskItem = memo(function TaskItem({
  id,
  fileName,
  verdict,
  confidence,
  family,
}: TaskItemProps) {
  const navigate = useNavigate();

  const handleClick = useCallback(() => {
    navigate(`/task/${id}`);
  }, [navigate, id]);

  const badgeStyle = VERDICT_BADGE_STYLES[verdict || 'unknown'] || VERDICT_BADGE_STYLES.unknown;
  const bgStyle = VERDICT_BG_STYLES[verdict || 'unknown'] || VERDICT_BG_STYLES.unknown;

  return (
    <div
      onClick={handleClick}
      className="bg-slate-900/50 p-4 rounded-xl border border-slate-700 hover:border-cyan-500/50 transition-all cursor-pointer group"
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start gap-4">
          <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${bgStyle}`}>
            <VerdictIcon verdict={verdict} />
          </div>

          <div>
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-slate-400" />
              <span className="text-white font-medium">{fileName || 'Unknown'}</span>
            </div>
            <div className="text-slate-500 text-sm font-mono mt-1">{id}</div>

            {family && (
              <div className="mt-2">
                <span className="text-xs px-2 py-0.5 bg-purple-900/30 text-purple-400 border border-purple-800 rounded">
                  Family: {family}
                </span>
              </div>
            )}
          </div>
        </div>

        <div className="text-right">
          <div
            className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${badgeStyle}`}
          >
            <VerdictIcon verdict={verdict} size="sm" />
            <span className="ml-1.5">{capitalize(verdict || '')}</span>
          </div>
          {confidence !== undefined && (
            <div className="mt-2 text-slate-400 text-sm">
              Confidence: <span className="text-white font-medium">{confidence}%</span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
});

export default TaskItem;
