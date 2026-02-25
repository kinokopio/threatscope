import type { QueueStats } from '../types';
import { 
  Activity, 
  Clock, 
  CheckCircle2, 
  XCircle, 
  Cpu,
  FileText
} from 'lucide-react';

interface StatsCardsProps {
  stats: QueueStats | null;
  isLoading: boolean;
}

export function StatsCards({ stats, isLoading }: StatsCardsProps) {
  const cards = [
    {
      label: 'Total Tasks',
      value: stats?.total_tasks ?? 0,
      icon: Activity,
      color: 'text-accent-cyan',
      bgColor: 'bg-accent-cyan/10',
    },
    {
      label: 'Pending',
      value: stats?.pending ?? 0,
      icon: Clock,
      color: 'text-accent-amber',
      bgColor: 'bg-accent-amber/10',
    },
    {
      label: 'Ghidra Queue',
      value: stats?.ghidra_waiting ?? 0,
      icon: Cpu,
      color: 'text-purple-400',
      bgColor: 'bg-purple-400/10',
    },
    {
      label: 'Report Queue',
      value: stats?.report_waiting ?? 0,
      icon: FileText,
      color: 'text-blue-400',
      bgColor: 'bg-blue-400/10',
    },
    {
      label: 'Completed',
      value: stats?.completed ?? 0,
      icon: CheckCircle2,
      color: 'text-accent-green',
      bgColor: 'bg-accent-green/10',
    },
    {
      label: 'Failed',
      value: stats?.failed ?? 0,
      icon: XCircle,
      color: 'text-accent-red',
      bgColor: 'bg-accent-red/10',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
      {cards.map((card) => {
        const Icon = card.icon;
        return (
          <div
            key={card.label}
            className="bg-cyber-800 rounded-xl p-4 border border-cyber-700"
          >
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${card.bgColor}`}>
                <Icon className={`w-5 h-5 ${card.color}`} />
              </div>
              <div>
                <p className="text-2xl font-bold text-gray-100">
                  {isLoading ? '-' : card.value}
                </p>
                <p className="text-xs text-gray-500">{card.label}</p>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
