import { useMemo, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  Clock, 
  FileText, 
  AlertCircle, 
  CheckCircle, 
  AlertTriangle, 
  Shield,
  TrendingUp,
  ChevronRight,
  Skull,
  ShieldCheck,
  ShieldAlert
} from 'lucide-react';
import { useTasks } from '../shared/api';
import { Spinner } from '../shared/ui';

type Verdict = 'malicious' | 'suspicious' | 'benign' | 'unknown';

interface AnalyzedTask {
  id: string;
  fileName: string;
  verdict: Verdict;
  confidence: number;
  family: string | null;
}

const VERDICT_CONFIG: Record<Verdict, { 
  icon: typeof AlertCircle; 
  color: string; 
  bg: string; 
  border: string;
  label: string;
}> = {
  malicious: { 
    icon: Skull, 
    color: 'text-red-400', 
    bg: 'bg-red-500/10', 
    border: 'border-red-500/30',
    label: 'Malicious'
  },
  suspicious: { 
    icon: ShieldAlert, 
    color: 'text-amber-400', 
    bg: 'bg-amber-500/10', 
    border: 'border-amber-500/30',
    label: 'Suspicious'
  },
  benign: { 
    icon: ShieldCheck, 
    color: 'text-emerald-400', 
    bg: 'bg-emerald-500/10', 
    border: 'border-emerald-500/30',
    label: 'Benign'
  },
  unknown: { 
    icon: Shield, 
    color: 'text-slate-400', 
    bg: 'bg-slate-500/10', 
    border: 'border-slate-500/30',
    label: 'Unknown'
  },
};

export default function History() {
  const navigate = useNavigate();
  const { data: tasksData, isLoading, error } = useTasks({ refetchInterval: 10000 });

  const { analyzedTasks, stats } = useMemo(() => {
    if (!tasksData?.tasks) {
      return { analyzedTasks: [], stats: { malicious: 0, suspicious: 0, benign: 0, total: 0 } };
    }

    const completed = tasksData.tasks.filter(t => t.status === 'completed');
    const analyzed: AnalyzedTask[] = completed.map(task => ({
      id: task.id || task.task_id || '',
      fileName: task.file_name || 'Unknown',
      verdict: (task.result?.unified_report?.verdict as Verdict) || 'unknown',
      confidence: task.result?.unified_report?.confidence || 0,
      family: task.result?.unified_report?.classification?.family || null,
    }));

    const stats = {
      malicious: analyzed.filter(t => t.verdict === 'malicious').length,
      suspicious: analyzed.filter(t => t.verdict === 'suspicious').length,
      benign: analyzed.filter(t => t.verdict === 'benign').length,
      total: analyzed.length,
    };

    return { analyzedTasks: analyzed, stats };
  }, [tasksData]);

  const handleTaskClick = useCallback((taskId: string) => {
    navigate(`/report/${taskId}`);
  }, [navigate]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Spinner size="lg" />
      </div>
    );
  }

  const threatRate = stats.total > 0 
    ? Math.round(((stats.malicious + stats.suspicious) / stats.total) * 100) 
    : 0;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center">
            <Clock className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Analysis History</h1>
            <p className="text-slate-400 text-sm">Completed malware analysis reports</p>
          </div>
        </div>
        <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-800 border border-slate-700">
          <TrendingUp className="w-4 h-4 text-slate-400" />
          <span className="text-sm text-slate-300">{stats.total} analyzed</span>
        </div>
      </div>

      <div className="grid grid-cols-4 gap-4">
        <div className="p-5 rounded-xl bg-slate-800/50 border border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <span className="text-slate-400 text-sm">Total Scans</span>
            <Shield className="w-4 h-4 text-slate-500" />
          </div>
          <p className="text-3xl font-bold text-white">{stats.total}</p>
        </div>
        
        <div className="p-5 rounded-xl bg-red-500/5 border border-red-500/20">
          <div className="flex items-center justify-between mb-3">
            <span className="text-red-400/80 text-sm">Malicious</span>
            <Skull className="w-4 h-4 text-red-500/50" />
          </div>
          <p className="text-3xl font-bold text-red-400">{stats.malicious}</p>
        </div>
        
        <div className="p-5 rounded-xl bg-amber-500/5 border border-amber-500/20">
          <div className="flex items-center justify-between mb-3">
            <span className="text-amber-400/80 text-sm">Suspicious</span>
            <AlertTriangle className="w-4 h-4 text-amber-500/50" />
          </div>
          <p className="text-3xl font-bold text-amber-400">{stats.suspicious}</p>
        </div>
        
        <div className="p-5 rounded-xl bg-emerald-500/5 border border-emerald-500/20">
          <div className="flex items-center justify-between mb-3">
            <span className="text-emerald-400/80 text-sm">Benign</span>
            <CheckCircle className="w-4 h-4 text-emerald-500/50" />
          </div>
          <p className="text-3xl font-bold text-emerald-400">{stats.benign}</p>
        </div>
      </div>

      {threatRate > 0 && (
        <div className="p-4 rounded-xl bg-gradient-to-r from-red-500/10 to-amber-500/10 border border-red-500/20">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
              <AlertCircle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-white font-medium">Threat Detection Rate: {threatRate}%</p>
              <p className="text-slate-400 text-sm">
                {stats.malicious + stats.suspicious} out of {stats.total} samples flagged as threats
              </p>
            </div>
          </div>
        </div>
      )}

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400" />
          <p className="text-red-400">Failed to load analysis history</p>
        </div>
      )}

      <div className="rounded-xl bg-slate-800/30 border border-slate-700/50 overflow-hidden">
        {analyzedTasks.length === 0 ? (
          <div className="p-16 text-center">
            <div className="w-16 h-16 mx-auto rounded-xl bg-slate-800 flex items-center justify-center mb-4">
              <Shield className="w-8 h-8 text-slate-600" />
            </div>
            <p className="text-slate-400 text-lg">No completed analyses yet</p>
            <p className="text-slate-500 text-sm mt-1">Upload a file to start analyzing</p>
          </div>
        ) : (
          <div className="divide-y divide-slate-700/50">
            {analyzedTasks.map((task) => {
              const config = VERDICT_CONFIG[task.verdict];
              const Icon = config.icon;
              
              return (
                <div
                  key={task.id}
                  onClick={() => handleTaskClick(task.id)}
                  className="p-4 hover:bg-slate-800/50 transition-colors cursor-pointer group"
                >
                  <div className="flex items-center gap-4">
                    <div className={`w-12 h-12 rounded-xl ${config.bg} ${config.border} border flex items-center justify-center flex-shrink-0`}>
                      <Icon className={`w-6 h-6 ${config.color}`} />
                    </div>
                    
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <FileText className="w-4 h-4 text-slate-500 flex-shrink-0" />
                        <span className="text-white font-medium truncate">{task.fileName}</span>
                      </div>
                      <div className="flex items-center gap-3 mt-1">
                        <span className="text-slate-500 text-xs font-mono">{task.id}</span>
                        {task.family && (
                          <span className="px-2 py-0.5 rounded bg-purple-500/20 text-purple-400 text-xs border border-purple-500/30">
                            {task.family}
                          </span>
                        )}
                      </div>
                    </div>
                    
                    <div className="flex items-center gap-4">
                      <div className="text-right">
                        <div className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-lg ${config.bg} ${config.border} border`}>
                          <Icon className={`w-4 h-4 ${config.color}`} />
                          <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
                        </div>
                        {task.confidence > 0 && (
                          <p className="text-slate-500 text-xs mt-1">
                            {task.confidence}% confidence
                          </p>
                        )}
                      </div>
                      <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-400 transition-colors" />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
