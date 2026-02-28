import { useState, useCallback, useMemo, memo } from 'react';
import { useNavigate } from 'react-router-dom';
import { 
  ListTodo, 
  FileText, 
  AlertCircle, 
  CheckCircle, 
  Loader2, 
  Search, 
  XCircle, 
  Clock, 
  RefreshCw,
  ChevronRight,
  Activity,
  Cpu,
  Brain,
  Filter
} from 'lucide-react';
import { useTasks, useTask } from '../shared/api';
import { Spinner } from '../shared/ui';

type TaskStatus = 'pending' | 'queued' | 'static_analysis' | 'ghidra_analysis' | 'report_generation' | 'completed' | 'failed';
type FilterType = 'all' | 'in_progress' | 'completed' | 'failed';

interface Task {
  id?: string;
  task_id?: string;
  status: string;
  file_name?: string;
  created_at?: string;
}

const STATUS_CONFIG: Record<TaskStatus, { 
  icon: typeof CheckCircle; 
  color: string; 
  bg: string; 
  border: string;
  label: string;
  description: string;
}> = {
  pending: { 
    icon: Clock, 
    color: 'text-slate-400', 
    bg: 'bg-slate-500/10', 
    border: 'border-slate-500/30',
    label: 'Pending',
    description: 'Waiting to start'
  },
  queued: { 
    icon: Clock, 
    color: 'text-blue-400', 
    bg: 'bg-blue-500/10', 
    border: 'border-blue-500/30',
    label: 'Queued',
    description: 'In queue'
  },
  static_analysis: { 
    icon: Activity, 
    color: 'text-cyan-400', 
    bg: 'bg-cyan-500/10', 
    border: 'border-cyan-500/30',
    label: 'Static Analysis',
    description: 'Analyzing binary structure'
  },
  ghidra_analysis: { 
    icon: Cpu, 
    color: 'text-violet-400', 
    bg: 'bg-violet-500/10', 
    border: 'border-violet-500/30',
    label: 'Ghidra Analysis',
    description: 'Deep reverse engineering'
  },
  report_generation: { 
    icon: Brain, 
    color: 'text-pink-400', 
    bg: 'bg-pink-500/10', 
    border: 'border-pink-500/30',
    label: 'AI Report',
    description: 'Generating analysis report'
  },
  completed: { 
    icon: CheckCircle, 
    color: 'text-emerald-400', 
    bg: 'bg-emerald-500/10', 
    border: 'border-emerald-500/30',
    label: 'Completed',
    description: 'Analysis finished'
  },
  failed: { 
    icon: XCircle, 
    color: 'text-red-400', 
    bg: 'bg-red-500/10', 
    border: 'border-red-500/30',
    label: 'Failed',
    description: 'Analysis failed'
  },
};

const FILTER_OPTIONS: { value: FilterType; label: string; icon: typeof Filter }[] = [
  { value: 'all', label: 'All Tasks', icon: ListTodo },
  { value: 'in_progress', label: 'In Progress', icon: Loader2 },
  { value: 'completed', label: 'Completed', icon: CheckCircle },
  { value: 'failed', label: 'Failed', icon: XCircle },
];

const IN_PROGRESS_STATUSES = ['pending', 'queued', 'static_analysis', 'ghidra_analysis', 'report_generation'];

interface TaskRowProps {
  task: Task;
  onNavigate: (id: string) => void;
}

const TaskRow = memo(function TaskRow({ task, onNavigate }: TaskRowProps) {
  const taskId = task.id || task.task_id || '';
  const status = (task.status as TaskStatus) || 'pending';
  const config = STATUS_CONFIG[status] || STATUS_CONFIG.pending;
  const Icon = config.icon;
  const isInProgress = IN_PROGRESS_STATUSES.includes(status);

  return (
    <div
      onClick={() => onNavigate(taskId)}
      className="p-4 hover:bg-slate-800/50 transition-all duration-200 cursor-pointer group"
    >
      <div className="flex items-center gap-4">
        <div className={`w-12 h-12 rounded-xl ${config.bg} ${config.border} border flex items-center justify-center flex-shrink-0`}>
          <Icon className={`w-6 h-6 ${config.color} ${isInProgress ? 'animate-pulse' : ''}`} />
        </div>
        
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-slate-500 flex-shrink-0" />
            <span className="text-white font-medium truncate">{task.file_name || 'Unknown'}</span>
          </div>
          <div className="flex items-center gap-3 mt-1">
            <span className="text-slate-500 text-xs font-mono truncate max-w-[200px]">{taskId}</span>
          </div>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="text-right">
            <div className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg ${config.bg} ${config.border} border`}>
              {isInProgress && <Loader2 className={`w-3.5 h-3.5 ${config.color} animate-spin`} />}
              <span className={`text-sm font-medium ${config.color}`}>{config.label}</span>
            </div>
            <p className="text-slate-500 text-xs mt-1">{config.description}</p>
          </div>
          <ChevronRight className="w-5 h-5 text-slate-600 group-hover:text-slate-400 transition-colors" />
        </div>
      </div>
    </div>
  );
});

interface StatsCardProps {
  label: string;
  value: number;
  icon: typeof CheckCircle;
  colorClass: string;
  bgClass: string;
  borderClass: string;
}

const StatsCard = memo(function StatsCard({ label, value, icon: Icon, colorClass, bgClass, borderClass }: StatsCardProps) {
  return (
    <div className={`p-5 rounded-xl ${bgClass} border ${borderClass}`}>
      <div className="flex items-center justify-between mb-3">
        <span className={`${colorClass} text-sm opacity-80`}>{label}</span>
        <Icon className={`w-4 h-4 ${colorClass} opacity-50`} />
      </div>
      <p className={`text-3xl font-bold ${colorClass}`}>{value}</p>
    </div>
  );
});

export default function Tasks() {
  const [searchId, setSearchId] = useState('');
  const [activeFilter, setActiveFilter] = useState<FilterType>('all');
  const navigate = useNavigate();
  
  const { data: tasksData, isLoading, error, refetch, isRefetching } = useTasks({ refetchInterval: 5000 });
  const { refetch: searchTask, isFetching: isSearching } = useTask(searchId, { enabled: false });

  const stats = useMemo(() => {
    if (!tasksData?.tasks) return { total: 0, inProgress: 0, completed: 0, failed: 0 };
    const tasks = tasksData.tasks;
    return {
      total: tasks.length,
      inProgress: tasks.filter(t => IN_PROGRESS_STATUSES.includes(t.status)).length,
      completed: tasks.filter(t => t.status === 'completed').length,
      failed: tasks.filter(t => t.status === 'failed').length,
    };
  }, [tasksData]);

  const filteredTasks = useMemo(() => {
    if (!tasksData?.tasks) return [];
    const tasks = tasksData.tasks as Task[];
    
    switch (activeFilter) {
      case 'in_progress':
        return tasks.filter(t => IN_PROGRESS_STATUSES.includes(t.status));
      case 'completed':
        return tasks.filter(t => t.status === 'completed');
      case 'failed':
        return tasks.filter(t => t.status === 'failed');
      default:
        return tasks;
    }
  }, [tasksData, activeFilter]);

  const handleSearch = useCallback(async () => {
    if (!searchId.trim()) return;
    const result = await searchTask();
    if (result.data) {
      navigate(`/task/${searchId}`);
    }
  }, [searchId, searchTask, navigate]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSearch();
  }, [handleSearch]);

  const handleNavigate = useCallback((taskId: string) => {
    navigate(`/task/${taskId}`);
  }, [navigate]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-[400px]">
        <Spinner size="lg" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center">
            <ListTodo className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Analysis Tasks</h1>
            <p className="text-slate-400 text-sm">Monitor and manage all analysis jobs</p>
          </div>
        </div>
        
        {/* Search */}
        <div className="flex items-center gap-2 p-2 rounded-xl bg-slate-800/50 border border-slate-700/50 w-full lg:w-auto">
          <div className="relative flex-1 lg:w-72">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
            <input 
              type="text" 
              placeholder="Search by Task ID..."
              className="w-full bg-slate-900/50 border border-slate-700 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-cyan-500/50 focus:ring-1 focus:ring-cyan-500/20 transition-all"
              value={searchId}
              onChange={(e) => setSearchId(e.target.value)}
              onKeyDown={handleKeyDown}
            />
          </div>
          <button 
            onClick={handleSearch}
            disabled={!searchId.trim() || isSearching}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-500 disabled:bg-slate-700 text-white text-sm font-medium rounded-lg transition-all disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
          >
            {isSearching ? <Loader2 className="w-4 h-4 animate-spin" /> : <Search className="w-4 h-4" />}
            Search
          </button>
        </div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatsCard 
          label="Total Tasks" 
          value={stats.total} 
          icon={ListTodo}
          colorClass="text-slate-300"
          bgClass="bg-slate-800/50"
          borderClass="border-slate-700/50"
        />
        <StatsCard 
          label="In Progress" 
          value={stats.inProgress} 
          icon={Loader2}
          colorClass="text-cyan-400"
          bgClass="bg-cyan-500/5"
          borderClass="border-cyan-500/20"
        />
        <StatsCard 
          label="Completed" 
          value={stats.completed} 
          icon={CheckCircle}
          colorClass="text-emerald-400"
          bgClass="bg-emerald-500/5"
          borderClass="border-emerald-500/20"
        />
        <StatsCard 
          label="Failed" 
          value={stats.failed} 
          icon={XCircle}
          colorClass="text-red-400"
          bgClass="bg-red-500/5"
          borderClass="border-red-500/20"
        />
      </div>

      {/* Error Message */}
      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 flex items-center gap-3">
          <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0" />
          <p className="text-red-400">Failed to load tasks. Please try again.</p>
        </div>
      )}

      {/* Filter Tabs & Task List */}
      <div className="rounded-xl bg-slate-800/30 border border-slate-700/50 overflow-hidden">
        {/* Filter Header */}
        <div className="flex items-center justify-between p-4 border-b border-slate-700/50 bg-slate-900/30">
          <div className="flex items-center gap-1 p-1 rounded-lg bg-slate-800/50">
            {FILTER_OPTIONS.map((option) => (
              <button
                key={option.value}
                onClick={() => setActiveFilter(option.value)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md text-sm font-medium transition-all ${
                  activeFilter === option.value
                    ? 'bg-slate-700 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-300 hover:bg-slate-700/50'
                }`}
              >
                <option.icon className="w-3.5 h-3.5" />
                {option.label}
              </button>
            ))}
          </div>
          
          <button
            onClick={() => refetch()}
            disabled={isRefetching}
            className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-700/50 hover:bg-slate-700 text-slate-300 text-sm font-medium transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isRefetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {/* Task List */}
        {filteredTasks.length === 0 ? (
          <div className="p-16 text-center">
            <div className="w-16 h-16 mx-auto rounded-xl bg-slate-800 flex items-center justify-center mb-4">
              <FileText className="w-8 h-8 text-slate-600" />
            </div>
            <p className="text-slate-400 text-lg">
              {activeFilter === 'all' ? 'No tasks found' : `No ${activeFilter.replace('_', ' ')} tasks`}
            </p>
            <p className="text-slate-500 text-sm mt-1">
              {activeFilter === 'all' ? 'Upload a file to start analyzing' : 'Try a different filter'}
            </p>
          </div>
        ) : (
          <div className="divide-y divide-slate-700/50">
            {filteredTasks.map((task) => (
              <TaskRow 
                key={task.id || task.task_id} 
                task={task} 
                onNavigate={handleNavigate}
              />
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
