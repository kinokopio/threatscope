import { 
  Clock, 
  CheckCircle2, 
  XCircle, 
  Loader2, 
  Trash2,
  ChevronRight,
  FileCode
} from 'lucide-react';
import type { AnalysisTask, TaskStatus } from '../types';

interface TaskListProps {
  tasks: AnalysisTask[];
  onSelectTask: (task: AnalysisTask) => void;
  onDeleteTask: (taskId: string) => void;
  selectedTaskId?: string;
}

const statusConfig: Record<TaskStatus, { icon: typeof Clock; color: string; label: string }> = {
  pending: { icon: Clock, color: 'text-gray-400', label: 'Pending' },
  stage_1_4: { icon: Loader2, color: 'text-accent-cyan', label: 'Static Analysis' },
  queued: { icon: Clock, color: 'text-accent-amber', label: 'Queued for Ghidra' },
  stage_5: { icon: Loader2, color: 'text-accent-cyan', label: 'Ghidra Analysis' },
  stage_6: { icon: Loader2, color: 'text-accent-cyan', label: 'AI Report' },
  completed: { icon: CheckCircle2, color: 'text-accent-green', label: 'Completed' },
  failed: { icon: XCircle, color: 'text-accent-red', label: 'Failed' },
};

export function TaskList({ tasks, onSelectTask, onDeleteTask, selectedTaskId }: TaskListProps) {
  if (tasks.length === 0) {
    return (
      <div className="text-center py-12 text-gray-500">
        <FileCode className="w-12 h-12 mx-auto mb-4 opacity-50" />
        <p>No analysis tasks yet</p>
        <p className="text-sm mt-1">Upload a file to get started</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      {tasks.map((task) => {
        const config = statusConfig[task.status] || statusConfig.pending;
        const Icon = config.icon;
        const isSelected = task.id === selectedTaskId;
        const isLoading = ['stage_1_4', 'stage_5', 'stage_6'].includes(task.status);

        return (
          <div
            key={task.id}
            className={`
              group flex items-center gap-3 p-3 rounded-lg cursor-pointer transition-all
              ${isSelected 
                ? 'bg-accent-cyan/20 border border-accent-cyan/50' 
                : 'bg-cyber-800 hover:bg-cyber-700 border border-transparent'
              }
            `}
            onClick={() => onSelectTask(task)}
          >
            <Icon 
              className={`w-5 h-5 ${config.color} ${isLoading ? 'animate-spin' : ''}`} 
            />
            
            <div className="flex-1 min-w-0">
              <p className="text-sm font-medium text-gray-200 truncate">
                {task.file_name || `Task ${task.id}`}
              </p>
              <p className={`text-xs ${config.color}`}>
                {config.label}
              </p>
            </div>

            <div className="flex items-center gap-2">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  if (task.id) onDeleteTask(task.id);
                }}
                className="p-1.5 rounded opacity-0 group-hover:opacity-100 hover:bg-cyber-600 transition-all"
              >
                <Trash2 className="w-4 h-4 text-gray-400 hover:text-accent-red" />
              </button>
              <ChevronRight className={`w-4 h-4 text-gray-500 ${isSelected ? 'text-accent-cyan' : ''}`} />
            </div>
          </div>
        );
      })}
    </div>
  );
}
