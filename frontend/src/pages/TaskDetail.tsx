import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, AlertCircle, Loader2, FileText, Clock, Hash } from 'lucide-react';
import { getTask } from '../shared/api';
import type { AnalysisTask, StepStatus } from '../shared/types';
import {
  TaskHeader,
  AnalysisStepsList,
  isInProgress,
  inferStepStates,
  STATUS_DISPLAY,
} from '../features/analysis';

const POLL_INTERVAL_MS = 1000;

interface StepState {
  status: StepStatus;
  preview?: Record<string, unknown>;
}

export default function TaskDetail() {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<AnalysisTask | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [stepStates, setStepStates] = useState<Record<string, StepState>>({});

  const fetchTaskStatus = useCallback(async (id: string) => {
    try {
      const data = await getTask(id);
      setTask(data);
      setLoading(false);

      if (data.status === 'failed' && data.error) {
        setErrorMessage(data.error);
      }

      if (data.result) {
        setStepStates((prev) => inferStepStates(data.result, prev));
      }
    } catch (err: unknown) {
      console.error('Failed to fetch task:', err);
      const error = err as { response?: { status: number } };
      if (error.response?.status === 404) {
        setErrorMessage('Task not found.');
      } else {
        setErrorMessage('Failed to fetch task status.');
      }
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!taskId) return;

    fetchTaskStatus(taskId);

    const interval = setInterval(() => {
      setTask((currentTask) => {
        if (!currentTask || isInProgress(currentTask.status)) {
          fetchTaskStatus(taskId);
        } else {
          clearInterval(interval);
        }
        return currentTask;
      });
    }, POLL_INTERVAL_MS);

    return () => clearInterval(interval);
  }, [taskId, fetchTaskStatus]);

  const currentStatus = task?.status || 'pending';

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto">
        <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
          <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
          <h3 className="text-2xl font-bold text-white">Loading...</h3>
        </div>
      </div>
    );
  }

  if (errorMessage && !task) {
    return (
      <div className="max-w-7xl mx-auto">
        <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
          <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
          <h3 className="text-2xl font-bold text-red-400">Error</h3>
          <p className="text-red-200 mt-2">{errorMessage}</p>
        </div>
      </div>
    );
  }

  if (!task) return null;

  return (
    <div className="max-w-7xl mx-auto">
      <button
        onClick={() => navigate('/tasks')}
        className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4 mr-2" /> Back to Tasks
      </button>

      <div className="space-y-6">
        <TaskHeader status={task.status} currentStep={task.current_step} fileName={task.file_name} />

        {/* Task Info Card */}
        <div className="bg-slate-800/50 rounded-xl border border-slate-700/50 p-5">
          <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-4">Task Information</h3>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-slate-700/50 flex items-center justify-center">
                <Hash className="w-5 h-5 text-slate-400" />
              </div>
              <div>
                <p className="text-xs text-slate-500">Task ID</p>
                <p className="text-sm text-slate-300 font-mono">{taskId}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-slate-700/50 flex items-center justify-center">
                <FileText className="w-5 h-5 text-slate-400" />
              </div>
              <div>
                <p className="text-xs text-slate-500">File Name</p>
                <p className="text-sm text-slate-300">{task.file_name || 'Unknown'}</p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-lg bg-slate-700/50 flex items-center justify-center">
                <Clock className="w-5 h-5 text-slate-400" />
              </div>
              <div>
                <p className="text-xs text-slate-500">Status</p>
                <p className="text-sm text-slate-300">{task.current_step || STATUS_DISPLAY[task.status]?.label || task.status}</p>
              </div>
            </div>
          </div>
        </div>

        {task.status === 'failed' && (
          <div className="bg-red-900/20 p-6 rounded-xl border border-red-800">
            <div className="flex items-start gap-3">
              <AlertCircle className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <h4 className="text-red-400 font-medium mb-1">Analysis Failed</h4>
                <p className="text-red-200/80 text-sm">{task.error || 'An unknown error occurred.'}</p>
              </div>
            </div>
          </div>
        )}

        {/* Analysis Steps - show for all non-pending states */}
        {(isInProgress(task.status) || task.status === 'completed' || task.status === 'failed') && (
          <div>
            <h3 className="text-sm font-medium text-slate-400 uppercase tracking-wider mb-4">Analysis Progress</h3>
            <AnalysisStepsList
              currentStatus={currentStatus}
              stepStates={stepStates}
              result={task.result}
            />
          </div>
        )}

        {/* Link to report for completed tasks */}
        {task.status === 'completed' && task.result && (
          <div className="bg-emerald-500/10 rounded-xl border border-emerald-500/30 p-5">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
                  <FileText className="w-5 h-5 text-emerald-400" />
                </div>
                <div>
                  <h4 className="text-emerald-400 font-medium">Analysis Complete</h4>
                  <p className="text-slate-400 text-sm">View the detailed analysis report</p>
                </div>
              </div>
              <button
                onClick={() => navigate(`/report/${taskId}`)}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white font-medium rounded-lg transition-colors"
              >
                View Report
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
