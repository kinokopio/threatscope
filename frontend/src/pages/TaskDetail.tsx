import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { AlertCircle, Loader2, ArrowLeft } from 'lucide-react';
import { getTask } from '../api/client';
import type { AnalysisTask, TaskStatus } from '../types';
import ReportView from '../components/ReportView';

const POLL_INTERVAL_MS = 2000;

// Status display mapping
const STATUS_DISPLAY: Record<TaskStatus, { label: string; color: string }> = {
  pending: { label: 'Pending', color: 'text-slate-400' },
  stage_1_4: { label: 'Static Analysis', color: 'text-cyan-400' },
  queued: { label: 'Waiting for Ghidra', color: 'text-yellow-400' },
  stage_5: { label: 'Ghidra Analysis', color: 'text-purple-400' },
  stage_6: { label: 'Generating Report', color: 'text-emerald-400' },
  completed: { label: 'Completed', color: 'text-green-400' },
  failed: { label: 'Failed', color: 'text-red-400' },
};

function isInProgress(status: TaskStatus): boolean {
  return ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6'].includes(status);
}

export default function TaskDetail() {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<AnalysisTask | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchTaskStatus = async (id: string) => {
    try {
      const data = await getTask(id);
      setTask(data);
      setLoading(false);
      
      if (data.status === 'failed' && data.error) {
        setErrorMessage(data.error);
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
  };

  useEffect(() => {
    if (!taskId) return;

    // Initial fetch
    fetchTaskStatus(taskId);

    // Polling for in-progress tasks
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
  }, [taskId]);

  const currentStatus = task?.status || 'pending';
  const statusInfo = STATUS_DISPLAY[currentStatus] || STATUS_DISPLAY.pending;

  return (
    <div className="max-w-7xl mx-auto">
      {/* Back Button */}
      <button
        onClick={() => navigate(-1)}
        className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4 mr-2" /> Back
      </button>

      {/* Loading State */}
      {loading && (
        <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
          <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
          <h3 className="text-2xl font-bold text-white">Loading...</h3>
        </div>
      )}

      {/* Error State (no task found) */}
      {!loading && errorMessage && !task && (
        <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
          <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
          <h3 className="text-2xl font-bold text-red-400">Error</h3>
          <p className="text-red-200 mt-2">{errorMessage}</p>
        </div>
      )}

      {/* Task Content */}
      {!loading && task && (
        <div className="animate-in fade-in duration-500">
          {/* In Progress State */}
          {isInProgress(task.status) && (
            <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
              <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
              <h3 className="text-2xl font-bold text-white">Analysis in Progress...</h3>
              <p className="text-slate-400 mt-2">
                AI Agents are analyzing the binary. This may take a few minutes.
              </p>
              <div className="mt-4">
                <span className="text-slate-300">Current Stage: </span>
                <span className={`font-semibold ${statusInfo.color}`}>
                  {statusInfo.label}
                </span>
              </div>
              
              {/* Progress Steps */}
              <div className="mt-6 flex justify-center">
                <div className="flex items-center space-x-2">
                  {(['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6'] as TaskStatus[]).map((stage, index) => {
                    const stageInfo = STATUS_DISPLAY[stage];
                    const isCurrentOrPast = 
                      ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6'].indexOf(task.status) >= index;
                    const isCurrent = task.status === stage;
                    
                    return (
                      <div key={stage} className="flex items-center">
                        <div
                          className={`w-3 h-3 rounded-full transition-all ${
                            isCurrent
                              ? 'bg-cyan-400 ring-4 ring-cyan-400/30'
                              : isCurrentOrPast
                              ? 'bg-emerald-500'
                              : 'bg-slate-600'
                          }`}
                          title={stageInfo.label}
                        />
                        {index < 4 && (
                          <div
                            className={`w-8 h-0.5 ${
                              isCurrentOrPast ? 'bg-emerald-500' : 'bg-slate-600'
                            }`}
                          />
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>
              
              {/* File name if available */}
              {task.file_name && (
                <p className="text-slate-500 mt-4 text-sm">
                  File: <span className="font-mono text-slate-400">{task.file_name}</span>
                </p>
              )}
            </div>
          )}

          {/* Failed State */}
          {task.status === 'failed' && (
            <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
              <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
              <h3 className="text-2xl font-bold text-red-400">Analysis Failed</h3>
              <p className="text-red-200 mt-2">{task.error || 'An unknown error occurred.'}</p>
            </div>
          )}

          {/* Completed State - Show Report */}
          {task.status === 'completed' && task.result && (
            <ReportView result={task.result} fileName={task.file_name} />
          )}
        </div>
      )}
    </div>
  );
}
