import { useEffect, useState, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, AlertCircle, Loader2, FileText, Shield } from 'lucide-react';
import { getTask } from '../shared/api';
import type { AnalysisTask } from '../shared/types';
import ReportView from '../features/report/components/ReportView';

export default function ReportDetail() {
  const { taskId } = useParams<{ taskId: string }>();
  const navigate = useNavigate();
  const [task, setTask] = useState<AnalysisTask | null>(null);
  const [loading, setLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fetchTask = useCallback(async (id: string) => {
    try {
      const data = await getTask(id);
      setTask(data);
      setLoading(false);

      if (data.status !== 'completed') {
        setErrorMessage('Report not available. Task is not completed yet.');
      }
    } catch (err: unknown) {
      console.error('Failed to fetch task:', err);
      const error = err as { response?: { status: number } };
      if (error.response?.status === 404) {
        setErrorMessage('Task not found.');
      } else {
        setErrorMessage('Failed to fetch report.');
      }
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    if (!taskId) return;
    fetchTask(taskId);
  }, [taskId, fetchTask]);

  if (loading) {
    return (
      <div className="max-w-7xl mx-auto">
        <div className="bg-slate-800 p-8 rounded-xl border border-slate-700 text-center">
          <Loader2 className="animate-spin w-12 h-12 mx-auto text-cyan-400 mb-4" />
          <h3 className="text-2xl font-bold text-white">Loading Report...</h3>
        </div>
      </div>
    );
  }

  if (errorMessage || !task?.result) {
    return (
      <div className="max-w-7xl mx-auto">
        <button
          onClick={() => navigate('/history')}
          className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
        >
          <ArrowLeft className="w-4 h-4 mr-2" /> Back to History
        </button>
        <div className="bg-red-900/20 p-8 rounded-xl border border-red-800 text-center">
          <AlertCircle className="w-12 h-12 mx-auto text-red-500 mb-4" />
          <h3 className="text-2xl font-bold text-red-400">Report Unavailable</h3>
          <p className="text-red-200 mt-2">{errorMessage || 'No analysis result available.'}</p>
          {task && task.status !== 'completed' && (
            <button
              onClick={() => navigate(`/task/${taskId}`)}
              className="mt-4 px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white rounded-lg transition-colors"
            >
              View Task Progress
            </button>
          )}
        </div>
      </div>
    );
  }

  const verdict = task.result.malware_report?.verdict || 'unknown';
  const verdictColors: Record<string, { bg: string; border: string; text: string }> = {
    malicious: { bg: 'bg-red-500/10', border: 'border-red-500/30', text: 'text-red-400' },
    suspicious: { bg: 'bg-amber-500/10', border: 'border-amber-500/30', text: 'text-amber-400' },
    benign: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400' },
    unknown: { bg: 'bg-slate-500/10', border: 'border-slate-500/30', text: 'text-slate-400' },
  };
  const colors = verdictColors[verdict] || verdictColors.unknown;

  return (
    <div className="max-w-7xl mx-auto">
      <button
        onClick={() => navigate('/history')}
        className="mb-6 flex items-center text-slate-400 hover:text-emerald-400 transition-colors cursor-pointer"
      >
        <ArrowLeft className="w-4 h-4 mr-2" /> Back to History
      </button>

      <div className="space-y-6">
        {/* Report Header */}
        <div className={`${colors.bg} rounded-xl border ${colors.border} p-6`}>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-4">
              <div className={`w-14 h-14 rounded-xl ${colors.bg} border ${colors.border} flex items-center justify-center`}>
                <Shield className={`w-7 h-7 ${colors.text}`} />
              </div>
              <div>
                <div className="flex items-center gap-3">
                  <h1 className="text-2xl font-bold text-white">Analysis Report</h1>
                  <span className={`px-3 py-1 rounded-full text-sm font-semibold uppercase ${colors.bg} ${colors.text} border ${colors.border}`}>
                    {verdict}
                  </span>
                </div>
                <div className="flex items-center gap-2 mt-1 text-slate-400">
                  <FileText className="w-4 h-4" />
                  <span>{task.file_name || 'Unknown file'}</span>
                </div>
              </div>
            </div>
            <button
              onClick={() => navigate(`/task/${taskId}`)}
              className="px-4 py-2 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded-lg transition-colors"
            >
              View Task Details
            </button>
          </div>
        </div>

        {/* Report Content */}
        <ReportView result={task.result} fileName={task.file_name} />
      </div>
    </div>
  );
}
