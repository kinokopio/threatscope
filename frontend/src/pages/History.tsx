import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Clock, FileText, AlertCircle, CheckCircle, Loader2, Shield, AlertTriangle, HelpCircle } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface Task {
  id: string;
  status: string;
  file_name?: string;
  created_at?: string;
  result?: {
    malware_report?: {
      verdict?: string;
      confidence?: number;
      family?: string | null;
    };
  };
}

export default function History() {
  const [completedTasks, setCompletedTasks] = useState<Task[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchCompletedTasks = async () => {
      try {
        const res = await axios.get(`${API_BASE}/tasks`);
        const allTasks = res.data.tasks || [];
        // Filter only completed tasks
        const completed = allTasks.filter((t: Task) => t.status === 'completed');
        setCompletedTasks(completed);
      } catch (err) {
        console.error(err);
        setError("Failed to load history.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchCompletedTasks();
    
    // Poll every 10 seconds (less frequent since we only show completed)
    const interval = setInterval(fetchCompletedTasks, 10000);
    return () => clearInterval(interval);
  }, []);

  const getVerdictIcon = (verdict?: string) => {
    switch (verdict) {
      case 'malicious':
        return <AlertCircle className="w-5 h-5 text-red-400" />;
      case 'suspicious':
        return <AlertTriangle className="w-5 h-5 text-yellow-400" />;
      case 'benign':
        return <CheckCircle className="w-5 h-5 text-emerald-400" />;
      default:
        return <HelpCircle className="w-5 h-5 text-slate-400" />;
    }
  };

  const getVerdictBadgeClass = (verdict?: string) => {
    switch (verdict) {
      case 'malicious':
        return 'bg-red-900/30 text-red-400 border-red-800';
      case 'suspicious':
        return 'bg-yellow-900/30 text-yellow-400 border-yellow-800';
      case 'benign':
        return 'bg-emerald-900/30 text-emerald-400 border-emerald-800';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getVerdictLabel = (verdict?: string) => {
    if (!verdict) return 'Unknown';
    return verdict.charAt(0).toUpperCase() + verdict.slice(1);
  };

  // Count by verdict
  const maliciousCount = completedTasks.filter(t => t.result?.malware_report?.verdict === 'malicious').length;
  const suspiciousCount = completedTasks.filter(t => t.result?.malware_report?.verdict === 'suspicious').length;
  const benignCount = completedTasks.filter(t => t.result?.malware_report?.verdict === 'benign').length;

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <header className="mb-8">
        <h1 className="text-3xl font-bold text-white flex items-center">
          <Clock className="mr-3 text-emerald-400" /> Analysis Results
        </h1>
        <p className="text-slate-400 mt-2">Completed malware analysis reports</p>
      </header>

      {/* Verdict Stats */}
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

      {error && (
        <div className="mb-6 bg-red-900/20 p-4 rounded-xl border border-red-800 text-center text-red-400">
          <AlertCircle className="w-5 h-5 inline mr-2" />
          {error}
        </div>
      )}

      <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-xl overflow-hidden">
        {completedTasks.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <Shield className="w-16 h-16 mx-auto mb-4 opacity-30" />
            <p className="text-lg">No completed analyses yet.</p>
            <p className="text-sm mt-2">Upload a file to start analyzing.</p>
          </div>
        ) : (
          <div className="grid gap-4 p-4">
            {completedTasks.map((task) => {
              const report = task.result?.malware_report;
              return (
                <div
                  key={task.id}
                  onClick={() => navigate(`/task/${task.id}`)}
                  className="bg-slate-900/50 p-4 rounded-xl border border-slate-700 hover:border-cyan-500/50 transition-all cursor-pointer group"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-4">
                      {/* Verdict Icon */}
                      <div className={`w-12 h-12 rounded-lg flex items-center justify-center ${
                        report?.verdict === 'malicious' ? 'bg-red-500/20' :
                        report?.verdict === 'suspicious' ? 'bg-yellow-500/20' :
                        report?.verdict === 'benign' ? 'bg-emerald-500/20' :
                        'bg-slate-700/50'
                      }`}>
                        {getVerdictIcon(report?.verdict)}
                      </div>
                      
                      {/* File Info */}
                      <div>
                        <div className="flex items-center gap-2">
                          <FileText className="w-4 h-4 text-slate-400" />
                          <span className="text-white font-medium">{task.file_name || 'Unknown'}</span>
                        </div>
                        <div className="text-slate-500 text-sm font-mono mt-1">{task.id}</div>
                        
                        {/* Family Tag */}
                        {report?.family && (
                          <div className="mt-2">
                            <span className="text-xs px-2 py-0.5 bg-purple-900/30 text-purple-400 border border-purple-800 rounded">
                              Family: {report.family}
                            </span>
                          </div>
                        )}
                      </div>
                    </div>
                    
                    {/* Right Side - Verdict & Confidence */}
                    <div className="text-right">
                      <div className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium border ${getVerdictBadgeClass(report?.verdict)}`}>
                        {getVerdictIcon(report?.verdict)}
                        <span className="ml-1.5">{getVerdictLabel(report?.verdict)}</span>
                      </div>
                      {report?.confidence !== undefined && (
                        <div className="mt-2 text-slate-400 text-sm">
                          Confidence: <span className="text-white font-medium">{report.confidence}%</span>
                        </div>
                      )}
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
