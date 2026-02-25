import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { Clock, FileText, AlertCircle, CheckCircle, Loader2, Search, XCircle } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000';

interface Task {
  id: string;
  status: string;
  file_name?: string;
  created_at?: string;
}

export default function History() {
  const [history, setHistory] = useState<Task[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchHash, setSearchHash] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await axios.get(`${API_BASE}/tasks`);
        setHistory(res.data.tasks || []);
      } catch (err) {
        console.error(err);
        setError("Failed to load history.");
      } finally {
        setIsLoading(false);
      }
    };

    fetchHistory();
    
    // Poll every 5 seconds
    const interval = setInterval(fetchHistory, 5000);
    return () => clearInterval(interval);
  }, []);

  const searchByHash = async () => {
    if (!searchHash) return;
    setIsSearching(true);
    setError(null);
    try {
      const res = await axios.get(`${API_BASE}/tasks/${searchHash}`);
      if (res.data) {
        navigate(`/task/${searchHash}`);
      }
    } catch (err) {
      setError("Task not found for this ID.");
      setIsSearching(false);
    }
  };

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircle className="w-5 h-5 text-emerald-400" />;
      case 'failed':
        return <XCircle className="w-5 h-5 text-red-400" />;
      case 'pending':
      case 'stage_1_4':
      case 'stage_5':
      case 'stage_6':
      case 'queued':
        return <Loader2 className="w-5 h-5 text-cyan-400 animate-spin" />;
      default:
        return <Clock className="w-5 h-5 text-slate-400" />;
    }
  };

  const getStatusBadgeClass = (status: string) => {
    switch (status) {
      case 'completed':
        return 'bg-emerald-900/30 text-emerald-400 border-emerald-800';
      case 'failed':
        return 'bg-red-900/30 text-red-400 border-red-800';
      case 'pending':
      case 'stage_1_4':
      case 'stage_5':
      case 'stage_6':
      case 'queued':
        return 'bg-cyan-900/30 text-cyan-400 border-cyan-800';
      default:
        return 'bg-slate-800 text-slate-400 border-slate-700';
    }
  };

  const getStatusLabel = (status: string) => {
    switch (status) {
      case 'stage_1_4':
        return 'Static Analysis';
      case 'stage_5':
        return 'Ghidra Analysis';
      case 'stage_6':
        return 'AI Report';
      case 'queued':
        return 'Queued';
      default:
        return status.charAt(0).toUpperCase() + status.slice(1);
    }
  };

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-64">
        <Loader2 className="w-8 h-8 text-cyan-400 animate-spin" />
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto">
      <header className="mb-8 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white flex items-center">
            <Clock className="mr-3 text-cyan-400" /> Analysis History
          </h1>
          <p className="text-slate-400 mt-2">Recent malware analysis tasks</p>
        </div>
        
        {/* Search Input */}
        <div className="flex items-center space-x-2 bg-slate-800 p-2 rounded-xl border border-slate-700 shadow-lg w-full md:w-96">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input 
              type="text" 
              placeholder="Enter Task ID"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition-colors"
              value={searchHash}
              onChange={(e) => setSearchHash(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && searchByHash()}
            />
          </div>
          <button 
            onClick={searchByHash}
            disabled={!searchHash || isSearching}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-bold rounded-lg transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
          >
            {isSearching ? 'Searching...' : 'Search'}
          </button>
        </div>
      </header>

      {error && (
        <div className="mb-6 bg-red-900/20 p-4 rounded-xl border border-red-800 text-center text-red-400">
          <AlertCircle className="w-5 h-5 inline mr-2" />
          {error}
        </div>
      )}

      <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-xl overflow-hidden">
        {history.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-30" />
            <p className="text-lg">No analysis history found.</p>
            <p className="text-sm mt-2">Upload a file to get started.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-900/50 border-b border-slate-700 text-slate-300 text-sm uppercase tracking-wider">
                  <th className="p-4 font-medium">Status</th>
                  <th className="p-4 font-medium">Filename</th>
                  <th className="p-4 font-medium">Task ID</th>
                  <th className="p-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {history.map((task) => (
                  <tr 
                    key={task.id} 
                    className="hover:bg-slate-700/30 transition-colors group cursor-pointer"
                    onClick={() => navigate(`/task/${task.id}`)}
                  >
                    <td className="p-4">
                      <div className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-medium border ${getStatusBadgeClass(task.status)}`}>
                        {getStatusIcon(task.status)}
                        <span className="ml-1.5">{getStatusLabel(task.status)}</span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="flex items-center text-slate-200 font-medium">
                        <FileText className="w-4 h-4 mr-2 text-slate-400 flex-shrink-0" />
                        <span className="truncate max-w-xs" title={task.file_name || 'Unknown'}>
                          {task.file_name || 'Unknown'}
                        </span>
                      </div>
                    </td>
                    <td className="p-4">
                      <div className="text-slate-400 font-mono text-sm">
                        {task.id}
                      </div>
                    </td>
                    <td className="p-4 text-right">
                      <button
                        onClick={(e) => {
                          e.stopPropagation();
                          navigate(`/task/${task.id}`);
                        }}
                        className="inline-flex items-center px-3 py-1.5 bg-slate-700 hover:bg-cyan-600 text-white text-sm font-medium rounded transition-colors cursor-pointer"
                      >
                        View Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
