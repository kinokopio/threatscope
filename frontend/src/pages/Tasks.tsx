import { useEffect, useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { ListTodo, FileText, AlertCircle, CheckCircle, Loader2, Search, XCircle, Clock, RefreshCw } from 'lucide-react';

const API_BASE = import.meta.env.VITE_API_URL || '';

interface Task {
  id: string;
  status: string;
  file_name?: string;
  created_at?: string;
}

export default function Tasks() {
  const [tasks, setTasks] = useState<Task[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [searchId, setSearchId] = useState("");
  const [isSearching, setIsSearching] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const navigate = useNavigate();

  const fetchTasks = async (showRefresh = false) => {
    if (showRefresh) setIsRefreshing(true);
    try {
      const res = await axios.get(`${API_BASE}/tasks`);
      setTasks(res.data.tasks || []);
      setError(null);
    } catch (err) {
      console.error(err);
      setError("Failed to load tasks.");
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    fetchTasks();
    
    // Poll every 5 seconds
    const interval = setInterval(() => fetchTasks(), 5000);
    return () => clearInterval(interval);
  }, []);

  const searchByTaskId = async () => {
    if (!searchId) return;
    setIsSearching(true);
    setError(null);
    try {
      const res = await axios.get(`${API_BASE}/tasks/${searchId}`);
      if (res.data) {
        navigate(`/task/${searchId}`);
      }
    } catch {
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

  // Count tasks by status
  const pendingCount = tasks.filter(t => ['pending', 'stage_1_4', 'stage_5', 'stage_6', 'queued'].includes(t.status)).length;
  const completedCount = tasks.filter(t => t.status === 'completed').length;
  const failedCount = tasks.filter(t => t.status === 'failed').length;

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
            <ListTodo className="mr-3 text-cyan-400" /> All Tasks
          </h1>
          <p className="text-slate-400 mt-2">View and manage all analysis tasks</p>
        </div>
        
        {/* Search Input */}
        <div className="flex items-center space-x-2 bg-slate-800 p-2 rounded-xl border border-slate-700 shadow-lg w-full md:w-96">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
            <input 
              type="text" 
              placeholder="Enter Task ID"
              className="w-full bg-slate-900 border border-slate-600 rounded-lg py-2 pl-10 pr-4 text-sm text-slate-100 focus:outline-none focus:border-cyan-500 transition-colors"
              value={searchId}
              onChange={(e) => setSearchId(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && searchByTaskId()}
            />
          </div>
          <button 
            onClick={searchByTaskId}
            disabled={!searchId || isSearching}
            className="px-4 py-2 bg-cyan-600 hover:bg-cyan-700 text-white text-sm font-bold rounded-lg transition-all disabled:opacity-50 cursor-pointer whitespace-nowrap"
          >
            {isSearching ? 'Searching...' : 'Search'}
          </button>
        </div>
      </header>

      {/* Stats Cards */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className="bg-slate-800/50 p-4 rounded-xl border border-slate-700 flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm">In Progress</p>
            <p className="text-2xl font-bold text-cyan-400">{pendingCount}</p>
          </div>
          <Loader2 className="w-8 h-8 text-cyan-400/30" />
        </div>
        <div className="bg-slate-800/50 p-4 rounded-xl border border-slate-700 flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm">Completed</p>
            <p className="text-2xl font-bold text-emerald-400">{completedCount}</p>
          </div>
          <CheckCircle className="w-8 h-8 text-emerald-400/30" />
        </div>
        <div className="bg-slate-800/50 p-4 rounded-xl border border-slate-700 flex items-center justify-between">
          <div>
            <p className="text-slate-400 text-sm">Failed</p>
            <p className="text-2xl font-bold text-red-400">{failedCount}</p>
          </div>
          <XCircle className="w-8 h-8 text-red-400/30" />
        </div>
      </div>

      {error && (
        <div className="mb-6 bg-red-900/20 p-4 rounded-xl border border-red-800 text-center text-red-400">
          <AlertCircle className="w-5 h-5 inline mr-2" />
          {error}
        </div>
      )}

      <div className="bg-slate-800 rounded-xl border border-slate-700 shadow-xl overflow-hidden">
        {/* Table Header with Refresh */}
        <div className="flex items-center justify-between p-4 border-b border-slate-700 bg-slate-900/50">
          <span className="text-slate-300 font-medium">{tasks.length} Tasks</span>
          <button
            onClick={() => fetchTasks(true)}
            disabled={isRefreshing}
            className="flex items-center px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-white text-sm font-medium rounded transition-colors cursor-pointer"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>

        {tasks.length === 0 ? (
          <div className="p-12 text-center text-slate-400">
            <FileText className="w-16 h-16 mx-auto mb-4 opacity-30" />
            <p className="text-lg">No tasks found.</p>
            <p className="text-sm mt-2">Upload a file to get started.</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-slate-900/30 border-b border-slate-700 text-slate-300 text-sm uppercase tracking-wider">
                  <th className="p-4 font-medium">Status</th>
                  <th className="p-4 font-medium">Filename</th>
                  <th className="p-4 font-medium">Task ID</th>
                  <th className="p-4 font-medium text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {tasks.map((task) => (
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
