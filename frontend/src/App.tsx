import { useState, useEffect, useCallback } from 'react';
import { QueryClient, QueryClientProvider, useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Shield, RefreshCw, Github } from 'lucide-react';
import { FileUpload } from './components/FileUpload';
import { TaskList } from './components/TaskList';
import { StatsCards } from './components/StatsCards';
import { AnalysisResultView } from './components/AnalysisResultView';
import { getTasks, getTask, uploadFile, deleteTask } from './api/client';
import type { AnalysisTask } from './types';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      refetchInterval: 3000, // Poll every 3 seconds
      staleTime: 1000,
    },
  },
});

function Dashboard() {
  const queryClientHook = useQueryClient();
  const [selectedTask, setSelectedTask] = useState<AnalysisTask | null>(null);

  // Fetch tasks
  const { data: tasksData, isLoading: tasksLoading } = useQuery({
    queryKey: ['tasks'],
    queryFn: getTasks,
  });

  // Fetch selected task details
  const { data: taskDetails, isLoading: taskLoading } = useQuery({
    queryKey: ['task', selectedTask?.id],
    queryFn: () => selectedTask ? getTask(selectedTask.id) : null,
    enabled: !!selectedTask,
    refetchInterval: selectedTask?.status !== 'completed' && selectedTask?.status !== 'failed' ? 2000 : false,
  });

  // Upload mutation
  const uploadMutation = useMutation({
    mutationFn: (file: File) => uploadFile(file),
    onSuccess: () => {
      queryClientHook.invalidateQueries({ queryKey: ['tasks'] });
    },
  });

  // Delete mutation
  const deleteMutation = useMutation({
    mutationFn: deleteTask,
    onSuccess: () => {
      queryClientHook.invalidateQueries({ queryKey: ['tasks'] });
      if (selectedTask) {
        setSelectedTask(null);
      }
    },
  });

  const handleUpload = useCallback((file: File) => {
    uploadMutation.mutate(file);
  }, [uploadMutation]);

  const handleSelectTask = useCallback((task: AnalysisTask) => {
    setSelectedTask(task);
  }, []);

  const handleDeleteTask = useCallback((taskId: string) => {
    deleteMutation.mutate(taskId);
  }, [deleteMutation]);

  // Update selected task when details change
  useEffect(() => {
    if (taskDetails && selectedTask) {
      setSelectedTask(taskDetails);
    }
  }, [taskDetails]);

  const tasks = tasksData?.tasks || [];
  const stats = tasksData?.queue_stats || null;

  return (
    <div className="min-h-screen bg-cyber-900">
      {/* Header */}
      <header className="bg-cyber-800 border-b border-cyber-700">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <Shield className="w-8 h-8 text-accent-cyan" />
              <div>
                <h1 className="text-xl font-bold text-gray-100">ThreatScope</h1>
                <p className="text-xs text-gray-500">AI-Powered Malware Analysis</p>
              </div>
            </div>
            <div className="flex items-center gap-4">
              <button
                onClick={() => queryClientHook.invalidateQueries({ queryKey: ['tasks'] })}
                className="p-2 rounded-lg hover:bg-cyber-700 transition-colors"
                title="Refresh"
              >
                <RefreshCw className="w-5 h-5 text-gray-400" />
              </button>
              <a
                href="https://github.com"
                target="_blank"
                rel="noopener noreferrer"
                className="p-2 rounded-lg hover:bg-cyber-700 transition-colors"
              >
                <Github className="w-5 h-5 text-gray-400" />
              </a>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto px-4 py-6">
        {/* Stats */}
        <div className="mb-6">
          <StatsCards stats={stats} isLoading={tasksLoading} />
        </div>

        {/* Main Grid */}
        <div className="grid lg:grid-cols-3 gap-6">
          {/* Left Panel - Upload & Tasks */}
          <div className="lg:col-span-1 space-y-6">
            {/* Upload */}
            <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
              <h2 className="text-lg font-semibold text-gray-200 mb-4">Upload Sample</h2>
              <FileUpload 
                onUpload={handleUpload} 
                isUploading={uploadMutation.isPending} 
              />
            </div>

            {/* Task List */}
            <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
              <h2 className="text-lg font-semibold text-gray-200 mb-4">
                Analysis Tasks
                {tasks.length > 0 && (
                  <span className="ml-2 text-sm font-normal text-gray-500">
                    ({tasks.length})
                  </span>
                )}
              </h2>
              <TaskList
                tasks={tasks}
                onSelectTask={handleSelectTask}
                onDeleteTask={handleDeleteTask}
                selectedTaskId={selectedTask?.id}
              />
            </div>
          </div>

          {/* Right Panel - Results */}
          <div className="lg:col-span-2">
            <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700 min-h-[600px]">
              <h2 className="text-lg font-semibold text-gray-200 mb-4">Analysis Results</h2>
              <AnalysisResultView
                result={selectedTask?.result || null}
                status={selectedTask?.status || 'pending'}
                error={selectedTask?.error}
                isLoading={taskLoading}
              />
            </div>
          </div>
        </div>
      </main>

      {/* Footer */}
      <footer className="bg-cyber-800 border-t border-cyber-700 mt-12">
        <div className="max-w-7xl mx-auto px-4 py-4">
          <p className="text-center text-sm text-gray-500">
            ThreatScope © 2024 - AI-Driven Malware Analysis Framework
          </p>
        </div>
      </footer>
    </div>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <Dashboard />
    </QueryClientProvider>
  );
}

export default App;
