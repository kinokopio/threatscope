import { useState, useCallback, useMemo } from 'react';
import { 
  Upload, 
  Shield, 
  Cpu, 
  FileSearch, 
  Zap,
  Binary,
  Network,
  Brain,
  ChevronRight,
  FileCode,
  AlertTriangle
} from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useUploadFile, useTasks } from '../shared/api';
import { formatFileSize } from '../shared/utils';

const ANALYSIS_PIPELINE = [
  { 
    icon: FileSearch, 
    title: 'Static Analysis', 
    items: ['Hash calculation', 'String extraction', 'Import analysis', 'YARA scanning'],
    color: 'from-emerald-500 to-teal-600'
  },
  { 
    icon: Network, 
    title: 'Threat Intel', 
    items: ['MalwareBazaar', 'ThreatFox', 'URLhaus', 'Hash lookup'],
    color: 'from-blue-500 to-cyan-600'
  },
  { 
    icon: Cpu, 
    title: 'Dynamic Analysis', 
    items: ['Syscall tracing', 'Network monitoring', 'File operations', 'Behavior analysis'],
    color: 'from-violet-500 to-purple-600'
  },
  { 
    icon: Brain, 
    title: 'AI Analysis', 
    items: ['Ghidra decompilation', 'Function analysis', 'MITRE mapping', 'Report generation'],
    color: 'from-rose-500 to-pink-600'
  },
] as const;

const SUPPORTED_FORMATS = [
  { name: 'ELF', desc: 'Linux executables' },
  { name: 'PE', desc: 'Windows executables' },
  { name: 'Mach-O', desc: 'macOS binaries' },
  { name: 'APK', desc: 'Android packages' },
] as const;

export default function Home() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isDragging, setIsDragging] = useState(false);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const navigate = useNavigate();
  const uploadMutation = useUploadFile();
  const { data: tasksData } = useTasks({ refetchInterval: 30000 });

  const stats = useMemo(() => {
    if (!tasksData?.tasks) return { total: 0, malicious: 0, pending: 0 };
    const tasks = tasksData.tasks;
    return {
      total: tasks.length,
      malicious: tasks.filter(t => t.result?.malware_report?.verdict === 'malicious').length,
      pending: tasks.filter(t => ['pending', 'stage_1_4', 'stage_5', 'stage_6', 'queued'].includes(t.status)).length,
    };
  }, [tasksData]);

  const handleFileChange = useCallback((event: React.ChangeEvent<HTMLInputElement>) => {
    const nextFile = event.target.files?.[0] || null;
    setSelectedFile(nextFile);
    setErrorMessage(null);
  }, []);

  const handleDrop = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(false);
    const nextFile = event.dataTransfer.files?.[0] || null;
    setSelectedFile(nextFile);
    setErrorMessage(null);
  }, []);

  const handleDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragging(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setIsDragging(false);
  }, []);

  const uploadFile = useCallback(async () => {
    if (!selectedFile) return;
    try {
      const result = await uploadMutation.mutateAsync({ file: selectedFile });
      navigate(`/task/${result.task_id}`);
    } catch {
      setErrorMessage('Upload failed. Please try again.');
    }
  }, [selectedFile, uploadMutation, navigate]);

  return (
    <div className="min-h-[calc(100vh-8rem)]">
      <div className="max-w-7xl mx-auto">
        <div className="grid lg:grid-cols-5 gap-8">
          <div className="lg:col-span-3 space-y-6">
            <div className="space-y-2">
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-600 flex items-center justify-center shadow-lg shadow-emerald-500/20">
                  <Shield className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="text-3xl font-bold text-white tracking-tight">
                    Malware Analysis
                  </h1>
                  <p className="text-slate-400 text-sm">AI-powered threat detection & analysis</p>
                </div>
              </div>
            </div>

            <div
              className={`relative group rounded-2xl border-2 border-dashed transition-all duration-300 ${
                isDragging 
                  ? 'border-emerald-400 bg-emerald-500/10' 
                  : selectedFile 
                    ? 'border-emerald-500/50 bg-slate-800/80' 
                    : 'border-slate-600 bg-slate-800/50 hover:border-slate-500 hover:bg-slate-800/80'
              }`}
              onDrop={handleDrop}
              onDragOver={handleDragOver}
              onDragLeave={handleDragLeave}
            >
              <input
                type="file"
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer z-10"
                onChange={handleFileChange}
              />
              
              <div className="p-8 text-center">
                {selectedFile ? (
                  <div className="space-y-4">
                    <div className="w-16 h-16 mx-auto rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-600 flex items-center justify-center">
                      <FileCode className="w-8 h-8 text-white" />
                    </div>
                    <div>
                      <p className="text-lg font-semibold text-white">{selectedFile.name}</p>
                      <p className="text-slate-400 text-sm mt-1">{formatFileSize(selectedFile.size)}</p>
                    </div>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedFile(null);
                      }}
                      className="text-slate-400 hover:text-white text-sm underline underline-offset-2"
                    >
                      Choose different file
                    </button>
                  </div>
                ) : (
                  <div className="space-y-4">
                    <div className="w-16 h-16 mx-auto rounded-xl bg-slate-700/50 flex items-center justify-center group-hover:bg-slate-700 transition-colors">
                      <Upload className="w-8 h-8 text-slate-400 group-hover:text-slate-300 transition-colors" />
                    </div>
                    <div>
                      <p className="text-lg font-medium text-slate-300">
                        Drop your binary here
                      </p>
                      <p className="text-slate-500 text-sm mt-1">or click to browse</p>
                    </div>
                    <div className="flex flex-wrap justify-center gap-2 pt-2">
                      {SUPPORTED_FORMATS.map((format) => (
                        <span
                          key={format.name}
                          className="px-2.5 py-1 rounded-md bg-slate-700/50 text-slate-400 text-xs font-medium"
                          title={format.desc}
                        >
                          {format.name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            </div>

            {errorMessage && (
              <div className="flex items-center gap-3 p-4 rounded-xl bg-red-500/10 border border-red-500/30">
                <AlertTriangle className="w-5 h-5 text-red-400 flex-shrink-0" />
                <p className="text-red-400 text-sm">{errorMessage}</p>
              </div>
            )}

            <button
              onClick={uploadFile}
              disabled={!selectedFile || uploadMutation.isPending}
              className="w-full py-4 px-6 rounded-xl font-semibold text-white transition-all duration-300 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-3 bg-gradient-to-r from-emerald-500 to-cyan-600 hover:from-emerald-400 hover:to-cyan-500 shadow-lg shadow-emerald-500/20 hover:shadow-emerald-500/30"
            >
              {uploadMutation.isPending ? (
                <>
                  <div className="w-5 h-5 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="w-5 h-5" />
                  Start Analysis
                </>
              )}
            </button>

            <div className="grid grid-cols-3 gap-3">
              <div className="p-4 rounded-xl bg-slate-800/50 border border-slate-700/50">
                <p className="text-2xl font-bold text-white">{stats.total}</p>
                <p className="text-slate-400 text-xs mt-1">Total Scans</p>
              </div>
              <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/20">
                <p className="text-2xl font-bold text-red-400">{stats.malicious}</p>
                <p className="text-slate-400 text-xs mt-1">Threats Found</p>
              </div>
              <div className="p-4 rounded-xl bg-cyan-500/10 border border-cyan-500/20">
                <p className="text-2xl font-bold text-cyan-400">{stats.pending}</p>
                <p className="text-slate-400 text-xs mt-1">In Progress</p>
              </div>
            </div>
          </div>

          <div className="lg:col-span-2 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wider">
                Analysis Pipeline
              </h2>
              <Binary className="w-4 h-4 text-slate-500" />
            </div>
            
            <div className="space-y-3">
              {ANALYSIS_PIPELINE.map((stage, index) => (
                <div
                  key={stage.title}
                  className="group p-4 rounded-xl bg-slate-800/50 border border-slate-700/50 hover:border-slate-600 transition-all duration-300"
                >
                  <div className="flex items-start gap-4">
                    <div className={`w-10 h-10 rounded-lg bg-gradient-to-br ${stage.color} flex items-center justify-center flex-shrink-0 shadow-lg`}>
                      <stage.icon className="w-5 h-5 text-white" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-slate-500 text-xs font-mono">0{index + 1}</span>
                        <h3 className="text-white font-medium">{stage.title}</h3>
                      </div>
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {stage.items.map((item) => (
                          <span
                            key={item}
                            className="px-2 py-0.5 rounded bg-slate-700/50 text-slate-400 text-xs"
                          >
                            {item}
                          </span>
                        ))}
                      </div>
                    </div>
                    <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 transition-colors flex-shrink-0 mt-1" />
                  </div>
                </div>
              ))}
            </div>

            <div className="p-4 rounded-xl bg-gradient-to-br from-slate-800 to-slate-800/50 border border-slate-700/50">
              <div className="flex items-center gap-3 mb-3">
                <div className="w-8 h-8 rounded-lg bg-amber-500/20 flex items-center justify-center">
                  <Shield className="w-4 h-4 text-amber-400" />
                </div>
                <span className="text-sm font-medium text-slate-300">MITRE ATT&CK</span>
              </div>
              <p className="text-slate-400 text-xs leading-relaxed">
                Automatic mapping of detected behaviors to MITRE ATT&CK framework tactics and techniques.
              </p>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
