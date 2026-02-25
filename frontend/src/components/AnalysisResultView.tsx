import type { AnalysisResult } from '../types';
import { ReportViewer } from './ReportViewer';
import { 
  FileCode, 
  Shield, 
  Activity, 
  Cpu, 
  AlertCircle,
  Loader2,
  Hash,
  FileText
} from 'lucide-react';

interface AnalysisResultViewProps {
  result: AnalysisResult | null;
  status: string;
  error?: string;
  isLoading: boolean;
}

export function AnalysisResultView({ result, status, error, isLoading }: AnalysisResultViewProps) {
  if (isLoading || ['pending', 'stage_1_4', 'queued', 'stage_5', 'stage_6'].includes(status)) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <Loader2 className="w-12 h-12 text-accent-cyan animate-spin mb-4" />
        <p className="text-lg text-gray-300">Analyzing sample...</p>
        <p className="text-sm text-gray-500 mt-2">
          {status === 'stage_1_4' && 'Running static analysis...'}
          {status === 'queued' && 'Waiting for Ghidra...'}
          {status === 'stage_5' && 'Deep analysis with Ghidra...'}
          {status === 'stage_6' && 'Generating AI report...'}
          {status === 'pending' && 'Starting analysis...'}
        </p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center py-20">
        <AlertCircle className="w-12 h-12 text-accent-red mb-4" />
        <p className="text-lg text-gray-300">Analysis Failed</p>
        <p className="text-sm text-gray-500 mt-2 max-w-md text-center">{error}</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-500">
        <FileCode className="w-12 h-12 mb-4 opacity-50" />
        <p>Select a task to view results</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* File Info Header */}
      <div className="bg-cyber-800 rounded-xl p-6 border border-cyber-700">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-cyber-700 rounded-lg">
            <FileText className="w-8 h-8 text-accent-cyan" />
          </div>
          <div className="flex-1">
            <h2 className="text-xl font-semibold text-gray-200">
              {result.metadata?.file_name || 'Unknown File'}
            </h2>
            {result.metadata?.hashes && (
              <div className="flex items-center gap-4 mt-2 text-sm text-gray-400">
                <span className="flex items-center gap-1">
                  <Hash className="w-3 h-3" />
                  MD5: <code className="text-gray-500">{result.metadata.hashes.md5?.slice(0, 16)}...</code>
                </span>
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Tabs / Sections */}
      <div className="flex gap-2 border-b border-cyber-700 pb-2">
        <TabButton icon={Shield} label="Report" active />
        <TabButton icon={Activity} label="Static" />
        <TabButton icon={Cpu} label="Ghidra" />
      </div>

      {/* Main Report */}
      {result.malware_report ? (
        <ReportViewer report={result.malware_report} />
      ) : (
        <div className="text-center py-12 text-gray-500">
          <p>No malware report available</p>
        </div>
      )}
    </div>
  );
}

function TabButton({ 
  icon: Icon, 
  label, 
  active = false 
}: { 
  icon: typeof Shield; 
  label: string; 
  active?: boolean;
}) {
  return (
    <button
      className={`
        flex items-center gap-2 px-4 py-2 rounded-lg text-sm font-medium transition-colors
        ${active 
          ? 'bg-accent-cyan/20 text-accent-cyan' 
          : 'text-gray-400 hover:text-gray-200 hover:bg-cyber-700'
        }
      `}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );
}
