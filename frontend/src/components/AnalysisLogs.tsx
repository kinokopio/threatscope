import { useRef, useEffect } from 'react';
import { Terminal, Wifi, WifiOff, Trash2 } from 'lucide-react';
import type { LogEntry } from '../hooks/useTaskProgress';

interface AnalysisLogsProps {
  logs: LogEntry[];
  isConnected: boolean;
  onClear: () => void;
}

export function AnalysisLogs({ logs, isConnected, onClear }: AnalysisLogsProps) {
  const logsEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom when new logs arrive
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const getLevelColor = (level: LogEntry['level']) => {
    switch (level) {
      case 'success':
        return 'text-green-400';
      case 'error':
        return 'text-red-400';
      case 'warning':
        return 'text-yellow-400';
      default:
        return 'text-gray-400';
    }
  };

  const getLevelIcon = (level: LogEntry['level']) => {
    switch (level) {
      case 'success':
        return '✓';
      case 'error':
        return '✗';
      case 'warning':
        return '⚠';
      default:
        return '›';
    }
  };

  return (
    <div className="bg-cyber-900 rounded-xl border border-cyber-700 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 bg-cyber-800 border-b border-cyber-700">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-accent-cyan" />
          <span className="text-sm font-medium text-gray-300">Analysis Logs</span>
        </div>
        <div className="flex items-center gap-3">
          {/* Connection status */}
          <div className="flex items-center gap-1.5">
            {isConnected ? (
              <>
                <Wifi className="w-3.5 h-3.5 text-green-400" />
                <span className="text-xs text-green-400">Connected</span>
              </>
            ) : (
              <>
                <WifiOff className="w-3.5 h-3.5 text-red-400" />
                <span className="text-xs text-red-400">Disconnected</span>
              </>
            )}
          </div>
          {/* Clear button */}
          <button
            onClick={onClear}
            className="p-1 rounded hover:bg-cyber-700 transition-colors"
            title="Clear logs"
          >
            <Trash2 className="w-3.5 h-3.5 text-gray-500 hover:text-gray-300" />
          </button>
        </div>
      </div>

      {/* Logs */}
      <div className="h-48 overflow-y-auto font-mono text-xs p-3 space-y-1">
        {logs.length === 0 ? (
          <div className="text-gray-600 text-center py-8">
            No logs yet. Upload a file to start analysis.
          </div>
        ) : (
          logs.map((log) => (
            <div key={log.id} className="flex gap-2">
              <span className="text-gray-600 shrink-0">
                {log.timestamp.toLocaleTimeString()}
              </span>
              <span className={`shrink-0 ${getLevelColor(log.level)}`}>
                {getLevelIcon(log.level)}
              </span>
              <span className={getLevelColor(log.level)}>
                {log.message}
              </span>
            </div>
          ))
        )}
        <div ref={logsEndRef} />
      </div>
    </div>
  );
}
