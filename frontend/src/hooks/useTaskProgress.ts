import { useState, useCallback } from 'react';

export interface LogEntry {
  id: string;
  timestamp: Date;
  event: string;
  message: string;
  level: 'info' | 'success' | 'error' | 'warning';
}

// WebSocket disabled - using polling instead
export function useTaskProgress(_taskId: string | null) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isConnected] = useState(false); // Always false since WS is disabled

  const addLog = useCallback((entry: Omit<LogEntry, 'id'>) => {
    setLogs(prev => [...prev, { ...entry, id: `${Date.now()}-${Math.random()}` }]);
  }, []);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  return { logs, isConnected, clearLogs, addLog };
}
