import { useEffect, useState, useCallback, useRef } from 'react';
import type { ProgressMessage } from '../types';

const WS_URL = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/ws/progress';

export interface LogEntry {
  id: string;
  timestamp: Date;
  event: string;
  message: string;
  level: 'info' | 'success' | 'error' | 'warning';
}

export function useTaskProgress(taskId: string | null) {
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [isConnected, setIsConnected] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<number | null>(null);

  const addLog = useCallback((entry: Omit<LogEntry, 'id'>) => {
    setLogs(prev => [...prev, { ...entry, id: `${Date.now()}-${Math.random()}` }]);
  }, []);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        addLog({
          timestamp: new Date(),
          event: 'connected',
          message: 'Connected to analysis server',
          level: 'info',
        });

        // Subscribe to task if we have one
        if (taskId) {
          ws.send(JSON.stringify({ action: 'subscribe', task_id: taskId }));
        }
      };

      ws.onmessage = (event) => {
        try {
          const msg: ProgressMessage = JSON.parse(event.data);
          
          let message = '';
          let level: LogEntry['level'] = 'info';

          switch (msg.event) {
            case 'task_started':
              message = `Analysis started: ${msg.data.file_path}`;
              level = 'info';
              break;
            case 'step_started':
              message = `Starting: ${msg.data.step_name}`;
              level = 'info';
              break;
            case 'step_completed':
              message = `Completed: ${msg.data.step_id} (${msg.data.duration_ms}ms)`;
              level = msg.data.status === 'completed' ? 'success' : 'warning';
              break;
            case 'task_completed':
              message = `Analysis ${msg.data.status}: ${JSON.stringify(msg.data.result_summary)}`;
              level = msg.data.status === 'completed' ? 'success' : 'error';
              break;
            case 'error':
              message = `Error: ${msg.data.error}`;
              level = 'error';
              break;
            default:
              message = JSON.stringify(msg);
          }

          addLog({
            timestamp: new Date(msg.timestamp),
            event: msg.event,
            message,
            level,
          });
        } catch (e) {
          console.error('Failed to parse WebSocket message:', e);
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        // Reconnect after 3 seconds
        reconnectTimeoutRef.current = window.setTimeout(() => {
          connect();
        }, 3000);
      };

      ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        addLog({
          timestamp: new Date(),
          event: 'error',
          message: 'Connection error',
          level: 'error',
        });
      };
    } catch (e) {
      console.error('Failed to connect WebSocket:', e);
    }
  }, [taskId, addLog]);

  // Connect on mount
  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, [connect]);

  // Subscribe to new task when taskId changes
  useEffect(() => {
    if (taskId && wsRef.current?.readyState === WebSocket.OPEN) {
      wsRef.current.send(JSON.stringify({ action: 'subscribe', task_id: taskId }));
      addLog({
        timestamp: new Date(),
        event: 'subscribed',
        message: `Subscribed to task: ${taskId}`,
        level: 'info',
      });
    }
  }, [taskId, addLog]);

  const clearLogs = useCallback(() => {
    setLogs([]);
  }, []);

  return { logs, isConnected, clearLogs };
}
