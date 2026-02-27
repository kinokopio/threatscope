import axios from 'axios';
import type { AnalysisTask, TaskListResponse, QueueStats } from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || '';

const api = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export async function healthCheck(): Promise<{ status: string }> {
  const response = await api.get('/health');
  return response.data;
}

export async function uploadFile(
  file: File,
  options?: {
    enableGhidra?: boolean;
    enableDynamic?: boolean;
    enableThreatIntel?: boolean;
  }
): Promise<{ task_id: string; status: string; message: string }> {
  const formData = new FormData();
  formData.append('file', file);

  const params = new URLSearchParams();
  if (options?.enableGhidra !== undefined) {
    params.append('enable_ghidra', String(options.enableGhidra));
  }
  if (options?.enableDynamic !== undefined) {
    params.append('enable_dynamic', String(options.enableDynamic));
  }
  if (options?.enableThreatIntel !== undefined) {
    params.append('enable_threat_intel', String(options.enableThreatIntel));
  }

  const response = await api.post(`/analyze?${params.toString()}`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
}

export async function uploadFileSync(
  file: File,
  options?: {
    enableGhidra?: boolean;
    enableDynamic?: boolean;
    enableThreatIntel?: boolean;
  }
): Promise<{ task_id: string; status: string; result?: unknown; error?: string }> {
  const formData = new FormData();
  formData.append('file', file);

  const params = new URLSearchParams();
  if (options?.enableGhidra !== undefined) {
    params.append('enable_ghidra', String(options.enableGhidra));
  }
  if (options?.enableDynamic !== undefined) {
    params.append('enable_dynamic', String(options.enableDynamic));
  }
  if (options?.enableThreatIntel !== undefined) {
    params.append('enable_threat_intel', String(options.enableThreatIntel));
  }

  const response = await api.post(`/analyze/sync?${params.toString()}`, formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  return response.data;
}

export async function getTask(taskId: string): Promise<AnalysisTask> {
  const response = await api.get(`/tasks/${taskId}`);
  const data = response.data;
  // Normalize: API returns task_id, but we use id internally
  return {
    ...data,
    id: data.task_id || data.id,
  };
}

export async function getTasks(): Promise<TaskListResponse> {
  const response = await api.get('/tasks');
  return response.data;
}

export async function deleteTask(taskId: string): Promise<{ message: string }> {
  const response = await api.delete(`/tasks/${taskId}`);
  return response.data;
}

export async function getQueueStats(): Promise<QueueStats> {
  const response = await api.get('/batch/stats');
  return response.data;
}

export default api;
