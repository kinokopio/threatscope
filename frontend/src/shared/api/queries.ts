import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getTask, getTasks, uploadFile, deleteTask, getQueueStats } from './client';
import type { UploadOptions } from './client';

// Query keys for cache management
export const queryKeys = {
  tasks: ['tasks'] as const,
  task: (id: string) => ['task', id] as const,
  queueStats: ['queueStats'] as const,
} as const;

// Hook: Fetch single task
export function useTask(taskId: string | undefined, options?: { enabled?: boolean; refetchInterval?: number }) {
  return useQuery({
    queryKey: queryKeys.task(taskId ?? ''),
    queryFn: () => getTask(taskId!),
    enabled: !!taskId && (options?.enabled ?? true),
    refetchInterval: options?.refetchInterval,
  });
}

// Hook: Fetch all tasks
export function useTasks(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: queryKeys.tasks,
    queryFn: getTasks,
    refetchInterval: options?.refetchInterval,
  });
}

// Hook: Fetch queue stats
export function useQueueStats(options?: { refetchInterval?: number }) {
  return useQuery({
    queryKey: queryKeys.queueStats,
    queryFn: getQueueStats,
    refetchInterval: options?.refetchInterval,
  });
}

// Hook: Upload file mutation
export function useUploadFile() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: ({ file, options }: { file: File; options?: UploadOptions }) =>
      uploadFile(file, options),
    onSuccess: () => {
      // Invalidate tasks list to show new task
      queryClient.invalidateQueries({ queryKey: queryKeys.tasks });
    },
  });
}

// Hook: Delete task mutation
export function useDeleteTask() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (taskId: string) => deleteTask(taskId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: queryKeys.tasks });
    },
  });
}
