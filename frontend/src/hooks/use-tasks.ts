import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  getTasks,
  getTask,
  createTask,
  deleteTask,
  cancelTask,
  reanalyzeTask,
  exportTask,
  type Task,
  type TaskCreateOptions,
  type TaskListParams,
} from '@/lib/api'

export function useTasks(params?: TaskListParams) {
  return useQuery({
    queryKey: ['tasks', params],
    queryFn: () => getTasks(params),
    refetchInterval: 3000,
  })
}

const ACTIVE_STATUSES = ['pending', 'queued', 'static_analysis', 'dynamic_analysis', 'ghidra_analysis', 'report_generation']

export function useTask(id: string) {
  return useQuery({
    queryKey: ['task', id],
    queryFn: () => getTask(id),
    enabled: !!id,
    refetchInterval: (query) => {
      const task = query.state.data as Task | undefined
      if (task?.status && ACTIVE_STATUSES.includes(task.status)) {
        return 2000
      }
      return false
    },
  })
}

export function useCreateTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ file, options }: { file: File; options?: TaskCreateOptions }) =>
      createTask(file, options),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}

export function useDeleteTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: deleteTask,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}

export function useCancelTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: cancelTask,
    onSuccess: (_, id) => {
      queryClient.invalidateQueries({ queryKey: ['task', id] })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
      queryClient.invalidateQueries({ queryKey: ['stats'] })
    },
  })
}

export function useReanalyzeTask() {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: ({ id, options }: { id: string; options?: TaskCreateOptions }) =>
      reanalyzeTask(id, options),
    onSuccess: (_, { id }) => {
      queryClient.invalidateQueries({ queryKey: ['task', id] })
      queryClient.invalidateQueries({ queryKey: ['tasks'] })
    },
  })
}

export function useExportTask() {
  return useMutation({
    mutationFn: exportTask,
  })
}
