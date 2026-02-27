// API client exports
export { default as api } from './client';
export {
  healthCheck,
  uploadFile,
  uploadFileSync,
  getTask,
  getTasks,
  deleteTask,
  getQueueStats,
} from './client';
export type { UploadOptions } from './client';

// React Query hooks
export {
  queryKeys,
  useTask,
  useTasks,
  useQueueStats,
  useUploadFile,
  useDeleteTask,
} from './queries';
