import axios from 'axios'

export const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json',
  },
})

// Types - matching backend API response
export interface Task {
  task_id: string
  id: string // alias for task_id
  status: 'pending' | 'running' | 'completed' | 'failed'
  file_name: string
  current_step?: string
  error?: string
  created_at?: string
  // Analysis results
  hashes?: {
    md5: string
    sha1: string
    sha256: string
    ssdeep?: string
  }
  file_type?: {
    format: string
    arch: string
    category: string
    platform: string
  }
  capa?: any
  strings?: string[]
  yara?: any[]
  threat_intel?: any
  dynamic_analysis?: any
  ghidra_analysis?: any
  unified_report?: {
    verdict?: string
    confidence?: number
    summary?: string
    recommendations?: string[]
    techniques?: any[]
  }
  // Computed fields for UI
  file_hash?: string
  file_size?: number
  verdict?: 'clean' | 'suspicious' | 'malicious' | 'unknown'
  family?: string
  progress?: number
}

// Task list item (simplified)
export interface TaskListItem {
  id: string
  status: string
  file_name: string
  created_at: string
  file_type?: string
  result_summary?: string
}

export interface StaticAnalysis {
  hashes: {
    md5: string
    sha1: string
    sha256: string
  }
  file_info: {
    type: string
    size: number
    magic: string
  }
  strings?: string[]
  capa_results?: CapaResults
  yara_matches?: YaraMatch[]
}

export interface CapaResults {
  capabilities: Array<{
    name: string
    namespace: string
    description?: string
  }>
}

export interface YaraMatch {
  rule: string
  tags: string[]
  meta: Record<string, string>
}

export interface DynamicAnalysis {
  syscalls?: Array<{
    name: string
    args: string[]
    return_value: number
  }>
  network?: Array<{
    type: string
    destination: string
    port?: number
  }>
  file_operations?: Array<{
    operation: string
    path: string
  }>
}

export interface GhidraAnalysis {
  functions?: Array<{
    name: string
    address: string
    size: number
    decompiled?: string
  }>
  imports?: string[]
  exports?: string[]
  strings?: string[]
}

export interface AIAnalysis {
  summary?: string
  verdict?: string
  confidence?: number
  techniques?: Array<{
    id: string
    name: string
    description?: string
  }>
  recommendations?: string[]
}

export interface SystemStats {
  queue_stats: {
    pending: number
    ghidra_waiting: number
    report_waiting: number
    total_tasks: number
    completed: number
    failed: number
  }
  database_stats: {
    total: number
  }
  verdict_stats: {
    malicious: number
    suspicious: number
    benign: number
  }
}

export interface HealthStatus {
  status: string
  version: string
  services: {
    api: boolean
    database: boolean
    ghidra_mcp: boolean
  }
}

export interface TaskCreateOptions {
  enable_capa?: boolean
  enable_strings?: boolean
  enable_yara?: boolean
  enable_dynamic?: boolean
  enable_ghidra?: boolean
}

export interface TaskListParams {
  skip?: number
  limit?: number
  status?: string
  verdict?: string
  file_type?: string
  search?: string
  date_from?: string
  date_to?: string
}

export interface TaskListResponse {
  items: TaskListItem[]
  total: number
  page: number
  page_size: number
  total_pages: number
  has_next: boolean
  has_prev: boolean
}

export async function getTasks(params?: TaskListParams): Promise<TaskListItem[]> {
  const response = await api.get<TaskListResponse>('/tasks', { params })
  return response.data.items
}

export async function getTask(id: string): Promise<Task> {
  const response = await api.get(`/tasks/${id}`)
  return response.data
}

export interface TaskCreateResponse {
  task_id: string
  status: string
  message: string
}

export async function createTask(file: File, options?: TaskCreateOptions): Promise<TaskCreateResponse> {
  const formData = new FormData()
  formData.append('file', file)
  if (options) {
    Object.entries(options).forEach(([key, value]) => {
      if (value !== undefined) {
        formData.append(key, String(value))
      }
    })
  }
  const response = await api.post<TaskCreateResponse>('/tasks', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  })
  return response.data
}

export async function deleteTask(id: string): Promise<void> {
  await api.delete(`/tasks/${id}`)
}

export async function reanalyzeTask(id: string, options?: TaskCreateOptions): Promise<Task> {
  const response = await api.post(`/tasks/${id}/reanalyze`, options)
  return response.data
}

export async function exportTask(id: string): Promise<Blob> {
  const response = await api.get(`/tasks/${id}/export`, {
    responseType: 'blob',
  })
  return response.data
}

export async function getStats(): Promise<SystemStats> {
  const response = await api.get('/system/stats')
  return response.data
}

export async function getHealth(): Promise<HealthStatus> {
  const response = await api.get('/system/health')
  return response.data
}
