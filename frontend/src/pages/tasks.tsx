import { useState, useMemo, useRef, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import { type ColumnDef } from '@tanstack/react-table'
import {
  Clock,
  RefreshCw,
  Code,
  FileText,
  Plus,
  CheckCircle,
  XCircle,
  Eye,
  Copy,
  Check,
  MoreHorizontal,
  Trash2,
  ChevronDown,
  Bot,
  Wrench,
} from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { Badge } from '@/components/ui/badge'
import { Progress } from '@/components/ui/progress'
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from '@/components/ui/collapsible'
import { ScrollArea } from '@/components/ui/scroll-area'
import { DataTable } from '@/components/ui/data-table'
import { DataTableColumnHeader } from '@/components/ui/data-table-column-header'
import { DataTablePagination } from '@/components/ui/data-table-pagination'
import { DataTableToolbar } from '@/components/ui/data-table-toolbar'
import { useTasks, useTask, useDeleteTask } from '@/hooks/use-tasks'
import type { TaskListItem, AILogEntry } from '@/lib/api'

const RUNNING_STATUSES = ['static_analysis', 'dynamic_analysis', 'ghidra_analysis', 'report_generation', 'queued']

const STEP_LABELS: Record<string, string> = {
  hashing: '哈希计算',
  file_identification: '文件识别',
  capa: '能力分析 (CAPA)',
  strings: '字符串提取',
  yara: 'YARA 扫描',
  threat_intel: '威胁情报',
  dynamic: '动态分析',
  ghidra: 'Ghidra 分析',
  report: '报告生成',
}

const GHIDRA_SUBSTEP_LABELS: Record<string, string> = {
  ghidra_startup: '启动 Ghidra',
  ghidra_connect: '连接服务',
  ghidra_upload: '上传文件',
  ghidra_analyze: '静态分析',
  ghidra_info: '获取信息',
  ghidra_ai_start: 'AI 深度分析',
}

const GHIDRA_SUBSTEPS = ['ghidra_startup', 'ghidra_connect', 'ghidra_upload', 'ghidra_analyze', 'ghidra_info', 'ghidra_ai_start']

function formatTimeAgo(dateString: string) {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)

  if (diffMins < 1) return '刚刚'
  if (diffMins < 60) return `${diffMins}分钟前`
  const diffHours = Math.floor(diffMins / 60)
  if (diffHours < 24) return `${diffHours}小时前`
  const diffDays = Math.floor(diffHours / 24)
  return `${diffDays}天前`
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <Button variant="ghost" size="icon" className="h-6 w-6" onClick={handleCopy}>
      {copied ? <Check className="h-3 w-3 text-green-500" /> : <Copy className="h-3 w-3" />}
    </Button>
  )
}

function StepStatusIcon({ status }: { status: string }) {
  switch (status) {
    case 'completed':
      return <CheckCircle className="h-4 w-4 text-green-500 flex-shrink-0" />
    case 'running':
      return <RefreshCw className="h-4 w-4 animate-spin text-primary flex-shrink-0" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-destructive flex-shrink-0" />
    default:
      return <Clock className="h-4 w-4 text-muted-foreground flex-shrink-0" />
  }
}

interface MergedToolCall {
  tool_call_count: number
  tool: string
  input?: Record<string, unknown>
  result?: string
  is_error?: boolean
  function?: string
  pattern?: string
  updated_at: string
}

function mergeToolCalls(logs: AILogEntry[]): MergedToolCall[] {
  const merged = new Map<number, MergedToolCall>()
  
  for (const log of logs) {
    const count = log.preview?.tool_call_count
    if (!count) continue
    
    const existing = merged.get(count)
    if (existing) {
      if (log.preview?.result) existing.result = log.preview.result
      if (log.preview?.is_error) existing.is_error = log.preview.is_error
      if (log.updated_at > existing.updated_at) existing.updated_at = log.updated_at
    } else {
      merged.set(count, {
        tool_call_count: count,
        tool: log.preview?.tool || log.step_id,
        input: log.preview?.input,
        result: log.preview?.result,
        is_error: log.preview?.is_error,
        function: log.preview?.function,
        pattern: log.preview?.pattern,
        updated_at: log.updated_at,
      })
    }
  }
  
  return Array.from(merged.values()).sort((a, b) => a.tool_call_count - b.tool_call_count)
}

function AILogsSection({ logs }: { logs?: AILogEntry[] }) {
  const [isOpen, setIsOpen] = useState(true)
  const [expandedLogs, setExpandedLogs] = useState<Set<number>>(new Set())
  const scrollRef = useRef<HTMLDivElement>(null)
  
  const toolCalls = useMemo(() => logs ? mergeToolCalls(logs) : [], [logs])
  const prevLength = useRef(0)

  useEffect(() => {
    if (toolCalls.length > prevLength.current && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
    prevLength.current = toolCalls.length
  }, [toolCalls.length])

  if (!logs || logs.length === 0) return null

  const toggleLog = (count: number) => {
    setExpandedLogs(prev => {
      const next = new Set(prev)
      if (next.has(count)) {
        next.delete(count)
      } else {
        next.add(count)
      }
      return next
    })
  }

  return (
    <div className="pt-4 border-t">
      <Collapsible open={isOpen} onOpenChange={setIsOpen}>
        <CollapsibleTrigger asChild>
          <Button variant="ghost" className="w-full justify-between p-0 h-auto hover:bg-transparent">
            <div className="flex items-center gap-2">
              <Bot className="h-4 w-4 text-primary" />
              <h4 className="text-sm font-medium">AI 分析日志</h4>
              <Badge variant="secondary" className="text-xs">
                {toolCalls.length} 次调用
              </Badge>
            </div>
            <ChevronDown className={`h-4 w-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
          </Button>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <ScrollArea className="h-[400px] mt-3" ref={scrollRef}>
            <div className="space-y-1 pr-4">
              {toolCalls.map((call) => {
                const isExpanded = expandedLogs.has(call.tool_call_count)
                const toolName = call.tool?.replace('mcp__ghidra__', '').replace('mcp__memory__', '').replace('mcp__utils__', '').replace('mcp__gdb__', '').replace(/_/g, ' ') || 'unknown'
                const isError = call.is_error
                const hasInput = call.input && Object.keys(call.input).length > 0
                const hasResult = call.result
                const hasDetails = hasResult || hasInput
                
                return (
                  <div 
                    key={call.tool_call_count} 
                    className={`rounded text-xs ${
                      isError ? 'bg-destructive/10 border border-destructive/30' : 'bg-muted/30'
                    }`}
                  >
                    <div 
                      className={`flex items-start gap-2 p-2 ${hasDetails ? 'cursor-pointer hover:bg-muted/50' : ''}`}
                      onClick={hasDetails ? () => toggleLog(call.tool_call_count) : undefined}
                    >
                      <div className="flex-shrink-0 mt-0.5">
                        {isError ? (
                          <XCircle className="h-3 w-3 text-destructive" />
                        ) : (
                          <Wrench className="h-3 w-3 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground">#{call.tool_call_count}</span>
                          <span className={`font-medium ${isError ? 'text-destructive' : ''}`}>{toolName}</span>
                          {hasDetails && (
                            <ChevronDown className={`h-3 w-3 text-muted-foreground transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                          )}
                        </div>
                        {call.function && (
                          <div className="text-muted-foreground truncate">
                            函数: <span className="font-mono">{call.function}</span>
                          </div>
                        )}
                        {call.pattern && (
                          <div className="text-muted-foreground truncate">
                            模式: <span className="font-mono">{call.pattern}</span>
                          </div>
                        )}
                      </div>
                      <span className="text-muted-foreground flex-shrink-0">
                        {new Date(call.updated_at).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                      </span>
                    </div>
                    {isExpanded && hasDetails && (
                      <div className="px-2 pb-2 space-y-2 border-t border-border/50 mt-1 pt-2">
                        {hasInput && (
                          <div>
                            <div className="text-muted-foreground mb-1 font-medium">输入:</div>
                            <pre className="bg-muted/50 p-2 rounded text-[10px] overflow-x-auto whitespace-pre-wrap break-all">
                              {JSON.stringify(call.input, null, 2)}
                            </pre>
                          </div>
                        )}
                        {hasResult && (
                          <div>
                            <div className="text-muted-foreground mb-1 font-medium">结果:</div>
                            <pre className={`p-2 rounded text-[10px] overflow-x-auto whitespace-pre-wrap break-all max-h-[200px] overflow-y-auto ${isError ? 'bg-destructive/10' : 'bg-muted/50'}`}>
                              {call.result}
                            </pre>
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          </ScrollArea>
        </CollapsibleContent>
      </Collapsible>
    </div>
  )
}

function TaskDetailSheet({ taskId, open, onOpenChange }: { taskId: string | null; open: boolean; onOpenChange: (open: boolean) => void }) {
  const { data: task, isLoading } = useTask(taskId || '')

  if (!open) return null

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full sm:max-w-xl md:max-w-2xl overflow-hidden flex flex-col p-0">
        {isLoading ? (
          <div className="flex items-center justify-center py-12 flex-1">
            <RefreshCw className="h-8 w-8 animate-spin text-primary" />
          </div>
        ) : !task ? (
          <div className="flex items-center justify-center py-12 flex-1 text-muted-foreground">
            任务未找到
          </div>
        ) : (
          <>
            <SheetHeader className="p-6 pb-4">
              <SheetTitle className="break-all pr-8">{task.file_name}</SheetTitle>
              <p className="text-sm text-muted-foreground font-mono break-all">{task.task_id}</p>
            </SheetHeader>

            <div className="px-6 py-4 border-b">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">分析进度</span>
                <span className="text-sm text-muted-foreground">
                  {Object.values(task.steps_progress || {}).filter((s: any) => s.status === 'completed').length}/
                  {Object.keys(task.steps_progress || {}).length || 1}
                </span>
              </div>
              <Progress 
                value={Math.round(
                  (Object.values(task.steps_progress || {}).filter((s: any) => s.status === 'completed').length / 
                  (Object.keys(task.steps_progress || {}).length || 1)) * 100
                )} 
                className="h-2" 
              />
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Badge variant={task.status === 'completed' ? 'default' : task.status === 'failed' ? 'destructive' : 'secondary'}>
                  {task.status === 'completed' ? '已完成' : task.status === 'failed' ? '失败' : task.current_step || '分析中'}
                </Badge>
                {task.file_type?.format && <Badge variant="outline">{task.file_type.format}</Badge>}
                {task.file_type?.platform && <Badge variant="outline">{task.file_type.platform}</Badge>}
                {task.file_type?.arch && <Badge variant="outline">{task.file_type.arch}</Badge>}
              </div>
            </div>

            <div className="flex-1 overflow-y-auto">
              <div className="space-y-6 px-6 py-4">
                <div>
                  <h4 className="text-sm font-medium mb-3">分析步骤</h4>
                  <div className="space-y-2">
                    {Object.entries(task.steps_progress || {})
                      .filter(([stepId]) => stepId !== 'ai_logs' && !GHIDRA_SUBSTEPS.includes(stepId))
                      .map(([stepId, stepData]) => {
                      const step = stepData as { status: string; updated_at?: string; preview?: any }
                      const isGhidraStep = stepId === 'ghidra'
                      const ghidraSubsteps = isGhidraStep 
                        ? GHIDRA_SUBSTEPS.map(subId => ({
                            id: subId,
                            ...(task.steps_progress as any)?.[subId]
                          })).filter(s => s.status)
                        : []
                      
                      return (
                        <div key={stepId}>
                          <div className="flex items-start gap-3 p-2 rounded-lg bg-muted/30">
                            <StepStatusIcon status={step.status} />
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center justify-between gap-2">
                                <span className="text-sm font-medium">{STEP_LABELS[stepId] || stepId}</span>
                                <span className="text-xs text-muted-foreground flex-shrink-0">
                                  {step.status === 'completed' ? '完成' : step.status === 'running' ? '运行中' : step.status === 'failed' ? '失败' : '等待'}
                                </span>
                              </div>
                              {step.preview && (
                                <div className="text-xs text-muted-foreground mt-1 space-y-0.5">
                                  {typeof step.preview === 'object' 
                                    ? Object.entries(step.preview).map(([k, v]) => (
                                        <div key={k} className="break-all"><span className="font-medium">{k}:</span> {String(v)}</div>
                                      ))
                                    : <div className="break-all">{String(step.preview)}</div>
                                  }
                                </div>
                              )}
                            </div>
                          </div>
                          {isGhidraStep && ghidraSubsteps.length > 0 && (
                            <div className="ml-7 mt-1 space-y-1 border-l-2 border-muted pl-3">
                              {ghidraSubsteps.map((sub) => (
                                <div key={sub.id} className="flex items-center gap-2 text-xs text-muted-foreground">
                                  <StepStatusIcon status={sub.status} />
                                  <span>{GHIDRA_SUBSTEP_LABELS[sub.id] || sub.id}</span>
                                  <span className="ml-auto">
                                    {sub.status === 'completed' ? '完成' : sub.status === 'running' ? '运行中' : sub.status === 'failed' ? '失败' : '等待'}
                                  </span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )
                    })}
                  </div>
                </div>

                <AILogsSection logs={(task.steps_progress as any)?.ai_logs} />

                {task.hashes && (
                  <div className="pt-4 border-t">
                    <h4 className="text-sm font-medium mb-3">文件哈希</h4>
                    <div className="space-y-2 text-xs font-mono bg-muted/30 p-3 rounded-lg">
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground w-16">MD5:</span>
                        <span className="break-all flex-1">{task.hashes.md5}</span>
                        <CopyButton text={task.hashes.md5} />
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground w-16">SHA1:</span>
                        <span className="break-all flex-1">{task.hashes.sha1}</span>
                        <CopyButton text={task.hashes.sha1} />
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-muted-foreground w-16">SHA256:</span>
                        <span className="break-all flex-1">{task.hashes.sha256}</span>
                        <CopyButton text={task.hashes.sha256} />
                      </div>
                      {task.hashes.ssdeep && (
                        <div className="flex items-center gap-2">
                          <span className="text-muted-foreground w-16">SSDEEP:</span>
                          <span className="break-all flex-1">{task.hashes.ssdeep}</span>
                          <CopyButton text={task.hashes.ssdeep} />
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {task.file_type && (
                  <div className="pt-4 border-t">
                    <h4 className="text-sm font-medium mb-3">文件类型</h4>
                    <div className="grid grid-cols-2 gap-2 text-sm bg-muted/30 p-3 rounded-lg">
                      <div><span className="text-muted-foreground">格式:</span> <span className="ml-1">{task.file_type.format || '-'}</span></div>
                      <div><span className="text-muted-foreground">架构:</span> <span className="ml-1">{task.file_type.arch || '-'}</span></div>
                      <div><span className="text-muted-foreground">类别:</span> <span className="ml-1">{task.file_type.category || '-'}</span></div>
                      <div><span className="text-muted-foreground">平台:</span> <span className="ml-1">{task.file_type.platform || '-'}</span></div>
                    </div>
                  </div>
                )}

                {task.yara?.matches && task.yara.matches.length > 0 && (
                  <div className="pt-4 border-t">
                    <h4 className="text-sm font-medium mb-3">YARA 匹配 ({task.yara.matches.length})</h4>
                    <div className="space-y-2">
                      {task.yara.matches.map((match: any, i: number) => (
                        <div key={i} className="p-3 rounded-lg bg-destructive/10 border border-destructive/20">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge variant="destructive">{match.rule}</Badge>
                            {match.namespace && <span className="text-xs text-muted-foreground">{match.namespace}</span>}
                          </div>
                          {match.meta && Object.keys(match.meta).length > 0 && (
                            <div className="text-xs space-y-1">
                              {Object.entries(match.meta).map(([k, v]) => (
                                <div key={k} className="break-all"><span className="text-muted-foreground">{k}:</span> {String(v)}</div>
                              ))}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {task.strings && (
                  <div className="pt-4 border-t">
                    <h4 className="text-sm font-medium mb-3">提取的字符串</h4>
                    <div className="space-y-3">
                      {task.strings.urls && task.strings.urls.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">URLs ({task.strings.urls.length})</span>
                          <div className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono space-y-1">
                            {task.strings.urls.map((url: string, i: number) => (
                              <div key={i} className="break-all">{url}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      {task.strings.domains && task.strings.domains.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">Domains ({task.strings.domains.length})</span>
                          <div className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono space-y-1">
                            {task.strings.domains.map((domain: string, i: number) => (
                              <div key={i} className="break-all">{domain}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      {task.strings.ips && task.strings.ips.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">IPs ({task.strings.ips.length})</span>
                          <div className="mt-1 p-2 bg-muted/30 rounded text-xs font-mono space-y-1">
                            {task.strings.ips.map((ip: string, i: number) => (
                              <div key={i} className="break-all">{ip}</div>
                            ))}
                          </div>
                        </div>
                      )}
                      {task.strings.suspicious && task.strings.suspicious.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">可疑字符串 ({task.strings.suspicious.length})</span>
                          <div className="mt-1 p-2 bg-amber-500/10 rounded text-xs font-mono space-y-1">
                            {task.strings.suspicious.map((s: string, i: number) => (
                              <div key={i} className="break-all">{s}</div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {task.dynamic_analysis && (
                  <div className="pt-4 border-t">
                    <h4 className="text-sm font-medium mb-3">动态分析</h4>
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-2 text-sm bg-muted/30 p-3 rounded-lg">
                        <div><span className="text-muted-foreground">方法:</span> <span className="ml-1">{task.dynamic_analysis.method || '-'}</span></div>
                        <div><span className="text-muted-foreground">事件数:</span> <span className="ml-1">{task.dynamic_analysis.raw_events_count || 0}</span></div>
                        <div><span className="text-muted-foreground">耗时:</span> <span className="ml-1">{task.dynamic_analysis.duration_seconds?.toFixed(2) || '-'}s</span></div>
                        <div><span className="text-muted-foreground">状态:</span> <span className="ml-1">{task.dynamic_analysis.success ? '成功' : '失败'}</span></div>
                      </div>

                      {task.dynamic_analysis.syscall_summary?.by_type && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">系统调用统计</span>
                          <div className="mt-1 flex flex-wrap gap-1">
                            {Object.entries(task.dynamic_analysis.syscall_summary.by_type).map(([name, count]) => (
                              <Badge key={name} variant="outline" className="text-xs">{name}: {String(count)}</Badge>
                            ))}
                          </div>
                        </div>
                      )}

                      {task.dynamic_analysis.network_summary && (
                        <div>
                          <span className="text-xs font-medium text-muted-foreground">网络活动</span>
                          <div className="mt-1 grid grid-cols-3 gap-2 text-xs bg-muted/30 p-2 rounded">
                            <div>DNS: {task.dynamic_analysis.network_summary.total_dns_queries || 0}</div>
                            <div>连接: {task.dynamic_analysis.network_summary.total_connections || 0}</div>
                            <div>HTTP: {task.dynamic_analysis.network_summary.http_requests?.length || 0}</div>
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {task.error && (
                  <div className="pt-4 border-t">
                    <h4 className="text-sm font-medium text-destructive mb-2">错误信息</h4>
                    <div className="p-3 bg-destructive/10 rounded-lg text-sm text-destructive break-all">{task.error}</div>
                  </div>
                )}
              </div>
            </div>

            <div className="p-6 pt-4 border-t">
              {task.status === 'completed' ? (
                <Button asChild className="w-full">
                  <Link to={`/report/${task.task_id}`}>
                    <Eye className="mr-2 h-4 w-4" />
                    查看完整报告
                  </Link>
                </Button>
              ) : (
                <p className="text-center text-sm text-muted-foreground">分析完成后可查看完整报告</p>
              )}
            </div>
          </>
        )}
      </SheetContent>
    </Sheet>
  )
}

function TaskStatusBadge({ status }: { status: string }) {
  const isRunning = RUNNING_STATUSES.includes(status)
  const isCompleted = status === 'completed'
  const isFailed = status === 'failed'
  const isPending = status === 'pending'

  return (
    <Badge
      variant={
        isCompleted ? 'default' 
        : isFailed ? 'destructive'
        : isRunning ? 'secondary' 
        : 'outline'
      }
    >
      {isCompleted ? '已完成' : isFailed ? '失败' : isRunning ? '分析中' : isPending ? '等待中' : status}
    </Badge>
  )
}

function TaskActions({ task, onViewDetail }: { task: TaskListItem; onViewDetail: () => void }) {
  const deleteTask = useDeleteTask()

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="h-8 w-8 p-0">
          <span className="sr-only">打开菜单</span>
          <MoreHorizontal className="h-4 w-4" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuItem onClick={onViewDetail}>
          <Eye className="mr-2 h-4 w-4" />
          查看详情
        </DropdownMenuItem>
        {task.status === 'completed' && (
          <DropdownMenuItem asChild>
            <Link to={`/report/${task.id}`}>
              <FileText className="mr-2 h-4 w-4" />
              查看报告
            </Link>
          </DropdownMenuItem>
        )}
        <DropdownMenuSeparator />
        <DropdownMenuItem
          className="text-destructive"
          onClick={() => deleteTask.mutate(task.id)}
          disabled={deleteTask.isPending}
        >
          <Trash2 className="mr-2 h-4 w-4" />
          删除任务
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}



export function TasksPage() {
  const location = useLocation()
  const newTask = (location.state as { newTask?: TaskListItem } | null)?.newTask
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(newTask?.id || null)
  const { data: fetchedTasks } = useTasks({ limit: 50 })

  const allTasks = useMemo(() => {
    if (!newTask) return fetchedTasks || []
    const tasks = fetchedTasks || []
    if (tasks.some(t => t.id === newTask.id)) return tasks
    return [newTask, ...tasks]
  }, [fetchedTasks, newTask])

  const columns = useMemo<ColumnDef<TaskListItem>[]>(() => [
    {
      accessorKey: 'file_name',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="文件名" />
      ),
      cell: ({ row }) => {
        const task = row.original
        const isRunning = RUNNING_STATUSES.includes(task.status)
        return (
          <div className="flex items-center gap-3">
            <div
              className={`relative flex h-9 w-9 flex-shrink-0 items-center justify-center rounded-lg ${
                isRunning ? 'bg-primary/10'
                  : task.status === 'pending' ? 'bg-amber-500/10'
                  : task.status === 'completed' ? 'bg-green-500/10'
                  : task.status === 'failed' ? 'bg-destructive/10'
                  : 'bg-muted'
              }`}
            >
              <FileText
                className={`h-4 w-4 ${
                  isRunning ? 'text-primary'
                    : task.status === 'pending' ? 'text-amber-500'
                    : task.status === 'completed' ? 'text-green-500'
                    : task.status === 'failed' ? 'text-destructive'
                    : 'text-muted-foreground'
                }`}
              />
              {isRunning && (
                <span className="absolute -right-0.5 -top-0.5 h-2.5 w-2.5 animate-pulse rounded-full bg-primary" />
              )}
            </div>
            <div className="min-w-0">
              <p className="font-medium truncate max-w-[200px]">{task.file_name}</p>
              <p className="text-xs text-muted-foreground font-mono truncate max-w-[200px]">{task.id}</p>
            </div>
          </div>
        )
      },
    },
    {
      accessorKey: 'status',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="状态" />
      ),
      cell: ({ row }) => <TaskStatusBadge status={row.original.status} />,
      filterFn: (row, id, value) => value.includes(row.getValue(id)),
    },
    {
      accessorKey: 'file_type',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="类型" />
      ),
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {row.original.file_type || '-'}
        </span>
      ),
    },
    {
      accessorKey: 'created_at',
      header: ({ column }) => (
        <DataTableColumnHeader column={column} title="创建时间" />
      ),
      cell: ({ row }) => (
        <span className="text-sm text-muted-foreground">
          {formatTimeAgo(row.original.created_at)}
        </span>
      ),
    },
    {
      id: 'actions',
      cell: ({ row }) => (
        <TaskActions 
          task={row.original} 
          onViewDetail={() => setSelectedTaskId(row.original.id)}
        />
      ),
    },
  ], [])

  const pendingTasks = allTasks.filter(t => t.status === 'pending')
  const runningTasks = allTasks.filter(t => RUNNING_STATUSES.includes(t.status))
  const completedTasks = allTasks.filter(t => t.status === 'completed')

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-6">
      <div className="grid gap-4 md:grid-cols-4">
        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-amber-500/10">
                <Clock className="h-5 w-5 text-amber-500" />
              </div>
              <div>
                <p className="text-2xl font-semibold">{pendingTasks.length}</p>
                <p className="text-sm text-muted-foreground">等待中</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10">
                {runningTasks.length > 0 ? (
                  <RefreshCw className="h-5 w-5 animate-spin text-primary" />
                ) : (
                  <RefreshCw className="h-5 w-5 text-primary" />
                )}
              </div>
              <div>
                <p className="text-2xl font-semibold">{runningTasks.length}</p>
                <p className="text-sm text-muted-foreground">分析中</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-purple-500/10">
                <Code className="h-5 w-5 text-purple-500" />
              </div>
              <div>
                <p className="text-2xl font-semibold">0</p>
                <p className="text-sm text-muted-foreground">Ghidra 队列</p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-green-500/10">
                <FileText className="h-5 w-5 text-green-500" />
              </div>
              <div>
                <p className="text-2xl font-semibold">{completedTasks.length}</p>
                <p className="text-sm text-muted-foreground">已完成</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader className="pb-3">
          <CardTitle>任务列表</CardTitle>
        </CardHeader>
        <CardContent>
          {allTasks.length > 0 ? (
            <DataTable 
              columns={columns} 
              data={allTasks}
              onRowClick={(row) => setSelectedTaskId(row.id)}
              pageSize={10}
            >
              {(table) => (
                <>
                  <DataTableToolbar 
                    table={table}
                    filterColumn="file_name"
                    filterPlaceholder="搜索文件名..."
                  />
                  <DataTablePagination table={table} showRowSelection={false} />
                </>
              )}
            </DataTable>
          ) : (
            <div className="py-12 text-center">
              <div className="mx-auto mb-4 flex h-16 w-16 items-center justify-center rounded-full bg-muted">
                <FileText className="h-8 w-8 text-muted-foreground" />
              </div>
              <h3 className="mb-2 text-lg font-medium">暂无任务</h3>
              <p className="mb-4 text-muted-foreground">上传文件开始新的分析</p>
              <Button asChild>
                <Link to="/">
                  <Plus className="mr-2 h-5 w-5" />
                  上传文件
                </Link>
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <TaskDetailSheet 
        taskId={selectedTaskId}
        open={!!selectedTaskId}
        onOpenChange={(open) => !open && setSelectedTaskId(null)}
      />
    </div>
  )
}
